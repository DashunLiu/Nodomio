//! Isolated verification of the control preparation and handoff protocol.
//!
//! The official installer supplies the preparation capability after checking
//! host readiness and authenticating the installation source.

use super::{
    FormalPackage, HealthConfirmationStore, InstallHost, InstallOperationResult, InstallPlan,
    InstallPublicationReadiness, LayoutEntry, ManagerEnablementEvidence, PlanError,
    ServiceManagerObservation,
    control::{LOCK_NAME, is_named_control, lock_identity},
    control_record::{
        ControlPhase, ControlRecord, ControlRecordError, PreparationClaim, advance_record,
        publish_claimed, read_record,
    },
    health_confirmation::boot_id,
    host::inspect_host,
    install_state::{
        InstallState, prepare_install_state, reopen_registration_state, reopen_service_start_state,
    },
    layout::{CONTROL_NAME, inspect_at, program_parent, state_parent},
    operation_journal::{
        Admission, BusinessPhase, InstallIntent, JournalError, OperationJournal,
        confirm_recovered_registration,
    },
    plan_store::{check_directory, check_file, effective_uid, open_at, same_inode, stat},
    readiness::ControlCapacity,
    registration::{PreparedRegistration, RegistrationAttemptError},
    registration_recovery::recover_original_registration,
    service_activation::ServiceActivation,
    service_readiness::{
        ManagerReadiness, ServiceDestination, inspect_at as inspect_service_at,
        protected_descendants,
    },
    staging::{
        PublicationContext, PublicationError, publish_formal_package, recover_formal_publication,
        verify_published_program,
    },
};
use crate::{
    execution::{ExecutionDomain, ExecutionError, Locked, Termination, WorkUnit},
    identity::{Enrollment, IdentityStore, Status, random_id},
    protocol::RegistrationMetadata,
    release::{
        binding::recheck_binding,
        github::{ReleaseClient, VerifiedRelease},
        manifest::{HostRequirements, ReleaseError},
    },
    runtime::RuntimeStore,
};
use std::{
    fs::File,
    io::{self, ErrorKind},
    os::{fd::AsRawFd, unix::process::ExitStatusExt},
    path::Path,
    sync::mpsc,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
enum PreparationError {
    Plan(PlanError),
    Layout,
    ExistingControl,
    ChangedControl,
    Io,
    Record(ControlRecordError),
    Execution(ExecutionError),
    Worker,
    Host,
    Release(ReleaseError),
    Service,
    DiskInsufficient,
    Journal(JournalError),
    Publication(PublicationError),
    Registration,
    Health,
}

enum ServiceStart {
    First,
    AfterReboot { was_enabled: bool },
}

struct AuthorizedPreparationIntent {
    plan: InstallPlan,
    record: ControlRecord,
}

impl AuthorizedPreparationIntent {
    fn for_fixture(plan: InstallPlan, key: &str) -> Result<Self, PreparationError> {
        let claim = PreparationClaim {
            operation_id: random_id().map_err(|_| PreparationError::Io)?,
            idempotency_key: key.into(),
            plan_id: plan.plan_id().into(),
            plan_digest: plan.digest().into(),
            installation_id: plan.target_id().into(),
            target: plan.target().clone(),
        };
        let domain_id = random_id().map_err(|_| PreparationError::Io)?;
        let record = ControlRecord::claimed(domain_id, claim).map_err(PreparationError::Record)?;
        Ok(Self { plan, record })
    }
}

struct PreparedControl {
    plan: InstallPlan,
    record: ControlRecord,
    parent: File,
    directory: File,
    lock: File,
    lock_id: (u64, u64),
    owner: libc::uid_t,
}

struct RecheckedInstall {
    verified: VerifiedRelease,
    package: Option<FormalPackage>,
}

struct PublishedInstall<'a> {
    journal: OperationJournal<'a>,
    service_sha256: [u8; 32],
}

struct IsolatedEnrollment<'a> {
    enrollment: Enrollment,
    metadata: &'a RegistrationMetadata,
    ca: &'a [u8],
    target_proof: Option<super::EnrollmentTargetProof>,
}

struct ReapedRegistrationWorker {
    operation_id: String,
    prior_boot_id: Option<String>,
}

impl ReapedRegistrationWorker {
    fn after_fixture_sigkill(
        operation_id: String,
        status: std::process::ExitStatus,
    ) -> Result<Self, PreparationError> {
        if status.signal() != Some(libc::SIGKILL) {
            return Err(PreparationError::Worker);
        }
        Ok(Self {
            operation_id,
            prior_boot_id: None,
        })
    }

    fn after_fixture_reboot(record: &ControlRecord) -> Result<Self, PreparationError> {
        let business = record.business().ok_or(PreparationError::Worker)?;
        business
            .pending_registration_id()
            .ok_or(PreparationError::Worker)?;
        let prior = business
            .registration_boot_id()
            .ok_or(PreparationError::Worker)?;
        if boot_id().map_err(|_| PreparationError::Worker)? == prior {
            return Err(PreparationError::Worker);
        }
        Ok(Self {
            operation_id: record.claim().operation_id.clone(),
            prior_boot_id: Some(prior.to_owned()),
        })
    }
}

fn check_layout(
    root: &File,
    owner: libc::uid_t,
    control: LayoutEntry,
) -> Result<(), PreparationError> {
    let layout = inspect_at(root, owner);
    if layout.program != LayoutEntry::Missing || layout.state != LayoutEntry::Missing {
        return Err(PreparationError::Layout);
    }
    match layout.control {
        observed if observed == control => Ok(()),
        LayoutEntry::Present if control == LayoutEntry::Missing => {
            Err(PreparationError::ExistingControl)
        }
        _ => Err(PreparationError::Layout),
    }
}

fn prepare_control(
    root: &File,
    intent: AuthorizedPreparationIntent,
    now_ms: impl Fn() -> u64,
) -> Result<PreparedControl, PreparationError> {
    let owner = effective_uid();
    intent
        .plan
        .check_validity(now_ms())
        .map_err(PreparationError::Plan)?;
    check_layout(root, owner, LayoutEntry::Missing)?;
    let parent = state_parent(root, owner).map_err(|_| PreparationError::Layout)?;
    let parent = open_at(&parent, c".", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| PreparationError::Io)?;
    // SAFETY: the trusted parent descriptor and the fixed component are live.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), CONTROL_NAME.as_ptr(), 0o700) } != 0 {
        return Err(match io::Error::last_os_error().kind() {
            ErrorKind::AlreadyExists => PreparationError::ExistingControl,
            _ => PreparationError::Io,
        });
    }
    let directory = open_at(&parent, CONTROL_NAME, libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| PreparationError::Io)?;
    check_directory(&directory, owner).map_err(|_| PreparationError::Layout)?;
    parent.sync_all().map_err(|_| PreparationError::Io)?;

    let lock_fd = open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| PreparationError::Io)?;
    let guard = Locked::acquire(lock_fd).map_err(PreparationError::Execution)?;
    if !is_named_control(&parent, &directory) {
        return Err(PreparationError::ChangedControl);
    }
    let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| PreparationError::Io)?;
    if entries.next().is_some() {
        return Err(PreparationError::ExistingControl);
    }
    check_layout(root, owner, LayoutEntry::Present)?;
    intent
        .plan
        .check_validity(now_ms())
        .map_err(PreparationError::Plan)?;
    publish_claimed(&directory, &intent.record).map_err(PreparationError::Record)?;
    let record = advance_record(&directory, &intent.record, ControlPhase::LockCreatePossible)
        .map_err(PreparationError::Record)?;

    // The one creation attempt is reachable only after the durable marker.
    let lock = open_at(
        &directory,
        LOCK_NAME,
        libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
    )
    .map_err(|_| PreparationError::Io)?;
    let opened = stat(&lock, None).map_err(|_| PreparationError::Io)?;
    check_file(&opened, owner).map_err(|_| PreparationError::ChangedControl)?;
    lock.sync_all().map_err(|_| PreparationError::Io)?;
    directory.sync_all().map_err(|_| PreparationError::Io)?;
    let named = stat(&directory, Some(LOCK_NAME)).map_err(|_| PreparationError::ChangedControl)?;
    if !same_inode(&named, &opened) || !is_named_control(&parent, &directory) {
        return Err(PreparationError::ChangedControl);
    }
    let record = advance_record(&directory, &record, ControlPhase::Ready)
        .map_err(PreparationError::Record)?;
    drop(guard);
    Ok(PreparedControl {
        plan: intent.plan,
        record,
        parent,
        directory,
        lock,
        lock_id: (opened.st_dev, opened.st_ino),
        owner,
    })
}

impl PreparedControl {
    fn open_fixture_before_publication(
        root: &File,
        plan: InstallPlan,
        operation_id: &str,
    ) -> Result<Self, PreparationError> {
        let opened = Self::open_fixture_control(root, plan, operation_id)?;
        if opened.record.business().is_some() {
            return Err(PreparationError::ChangedControl);
        }
        Ok(opened)
    }

    fn open_fixture_control(
        root: &File,
        plan: InstallPlan,
        operation_id: &str,
    ) -> Result<Self, PreparationError> {
        let owner = effective_uid();
        let parent = state_parent(root, owner).map_err(|_| PreparationError::Layout)?;
        let directory = open_at(&parent, CONTROL_NAME, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| PreparationError::ChangedControl)?;
        check_directory(&directory, owner).map_err(|_| PreparationError::ChangedControl)?;
        let record = read_record(&directory).map_err(PreparationError::Record)?;
        let claim = record.claim();
        if record.phase() != ControlPhase::Ready
            || claim.operation_id != operation_id
            || claim.plan_id != plan.plan_id()
            || claim.plan_digest != plan.digest()
            || claim.installation_id != plan.target_id()
            || &claim.target != plan.target()
        {
            return Err(PreparationError::ChangedControl);
        }
        let lock = open_at(&directory, LOCK_NAME, libc::O_RDONLY)
            .map_err(|_| PreparationError::ChangedControl)?;
        let opened = stat(&lock, None).map_err(|_| PreparationError::ChangedControl)?;
        let opened = Self {
            plan,
            record,
            parent,
            directory,
            lock,
            lock_id: (opened.st_dev, opened.st_ino),
            owner,
        };
        opened.check_current()?;
        Ok(opened)
    }

    fn check_anchor(&self) -> Result<(), PreparationError> {
        let opened = stat(&self.lock, None).map_err(|_| PreparationError::ChangedControl)?;
        check_file(&opened, self.owner).map_err(|_| PreparationError::ChangedControl)?;
        if !is_named_control(&self.parent, &self.directory)
            || lock_identity(&self.directory, self.owner) != Some(self.lock_id)
        {
            return Err(PreparationError::ChangedControl);
        }
        Ok(())
    }

    fn check_current(&self) -> Result<(), PreparationError> {
        self.check_anchor()?;
        if read_record(&self.directory).map_err(PreparationError::Record)? != self.record {
            return Err(PreparationError::ChangedControl);
        }
        Ok(())
    }

    fn recheck_release(
        self,
        root: File,
        control_path: &Path,
        mut client: ReleaseClient,
        archive: Option<File>,
        now_ms: impl Fn() -> u64 + Send + 'static,
    ) -> Result<VerifiedRelease, PreparationError> {
        let domain = ExecutionDomain::open_existing(control_path, self.owner)
            .map_err(PreparationError::Execution)?;
        if !domain.matches_prepared(&self.directory, self.lock_id) {
            return Err(PreparationError::ChangedControl);
        }
        let (send, receive) = mpsc::channel();
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let result = self
                .check_under_lease(&root, &mut client, archive.as_ref(), now_ms)
                .map(|checked| checked.verified);
            let _ = send.send(result);
            Ok(())
        })];
        let outcome = domain
            .start(&mut pending)
            .map_err(PreparationError::Execution)?
            .join();
        if outcome.termination != Termination::Completed {
            return Err(PreparationError::Worker);
        }
        receive.recv().map_err(|_| PreparationError::Worker)?
    }

    fn check_under_lease(
        &self,
        root: &File,
        client: &mut ReleaseClient,
        archive: Option<&File>,
        now_ms: impl Fn() -> u64,
    ) -> Result<RecheckedInstall, PreparationError> {
        self.check_current()?;
        let start = Instant::now();
        let before_ms = now_ms();
        let remaining = self
            .plan
            .remaining_ms(before_ms)
            .map_err(PreparationError::Plan)?;
        check_layout(root, self.owner, LayoutEntry::Present)?;
        let host = inspect_host();
        let requirements = fixture_requirements(&host)?;
        let (verified, package) = match archive {
            Some(archive) => {
                let (release, package) = self
                    .plan
                    .recheck_formal_apply(client, requirements, archive)
                    .map_err(PreparationError::Plan)?;
                (release, Some(package))
            }
            None if self.plan.has_package_binding() => {
                return Err(PreparationError::Plan(PlanError::PackageRequired));
            }
            None => (
                recheck_binding(client, self.plan.binding(), requirements)
                    .map_err(PreparationError::Release)?,
                None,
            ),
        };
        self.check_current()?;
        check_layout(root, self.owner, LayoutEntry::Present)?;
        if host != inspect_host() {
            return Err(PreparationError::Host);
        }
        let after_ms = now_ms();
        self.plan
            .check_validity(after_ms)
            .map_err(PreparationError::Plan)?;
        if after_ms < before_ms || start.elapsed() >= Duration::from_millis(remaining) {
            return Err(PreparationError::Plan(PlanError::StalePlan));
        }
        Ok(RecheckedInstall { verified, package })
    }

    fn publish_fixture(
        self,
        root: File,
        control_path: &Path,
        manager: super::ServiceManagerObservation,
        mut client: ReleaseClient,
        archive: File,
        now_ms: impl Fn() -> u64 + Send + 'static,
    ) -> Result<(), PreparationError> {
        let domain = ExecutionDomain::open_existing(control_path, self.owner)
            .map_err(PreparationError::Execution)?;
        if !domain.matches_prepared(&self.directory, self.lock_id) {
            return Err(PreparationError::ChangedControl);
        }
        let (send, receive) = mpsc::channel();
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let result = self
                .publish_under_lease(&root, manager, &mut client, &archive, now_ms)
                .map(|_| ());
            let _ = send.send(result);
            Ok(())
        })];
        if domain
            .start(&mut pending)
            .map_err(PreparationError::Execution)?
            .join()
            .termination
            != Termination::Completed
        {
            return Err(PreparationError::Worker);
        }
        receive.recv().map_err(|_| PreparationError::Worker)?
    }

    fn publish_under_lease(
        &self,
        root: &File,
        manager: super::ServiceManagerObservation,
        client: &mut ReleaseClient,
        archive: &File,
        now_ms: impl Fn() -> u64,
    ) -> Result<PublishedInstall<'_>, PreparationError> {
        self.publish_under_lease_with_hook(root, manager, client, archive, now_ms, || Ok(()))
    }

    fn publish_under_lease_with_hook(
        &self,
        root: &File,
        manager: ServiceManagerObservation,
        client: &mut ReleaseClient,
        archive: &File,
        now_ms: impl Fn() -> u64,
        after_program_published: impl FnOnce() -> Result<(), PublicationError>,
    ) -> Result<PublishedInstall<'_>, PreparationError> {
        ServiceActivation::check_manager_configuration(manager)
            .map_err(|_| PreparationError::Service)?;
        let checked = self.check_under_lease(root, client, Some(archive), &now_ms)?;
        let package = checked
            .package
            .ok_or(PreparationError::Plan(PlanError::PackageRequired))?;
        let service_sha256 = service_digest(&package, manager)?;
        let program = program_parent(root, self.owner).map_err(|_| PreparationError::Layout)?;
        let service = inspect_service_at(root, self.owner, manager, manager);
        let ServiceDestination::Missing {
            parent: service_parent,
            ..
        } = service.destination
        else {
            return Err(PreparationError::Service);
        };
        if service.manager != ManagerReadiness::InterfaceObserved {
            return Err(PreparationError::Service);
        }
        let state = state_parent(root, self.owner).map_err(|_| PreparationError::Layout)?;
        let capacity = InstallPublicationReadiness::from_held_targets(
            &package,
            manager,
            [&program, &state, &service_parent],
        );
        let enablement = ManagerEnablementEvidence::inspect_held_root(root, self.owner, manager);
        if capacity.definite_startup_shortage(
            &enablement,
            Some((ControlCapacity::Existing(&self.directory), false)),
        ) {
            return Err(PreparationError::DiskInsufficient);
        }
        self.check_current()?;
        let claim = self.record.claim();
        let worker_boot_id = boot_id().map_err(|_| PreparationError::Worker)?;
        let intent = InstallIntent::new(
            self.plan.plan_id(),
            self.plan.digest(),
            self.plan.target_id(),
            &claim.idempotency_key,
        )
        .map_err(PreparationError::Journal)?;
        self.plan
            .check_validity(now_ms())
            .map_err(PreparationError::Plan)?;
        let Admission::New(mut journal) =
            OperationJournal::begin(&self.directory, &self.record, &intent, now_ms())
                .map_err(PreparationError::Journal)?
        else {
            return Err(PreparationError::ChangedControl);
        };
        journal
            .advance(BusinessPhase::LocalPublicationPossible, now_ms())
            .map_err(PreparationError::Journal)?;
        if let Err(error) = publish_formal_package(
            &PublicationContext {
                control: &self.directory,
                program_parent: &program,
                service_parent: &service_parent,
                owner: self.owner,
                manager,
                operation_id: &claim.operation_id,
                plan_digest: &claim.plan_digest,
                release_id: checked.verified.target().release_id.as_str(),
            },
            archive,
            &package,
            &worker_boot_id,
            after_program_published,
        ) {
            journal
                .mark_unknown(now_ms())
                .map_err(PreparationError::Journal)?;
            return Err(PreparationError::Publication(error));
        }
        journal
            .advance(BusinessPhase::LocalPublished, now_ms())
            .map_err(PreparationError::Journal)?;
        Ok(PublishedInstall {
            journal,
            service_sha256,
        })
    }

    /// Internal reboot takeover for the existing operation while holding its
    /// reopened execution lease. The original approval and archive remain
    /// binding even if its plan expired after business admission.
    fn recover_publication_after_fixture_reboot(
        &self,
        root: &File,
        manager: ServiceManagerObservation,
        client: &mut ReleaseClient,
        archive: &File,
        now_ms: impl Fn() -> u64,
    ) -> Result<PublishedInstall<'_>, PreparationError> {
        self.check_current()?;
        let mut journal = OperationJournal::resume_local_publication(&self.directory, &self.record)
            .map_err(PreparationError::Journal)?;
        let host = inspect_host();
        if host.service_manager != manager {
            return Err(PreparationError::Host);
        }
        let (release, package) = self
            .plan
            .recheck_formal_apply(client, fixture_requirements(&host)?, archive)
            .map_err(PreparationError::Plan)?;
        self.check_current()?;
        if host != inspect_host() {
            return Err(PreparationError::Host);
        }
        let layout = inspect_at(root, self.owner);
        if layout.state != LayoutEntry::Missing
            || layout.control != LayoutEntry::Present
            || !matches!(layout.program, LayoutEntry::Missing | LayoutEntry::Present)
            || !stat(&self.directory, Some(c"supervisor.lock"))
                .is_err_and(|error| error.kind() == ErrorKind::NotFound)
        {
            return Err(PreparationError::Layout);
        }
        ServiceActivation::check_manager_configuration(manager)
            .map_err(|_| PreparationError::Service)?;
        let service = inspect_service_at(root, self.owner, manager, host.service_manager);
        if service.manager != ManagerReadiness::InterfaceObserved {
            return Err(PreparationError::Service);
        }
        let service_parent = match service.destination {
            ServiceDestination::Missing { parent, .. } => parent,
            ServiceDestination::Existing => {
                let components: &[_] = match manager {
                    ServiceManagerObservation::Systemd => &[c"etc", c"systemd", c"system"],
                    ServiceManagerObservation::OpenRc => &[c"etc", c"init.d"],
                    _ => return Err(PreparationError::Service),
                };
                protected_descendants(root, components, self.owner)
                    .map_err(|_| PreparationError::Service)?
            }
            _ => return Err(PreparationError::Service),
        };
        let program = program_parent(root, self.owner).map_err(|_| PreparationError::Layout)?;
        let claim = self.record.claim();
        let service_sha256 = service_digest(&package, manager)?;
        let current_boot_id = boot_id().map_err(|_| PreparationError::Worker)?;
        recover_formal_publication(
            &PublicationContext {
                control: &self.directory,
                program_parent: &program,
                service_parent: &service_parent,
                owner: self.owner,
                manager,
                operation_id: &claim.operation_id,
                plan_digest: &claim.plan_digest,
                release_id: release.target().release_id.as_str(),
            },
            &package,
            &current_boot_id,
        )
        .map_err(PreparationError::Publication)?;
        self.check_current()?;
        journal
            .advance(BusinessPhase::LocalPublished, now_ms())
            .map_err(PreparationError::Journal)?;
        Ok(PublishedInstall {
            journal,
            service_sha256,
        })
    }

    fn finish_isolated_install(
        &self,
        root: &File,
        manager: ServiceManagerObservation,
        published: PublishedInstall<'_>,
        input: IsolatedEnrollment<'_>,
        now_ms: impl Fn() -> u64,
    ) -> Result<InstallOperationResult, PreparationError> {
        const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
        let PublishedInstall {
            mut journal,
            service_sha256,
        } = published;
        journal
            .advance(BusinessPhase::SupervisorLockCreatePossible, now_ms())
            .map_err(PreparationError::Journal)?;
        let target = self.plan.target();
        let state = prepare_install_state(
            root,
            &self.directory,
            self.owner,
            target,
            self.plan.update_mode(),
            Some(input.ca),
        )
        .map_err(PreparationError::Publication)?;
        journal
            .advance(BusinessPhase::SupervisorLockReady, now_ms())
            .map_err(PreparationError::Journal)?;
        let identity_path = state.identity_path();
        let worker_boot = boot_id().map_err(|_| PreparationError::Registration)?;
        let prepared = PreparedRegistration::initialize(
            &identity_path,
            target.clone(),
            Some(input.ca),
            HTTP_TIMEOUT,
        )
        .map_err(|_| PreparationError::Registration)?;
        let identity = match prepared.register_once(
            input.enrollment,
            input.metadata,
            input
                .target_proof
                .as_ref()
                .map(|proof| proof.deployment_id()),
            |operation| {
                journal.mark_registration_possible_with_boot(
                    operation,
                    Some(&worker_boot),
                    now_ms(),
                )
            },
        ) {
            Ok(identity) => identity,
            Err(RegistrationAttemptError::OutcomeUnknown(_)) => {
                let expected = read_record(&self.directory).map_err(PreparationError::Record)?;
                if expected.claim() != self.record.claim() {
                    return Err(PreparationError::ChangedControl);
                }
                recover_original_registration(
                    &self.directory,
                    &expected,
                    state.directory(),
                    Some(input.ca),
                    HTTP_TIMEOUT,
                )
                .map_err(|_| PreparationError::Registration)?
            }
            Err(RegistrationAttemptError::Marker(error)) => {
                return Err(PreparationError::Journal(error));
            }
            Err(RegistrationAttemptError::Local(_)) => return Err(PreparationError::Registration),
        };
        let binding = identity.binding();
        journal
            .confirm_registration(binding, now_ms())
            .map_err(PreparationError::Journal)?;
        let activation = ServiceActivation::prepare(manager, &service_sha256)
            .map_err(|_| PreparationError::Service)?;
        self.activate_after_registration(activation, state, journal, now_ms)
    }

    fn recover_after_fixture_worker_exit(
        &self,
        root: &File,
        manager: ServiceManagerObservation,
        client: &mut ReleaseClient,
        archive: &File,
        ca: &[u8],
        reaped: ReapedRegistrationWorker,
        now_ms: impl Fn() -> u64,
    ) -> Result<InstallOperationResult, PreparationError> {
        if reaped.operation_id != self.record.claim().operation_id {
            return Err(PreparationError::Worker);
        }
        self.check_anchor()?;
        let expected = read_record(&self.directory).map_err(PreparationError::Record)?;
        if expected.phase() != ControlPhase::Ready
            || expected.control_domain_id() != self.record.control_domain_id()
            || expected.claim() != self.record.claim()
            || expected
                .business()
                .and_then(|business| business.pending_registration_id())
                .is_none()
        {
            return Err(PreparationError::ChangedControl);
        }
        if let Some(prior_boot) = &reaped.prior_boot_id
            && (expected
                .business()
                .and_then(|business| business.registration_boot_id())
                != Some(prior_boot.as_str())
                || boot_id().map_err(|_| PreparationError::Worker)? == *prior_boot)
        {
            return Err(PreparationError::Worker);
        }
        let host = inspect_host();
        if host.service_manager != manager {
            return Err(PreparationError::Host);
        }
        let (release, package) = self
            .plan
            .recheck_formal_apply(client, fixture_requirements(&host)?, archive)
            .map_err(PreparationError::Plan)?;
        let parent = program_parent(root, self.owner).map_err(|_| PreparationError::Layout)?;
        verify_published_program(
            &parent,
            self.owner,
            release.target().release_id.as_str(),
            &package,
        )
        .map_err(PreparationError::Publication)?;
        let service_sha256 = service_digest(&package, manager)?;
        let activation = ServiceActivation::prepare(manager, &service_sha256)
            .map_err(|_| PreparationError::Service)?;
        let state = reopen_registration_state(
            root,
            &self.directory,
            self.owner,
            self.plan.target(),
            self.plan.update_mode(),
            ca,
        )
        .map_err(PreparationError::Publication)?;
        self.check_anchor()?;
        let (_, journal) = confirm_recovered_registration(
            &self.directory,
            &expected,
            state.directory(),
            Some(ca),
            Duration::from_secs(5),
            &now_ms,
        )
        .map_err(|_| PreparationError::Registration)?;
        self.activate_after_registration(activation, state, journal, now_ms)
    }

    /// Test-only takeover under the original execution lease, after a real
    /// cold boot. Never sends registration or re-publishes the program.
    fn recover_service_after_fixture_reboot(
        &self,
        root: &File,
        manager: ServiceManagerObservation,
        client: &mut ReleaseClient,
        archive: &File,
        ca: &[u8],
        now_ms: impl Fn() -> u64,
    ) -> Result<InstallOperationResult, PreparationError> {
        self.check_current()?;
        if !ServiceActivation::supports(manager) {
            return Err(PreparationError::Service);
        }
        let mut journal = OperationJournal::reopen_pending_service(&self.directory, &self.record)
            .map_err(PreparationError::Journal)?;
        let host = inspect_host();
        if host.service_manager != manager {
            return Err(PreparationError::Host);
        }
        let (release, package) = self
            .plan
            .recheck_formal_apply(client, fixture_requirements(&host)?, archive)
            .map_err(PreparationError::Plan)?;
        let program = program_parent(root, self.owner).map_err(|_| PreparationError::Layout)?;
        verify_published_program(
            &program,
            self.owner,
            release.target().release_id.as_str(),
            &package,
        )
        .map_err(PreparationError::Publication)?;
        let activation =
            ServiceActivation::prepare_recovery(manager, &service_digest(&package, manager)?)
                .map_err(|_| PreparationError::Service)?;
        let allow_disabled = journal.phase() == BusinessPhase::ServiceStartPossible;
        // OpenRC can still be draining the template's three 2-second
        // respawns. The cold path grants no startup window while it is live.
        let observation_deadline = Instant::now()
            + Duration::from_secs(if manager == ServiceManagerObservation::OpenRc {
                12
            } else {
                5
            });
        let enabled = loop {
            match activation.cold_enabled(allow_disabled) {
                Ok(enabled) => break enabled,
                Err(_) if Instant::now() < observation_deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => return Err(PreparationError::Service),
            }
        };
        let target = self.plan.target();
        let (state, supervisor_guard) = reopen_service_start_state(
            root,
            &self.directory,
            self.owner,
            target,
            self.plan.update_mode(),
            ca,
        )
        .map_err(PreparationError::Publication)?;
        let identity = IdentityStore::open(&state.identity_path(), target)
            .map_err(|_| PreparationError::Registration)?;
        if identity.status() != Status::Bound
            || Some(identity.operation_id()) != journal.registration_operation_id()
            || identity.binding() != journal.registration_binding()
        {
            return Err(PreparationError::Registration);
        }
        let host_path = std::path::PathBuf::from(format!(
            "/proc/self/fd/{}/runtime",
            state.directory().as_raw_fd()
        ));
        RuntimeStore::preflight_first_health(&host_path, &identity)
            .map_err(|_| PreparationError::Health)?;
        let prior_health = HealthConfirmationStore::open(
            state.health.try_clone().map_err(|_| PreparationError::Io)?,
        )
        .map_err(|_| PreparationError::Health)?;
        prior_health
            .check_previous_boot(
                target,
                identity.binding().ok_or(PreparationError::Registration)?,
                identity.operation_id(),
            )
            .map_err(|_| PreparationError::Health)?;
        drop(identity);
        self.check_current()?;
        if inspect_host() != host || activation.cold_enabled(allow_disabled) != Ok(enabled) {
            return Err(PreparationError::Service);
        }
        let startup = journal
            .renew_service_window(now_ms())
            .map_err(PreparationError::Journal)?;
        drop(supervisor_guard);
        self.start_and_verify(
            activation,
            state,
            journal,
            startup,
            ServiceStart::AfterReboot {
                was_enabled: enabled,
            },
            now_ms,
        )
    }

    fn activate_after_registration(
        &self,
        activation: ServiceActivation,
        state: InstallState,
        mut journal: OperationJournal<'_>,
        now_ms: impl Fn() -> u64,
    ) -> Result<InstallOperationResult, PreparationError> {
        let startup = super::StartupWindow::start().map_err(|_| PreparationError::Health)?;
        journal
            .mark_service_start_possible(startup.clone(), now_ms())
            .map_err(PreparationError::Journal)?;
        self.start_and_verify(
            activation,
            state,
            journal,
            startup,
            ServiceStart::First,
            now_ms,
        )
    }

    fn start_and_verify(
        &self,
        activation: ServiceActivation,
        state: InstallState,
        mut journal: OperationJournal<'_>,
        startup: super::StartupWindow,
        start_mode: ServiceStart,
        now_ms: impl Fn() -> u64,
    ) -> Result<InstallOperationResult, PreparationError> {
        let target = self.plan.target();
        let binding = journal
            .registration_binding()
            .ok_or(PreparationError::Registration)?
            .clone();
        let identity_operation_id = journal
            .registration_operation_id()
            .ok_or(PreparationError::Registration)?
            .to_owned();
        let private_state = state
            .directory()
            .try_clone()
            .map_err(|_| PreparationError::Io)?;
        let store =
            HealthConfirmationStore::open(state.health).map_err(|_| PreparationError::Health)?;
        let minimum_start = startup.started_ns();
        let (need_enable, recover_enabled) = match start_mode {
            ServiceStart::First => (true, false),
            ServiceStart::AfterReboot { was_enabled } => (!was_enabled, was_enabled),
        };
        if need_enable {
            startup.remaining().map_err(|_| PreparationError::Health)?;
            activation.enable().map_err(|_| PreparationError::Service)?;
        }
        startup.remaining().map_err(|_| PreparationError::Health)?;
        let started = activation
            .start(recover_enabled)
            .map_err(|_| PreparationError::Service)?;
        if journal.phase() == BusinessPhase::ServiceStartPossible {
            journal
                .advance(BusinessPhase::Verifying, now_ms())
                .map_err(PreparationError::Journal)?;
        }
        loop {
            startup.remaining().map_err(|_| PreparationError::Health)?;
            if let Ok(proof) = store.verify_for_install(
                target,
                &binding,
                &identity_operation_id,
                minimum_start,
                super::StartupWindow::DURATION,
            ) && started.main_pid == Some(proof.supervisor_pid())
            {
                let current = activation
                    .observe_started()
                    .map_err(|_| PreparationError::Service)?;
                if current != started {
                    return Err(PreparationError::Health);
                }
                assert_first_health_storage(&private_state)?;
                startup.remaining().map_err(|_| PreparationError::Health)?;
                return journal
                    .settle_success(now_ms())
                    .map_err(PreparationError::Journal);
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
}

fn assert_first_health_storage(state: &File) -> Result<(), PreparationError> {
    let held = format!("/proc/self/fd/{}", state.as_raw_fd());
    let path = Path::new(&held);
    if std::fs::read_dir(path.join("ssh-queue"))
        .map_err(|_| PreparationError::Io)?
        .next()
        .is_some()
    {
        return Err(PreparationError::Health);
    }
    let manifest =
        std::fs::read(path.join("runtime/runtime.json")).map_err(|_| PreparationError::Io)?;
    let value: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|_| PreparationError::Health)?;
    if manifest.len() > crate::runtime::FIRST_HEALTH_MANIFEST_MAX_BYTES
        || value.get("latest") != Some(&serde_json::Value::Null)
        || value.get("inflight") != Some(&serde_json::Value::Null)
        || !value
            .get("configuration")
            .is_some_and(serde_json::Value::is_object)
        || path.join("runtime/runtime.next").exists()
    {
        return Err(PreparationError::Health);
    }
    Ok(())
}

fn service_digest(
    package: &FormalPackage,
    manager: ServiceManagerObservation,
) -> Result<[u8; 32], PreparationError> {
    let index = match manager {
        ServiceManagerObservation::Systemd => 3,
        ServiceManagerObservation::OpenRc => 4,
        _ => return Err(PreparationError::Service),
    };
    package
        .members
        .get(index)
        .and_then(|member| decode_digest(&member.sha256))
        .ok_or(PreparationError::Service)
}

fn decode_digest(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut digest = [0; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn fixture_requirements(host: &InstallHost) -> Result<HostRequirements, PreparationError> {
    Ok(HostRequirements {
        platform: host.platform.ok_or(PreparationError::Host)?,
        kernel: host
            .kernel
            .as_ref()
            .and_then(|kernel| kernel.version)
            .ok_or(PreparationError::Host)?,
        libc: host.libc,
        // The fixture declares these formats in its manifest. Production values
        // must come from the actual installer and supervisor.
        wire_protocol: 1,
        supervisor_protocol: 1,
        config_format: 1,
        queue_format: 1,
    })
}

#[cfg(test)]
#[path = "preparation_reboot_tests.rs"]
mod reboot_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation::{
            InstallControlObservation, InstallPlanInput, InstallPlanStore, InstallPreflight,
            InstallPreparationLookup, PackageInspectionError, control,
            operation_journal::{lookup_apply, lookup_status},
            package::{fixture_formal_archive, package_file},
        },
        release::{github::ReleaseReadOptions, github_tests::Fixture, manifest::GithubReleaseId},
    };
    use std::{
        fs::{self, Permissions},
        io::{BufRead, BufReader},
        os::unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    const KEY: &str = "5a3efbee-8dbb-4a56-96b5-0d8dbf98dca0";
    const OTHER_KEY: &str = "63d9e8cb-e5ff-4900-9a77-ec97abe1a7dd";
    const NOW: u64 = 1_700_000_000_123;
    const EXPIRES: u64 = NOW + 600_000;
    const EXACT_PATH: &str = "/repos/DashunLiu/Nodomio/releases/123";

    struct Sandbox {
        directory: tempfile::TempDir,
        root: File,
    }

    impl Sandbox {
        fn new() -> Self {
            Self::at(tempfile::tempdir().unwrap())
        }

        fn at(directory: tempfile::TempDir) -> Self {
            fs::create_dir(directory.path().join("opt")).unwrap();
            fs::create_dir_all(directory.path().join("var/lib")).unwrap();
            let root = File::open(directory.path()).unwrap();
            Self { directory, root }
        }

        fn control(&self) -> PathBuf {
            self.directory.path().join("var/lib/nodomi-agent-control")
        }

        fn inspect(&self) -> InstallControlObservation {
            control::inspect_at(&self.root, effective_uid())
        }

        fn systemd(&self) -> UnixListener {
            let root = self.directory.path();
            fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
            fs::create_dir_all(root.join("run/systemd/system")).unwrap();
            fs::create_dir_all(root.join("usr/bin")).unwrap();
            let tool = root.join("usr/bin/systemctl");
            fs::write(&tool, b"fixture command").unwrap();
            fs::set_permissions(tool, Permissions::from_mode(0o755)).unwrap();
            let socket = root.join("run/systemd/private");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(socket, Permissions::from_mode(0o600)).unwrap();
            listener
        }

        fn plan(&self, release: &VerifiedRelease) -> InstallPlan {
            InstallPlan::create(
                InstallPlanInput {
                    management_origin: "https://management.example.test",
                    expected_server_id: "server-fixture",
                    release_id: release.target().release_id.as_str(),
                    update_mode: None,
                },
                release,
                InstallPreflight {
                    host: inspect_host(),
                    layout: inspect_at(&self.root, effective_uid()),
                },
                NOW,
            )
            .unwrap()
        }

        fn prepare(&self, release: &VerifiedRelease) -> PreparedControl {
            let intent = AuthorizedPreparationIntent::for_fixture(self.plan(release), KEY).unwrap();
            prepare_control(&self.root, intent, || NOW).unwrap()
        }

        fn lookup(&self, key: &str, plan: &InstallPlan, digest: &str) -> InstallPreparationLookup {
            control::lookup_at(
                &self.root,
                effective_uid(),
                key,
                plan.plan_id(),
                plan.target_id(),
                digest,
            )
        }

        fn recheck(
            &self,
            prepared: PreparedControl,
            fixture: &Fixture,
            now_ms: impl Fn() -> u64 + Send + 'static,
        ) -> Result<VerifiedRelease, PreparationError> {
            prepared.recheck_release(
                self.root.try_clone().unwrap(),
                &self.control(),
                fixture.client(ReleaseReadOptions::default()),
                None,
                now_ms,
            )
        }
    }

    fn release_fixture(scenario: &str) -> (Fixture, VerifiedRelease) {
        let requirements = fixture_requirements(&inspect_host()).unwrap();
        let fixture = Fixture::for_platform(scenario, requirements.platform);
        let release = fixture
            .client(ReleaseReadOptions::default())
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        (fixture, release)
    }

    fn exact_reads(fixture: &Fixture) -> usize {
        fixture
            .paths()
            .iter()
            .filter(|path| path.as_str() == EXACT_PATH)
            .count()
    }

    pub(super) struct FixtureProcess(pub(super) Child);

    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "writes fixed paths only inside an isolated systemd acceptance container"]
    fn systemd_first_install_reaches_health_after_original_registration() {
        isolated_first_install(ServiceManagerObservation::Systemd, "systemd");
    }

    #[test]
    #[ignore = "writes fixed paths only inside an isolated OpenRC acceptance container"]
    fn openrc_first_install_reaches_health_after_original_registration() {
        isolated_first_install(ServiceManagerObservation::OpenRc, "openrc");
    }

    fn isolated_first_install(manager: ServiceManagerObservation, fixture_name: &str) {
        assert_eq!(
            std::env::var("NODOMI_ISOLATED_FIRST_INSTALL").as_deref(),
            Ok(fixture_name)
        );
        assert!(Path::new("/.dockerenv").exists());
        assert_eq!(effective_uid(), 0);
        assert_eq!(inspect_host().service_manager, manager);
        assert!(ServiceActivation::supports(manager));
        let root = super::super::layout::open_root().unwrap();
        check_layout(&root, 0, LayoutEntry::Missing).unwrap();
        let scenario =
            std::env::var("NODOMI_INSTALL_FIXTURE_SCENARIO").unwrap_or_else(|_| "healthy".into());
        assert!(matches!(
            scenario.as_str(),
            "healthy" | "lost-registration-response" | "hold-registration-response"
        ));
        let kill_worker = scenario == "hold-registration-response";
        assert!(!kill_worker || manager == ServiceManagerObservation::Systemd);
        let temporary = tempfile::tempdir().unwrap();
        let fixture_script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/https_service.py");
        let mut management = FixtureProcess(
            Command::new("/usr/bin/python3")
                .arg(fixture_script)
                .arg(temporary.path())
                .args(["0", &scenario])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(management.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line.trim().parse().unwrap();
        let origin = format!("https://localhost:{port}");
        let ca = include_bytes!("../../tests/fixtures/tls/ca.pem");
        let token = temporary.path().join("enrollment");
        fs::write(&token, format!("ndme_{}", "A".repeat(43))).unwrap();
        fs::set_permissions(&token, Permissions::from_mode(0o400)).unwrap();
        let requirements = fixture_requirements(&inspect_host()).unwrap();
        let archive_path = Path::new("/first-install-arm64.tar.gz");
        let release_fixture =
            Fixture::with_artifact(requirements.platform, &fs::read(archive_path).unwrap());
        let mut client = release_fixture.client(ReleaseReadOptions::default());
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: &origin,
                expected_server_id: "server-1",
                release_id: release.target().release_id.as_str(),
                update_mode: Some(super::super::InstallUpdateMode::Manual),
            },
            &release,
            Some(ca),
            File::open(archive_path).unwrap(),
        )
        .unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        client.download(&release, &mut archive).unwrap();
        let metadata = fixture_metadata(manager);
        let plans = temporary.path().join("plans");
        fs::create_dir(&plans).unwrap();
        fs::set_permissions(&plans, Permissions::from_mode(0o700)).unwrap();
        InstallPlanStore::open(File::open(&plans).unwrap())
            .unwrap()
            .save(&plan)
            .unwrap();
        let plan_id = plan.plan_id().to_owned();
        let intent = AuthorizedPreparationIntent::for_fixture(plan, KEY).unwrap();
        let operation_id = intent.record.claim().operation_id.clone();
        let target_id = intent.record.claim().installation_id.clone();
        let prepared = prepare_control(&root, intent, fixture_now).unwrap();
        let control = Path::new("/var/lib/nodomi-agent-control");
        let domain = ExecutionDomain::open_existing(control, 0).unwrap();
        assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
        let observed_path = temporary.path().join("service-observations.json");
        let reaped = if kill_worker {
            Some(kill_registration_worker(
                &domain,
                &prepared,
                &plans,
                &plan_id,
                release_fixture.origin(),
                &token,
                &observed_path,
            ))
        } else {
            None
        };
        let enrollment = if kill_worker {
            assert!(!token.exists());
            None
        } else {
            Some(take_enrollment(&token))
        };
        let (send, receive) = mpsc::channel();
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let result = (|| {
                if let Some(reaped) = reaped {
                    return prepared.recover_after_fixture_worker_exit(
                        &root,
                        manager,
                        &mut client,
                        &archive,
                        ca,
                        reaped,
                        fixture_now,
                    );
                }
                let published = prepared.publish_under_lease(
                    &root,
                    manager,
                    &mut client,
                    &archive,
                    fixture_now,
                )?;
                prepared.finish_isolated_install(
                    &root,
                    manager,
                    published,
                    IsolatedEnrollment {
                        enrollment: enrollment.ok_or(PreparationError::Registration)?,
                        metadata: &metadata,
                        ca,
                        target_proof: None,
                    },
                    fixture_now,
                )
            })();
            let _ = send.send(result);
            Ok(())
        })];
        assert_eq!(
            domain.start(&mut pending).unwrap().join().termination,
            Termination::Completed
        );
        let result = receive.recv().unwrap().unwrap();
        assert_eq!(result.exit_code(), 0);
        assert_eq!(
            super::super::lookup_install_operation(&operation_id, &target_id),
            Ok(result)
        );
        let state = Path::new("/var/lib/nodomi-agent");
        assert_eq!(
            fs::read(state.join("update-mode.json")).unwrap(),
            br#"{"updateMode":"MANUAL"}"#
        );
        let events: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(observed_path).unwrap()).unwrap();
        let count = |kind: &str| events.iter().filter(|row| row["kind"] == kind).count();
        assert_eq!(count("registration"), 1);
        assert!(
            count("identity")
                >= if scenario == "lost-registration-response" || kill_worker {
                    2
                } else {
                    1
                }
        );
        assert!(count("heartbeat") > 0 && count("receipt") > 0 && count("metric") > 0);
        println!(
            "isolated {fixture_name} {scenario} completed original install with {} identity reads",
            count("identity")
        );
    }

    pub(super) fn fixture_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn fixture_metadata(manager: ServiceManagerObservation) -> RegistrationMetadata {
        let (distribution, version) = if manager == ServiceManagerObservation::OpenRc {
            ("alpine", "3.23")
        } else {
            ("debian", "12")
        };
        serde_json::from_value(serde_json::json!({
            "version":"0.1.0", "architecture":"ARM64", "distribution":distribution,
            "distributionVersion":version, "hostname":"fixture-first-install",
            "capabilities":{"system":"AVAILABLE","processes":"UNSUPPORTED",
                            "containers":"UNSUPPORTED","sshEvents":"UNSUPPORTED"}
        }))
        .unwrap()
    }

    fn take_enrollment(path: &Path) -> Enrollment {
        let enrollment = Enrollment::from_private_file(path).unwrap();
        fs::remove_file(path).unwrap();
        enrollment
    }

    fn kill_registration_worker(
        domain: &ExecutionDomain,
        prepared: &PreparedControl,
        plans: &Path,
        plan_id: &str,
        release_origin: &str,
        token: &Path,
        observed_path: &Path,
    ) -> ReapedRegistrationWorker {
        let operation_id = prepared.record.claim().operation_id.clone();
        let mut child =
            spawn_registration_worker(&operation_id, plans, plan_id, release_origin, token);
        let pending = wait_registration_pending(&mut child, domain, prepared, observed_path);
        child.0.kill().unwrap();
        let reaped =
            ReapedRegistrationWorker::after_fixture_sigkill(operation_id, child.0.wait().unwrap())
                .unwrap();
        assert_eq!(read_record(&prepared.directory).unwrap(), pending);
        let claim = pending.claim();
        let status =
            super::super::lookup_install_operation(&claim.operation_id, &claim.installation_id)
                .unwrap();
        assert_eq!(status.exit_code(), 6);
        assert_eq!(status.operation_id(), claim.operation_id);
        assert_eq!(read_record(&prepared.directory).unwrap(), pending);
        reaped
    }

    pub(super) fn spawn_registration_worker(
        operation_id: &str,
        plans: &Path,
        plan_id: &str,
        release_origin: &str,
        token: &Path,
    ) -> FixtureProcess {
        FixtureProcess(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "installation::preparation::tests::isolated_registration_worker_for_sigkill",
                    "--ignored",
                    "--exact",
                ])
                .env("NODOMI_INSTALL_TEST_CHILD_PLANS", plans)
                .env("NODOMI_INSTALL_TEST_CHILD_PLAN_ID", plan_id)
                .env("NODOMI_INSTALL_TEST_CHILD_OPERATION", operation_id)
                .env("NODOMI_INSTALL_TEST_CHILD_RELEASE_ORIGIN", release_origin)
                .env("NODOMI_INSTALL_TEST_CHILD_ENROLLMENT", token)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    pub(super) fn wait_registration_pending(
        child: &mut FixtureProcess,
        domain: &ExecutionDomain,
        prepared: &PreparedControl,
        observed_path: &Path,
    ) -> ControlRecord {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "registration worker exited early"
            );
            if let Ok(bytes) = fs::read(observed_path)
                && let Ok(events) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
                && events.iter().any(|row| row["kind"] == "registration")
            {
                break;
            }
            assert!(Instant::now() < deadline, "missing committed registration");
            thread::sleep(Duration::from_millis(15));
        }
        let pending = read_record(&prepared.directory).unwrap();
        assert_eq!(pending.claim(), prepared.record.claim());
        assert!(
            pending
                .business()
                .unwrap()
                .pending_registration_id()
                .is_some()
        );
        let expected_identity = pending
            .business()
            .unwrap()
            .pending_registration_id()
            .unwrap();
        let identity_bytes = fs::read("/var/lib/nodomi-agent/identity/identity.json").unwrap();
        let identity: serde_json::Value = serde_json::from_slice(&identity_bytes).unwrap();
        assert_eq!(identity["operationId"], expected_identity);
        assert_eq!(identity["status"], "UNCERTAIN");
        let mut must_not_run: Vec<WorkUnit> =
            vec![Box::new(|| panic!("live installer still owns the lease"))];
        assert!(matches!(
            domain.start(&mut must_not_run),
            Err(ExecutionError::Busy)
        ));
        pending
    }

    #[test]
    #[ignore = "child of the isolated SIGKILL first-install acceptance"]
    fn isolated_registration_worker_for_sigkill() {
        assert!(Path::new("/.dockerenv").exists() || reboot_tests::inside_reboot_fixture());
        assert_eq!(
            std::env::var("NODOMI_ISOLATED_FIRST_INSTALL").as_deref(),
            Ok("systemd")
        );
        assert!(matches!(
            std::env::var("NODOMI_INSTALL_FIXTURE_SCENARIO").as_deref(),
            Ok("hold-registration-response" | "reboot-registration")
        ));
        let plans = std::env::var_os("NODOMI_INSTALL_TEST_CHILD_PLANS").unwrap();
        let plan_id = std::env::var("NODOMI_INSTALL_TEST_CHILD_PLAN_ID").unwrap();
        let operation_id = std::env::var("NODOMI_INSTALL_TEST_CHILD_OPERATION").unwrap();
        let origin = std::env::var("NODOMI_INSTALL_TEST_CHILD_RELEASE_ORIGIN").unwrap();
        let token =
            PathBuf::from(std::env::var_os("NODOMI_INSTALL_TEST_CHILD_ENROLLMENT").unwrap());
        let ca = include_bytes!("../../tests/fixtures/tls/ca.pem");
        let plan = InstallPlanStore::open(File::open(plans).unwrap())
            .unwrap()
            .load(&plan_id)
            .unwrap();
        let root = super::super::layout::open_root().unwrap();
        let prepared =
            PreparedControl::open_fixture_before_publication(&root, plan, &operation_id).unwrap();
        let domain =
            ExecutionDomain::open_existing(Path::new("/var/lib/nodomi-agent-control"), 0).unwrap();
        assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
        let mut client =
            ReleaseClient::for_fixture(&origin, ca, ReleaseReadOptions::default()).unwrap();
        let archive = File::open("/first-install-arm64.tar.gz").unwrap();
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let manager = ServiceManagerObservation::Systemd;
            let enrollment = take_enrollment(&token);
            let target_proof = if reboot_tests::inside_reboot_fixture() {
                let local = super::super::target_admission::inspect_target_admission(
                    &prepared.plan,
                    &inspect_host(),
                    manager,
                    Some(ca),
                )
                .unwrap();
                let proof = local
                    .prove_remote(&enrollment, reboot_tests::DEPLOYMENT)
                    .unwrap();
                assert_eq!(proof.binding_revision(), 1);
                Some(proof)
            } else {
                None
            };
            let published = prepared
                .publish_under_lease(&root, manager, &mut client, &archive, fixture_now)
                .unwrap();
            let input = IsolatedEnrollment {
                enrollment,
                metadata: &fixture_metadata(manager),
                ca,
                target_proof,
            };
            let result =
                prepared.finish_isolated_install(&root, manager, published, input, fixture_now);
            panic!("registration worker should have been reaped, observed {result:?}");
        })];
        let outcome = domain.start(&mut pending).unwrap().join();
        panic!("registration worker unexpectedly returned {outcome:?}");
    }

    #[test]
    fn formal_apply_publishes_only_under_the_original_journal_and_replays_read_only() {
        use super::super::ServiceManagerObservation::Systemd;
        let requirements = fixture_requirements(&inspect_host()).unwrap();
        let bytes = fixture_formal_archive(requirements.platform, b"fixture\n");
        let fixture = Fixture::with_artifact(requirements.platform, &bytes);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let sandbox = Sandbox::new();
        let _interface = sandbox.systemd();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: "https://127.0.0.1:1",
                expected_server_id: "server-fixture",
                release_id: release.target().release_id.as_str(),
                update_mode: None,
            },
            &release,
            None,
            package_file(&bytes),
        )
        .unwrap();
        let intent =
            InstallIntent::new(plan.plan_id(), plan.digest(), plan.target_id(), KEY).unwrap();
        let conflict =
            InstallIntent::new(plan.plan_id(), plan.digest(), plan.target_id(), OTHER_KEY).unwrap();
        let installation_id = plan.target_id().to_owned();
        let authorized = AuthorizedPreparationIntent::for_fixture(plan, KEY).unwrap();
        let operation_id = authorized.record.claim().operation_id.clone();
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        };
        let prepared = prepare_control(&sandbox.root, authorized, now).unwrap();
        let mut held_archive = tempfile::tempfile().unwrap();
        client.download(&release, &mut held_archive).unwrap();
        prepared
            .publish_fixture(
                sandbox.root.try_clone().unwrap(),
                &sandbox.control(),
                Systemd,
                client,
                held_archive,
                now,
            )
            .unwrap();
        let root = sandbox.directory.path();
        assert!(root.join("opt/nodomi-agent/bin/nodomi-agentctl").is_file());
        assert_eq!(
            fs::read(root.join("etc/systemd/system/nodomi-agent.service")).unwrap(),
            b"fixture\n"
        );
        assert!(!root.join("var/lib/nodomi-agent").exists());
        let control = File::open(sandbox.control()).unwrap();
        let before = fs::read(sandbox.control().join("control.json")).unwrap();
        assert_eq!(
            read_record(&control).unwrap().business().unwrap().phase(),
            BusinessPhase::LocalPublished
        );
        let result = lookup_apply(&control, &intent).unwrap().unwrap();
        assert_eq!(result.exit_code(), 6);
        assert_eq!(result.operation_id(), operation_id);
        assert_eq!(
            lookup_status(&control, &operation_id, &installation_id).unwrap(),
            Some(result)
        );
        assert_eq!(
            lookup_apply(&control, &conflict),
            Err(JournalError::OtherIntent)
        );
        assert_eq!(
            fs::read(sandbox.control().join("control.json")).unwrap(),
            before
        );
    }

    #[test]
    #[ignore = "requires an isolated inode-limited tmpfs at /install-lease-capacity-fixture"]
    fn lease_rechecks_shared_inodes_before_admission_and_allows_retry() {
        use super::super::{ServiceManagerObservation::Systemd, observe_directory};

        let requirements = fixture_requirements(&inspect_host()).unwrap();
        let bytes = fixture_formal_archive(requirements.platform, b"fixture\n");
        let fixture = Fixture::with_artifact(requirements.platform, &bytes);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let sandbox = Sandbox::at(tempfile::tempdir_in("/install-lease-capacity-fixture").unwrap());
        let _interface = sandbox.systemd();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: "https://127.0.0.1:1",
                expected_server_id: "server-fixture",
                release_id: release.target().release_id.as_str(),
                update_mode: None,
            },
            &release,
            None,
            package_file(&bytes),
        )
        .unwrap();
        let plans = tempfile::tempdir().unwrap();
        fs::set_permissions(plans.path(), Permissions::from_mode(0o700)).unwrap();
        let store = InstallPlanStore::open(File::open(plans.path()).unwrap()).unwrap();
        store.save(&plan).unwrap();
        let plan_id = plan.plan_id().to_owned();
        let authorized = AuthorizedPreparationIntent::for_fixture(plan, KEY).unwrap();
        let operation_id = authorized.record.claim().operation_id.clone();
        let prepared = prepare_control(&sandbox.root, authorized, fixture_now).unwrap();
        let record_path = sandbox.control().join("control.json");
        let initial = fs::read(&record_path).unwrap();

        let free = observe_directory(&sandbox.root)
            .unwrap()
            .available_inodes
            .unwrap();
        assert!((27..=256).contains(&free));
        let held = sandbox.directory.path();
        let fillers: Vec<_> = (0..free - 26)
            .map(|n| held.join(format!("filler-{n}")))
            .collect();
        for name in &fillers {
            File::create_new(name).unwrap();
        }
        assert_eq!(
            observe_directory(&sandbox.root).unwrap().available_inodes,
            Some(26)
        );
        assert_eq!(
            prepared.publish_fixture(
                sandbox.root.try_clone().unwrap(),
                &sandbox.control(),
                Systemd,
                client,
                package_file(&bytes),
                fixture_now,
            ),
            Err(PreparationError::DiskInsufficient)
        );
        assert_eq!(fs::read(&record_path).unwrap(), initial);
        assert_eq!(fs::read_dir(held.join("opt")).unwrap().count(), 0);
        assert_eq!(
            fs::read_dir(held.join("etc/systemd/system"))
                .unwrap()
                .count(),
            0
        );
        assert!(!held.join("var/lib/nodomi-agent").exists());

        fs::remove_file(&fillers[0]).unwrap();
        assert_eq!(
            observe_directory(&sandbox.root).unwrap().available_inodes,
            Some(27)
        );
        let plan = store.load(&plan_id).unwrap();
        let original =
            PreparedControl::open_fixture_before_publication(&sandbox.root, plan, &operation_id)
                .unwrap();
        original
            .publish_fixture(
                sandbox.root.try_clone().unwrap(),
                &sandbox.control(),
                Systemd,
                fixture.client(ReleaseReadOptions::default()),
                package_file(&bytes),
                fixture_now,
            )
            .unwrap();
        let record = read_record(&File::open(sandbox.control()).unwrap()).unwrap();
        assert_eq!(record.claim().operation_id, operation_id);
        assert_eq!(
            record.business().unwrap().phase(),
            BusinessPhase::LocalPublished
        );
    }

    #[test]
    fn formal_apply_revalidates_the_persisted_package_inside_the_execution_lease() {
        let requirements = fixture_requirements(&inspect_host()).unwrap();
        let bytes = fixture_formal_archive(requirements.platform, b"fixture\n");
        let changed = fixture_formal_archive(requirements.platform, b"changed\n");
        let fixture = Fixture::with_artifact(requirements.platform, &bytes);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        client.download(&release, &mut archive).unwrap();

        for (candidate, expected) in [
            (Some(archive), Ok(())),
            (
                Some(package_file(&changed)),
                Err(PreparationError::Plan(PlanError::Package(
                    PackageInspectionError::DigestMismatch,
                ))),
            ),
            (
                None,
                Err(PreparationError::Plan(PlanError::PackageRequired)),
            ),
        ] {
            let sandbox = Sandbox::new();
            let plans = tempfile::tempdir().unwrap();
            fs::set_permissions(plans.path(), Permissions::from_mode(0o700)).unwrap();
            let store = InstallPlanStore::open(File::open(plans.path()).unwrap()).unwrap();
            let plan = InstallPlan::inspect_formal_and_create(
                InstallPlanInput {
                    management_origin: "https://127.0.0.1:1",
                    expected_server_id: "server-fixture",
                    release_id: release.target().release_id.as_str(),
                    update_mode: None,
                },
                &release,
                None,
                package_file(&bytes),
            )
            .unwrap();
            store.save(&plan).unwrap();
            let loaded = store.load(plan.plan_id()).unwrap();
            let now = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
            };
            loaded
                .check_confirmation(plan.plan_id(), plan.target_id(), plan.digest(), now())
                .unwrap();
            let intent = AuthorizedPreparationIntent::for_fixture(loaded, KEY).unwrap();
            let prepared = prepare_control(&sandbox.root, intent, now).unwrap();
            let journal = sandbox.control().join("control.json");
            let before = fs::read(&journal).unwrap();
            let previous_reads = exact_reads(&fixture);
            let expected_reads = if candidate.is_some() { 2 } else { 0 };
            let checked = prepared.recheck_release(
                sandbox.root.try_clone().unwrap(),
                &sandbox.control(),
                fixture.client(ReleaseReadOptions::default()),
                candidate,
                now,
            );
            if let Ok(ref checked) = checked {
                assert_eq!(checked.target(), release.target());
            }
            assert_eq!(checked.map(|_| ()), expected);
            assert_eq!(exact_reads(&fixture), previous_reads + expected_reads);
            assert_eq!(fs::read(journal).unwrap(), before);
            assert_eq!(sandbox.inspect(), InstallControlObservation::Prepared);
        }
    }

    #[test]
    fn original_lookup_and_exact_release_handoff_preserve_control_bytes() {
        let (fixture, release) = release_fixture("happy");
        let sandbox = Sandbox::new();
        assert_eq!(sandbox.inspect(), InstallControlObservation::Missing);
        let plans = tempfile::tempdir().unwrap();
        fs::set_permissions(plans.path(), Permissions::from_mode(0o700)).unwrap();
        let store = InstallPlanStore::open(File::open(plans.path()).unwrap()).unwrap();
        let plan = sandbox.plan(&release);
        store.save(&plan).unwrap();
        let loaded = store.load(plan.plan_id()).unwrap();
        loaded
            .check_confirmation(plan.plan_id(), plan.target_id(), plan.digest(), NOW)
            .unwrap();
        let intent = AuthorizedPreparationIntent::for_fixture(loaded, KEY).unwrap();
        let prepared = prepare_control(&sandbox.root, intent, || NOW).unwrap();
        assert_eq!(sandbox.inspect(), InstallControlObservation::Prepared);
        let control = sandbox.control();
        let journal = control.join("control.json");
        let snapshot = (
            fs::read(&journal).unwrap(),
            fs::metadata(&journal).unwrap().ino(),
        );
        assert_eq!(fs::read_dir(&control).unwrap().count(), 2);
        assert_eq!(fs::metadata(&control).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(
            fs::metadata(control.join("execution.lock")).unwrap().mode() & 0o7777,
            0o600
        );

        assert_eq!(
            sandbox.lookup(&KEY.to_uppercase(), &prepared.plan, prepared.plan.digest()),
            InstallPreparationLookup::Original {
                operation_id: prepared.record.claim().operation_id.clone(),
                control: InstallControlObservation::Prepared,
            }
        );
        assert_eq!(
            sandbox.lookup(KEY, &prepared.plan, &"0".repeat(64)),
            InstallPreparationLookup::ConflictingConfirmation
        );
        assert_eq!(
            sandbox.lookup(OTHER_KEY, &prepared.plan, prepared.plan.digest()),
            InstallPreparationLookup::OtherPendingIntent
        );
        assert_eq!(
            sandbox.lookup("invalid", &prepared.plan, prepared.plan.digest()),
            InstallPreparationLookup::InvalidConfirmation
        );
        assert_eq!(exact_reads(&fixture), 2);

        let rechecked = sandbox.recheck(prepared, &fixture, || NOW + 1).unwrap();
        assert_eq!(rechecked.target(), release.target());
        let paths = fixture.paths();
        assert_eq!(exact_reads(&fixture), 4);
        assert!(
            paths
                .iter()
                .all(|p| p != "/repos/DashunLiu/Nodomio/releases" && !p.ends_with("/latest"))
        );
        assert_eq!(
            (
                fs::read(&journal).unwrap(),
                fs::metadata(&journal).unwrap().ino()
            ),
            snapshot
        );
    }

    #[test]
    fn two_preparations_cannot_replace_the_original_claim() {
        let (_, release) = release_fixture("happy");
        let sandbox = Sandbox::new();
        let left = AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), KEY).unwrap();
        let right =
            AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), OTHER_KEY).unwrap();
        let ready = Barrier::new(2);
        let root = &sandbox.root;
        let (left, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                ready.wait();
                prepare_control(root, left, || NOW)
            });
            let right = scope.spawn(|| {
                ready.wait();
                prepare_control(root, right, || NOW)
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        let prepared = match (left, right) {
            (Ok(winner), Err(PreparationError::ExistingControl))
            | (Err(PreparationError::ExistingControl), Ok(winner)) => winner,
            _ => panic!("expected one durable original claim"),
        };
        assert_eq!(read_record(&prepared.directory).unwrap(), prepared.record);
        assert_eq!(fs::read_dir(sandbox.control()).unwrap().count(), 2);
    }

    #[test]
    fn expired_unclaimed_directory_and_symlink_are_never_adopted() {
        let (_, release) = release_fixture("happy");
        let sandbox = Sandbox::new();
        let intent = AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), KEY).unwrap();
        let reads = AtomicUsize::new(0);
        assert!(matches!(
            prepare_control(&sandbox.root, intent, || {
                if reads.fetch_add(1, Ordering::Relaxed) == 0 {
                    NOW
                } else {
                    EXPIRES
                }
            }),
            Err(PreparationError::Plan(PlanError::StalePlan))
        ));
        assert_eq!(
            sandbox.inspect(),
            InstallControlObservation::RecoveryRequired
        );
        let directory = sandbox.control();
        let inode = fs::metadata(&directory).unwrap().ino();
        let intent =
            AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), OTHER_KEY).unwrap();
        assert!(matches!(
            prepare_control(&sandbox.root, intent, || NOW),
            Err(PreparationError::ExistingControl)
        ));
        assert_eq!(fs::metadata(&directory).unwrap().ino(), inode);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

        let original = directory.with_extension("unclaimed");
        fs::rename(&directory, &original).unwrap();
        symlink(&original, &directory).unwrap();
        assert_eq!(sandbox.inspect(), InstallControlObservation::Unsafe);
        let intent =
            AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), OTHER_KEY).unwrap();
        assert!(matches!(
            prepare_control(&sandbox.root, intent, || NOW),
            Err(PreparationError::Layout)
        ));
        assert_eq!(fs::metadata(&original).unwrap().ino(), inode);
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    }

    #[test]
    fn interrupted_lock_creation_is_read_only_even_when_structurally_openable() {
        let (_, release) = release_fixture("happy");
        let sandbox = Sandbox::new();
        let intent = AuthorizedPreparationIntent::for_fixture(sandbox.plan(&release), KEY).unwrap();
        let path = sandbox.control();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        let control = File::open(&path).unwrap();
        let guard = Locked::acquire(control.try_clone().unwrap()).unwrap();
        publish_claimed(&control, &intent.record).unwrap();
        let marked =
            advance_record(&control, &intent.record, ControlPhase::LockCreatePossible).unwrap();
        drop(guard);
        assert_eq!(
            sandbox.inspect(),
            InstallControlObservation::RecoveryRequired
        );
        assert_eq!(
            sandbox.lookup(KEY, &intent.plan, intent.plan.digest()),
            InstallPreparationLookup::Original {
                operation_id: marked.claim().operation_id.clone(),
                control: InstallControlObservation::RecoveryRequired,
            }
        );
        assert!(matches!(
            prepare_control(&sandbox.root, intent, || NOW),
            Err(PreparationError::ExistingControl)
        ));
        assert!(!path.join("execution.lock").exists());
        assert_eq!(read_record(&control).unwrap(), marked);

        open_at(
            &control,
            LOCK_NAME,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
        )
        .unwrap();
        assert!(ExecutionDomain::open_existing(&path, effective_uid()).is_ok());
        assert_eq!(
            sandbox.inspect(),
            InstallControlObservation::RecoveryRequired
        );
        assert_eq!(read_record(&control).unwrap(), marked);
    }

    #[test]
    fn busy_replaced_lock_and_expired_plan_cannot_recheck_or_repair() {
        let (fixture, release) = release_fixture("happy");
        let sandbox = Sandbox::new();
        let prepared = sandbox.prepare(&release);
        let guard = Locked::acquire(
            open_at(
                &prepared.directory,
                c".",
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            sandbox.recheck(prepared, &fixture, || NOW),
            Err(PreparationError::Execution(ExecutionError::Busy))
        ));
        drop(guard);

        let sandbox = Sandbox::new();
        let prepared = sandbox.prepare(&release);
        let path = sandbox.control();
        fs::rename(path.join("execution.lock"), path.join("old.lock")).unwrap();
        open_at(
            &prepared.directory,
            LOCK_NAME,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
        )
        .unwrap();
        assert!(matches!(
            sandbox.recheck(prepared, &fixture, || NOW),
            Err(PreparationError::ChangedControl)
        ));

        let sandbox = Sandbox::new();
        let prepared = sandbox.prepare(&release);
        let confirmation = (
            prepared.plan.plan_id().to_owned(),
            prepared.plan.target_id().to_owned(),
            prepared.plan.digest().to_owned(),
        );
        assert!(matches!(
            sandbox.recheck(prepared, &fixture, || EXPIRES),
            Err(PreparationError::Plan(PlanError::StalePlan))
        ));
        assert!(matches!(
            control::lookup_at(
                &sandbox.root,
                effective_uid(),
                KEY,
                &confirmation.0,
                &confirmation.1,
                &confirmation.2
            ),
            InstallPreparationLookup::Original { .. }
        ));
        assert_eq!(exact_reads(&fixture), 2);
    }

    #[test]
    fn checks_expiry_rollback_and_release_changes_after_https_request() {
        let (fixture, release) = release_fixture("happy");
        for end in [EXPIRES, NOW] {
            let sandbox = Sandbox::new();
            let prepared = sandbox.prepare(&release);
            let reads = AtomicUsize::new(0);
            assert!(matches!(
                sandbox.recheck(prepared, &fixture, move || {
                    if reads.fetch_add(1, Ordering::Relaxed) == 0 {
                        NOW + 5
                    } else {
                        end
                    }
                }),
                Err(PreparationError::Plan(PlanError::StalePlan))
            ));
            assert_eq!(sandbox.inspect(), InstallControlObservation::Prepared);
        }
        assert_eq!(exact_reads(&fixture), 6);

        let platform = release.target().platform;
        let delayed = Fixture::for_platform("control-deadline", platform);
        let sandbox = Sandbox::new();
        let prepared = sandbox.prepare(&release);
        assert!(matches!(
            sandbox.recheck(prepared, &delayed, || EXPIRES - 1),
            Err(PreparationError::Plan(PlanError::StalePlan))
        ));
        assert_eq!(exact_reads(&delayed), 2);

        let fixture = Fixture::for_platform("binding-program-id", platform);
        let sandbox = Sandbox::new();
        let prepared = sandbox.prepare(&release);
        assert!(matches!(
            sandbox.recheck(prepared, &fixture, || NOW),
            Err(PreparationError::Release(ReleaseError::ReleaseChanged))
        ));
        assert_eq!(exact_reads(&fixture), 2);
        assert_eq!(sandbox.inspect(), InstallControlObservation::Prepared);
    }
}
