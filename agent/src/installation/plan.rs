use super::{
    FilesystemObservation, FormalPackage, InstallFilesystemReadiness, InstallPreflight,
    InstallPublicationReadiness, LayoutEntry, PackageInspectionError, ServiceManagerObservation,
    ServiceObservation, inspect_filesystem_readiness, inspect_first_install,
    package::{FORMAL_MEMBER_COUNT, formal_member_lengths_valid, verify_formal_package},
};
use crate::{
    client::ProtocolClient,
    identity::{Target, random_id, uuid},
    release::{
        binding::{
            PlanInstallation, PlanTargetContext, ReleasePlanBinding, bind_release, public_target,
            recheck_binding,
        },
        github::{ReleaseClient, VerifiedRelease},
        manifest::{HostRequirements, Platform, PlatformCompatibility, ReleaseError},
    },
};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::OffsetDateTime;

pub(super) const MAX_PLAN_BYTES: usize = 16 * 1024;
const VALID_FOR_MS: u64 = 10 * 60 * 1_000;
const LEGACY_VERSION: u32 = 1;
const READINESS_VERSION: u32 = 2;
const FORMAL_PACKAGE_VERSION: u32 = 3;
const PUBLICATION_READINESS_VERSION: u32 = 4;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    InvalidTarget,
    ReleaseMismatch,
    Release(ReleaseError),
    Package(PackageInspectionError),
    PackageRequired,
    PackageMismatch,
    InvalidProbeOptions,
    InvalidTime,
    RandomSource,
    InvalidRecord,
    ConfirmationMismatch,
    StalePlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallUpdateMode {
    Auto,
    Manual,
}

/// Non-secret inputs from the install request. Enrollment is handled at apply.
pub struct InstallPlanInput<'a> {
    pub management_origin: &'a str,
    pub expected_server_id: &'a str,
    pub release_id: &'a str,
    pub update_mode: Option<InstallUpdateMode>,
}

/// An immutable install proposal. The plan owner checks readiness and repeats
/// local and remote preconditions before admitting an operation.
pub struct InstallPlan(PlanEnvelope);

impl InstallPlan {
    /// Build a version 1 plan from supplied observations without live probes.
    /// New installation workflows should use inspect_and_create.
    pub fn create(
        input: InstallPlanInput<'_>,
        release: &VerifiedRelease,
        preflight: InstallPreflight,
        now_unix_ms: u64,
    ) -> Result<Self, PlanError> {
        let target = plan_target(&input, release)?;
        Self::create_record(
            target,
            input.update_mode,
            release,
            preflight,
            None,
            now_unix_ms,
            None,
        )
    }

    /// Collect current local facts and verify HTTPS to the configured origin.
    /// This is a read-only check. Remote identity and binding are verified by
    /// the enrollment owner, and apply repeats its required preconditions.
    pub fn inspect_and_create(
        input: InstallPlanInput<'_>,
        release: &VerifiedRelease,
        explicit_ca: Option<&[u8]>,
    ) -> Result<Self, PlanError> {
        Self::inspect(input, release, explicit_ca, None)
    }

    /// Inspect an already opened formal archive and bind its member facts to
    /// the plan along with the release and local observations.
    pub fn inspect_formal_and_create(
        input: InstallPlanInput<'_>,
        release: &VerifiedRelease,
        explicit_ca: Option<&[u8]>,
        archive: File,
    ) -> Result<Self, PlanError> {
        Self::inspect(input, release, explicit_ca, Some(archive))
    }

    fn inspect(
        input: InstallPlanInput<'_>,
        release: &VerifiedRelease,
        explicit_ca: Option<&[u8]>,
        archive: Option<File>,
    ) -> Result<Self, PlanError> {
        let target = plan_target(&input, release)?;
        let inspection = archive
            .map(|file| verify_formal_package(file, release).map_err(PlanError::Package))
            .transpose()?;
        let package = inspection
            .as_ref()
            .map(InstallPackageBinding::from_inspection)
            .transpose()?;
        let tls_verified = ProtocolClient::verify_tls_origin(&target, explicit_ca, PROBE_TIMEOUT)
            .map_err(|_| PlanError::InvalidProbeOptions)?;
        let tls_origin = if tls_verified {
            TlsObservation::Verified
        } else {
            TlsObservation::Unverified
        };
        let preflight = inspect_first_install();
        let readiness = InstallReadiness {
            platform: release.platform_compatibility(
                preflight.host.platform,
                preflight
                    .host
                    .kernel
                    .as_ref()
                    .and_then(|kernel| kernel.version),
                preflight.host.libc,
            ),
            filesystem: inspect_filesystem_readiness(),
            tls_origin,
            publication: inspection.as_ref().map(|package| {
                InstallPublicationReadiness::inspect(package, preflight.host.service_manager)
            }),
        };
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(PlanError::InvalidTime)?;
        Self::create_record(
            target,
            input.update_mode,
            release,
            preflight,
            Some(readiness),
            now_unix_ms,
            package,
        )
    }

    fn create_record(
        target: Target,
        update_mode: Option<InstallUpdateMode>,
        release: &VerifiedRelease,
        preflight: InstallPreflight,
        readiness: Option<InstallReadiness>,
        now_unix_ms: u64,
        package: Option<InstallPackageBinding>,
    ) -> Result<Self, PlanError> {
        let expires_at_unix_ms = deadline(now_unix_ms)?;
        let plan_id = random_id().map_err(|_| PlanError::RandomSource)?;
        let target_id = random_id().map_err(|_| PlanError::RandomSource)?;
        if plan_id == target_id {
            return Err(PlanError::RandomSource);
        }
        let context = PlanTargetContext::new(
            PlanInstallation::FreshInstall {
                installation_id: target_id.clone(),
            },
            expires_at_unix_ms,
        )
        .map_err(|_| PlanError::InvalidTime)?;
        let checks = install_checks(&preflight, release.target().platform, readiness.as_ref());
        let record = PlanRecord {
            version: match (&readiness, &package) {
                (Some(readiness), Some(_)) if readiness.publication.is_some() => {
                    PUBLICATION_READINESS_VERSION
                }
                (Some(_), Some(_)) => FORMAL_PACKAGE_VERSION,
                (Some(_), None) => READINESS_VERSION,
                (None, None) => LEGACY_VERSION,
                (None, Some(_)) => return Err(PlanError::InvalidRecord),
            },
            action: Action::AgentInstall,
            layout: Layout::V1,
            plan_id,
            target_id,
            target,
            update_mode: update_mode.unwrap_or(InstallUpdateMode::Auto),
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            preflight,
            checks,
            effects: [Effect::RegisterAgent],
            binding: bind_release(release, &context),
            readiness,
            package,
        };
        Self::seal(record)
    }

    fn seal(record: PlanRecord) -> Result<Self, PlanError> {
        let plan_digest = plan_digest(&record)?;
        let plan = Self(PlanEnvelope {
            record,
            plan_digest,
        });
        plan.encode()?;
        Ok(plan)
    }

    pub fn plan_id(&self) -> &str {
        &self.0.record.plan_id
    }

    pub fn target_id(&self) -> &str {
        &self.0.record.target_id
    }

    pub fn digest(&self) -> &str {
        &self.0.plan_digest
    }

    pub fn target(&self) -> &Target {
        &self.0.record.target
    }

    pub fn update_mode(&self) -> InstallUpdateMode {
        self.0.record.update_mode
    }

    pub fn binding(&self) -> &ReleasePlanBinding {
        &self.0.record.binding
    }

    pub fn publication_readiness(&self) -> Option<&InstallPublicationReadiness> {
        self.0.record.readiness.as_ref()?.publication.as_ref()
    }

    pub(super) fn service_manager(&self) -> ServiceManagerObservation {
        self.0.record.preflight.host.service_manager
    }

    /// Refresh the bound numeric release and revalidate the already open
    /// archive. The apply owner holds its execution lease during this check.
    pub fn recheck_formal_apply(
        &self,
        client: &mut ReleaseClient,
        host: HostRequirements,
        archive: &File,
    ) -> Result<(VerifiedRelease, FormalPackage), PlanError> {
        if self.0.record.package.is_none() {
            return Err(PlanError::PackageRequired);
        }
        let release = recheck_binding(client, self.binding(), host).map_err(PlanError::Release)?;
        let package = self.verify_apply_package(&release, archive)?;
        Ok((release, package))
    }

    pub(super) fn verify_apply_package(
        &self,
        release: &VerifiedRelease,
        archive: &File,
    ) -> Result<FormalPackage, PlanError> {
        let expected = self
            .0
            .record
            .package
            .as_ref()
            .ok_or(PlanError::PackageRequired)?;
        if bind_release(release, self.binding().context()) != *self.binding() {
            return Err(PlanError::ReleaseMismatch);
        }
        let file = archive
            .try_clone()
            .map_err(|_| PlanError::Package(PackageInspectionError::Io))?;
        let inspection = verify_formal_package(file, release).map_err(PlanError::Package)?;
        if InstallPackageBinding::from_inspection(&inspection)? != *expected {
            return Err(PlanError::PackageMismatch);
        }
        Ok(inspection)
    }

    #[cfg(test)]
    pub(super) fn has_package_binding(&self) -> bool {
        self.0.record.package.is_some()
    }

    /// Check the confirmed plan identifiers, digest, and validity interval.
    /// Operation admission separately checks readiness, live state and the journal.
    pub fn check_confirmation(
        &self,
        plan_id: &str,
        confirm_target_id: &str,
        digest: &str,
        now_unix_ms: u64,
    ) -> Result<(), PlanError> {
        self.match_confirmation(plan_id, confirm_target_id, digest)?;
        self.check_validity(now_unix_ms)
    }

    pub(super) fn match_confirmation(
        &self,
        plan_id: &str,
        confirm_target_id: &str,
        digest: &str,
    ) -> Result<(), PlanError> {
        if self.plan_id() != plan_id
            || self.target_id() != confirm_target_id
            || self.digest() != digest
        {
            return Err(PlanError::ConfirmationMismatch);
        }
        Ok(())
    }

    pub(super) fn check_validity(&self, now_unix_ms: u64) -> Result<(), PlanError> {
        self.remaining_ms(now_unix_ms).map(|_| ())
    }

    pub(super) fn remaining_ms(&self, now_unix_ms: u64) -> Result<u64, PlanError> {
        let record = &self.0.record;
        if !(record.created_at_unix_ms..record.expires_at_unix_ms).contains(&now_unix_ms) {
            return Err(PlanError::StalePlan);
        }
        Ok(record.expires_at_unix_ms - now_unix_ms)
    }

    /// The existing LocalPlan fields. The resolved update mode is available
    /// through update_mode() for the install review UI.
    pub fn preview(&self) -> InstallPlanPreview<'_> {
        let record = &self.0.record;
        let state = if record
            .checks
            .iter()
            .any(|check| check.status == Status::Blocked)
        {
            State::Blocked
        } else {
            State::Unknown
        };
        InstallPlanPreview {
            plan_id: self.plan_id(),
            action: record.action,
            target_id: self.target_id(),
            plan_digest: self.digest(),
            expires_at: timestamp(record.expires_at_unix_ms)
                .expect("plan deadlines are validated at creation and load"),
            state,
            checks: &record.checks,
            effects: &record.effects,
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, PlanError> {
        let bytes = serde_json::to_vec(&self.0).map_err(|_| PlanError::InvalidRecord)?;
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(PlanError::InvalidRecord);
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, PlanError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(PlanError::InvalidRecord);
        }
        let envelope: PlanEnvelope =
            serde_json::from_slice(bytes).map_err(|_| PlanError::InvalidRecord)?;
        let plan = Self(envelope);
        let record = &plan.0.record;
        let target_matches =
            canonical_target(&record.target.origin, &record.target.expected_server_id)
                .is_ok_and(|target| target == record.target);
        if !matches!(
            (
                record.version,
                &record.readiness,
                &record.package,
                plan.publication_readiness()
            ),
            (LEGACY_VERSION, None, None, None)
                | (READINESS_VERSION, Some(_), None, None)
                | (FORMAL_PACKAGE_VERSION, Some(_), Some(_), None)
                | (PUBLICATION_READINESS_VERSION, Some(_), Some(_), Some(_))
        ) || !publication_facts_consistent(record)
            || record
                .package
                .as_ref()
                .is_some_and(|package| !package.valid())
            || !valid_plan_id(&record.plan_id)
            || !valid_plan_id(&record.target_id)
            || record.plan_id == record.target_id
            || !target_matches
            || deadline(record.created_at_unix_ms) != Ok(record.expires_at_unix_ms)
            || record.binding.context().expires_at_unix_ms() != record.expires_at_unix_ms
            || !matches!(
                record.binding.context().installation(),
                PlanInstallation::FreshInstall { installation_id }
                    if installation_id == &record.target_id
            )
            || record.checks
                != install_checks(
                    &record.preflight,
                    record.binding.platform(),
                    record.readiness.as_ref(),
                )
            || plan_digest(record)? != plan.digest()
            || plan.encode()?.as_slice() != bytes
        {
            return Err(PlanError::InvalidRecord);
        }
        Ok(plan)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanEnvelope {
    record: PlanRecord,
    plan_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanRecord {
    version: u32,
    action: Action,
    layout: Layout,
    plan_id: String,
    target_id: String,
    target: Target,
    update_mode: InstallUpdateMode,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    preflight: InstallPreflight,
    checks: [Check; 10],
    effects: [Effect; 1],
    binding: ReleasePlanBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    readiness: Option<InstallReadiness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package: Option<InstallPackageBinding>,
}

fn publication_facts_consistent(record: &PlanRecord) -> bool {
    let Some(publication) = record
        .readiness
        .as_ref()
        .and_then(|readiness| readiness.publication.as_ref())
    else {
        return true;
    };
    if !publication.allocation_consistent() {
        return false;
    }
    let service_index = match record.preflight.host.service_manager {
        ServiceManagerObservation::Systemd => 3,
        ServiceManagerObservation::OpenRc => 4,
        _ => return publication.package.is_none(),
    };
    let (Some(bound), Some(observed)) = (&record.package, &publication.package) else {
        return false;
    };
    let lengths = &bound.0;
    observed.program_files == [0, 1, 2, 5].map(|index| lengths[index].length)
        && observed.service_file == lengths[service_index].length
        && observed.archive_bytes == public_target(&record.binding).length
}

/// Entries follow the canonical package order. The compressed archive
/// identity is already part of the release binding in the same digest.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct InstallPackageBinding([InstallMemberBinding; FORMAL_MEMBER_COUNT]);

impl InstallPackageBinding {
    fn from_inspection(inspection: &FormalPackage) -> Result<Self, PlanError> {
        let members: &[super::FormalPackageMember; FORMAL_MEMBER_COUNT] = inspection
            .members
            .as_slice()
            .try_into()
            .map_err(|_| PlanError::InvalidRecord)?;
        Ok(Self(std::array::from_fn(|index| InstallMemberBinding {
            length: members[index].length,
            sha256: members[index].sha256.clone(),
        })))
    }

    fn valid(&self) -> bool {
        formal_member_lengths_valid(std::array::from_fn(|index| self.0[index].length))
            && self.0.iter().all(|member| {
                member.sha256.len() == 64
                    && member
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallMemberBinding {
    length: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallReadiness {
    platform: PlatformCompatibility,
    filesystem: InstallFilesystemReadiness,
    tls_origin: TlsObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication: Option<InstallPublicationReadiness>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TlsObservation {
    Verified,
    Unverified,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallPlanPreview<'a> {
    plan_id: &'a str,
    action: Action,
    target_id: &'a str,
    plan_digest: &'a str,
    expires_at: String,
    state: State,
    checks: &'a [Check; 10],
    effects: &'a [Effect; 1],
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Action {
    AgentInstall,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Layout {
    V1,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Effect {
    RegisterAgent,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CheckName {
    ReleaseTrust,
    Platform,
    ServiceManager,
    ExclusiveLock,
    TargetIdentity,
    Persistence,
    DiskSpace,
    TlsOrigin,
    Binding,
    UpgradeState,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Status {
    Pass,
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Reason {
    None,
    NotTested,
    UnsupportedPlatform,
    UnsupportedServiceManager,
    IncompatibleVersion,
    PermissionDenied,
    PartialInitialization,
    DiskInsufficient,
    OutcomeUnknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Check {
    check: CheckName,
    status: Status,
    reason_code: Reason,
}

impl Check {
    fn pass(check: CheckName) -> Self {
        Self {
            check,
            status: Status::Pass,
            reason_code: Reason::None,
        }
    }

    fn unknown(check: CheckName) -> Self {
        Self {
            check,
            status: Status::Unknown,
            reason_code: Reason::NotTested,
        }
    }

    fn blocked(check: CheckName, reason_code: Reason) -> Self {
        Self {
            check,
            status: Status::Blocked,
            reason_code,
        }
    }
}

fn install_checks(
    preflight: &InstallPreflight,
    platform: Platform,
    readiness: Option<&InstallReadiness>,
) -> [Check; 10] {
    use CheckName::*;
    let checks = legacy_checks(preflight, platform);
    let Some(readiness) = readiness else {
        return checks;
    };
    let program = readiness.filesystem.program_parent;
    let state = readiness.filesystem.state_parent;
    let publication = readiness.publication.as_ref();
    let unsafe_mount = matches!(
        program,
        FilesystemObservation::Unsafe
            | FilesystemObservation::Observed {
                read_only: true,
                ..
            }
            | FilesystemObservation::Observed { no_exec: true, .. }
    ) || matches!(
        state,
        FilesystemObservation::Unsafe
            | FilesystemObservation::Observed {
                read_only: true,
                ..
            }
    ) || publication
        .and_then(|observation| observation.service_space)
        .is_some_and(|space| space.read_only);
    checks.map(|check| match check.check {
        ReleaseTrust => Check::pass(ReleaseTrust),
        Platform if readiness.platform == PlatformCompatibility::Incompatible => {
            let reason = if preflight
                .host
                .platform
                .is_some_and(|observed| observed != platform)
            {
                Reason::UnsupportedPlatform
            } else {
                Reason::IncompatibleVersion
            };
            Check::blocked(Platform, reason)
        }
        ServiceManager
            if preflight.host.service_manager == ServiceManagerObservation::Ambiguous =>
        {
            Check::blocked(ServiceManager, Reason::UnsupportedServiceManager)
        }
        ServiceManager => match publication.map(|observation| observation.service) {
            Some(ServiceObservation::DestinationExisting) => {
                Check::blocked(ServiceManager, Reason::PartialInitialization)
            }
            Some(ServiceObservation::DestinationUnsafe) => {
                Check::blocked(ServiceManager, Reason::PermissionDenied)
            }
            Some(ServiceObservation::ManagerConflict) => {
                Check::blocked(ServiceManager, Reason::UnsupportedServiceManager)
            }
            _ => check,
        },
        Persistence if unsafe_mount => Check::blocked(Persistence, Reason::PermissionDenied),
        DiskSpace
            if publication.is_some_and(InstallPublicationReadiness::definite_disk_shortage) =>
        {
            Check::blocked(DiskSpace, Reason::DiskInsufficient)
        }
        TlsOrigin => match readiness.tls_origin {
            TlsObservation::Verified => Check::pass(TlsOrigin),
            TlsObservation::Unverified => Check {
                check: TlsOrigin,
                status: Status::Unknown,
                reason_code: Reason::OutcomeUnknown,
            },
        },
        _ => check,
    })
}

// Version 1 records carry only their original observations and must replay
// exactly, including the original checks, digest, and confirmation fields.
fn legacy_checks(preflight: &InstallPreflight, platform: Platform) -> [Check; 10] {
    use CheckName::*;
    let entries = [
        preflight.layout.program,
        preflight.layout.state,
        preflight.layout.control,
    ];
    let mut release = Check::unknown(ReleaseTrust);
    let mut host_platform = Check::unknown(CheckName::Platform);
    match preflight.host.platform {
        Some(observed) if observed == platform => {
            release = Check::pass(ReleaseTrust);
        }
        Some(_) => {
            host_platform = Check::blocked(CheckName::Platform, Reason::UnsupportedPlatform);
        }
        None => {}
    }
    let persistence = if preflight.host.effective_uid != 0 || entries.contains(&LayoutEntry::Unsafe)
    {
        Check::blocked(Persistence, Reason::PermissionDenied)
    } else {
        Check::unknown(Persistence)
    };
    // A retained control directory can belong to a settled prior lifecycle.
    // The owner checks its journal before judging that case.
    let binding = if preflight.layout.program == LayoutEntry::Present
        || preflight.layout.state == LayoutEntry::Present
        || entries.contains(&LayoutEntry::Unsafe)
    {
        Check::blocked(Binding, Reason::PartialInitialization)
    } else {
        Check::unknown(Binding)
    };
    [
        release,
        host_platform,
        Check::unknown(ServiceManager),
        Check::unknown(ExclusiveLock),
        Check::unknown(TargetIdentity),
        persistence,
        Check::unknown(DiskSpace),
        Check::unknown(TlsOrigin),
        binding,
        Check::unknown(UpgradeState),
    ]
}

fn plan_target(
    input: &InstallPlanInput<'_>,
    release: &VerifiedRelease,
) -> Result<Target, PlanError> {
    let target = canonical_target(input.management_origin, input.expected_server_id)?;
    if !release
        .target()
        .release_id
        .as_str()
        .eq_ignore_ascii_case(input.release_id)
    {
        return Err(PlanError::ReleaseMismatch);
    }
    Ok(target)
}

pub(super) fn canonical_target(origin: &str, server: &str) -> Result<Target, PlanError> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or(PlanError::InvalidTarget)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if origin.len() > 2048
        || authority.is_empty()
        || authority.ends_with(':')
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/?#@\\".contains(c))
    {
        return Err(PlanError::InvalidTarget);
    }
    let target = Target::new(origin, server).map_err(|_| PlanError::InvalidTarget)?;
    if target.origin.ends_with(":0") {
        return Err(PlanError::InvalidTarget);
    }
    Ok(target)
}

fn deadline(created: u64) -> Result<u64, PlanError> {
    let expires = created
        .checked_add(VALID_FOR_MS)
        .ok_or(PlanError::InvalidTime)?;
    timestamp(expires)?;
    Ok(expires)
}

fn timestamp(millis: u64) -> Result<String, PlanError> {
    let seconds = i64::try_from(millis / 1000).map_err(|_| PlanError::InvalidTime)?;
    let at = OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| PlanError::InvalidTime)?;
    if !(1970..=9999).contains(&at.year()) {
        return Err(PlanError::InvalidTime);
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        millis % 1000,
    ))
}

pub(super) fn valid_plan_id(value: &str) -> bool {
    uuid(value) && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn plan_digest(record: &PlanRecord) -> Result<String, PlanError> {
    let bytes = serde_json::to_vec(record).map_err(|_| PlanError::InvalidRecord)?;
    let mut hash = Context::new(&SHA256);
    hash.update(match record.version {
        LEGACY_VERSION => b"nodomi:agent-install-plan:v1\0",
        READINESS_VERSION => b"nodomi:agent-install-plan:v2\0",
        FORMAL_PACKAGE_VERSION => b"nodomi:agent-install-plan:v3\0",
        PUBLICATION_READINESS_VERSION => b"nodomi:agent-install-plan:v4\0",
        _ => return Err(PlanError::InvalidRecord),
    });
    hash.update(&bytes);
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation::{
            InstallHost, InstallLayout, InstallPlanStore, PlanStoreError,
            ServiceManagerObservation,
            package::{fixture_formal_archive, package_file},
        },
        release::{
            binding::recheck_binding,
            github::ReleaseReadOptions,
            github_tests::Fixture,
            manifest::{GithubReleaseId, HostRequirements},
        },
    };
    use serde_json::json;
    use std::{
        fs::{self, File, Permissions},
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    const NOW: u64 = 1_700_000_000_123;

    fn host_requirements() -> HostRequirements {
        HostRequirements {
            platform: Platform::LinuxAarch64,
            kernel: [6, 1, 0],
            libc: None,
            wire_protocol: 1,
            supervisor_protocol: 1,
            config_format: 1,
            queue_format: 1,
        }
    }

    fn fixture_release(fixture: &Fixture) -> VerifiedRelease {
        fixture
            .client(ReleaseReadOptions::default())
            .load_exact(GithubReleaseId::new(123).unwrap(), host_requirements())
            .unwrap()
    }

    fn preflight() -> InstallPreflight {
        InstallPreflight {
            host: InstallHost {
                platform: Some(Platform::LinuxAarch64),
                kernel: None,
                libc: None,
                effective_uid: 0,
                service_manager: ServiceManagerObservation::Unknown,
            },
            layout: InstallLayout {
                program: LayoutEntry::Missing,
                state: LayoutEntry::Missing,
                control: LayoutEntry::Missing,
            },
        }
    }

    fn input(release: &VerifiedRelease) -> InstallPlanInput<'_> {
        InstallPlanInput {
            management_origin: "https://manager.example.invalid/",
            expected_server_id: "server-1",
            release_id: release.target().release_id.as_str(),
            update_mode: None,
        }
    }

    #[test]
    fn formal_member_facts_are_sealed_and_legacy_plans_cannot_admit_a_package() {
        let platform = host_requirements().platform;
        let bytes = fixture_formal_archive(platform, b"fixture\n");
        let release = fixture_release(&Fixture::with_artifact(platform, &bytes));
        let legacy = InstallPlan::create(input(&release), &release, preflight(), NOW).unwrap();
        assert_eq!(
            legacy.verify_apply_package(&release, &package_file(&bytes)),
            Err(PlanError::PackageRequired)
        );
        let mut plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: "https://127.0.0.1:1",
                ..input(&release)
            },
            &release,
            None,
            package_file(&bytes),
        )
        .unwrap();
        assert_eq!(plan.0.record.version, PUBLICATION_READINESS_VERSION);
        assert!(plan.publication_readiness().is_some());
        assert_eq!(
            InstallPlan::decode(&plan.encode().unwrap())
                .unwrap()
                .digest(),
            plan.digest()
        );
        plan.0.record.package.as_mut().unwrap().0[0].sha256 = "0".repeat(64);
        assert_eq!(
            InstallPlan::decode(&plan.encode().unwrap()).err(),
            Some(PlanError::InvalidRecord)
        );
        assert_eq!(
            plan.verify_apply_package(&release, &package_file(&bytes)),
            Err(PlanError::PackageMismatch)
        );
    }

    #[test]
    fn formal_plan_blocks_observed_conflicts_and_inode_shortage_and_reads_v3() {
        use crate::installation::{DirectorySpace, PackageDiskInputs};
        let platform = host_requirements().platform;
        let bytes = fixture_formal_archive(platform, b"fixture\n");
        let release = fixture_release(&Fixture::with_artifact(platform, &bytes));
        let mut plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: "https://127.0.0.1:1",
                ..input(&release)
            },
            &release,
            None,
            package_file(&bytes),
        )
        .unwrap();
        let record = &mut plan.0.record;
        let readiness = record.readiness.as_mut().unwrap();
        let publication = readiness.publication.as_mut().unwrap();
        publication.allocation = None;
        publication.service = ServiceObservation::DestinationExisting;
        publication.program_space = Some(DirectorySpace {
            device: 1,
            inode: 1,
            available_bytes: Some(1_000_000),
            available_inodes: Some(8),
            fragment_bytes: Some(4096),
            read_only: false,
        });
        let package = verify_formal_package(package_file(&bytes), &release).unwrap();
        record.preflight.host.service_manager = ServiceManagerObservation::Systemd;
        publication.package = Some(
            PackageDiskInputs::from_package(&package, ServiceManagerObservation::Systemd).unwrap(),
        );
        record.checks = install_checks(&record.preflight, platform, Some(readiness));
        plan.0.plan_digest = plan_digest(record).unwrap();
        let saved = plan.encode().unwrap();
        let loaded = InstallPlan::decode(&saved).unwrap();
        assert_check(&loaded, "DISK_SPACE", "BLOCKED", "DISK_INSUFFICIENT");
        assert_check(
            &loaded,
            "SERVICE_MANAGER",
            "BLOCKED",
            "PARTIAL_INITIALIZATION",
        );
        let record = &mut plan.0.record;
        record.version = FORMAL_PACKAGE_VERSION;
        record.readiness.as_mut().unwrap().publication = None;
        record.checks = install_checks(&record.preflight, platform, record.readiness.as_ref());
        plan.0.plan_digest = plan_digest(record).unwrap();
        let old = InstallPlan::decode(&plan.encode().unwrap()).unwrap();
        assert!(old.publication_readiness().is_none());
        assert_check(&old, "DISK_SPACE", "UNKNOWN", "NOT_TESTED");
    }

    fn assert_check(plan: &InstallPlan, name: &str, status: &str, reason: &str) {
        let preview = serde_json::to_value(plan.preview()).unwrap();
        let check = preview["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["check"] == name)
            .unwrap();
        assert_eq!(
            *check,
            json!({"check": name, "status": status, "reasonCode": reason})
        );
    }

    #[test]
    fn version_one_plan_digest_uses_original_encoding() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        let mut plan = InstallPlan::create(input(&release), &release, preflight(), NOW).unwrap();
        plan.0.record.plan_id = "00000000-0000-4000-8000-000000000001".into();
        let installation_id = "00000000-0000-4000-8000-000000000002".to_owned();
        plan.0.record.target_id = installation_id.clone();
        let context = PlanTargetContext::new(
            PlanInstallation::FreshInstall { installation_id },
            deadline(NOW).unwrap(),
        )
        .unwrap();
        plan.0.record.binding = bind_release(&release, &context);
        let plan = InstallPlan::seal(plan.0.record).unwrap();
        let stored = plan.encode().unwrap();
        let reopened = InstallPlan::decode(&stored).unwrap();
        // The version 1 encoding includes the exact release binding. This
        // vector uses the public catalog identity and its derived release ID.
        assert_eq!(reopened.0.record.version, LEGACY_VERSION);
        assert_eq!(
            reopened.digest(),
            "9a376dd1c8eb8449cb54f97a8d5fb78e0cd96b8a728eb3d1c414b763db64e2b0"
        );
        assert_eq!(reopened.encode().unwrap(), stored);
        assert!(
            serde_json::from_slice::<serde_json::Value>(&stored).unwrap()["record"]
                .get("readiness")
                .is_none()
        );
    }

    #[test]
    fn live_plan_records_tls_without_following_redirect_or_sending_credentials() {
        let fixture = Fixture::new("tls-probe");
        let release = fixture_release(&fixture);
        let previous_requests = fixture.requests().len();
        let ca = include_bytes!("../../tests/fixtures/tls/ca.pem");
        let probe_input = || InstallPlanInput {
            management_origin: fixture.origin(),
            ..input(&release)
        };
        let plan = InstallPlan::inspect_and_create(probe_input(), &release, Some(ca)).unwrap();
        assert_check(&plan, "TLS_ORIGIN", "PASS", "NONE");
        for pending in [
            "TARGET_IDENTITY",
            "EXCLUSIVE_LOCK",
            "DISK_SPACE",
            "UPGRADE_STATE",
        ] {
            assert_check(&plan, pending, "UNKNOWN", "NOT_TESTED");
        }
        assert_eq!(plan.0.record.version, READINESS_VERSION);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let store = InstallPlanStore::open(File::open(directory.path()).unwrap()).unwrap();
        store.save(&plan).unwrap();
        let loaded = store.load(plan.plan_id()).unwrap();
        assert_eq!(loaded.encode().unwrap(), plan.encode().unwrap());
        assert!(
            !std::str::from_utf8(&loaded.encode().unwrap())
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );

        let untrusted = InstallPlan::inspect_and_create(probe_input(), &release, None).unwrap();
        assert_check(&untrusted, "TLS_ORIGIN", "UNKNOWN", "OUTCOME_UNKNOWN");
        assert!(matches!(
            InstallPlan::inspect_and_create(probe_input(), &release, Some(b"invalid PEM")),
            Err(PlanError::InvalidProbeOptions)
        ));
        let requests = fixture.requests();
        assert_eq!(
            &requests[previous_requests..],
            &[json!({"method":"HEAD","path":"/","credentials":[]})]
        );
    }

    #[test]
    fn actual_readiness_facts_block_conflicts_without_inferring_install_capacity() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        let observed_mount = |read_only, no_exec| FilesystemObservation::Observed {
            available_bytes: Some(100),
            read_only,
            no_exec,
        };
        for (program, state, persistence) in [
            (
                observed_mount(true, false),
                observed_mount(false, false),
                "BLOCKED",
            ),
            (
                observed_mount(false, true),
                observed_mount(false, false),
                "BLOCKED",
            ),
            (
                observed_mount(false, false),
                observed_mount(true, false),
                "BLOCKED",
            ),
            (
                observed_mount(false, false),
                observed_mount(false, true),
                "UNKNOWN",
            ),
            (
                FilesystemObservation::Unsafe,
                FilesystemObservation::Unavailable,
                "BLOCKED",
            ),
        ] {
            let mut observed = preflight();
            observed.host.service_manager = ServiceManagerObservation::Ambiguous;
            let platform =
                release.platform_compatibility(observed.host.platform, Some([4, 18, 0]), None);
            let mut plan = InstallPlan::create_record(
                plan_target(&input(&release), &release).unwrap(),
                None,
                &release,
                observed,
                Some(InstallReadiness {
                    platform,
                    filesystem: InstallFilesystemReadiness {
                        program_parent: program,
                        state_parent: state,
                    },
                    tls_origin: TlsObservation::Unverified,
                    publication: None,
                }),
                NOW,
                None,
            )
            .unwrap();
            let reason = if persistence == "BLOCKED" {
                "PERMISSION_DENIED"
            } else {
                "NOT_TESTED"
            };
            assert_check(&plan, "PERSISTENCE", persistence, reason);
            assert_check(&plan, "PLATFORM", "BLOCKED", "INCOMPATIBLE_VERSION");
            assert_check(
                &plan,
                "SERVICE_MANAGER",
                "BLOCKED",
                "UNSUPPORTED_SERVICE_MANAGER",
            );
            assert_check(&plan, "DISK_SPACE", "UNKNOWN", "NOT_TESTED");

            if let FilesystemObservation::Observed {
                available_bytes, ..
            } = &mut plan
                .0
                .record
                .readiness
                .as_mut()
                .unwrap()
                .filesystem
                .program_parent
            {
                *available_bytes = Some(101);
                assert!(matches!(
                    InstallPlan::decode(&plan.encode().unwrap()),
                    Err(PlanError::InvalidRecord)
                ));
            }
        }
    }

    #[test]
    fn protected_plan_round_trip_retains_exact_target_and_expiry() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        let plan = InstallPlan::create(input(&release), &release, preflight(), NOW).unwrap();
        assert_eq!(plan.update_mode(), InstallUpdateMode::Auto);
        assert_eq!(plan.target().origin, "https://manager.example.invalid");
        assert_ne!(plan.plan_id(), plan.target_id());

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let store = InstallPlanStore::open(File::open(directory.path()).unwrap()).unwrap();
        store.save(&plan).unwrap();
        assert_eq!(store.save(&plan), Err(PlanStoreError::AlreadyExists));
        drop(store);
        let path = directory.path().join(format!("{}.json", plan.plan_id()));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        let store = InstallPlanStore::open(File::open(directory.path()).unwrap()).unwrap();
        let loaded = store.load(plan.plan_id()).unwrap();
        assert_eq!(loaded.encode().unwrap(), plan.encode().unwrap());
        let other_id = "00000000-0000-4000-8000-000000000002";
        fs::copy(&path, directory.path().join(format!("{other_id}.json"))).unwrap();
        assert!(matches!(
            store.load(other_id),
            Err(PlanStoreError::InvalidPlan)
        ));
        assert_eq!(
            loaded.check_confirmation(plan.plan_id(), plan.target_id(), plan.digest(), NOW),
            Ok(())
        );
        assert_eq!(
            loaded.check_confirmation(plan.plan_id(), plan.target_id(), plan.digest(), NOW - 1),
            Err(PlanError::StalePlan)
        );
        assert_eq!(
            loaded.check_confirmation(
                plan.plan_id(),
                plan.target_id(),
                plan.digest(),
                NOW + 600_000
            ),
            Err(PlanError::StalePlan)
        );
        assert_eq!(
            loaded.check_confirmation(plan.plan_id(), plan.plan_id(), plan.digest(), NOW),
            Err(PlanError::ConfirmationMismatch)
        );
        assert_eq!(
            loaded.check_confirmation(plan.plan_id(), plan.target_id(), &"0".repeat(64), NOW),
            Err(PlanError::ConfirmationMismatch)
        );
        let preview = serde_json::to_value(loaded.preview()).unwrap();
        assert_eq!(preview.as_object().unwrap().len(), 8);
        assert_eq!(preview["action"], "AGENT_INSTALL");
        assert_eq!(preview["state"], "UNKNOWN");
        assert_eq!(preview["effects"], json!(["REGISTER_AGENT"]));
        assert_eq!(preview["expiresAt"], "2023-11-14T22:23:20.123Z");
        assert_eq!(preview["checks"].as_array().unwrap().len(), 10);
        assert_eq!(preview["checks"][0]["status"], "PASS");
        let checked = recheck_binding(
            &mut fixture.client(ReleaseReadOptions::default()),
            loaded.binding(),
            host_requirements(),
        )
        .unwrap();
        assert_eq!(checked.target(), release.target());
    }

    #[test]
    fn preflight_conflicts_are_reported_in_a_blocked_preview() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        let mut observed = preflight();
        observed.host.effective_uid = 65_534;
        observed.host.platform = Some(Platform::LinuxX86_64);
        observed.layout.program = LayoutEntry::Present;
        let plan = InstallPlan::create(
            InstallPlanInput {
                update_mode: Some(InstallUpdateMode::Manual),
                ..input(&release)
            },
            &release,
            observed,
            NOW,
        )
        .unwrap();
        assert_eq!(plan.update_mode(), InstallUpdateMode::Manual);
        let preview = serde_json::to_value(plan.preview()).unwrap();
        assert_eq!(preview["state"], "BLOCKED");
        let reason = |name| {
            preview["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["check"] == name)
                .unwrap()["reasonCode"]
                .clone()
        };
        assert_eq!(reason("BINDING"), "PARTIAL_INITIALIZATION");
        assert_eq!(reason("PERSISTENCE"), "PERMISSION_DENIED");
        assert_eq!(reason("PLATFORM"), "UNSUPPORTED_PLATFORM");
        assert_eq!(reason("RELEASE_TRUST"), "NOT_TESTED");

        let mut observed = preflight();
        observed.layout.control = LayoutEntry::Present;
        let retained = InstallPlan::create(input(&release), &release, observed, NOW).unwrap();
        let preview = serde_json::to_value(retained.preview()).unwrap();
        assert_eq!(preview["state"], "UNKNOWN");
        assert!(
            preview["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| { check["check"] == "BINDING" && check["status"] == "UNKNOWN" })
        );
    }

    #[test]
    fn stored_bytes_bind_mode_manifest_and_reviewed_checks() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        let mut plan = InstallPlan::create(input(&release), &release, preflight(), NOW).unwrap();
        let original = plan.encode().unwrap();
        let digest = plan.digest().to_owned();
        plan.0.record.update_mode = InstallUpdateMode::Manual;
        assert!(matches!(
            InstallPlan::decode(&plan.encode().unwrap()),
            Err(PlanError::InvalidRecord)
        ));
        let plan = InstallPlan::seal(plan.0.record).unwrap();
        assert_ne!(plan.digest(), digest);

        let manifest_sha = &release.manifest_asset().sha256;
        let changed = std::str::from_utf8(&original).unwrap().replacen(
            manifest_sha.as_str(),
            &"a".repeat(64),
            1,
        );
        assert_ne!(changed.as_bytes(), original);
        let structurally_valid: PlanEnvelope = serde_json::from_str(&changed).unwrap();
        assert_eq!(
            serde_json::to_vec(&structurally_valid).unwrap(),
            changed.as_bytes()
        );
        assert!(matches!(
            InstallPlan::decode(changed.as_bytes()),
            Err(PlanError::InvalidRecord)
        ));

        let mut reordered_checks = InstallPlan::decode(&original).unwrap();
        reordered_checks.0.record.checks.swap(0, 1);
        let resealed = InstallPlan::seal(reordered_checks.0.record).unwrap();
        assert!(matches!(
            InstallPlan::decode(&resealed.encode().unwrap()),
            Err(PlanError::InvalidRecord)
        ));
        let mut padded = original;
        padded.push(b'\n');
        assert!(matches!(
            InstallPlan::decode(&padded),
            Err(PlanError::InvalidRecord)
        ));
    }

    #[test]
    fn rejects_normalized_paths_secrets_and_other_releases() {
        let fixture = Fixture::new("happy");
        let release = fixture_release(&fixture);
        for origin in [
            "https://manager.example.invalid/path/..",
            "https://manager.example.invalid/?token=fixture",
            "https://user@manager.example.invalid",
            "https://manager.example.invalid:0",
            "https://manager.example.invalid:",
        ] {
            assert!(
                matches!(
                    InstallPlan::create(
                        InstallPlanInput {
                            management_origin: origin,
                            ..input(&release)
                        },
                        &release,
                        preflight(),
                        NOW
                    ),
                    Err(PlanError::InvalidTarget)
                ),
                "{origin}"
            );
        }
        assert!(matches!(
            InstallPlan::create(
                InstallPlanInput {
                    release_id: "00000000-0000-4000-8000-000000000001",
                    ..input(&release)
                },
                &release,
                preflight(),
                NOW
            ),
            Err(PlanError::ReleaseMismatch)
        ));
    }
}
