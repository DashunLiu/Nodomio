//! Read-only target checks before a fresh install is admitted.

use super::{
    InstallPlan, LayoutEntry, ServiceManagerObservation,
    host::InstallHost,
    layout::{CONTROL_NAME, inspect_at as inspect_layout, open_root, program_parent, state_parent},
    plan::canonical_target,
    plan_store::{check_directory, open_at},
    service_activation::{ActivationError, ServiceActivation},
    service_readiness::{
        ManagerReadiness, ServiceDestination, inspect_at as inspect_service, openrc_runtime,
        protected_descendants,
    },
    validate_service_ca,
};
use crate::{
    client::ProtocolClient,
    identity::{Enrollment, Target},
    protocol::canonical_deployment_id,
    release::manifest::Platform,
};
use serde::Deserialize;
use std::{fs::File, mem::MaybeUninit, os::fd::AsRawFd, time::Duration};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PRE_REGISTRATION_REVISION: u64 = 9_007_199_254_740_990;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAdmissionError {
    RequiresRoot,
    PlatformMismatch,
    HostUnavailable,
    LayoutUnsafe,
    LayoutUnavailable,
    ExistingInstallation,
    ManagerConflict,
    ManagerUnavailable,
    ReadOnlyMount,
    NoExecMount,
    MountUnavailable,
    InvalidOrigin,
    InvalidCa,
    EnrollmentRejected,
    TargetMismatch,
    InvalidProof,
    RateLimited,
    RemoteUnavailable,
}

/// Live token-scoped evidence for the server before registration. Registration
/// creates the next binding revision. This revision is the one the token has now.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentTargetProof {
    deployment_id: String,
    server_id: String,
    binding_revision: u64,
}

impl EnrollmentTargetProof {
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn binding_revision(&self) -> u64 {
        self.binding_revision
    }
}

/// Local facts observed before effects. The execution owner still owns its
/// release, disk-budget, journal and lease checks.
pub(super) struct LocalTargetAdmission<'a> {
    target: &'a Target,
    explicit_ca: Option<&'a [u8]>,
}

impl LocalTargetAdmission<'_> {
    pub(super) fn prove_remote(
        &self,
        enrollment: &Enrollment,
        expected_deployment_id: &str,
    ) -> Result<EnrollmentTargetProof, TargetAdmissionError> {
        let proof = probe_enrollment_target(self.target, self.explicit_ca, enrollment)?;
        if proof.deployment_id() != expected_deployment_id {
            return Err(TargetAdmissionError::TargetMismatch);
        }
        Ok(proof)
    }
}

/// Recheck the fixed local namespace and HTTPS inputs for the sealed plan.
/// If supplied, the explicit CA augments the built-in trust roots, as it does
/// during registration and foreground service operation.
pub(super) fn inspect_target_admission<'a>(
    plan: &'a InstallPlan,
    host: &InstallHost,
    manager: ServiceManagerObservation,
    explicit_ca: Option<&'a [u8]>,
) -> Result<LocalTargetAdmission<'a>, TargetAdmissionError> {
    validate_transport(plan.target(), explicit_ca)?;
    if host.effective_uid != 0 {
        return Err(TargetAdmissionError::RequiresRoot);
    }
    let root = open_root().map_err(layout_error)?;
    inspect_local(&root, host, plan.binding().platform(), manager, 0)?;
    ServiceActivation::check_manager_configuration(manager).map_err(|error| match error {
        ActivationError::Blocked => TargetAdmissionError::ManagerConflict,
        _ => TargetAdmissionError::ManagerUnavailable,
    })?;
    Ok(LocalTargetAdmission {
        target: plan.target(),
        explicit_ca,
    })
}

pub(super) fn probe_enrollment_target(
    target: &Target,
    explicit_ca: Option<&[u8]>,
    enrollment: &Enrollment,
) -> Result<EnrollmentTargetProof, TargetAdmissionError> {
    validate_transport(target, explicit_ca)?;
    let response =
        ProtocolClient::read_enrollment_target(target, explicit_ca, enrollment, PROBE_TIMEOUT)
            .map_err(|error| match error {
                "CREDENTIAL_REJECTED" => TargetAdmissionError::EnrollmentRejected,
                "TARGET_MISMATCH" => TargetAdmissionError::TargetMismatch,
                "RATE_LIMITED" => TargetAdmissionError::RateLimited,
                "INVALID_CA" => TargetAdmissionError::InvalidCa,
                "INVALID_PROTOCOL" | "RESPONSE_TOO_LARGE" | "RESPONSE_HEADERS_TOO_LARGE" => {
                    TargetAdmissionError::InvalidProof
                }
                _ => TargetAdmissionError::RemoteUnavailable,
            })?;
    parse_proof(target, &response)
}

fn validate_transport(
    target: &Target,
    explicit_ca: Option<&[u8]>,
) -> Result<(), TargetAdmissionError> {
    if canonical_target(&target.origin, &target.expected_server_id)
        .ok()
        .as_ref()
        != Some(target)
    {
        return Err(TargetAdmissionError::InvalidOrigin);
    }
    if let Some(ca) = explicit_ca {
        validate_service_ca(ca).map_err(|_| TargetAdmissionError::InvalidCa)?;
    }
    Ok(())
}

fn parse_proof(
    target: &Target,
    bytes: &[u8],
) -> Result<EnrollmentTargetProof, TargetAdmissionError> {
    let proof: EnrollmentTargetProof =
        serde_json::from_slice(bytes).map_err(|_| TargetAdmissionError::InvalidProof)?;
    if !canonical_deployment_id(&proof.deployment_id)
        || !(1..=MAX_PRE_REGISTRATION_REVISION).contains(&proof.binding_revision)
    {
        return Err(TargetAdmissionError::InvalidProof);
    }
    if proof.server_id != target.expected_server_id {
        return Err(TargetAdmissionError::TargetMismatch);
    }
    Ok(proof)
}

fn inspect_local(
    root: &File,
    host: &InstallHost,
    platform: Platform,
    manager: ServiceManagerObservation,
    owner: libc::uid_t,
) -> Result<(), TargetAdmissionError> {
    match host.platform {
        Some(observed) if observed == platform => {}
        Some(_) => return Err(TargetAdmissionError::PlatformMismatch),
        None => return Err(TargetAdmissionError::HostUnavailable),
    }
    match host.service_manager {
        ServiceManagerObservation::Systemd | ServiceManagerObservation::OpenRc
            if host.service_manager == manager => {}
        ServiceManagerObservation::Systemd
        | ServiceManagerObservation::OpenRc
        | ServiceManagerObservation::Ambiguous => {
            return Err(TargetAdmissionError::ManagerConflict);
        }
        ServiceManagerObservation::Unknown => return Err(TargetAdmissionError::ManagerUnavailable),
    }
    let layout = inspect_layout(root, owner);
    let entries = [layout.program, layout.state, layout.control];
    if entries.contains(&LayoutEntry::Unsafe) {
        return Err(TargetAdmissionError::LayoutUnsafe);
    }
    if entries.contains(&LayoutEntry::Unavailable) {
        return Err(TargetAdmissionError::LayoutUnavailable);
    }
    if layout.program == LayoutEntry::Present || layout.state == LayoutEntry::Present {
        return Err(TargetAdmissionError::ExistingInstallation);
    }

    let service = inspect_service(root, owner, manager, host.service_manager);
    if service.manager == ManagerReadiness::Conflict {
        return Err(TargetAdmissionError::ManagerConflict);
    }
    let service_parent = match service.destination {
        ServiceDestination::Missing { parent, .. } => parent,
        ServiceDestination::Existing => return Err(TargetAdmissionError::ExistingInstallation),
        ServiceDestination::Unsafe => return Err(TargetAdmissionError::LayoutUnsafe),
        ServiceDestination::Unavailable => return Err(TargetAdmissionError::LayoutUnavailable),
    };
    if service.manager != ManagerReadiness::InterfaceObserved {
        return Err(TargetAdmissionError::ManagerUnavailable);
    }

    let program = program_parent(root, owner).map_err(layout_error)?;
    let state = state_parent(root, owner).map_err(layout_error)?;
    check_mount(&program, true, true)?;
    check_mount(&state, true, false)?;
    if layout.control == LayoutEntry::Present {
        let control = open_at(&state, CONTROL_NAME, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| TargetAdmissionError::LayoutUnavailable)?;
        check_directory(&control, owner).map_err(|_| TargetAdmissionError::LayoutUnsafe)?;
        check_mount(&control, true, false)?;
    }

    let openrc = manager == ServiceManagerObservation::OpenRc;
    check_mount(&service_parent, true, openrc)?;
    if openrc {
        let runtime = openrc_runtime(root, owner).map_err(layout_error)?;
        check_mount(&runtime, true, false)?;
        let enable = protected_descendants(root, &[c"etc", c"runlevels", c"default"], owner)
            .map_err(layout_error)?;
        check_mount(&enable, true, false)?;
        let tools = protected_descendants(root, &[c"sbin"], owner).map_err(layout_error)?;
        check_mount(&tools, false, true)?;
    } else {
        let runtime =
            protected_descendants(root, &[c"run", c"systemd"], owner).map_err(layout_error)?;
        check_mount(&runtime, true, false)?;
        match protected_descendants(&service_parent, &[c"multi-user.target.wants"], owner) {
            Ok(enable) => check_mount(&enable, true, false)?,
            Err(LayoutEntry::Missing) => {} // Created on the checked service mount.
            Err(error) => return Err(layout_error(error)),
        }
        let tools = protected_descendants(root, &[c"usr", c"bin"], owner).map_err(layout_error)?;
        check_mount(&tools, false, true)?;
    }
    Ok(())
}

fn layout_error(error: LayoutEntry) -> TargetAdmissionError {
    match error {
        LayoutEntry::Unsafe => TargetAdmissionError::LayoutUnsafe,
        _ => TargetAdmissionError::LayoutUnavailable,
    }
}

fn check_mount(directory: &File, writes: bool, executes: bool) -> Result<(), TargetAdmissionError> {
    let mut raw = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: directory is held and raw points to writable statvfs storage.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
        return Err(TargetAdmissionError::MountUnavailable);
    }
    // SAFETY: fstatvfs initialized raw on success.
    check_mount_flags(unsafe { raw.assume_init() }.f_flag, writes, executes)
}

fn check_mount_flags(
    flags: libc::c_ulong,
    writes: bool,
    executes: bool,
) -> Result<(), TargetAdmissionError> {
    if writes && flags & libc::ST_RDONLY != 0 {
        return Err(TargetAdmissionError::ReadOnlyMount);
    }
    if executes && flags & libc::ST_NOEXEC != 0 {
        return Err(TargetAdmissionError::NoExecMount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, Permissions},
        io::{BufRead, BufReader},
        os::unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
        process::{Child, Command, Stdio},
    };

    const DEPLOYMENT: &str = "6dc0a032-3f68-42ae-9dd9-14dc1a41ab01";
    const CA: &[u8] = include_bytes!("../../tests/fixtures/tls/ca.pem");

    #[test]
    fn tls_success_without_token_scoped_identity_is_not_proof() {
        let target = Target::new("https://example.invalid", "server-1").unwrap();
        assert_eq!(
            parse_proof(&target, br#"{"status":"foundation_ready"}"#),
            Err(TargetAdmissionError::InvalidProof)
        );
        let good = format!(
            r#"{{"deploymentId":"{DEPLOYMENT}","serverId":"server-1","bindingRevision":1}}"#
        );
        let proof = parse_proof(&target, good.as_bytes()).unwrap();
        assert_eq!(
            (
                proof.deployment_id(),
                proof.server_id(),
                proof.binding_revision()
            ),
            (DEPLOYMENT, "server-1", 1)
        );
        for invalid in [
            good.replace("server-1", "server-other"),
            good.replace("bindingRevision\":1", "bindingRevision\":9007199254740991"),
            good.replace(
                "bindingRevision\":1",
                "bindingRevision\":1,\"bindingRevision\":2",
            ),
            good.replace(DEPLOYMENT, "not-a-deployment-id"),
        ] {
            assert!(parse_proof(&target, invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn local_admission_rechecks_fixed_destination_and_init_without_writing() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path();
        for directory in [
            "opt",
            "var/lib",
            "etc/systemd/system",
            "run/systemd/system",
            "usr/bin",
        ] {
            fs::create_dir_all(path.join(directory)).unwrap();
        }
        let socket = path.join("run/systemd/private");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, Permissions::from_mode(0o600)).unwrap();
        let systemctl = path.join("usr/bin/systemctl");
        fs::write(&systemctl, b"canary").unwrap();
        fs::set_permissions(&systemctl, Permissions::from_mode(0o755)).unwrap();
        let root = File::open(path).unwrap();
        let owner = root.metadata().unwrap().uid();
        let host = InstallHost {
            platform: Some(Platform::LinuxAarch64),
            kernel: None,
            libc: None,
            effective_uid: owner,
            service_manager: ServiceManagerObservation::Systemd,
        };
        let inspect = |manager| inspect_local(&root, &host, Platform::LinuxAarch64, manager, owner);
        assert_eq!(inspect(ServiceManagerObservation::Systemd), Ok(()));
        assert_eq!(
            inspect(ServiceManagerObservation::OpenRc),
            Err(TargetAdmissionError::ManagerConflict)
        );
        assert_eq!(fs::read(&systemctl).unwrap(), b"canary");
        assert_eq!(fs::read_dir(path.join("opt")).unwrap().count(), 0);
        let state = path.join("var/lib/nodomi-agent");
        fs::create_dir(&state).unwrap();
        assert_eq!(
            inspect(ServiceManagerObservation::Systemd),
            Err(TargetAdmissionError::ExistingInstallation)
        );
        fs::remove_dir(state).unwrap();
        symlink("/tmp", path.join("var/lib/nodomi-agent-control")).unwrap();
        assert_eq!(
            inspect(ServiceManagerObservation::Systemd),
            Err(TargetAdmissionError::LayoutUnsafe)
        );
    }

    #[test]
    fn noexec_blocks_only_executable_mounts_and_readonly_blocks_writes() {
        assert_eq!(check_mount_flags(libc::ST_NOEXEC, true, false), Ok(()));
        assert_eq!(
            check_mount_flags(libc::ST_NOEXEC, false, true),
            Err(TargetAdmissionError::NoExecMount)
        );
        assert_eq!(check_mount_flags(libc::ST_RDONLY, false, true), Ok(()));
        assert_eq!(
            check_mount_flags(libc::ST_RDONLY, true, false),
            Err(TargetAdmissionError::ReadOnlyMount)
        );
    }

    struct ProbeServer(Child);

    impl Drop for ProbeServer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn authenticates_the_fixed_https_probe_and_rejects_a_different_server() {
        let fixture = tempfile::tempdir().unwrap();
        let input = fixture.path().join("enrollment");
        fs::write(&input, format!("ndme_{}", "A".repeat(43))).unwrap();
        fs::set_permissions(&input, Permissions::from_mode(0o400)).unwrap();
        let enrollment = Enrollment::from_private_file(&input).unwrap();
        fs::remove_file(&input).unwrap();
        let server = Command::new("python3")
            .arg("-c")
            .arg(include_str!("target_admission/https_fixture.py"))
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut server = ProbeServer(server);
        let mut port = String::new();
        BufReader::new(server.0.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        let port: u16 = port.trim().parse().unwrap();
        let origin = format!("https://localhost:{port}");
        let target = Target::new(&origin, "server-1").unwrap();
        assert!(matches!(
            probe_enrollment_target(&target, None, &enrollment),
            Err(TargetAdmissionError::RemoteUnavailable)
        ));
        assert_eq!(
            probe_enrollment_target(&target, Some(b"not a CA"), &enrollment),
            Err(TargetAdmissionError::InvalidCa)
        );
        let proof = probe_enrollment_target(&target, Some(CA), &enrollment).unwrap();
        assert_eq!(
            (
                proof.deployment_id(),
                proof.server_id(),
                proof.binding_revision()
            ),
            (DEPLOYMENT, "server-1", 7)
        );
        let wrong = Target::new(&origin, "different-server").unwrap();
        assert_eq!(
            probe_enrollment_target(&wrong, Some(CA), &enrollment),
            Err(TargetAdmissionError::TargetMismatch)
        );
        let redirect = Target::new(&origin, "redirect-server").unwrap();
        assert_eq!(
            probe_enrollment_target(&redirect, Some(CA), &enrollment),
            Err(TargetAdmissionError::RemoteUnavailable)
        );
        let malformed = Target::new(&origin, "foreign-body").unwrap();
        assert_eq!(
            probe_enrollment_target(&malformed, Some(CA), &enrollment),
            Err(TargetAdmissionError::TargetMismatch)
        );
    }
}
