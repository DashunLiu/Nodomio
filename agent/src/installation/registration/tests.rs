use super::*;
use crate::protocol::{Architecture, Capabilities, Capability};
use std::{
    fs::{self, File, Permissions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const TIMEOUT: Duration = Duration::from_secs(2);
const CA: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
const OTHER_ID: &str = "55555555-5555-4555-8555-555555555555";

struct Fixture {
    directory: tempfile::TempDir,
    child: Child,
    target: Target,
    identity: PathBuf,
}

impl Fixture {
    fn new(scenario: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("identity");
        fs::create_dir(&identity).unwrap();
        fs::set_permissions(&identity, Permissions::from_mode(0o700)).unwrap();
        File::open(directory.path()).unwrap().sync_all().unwrap();
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/installation/registration/https_fixture.py",
            ))
            .arg(directory.path())
            .arg(scenario)
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut port = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        let port: u16 = port.trim().parse().unwrap();
        let target = Target::new(&format!("https://localhost:{port}"), "server-1").unwrap();
        Self {
            directory,
            child,
            target,
            identity,
        }
    }

    fn prepare(&self) -> PreparedRegistration {
        PreparedRegistration::initialize(&self.identity, self.target.clone(), Some(CA), TIMEOUT)
            .unwrap()
    }

    fn enrollment(&self) -> Enrollment {
        let path = self.directory.path().join("input");
        fs::write(&path, format!("ndme_{}", "A".repeat(43))).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
        let enrollment = Enrollment::from_private_file(&path).unwrap();
        fs::remove_file(path).unwrap();
        enrollment
    }

    fn mark(&self, expected_id: &str) -> Result<(), ()> {
        let state: serde_json::Value = serde_json::from_slice(&self.identity_bytes()).unwrap();
        assert_eq!(state["operationId"], expected_id);
        assert_eq!(state["status"], "PREPARED");
        let mut marker = File::create(self.directory.path().join("registration-possible")).unwrap();
        marker.write_all(expected_id.as_bytes()).unwrap();
        marker.sync_all().unwrap();
        File::open(self.directory.path())
            .unwrap()
            .sync_all()
            .unwrap();
        Ok(())
    }

    fn marked_id(&self) -> String {
        fs::read_to_string(self.directory.path().join("registration-possible")).unwrap()
    }

    fn requests(&self) -> String {
        let path = self.directory.path().join("requests");
        match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("{error}"),
        }
    }

    fn recover(&self, operation_id: &str) -> Result<AgentIdentity, RegistrationError> {
        recover_registration(
            &self.identity,
            &self.target,
            operation_id,
            Some(CA),
            TIMEOUT,
        )
    }

    fn identity_bytes(&self) -> Vec<u8> {
        fs::read(self.identity.join("identity.json")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn metadata() -> RegistrationMetadata {
    RegistrationMetadata {
        version: "0.1.0".into(),
        architecture: Architecture::Arm64,
        distribution: "debian".into(),
        distribution_version: "12".into(),
        hostname: "registration-fixture".into(),
        capabilities: Capabilities {
            system: Capability::Available,
            processes: Capability::Unsupported,
            containers: Capability::Unsupported,
            ssh_events: Capability::Unsupported,
        },
    }
}

#[test]
fn durable_credential_and_marker_precede_the_single_registration_post() {
    let fixture = Fixture::new("healthy");
    let registered = fixture
        .prepare()
        .register_once(fixture.enrollment(), &metadata(), None, |id| {
            fixture.mark(id)
        })
        .unwrap();
    assert_eq!(registered.server_id, fixture.target.expected_server_id);
    assert_eq!(registered.binding_revision, 2);
    let state = IdentityStore::open(&fixture.identity, &fixture.target).unwrap();
    assert_eq!(state.status(), Status::Bound);
    assert_eq!(state.operation_id(), fixture.marked_id());
    assert_eq!(state.binding(), Some(&registered.binding()));
    drop(state);
    assert!(matches!(
        PreparedRegistration::initialize(
            &fixture.identity,
            fixture.target.clone(),
            Some(CA),
            TIMEOUT
        ),
        Err(RegistrationError::Local("PARTIAL_OR_UNKNOWN_STATE"))
    ));
    assert_eq!(fixture.requests(), "POST\n");
}

#[test]
fn lost_committed_reply_recovers_original_identity_only_by_get() {
    let fixture = Fixture::new("committed");
    let error = fixture
        .prepare()
        .register_once(fixture.enrollment(), &metadata(), None, |id| {
            fixture.mark(id)
        })
        .unwrap_err();
    assert_eq!(
        error,
        RegistrationAttemptError::OutcomeUnknown("NETWORK_OR_TLS_ERROR")
    );
    let before = fixture.identity_bytes();
    let different_target = Target::new(&fixture.target.origin, "other-server").unwrap();
    assert_eq!(
        recover_registration(
            &fixture.identity,
            &different_target,
            &fixture.marked_id(),
            Some(CA),
            TIMEOUT,
        ),
        Err(RegistrationError::Local("CORRUPT_OR_DIFFERENT_TARGET"))
    );
    assert_eq!(
        fixture.recover(OTHER_ID),
        Err(RegistrationError::InvalidOriginalIdentity)
    );
    assert!(before == fixture.identity_bytes());
    assert_eq!(fixture.requests(), "POST\n");
    let registered = fixture.recover(&fixture.marked_id()).unwrap();
    assert_eq!(registered.binding_revision, 2);
    assert_eq!(fixture.requests(), "POST\nGET\n");
    let state = IdentityStore::open(&fixture.identity, &fixture.target).unwrap();
    assert_eq!(state.operation_id(), fixture.marked_id());
    assert_eq!(state.binding(), Some(&registered.binding()));
}

#[test]
fn one_get_401_retains_original_state_and_never_reposts() {
    let fixture = Fixture::new("uncommitted");
    let error = fixture
        .prepare()
        .register_once(fixture.enrollment(), &metadata(), None, |id| {
            fixture.mark(id)
        })
        .unwrap_err();
    assert_eq!(
        error,
        RegistrationAttemptError::OutcomeUnknown("NETWORK_OR_TLS_ERROR")
    );
    let before = fixture.identity_bytes();
    assert_eq!(
        fixture.recover(&fixture.marked_id()),
        Err(RegistrationError::OutcomeUnknown("CREDENTIAL_REJECTED"))
    );
    assert!(before == fixture.identity_bytes());
    assert_eq!(fixture.requests(), "POST\nGET\n");
}

#[test]
fn marker_failure_and_malformed_metadata_send_nothing() {
    let first = Fixture::new("healthy");
    let prepared = first.prepare();
    let before = first.identity_bytes();
    let result = prepared.register_once(first.enrollment(), &metadata(), None, |_| {
        Err("marker not confirmed")
    });
    assert_eq!(
        result,
        Err(RegistrationAttemptError::Marker("marker not confirmed"))
    );
    assert_eq!(first.requests(), "");
    assert!(before == first.identity_bytes());
    let second = Fixture::new("healthy");
    let mut invalid = metadata();
    invalid.hostname.clear();
    let result = second.prepare().register_once(
        second.enrollment(),
        &invalid,
        None,
        |_| -> Result<(), ()> { panic!("invalid metadata must fail before the marker") },
    );
    assert_eq!(
        result,
        Err(RegistrationAttemptError::Local(
            "INVALID_REGISTRATION_METADATA"
        ))
    );
    assert_eq!(second.requests(), "");
}

#[test]
fn wrong_remote_binding_and_missing_local_identity_stay_unconfirmed() {
    let fixture = Fixture::new("wrong-server");
    let result = fixture
        .prepare()
        .register_once(fixture.enrollment(), &metadata(), None, |id| {
            fixture.mark(id)
        });
    assert_eq!(
        result,
        Err(RegistrationAttemptError::OutcomeUnknown(
            "IDENTITY_MISMATCH"
        ))
    );
    assert_eq!(
        fixture.recover(&fixture.marked_id()),
        Err(RegistrationError::OutcomeUnknown("IDENTITY_MISMATCH"))
    );
    let state = IdentityStore::open(&fixture.identity, &fixture.target).unwrap();
    assert_eq!(state.status(), Status::Uncertain);
    assert_eq!(state.binding(), None);
    drop(state);
    let empty = fixture.directory.path().join("empty-identity");
    fs::create_dir(&empty).unwrap();
    fs::set_permissions(&empty, Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        recover_registration(
            &empty,
            &fixture.target,
            &fixture.marked_id(),
            Some(CA),
            TIMEOUT
        ),
        Err(RegistrationError::Local(_))
    ));
    assert_eq!(fs::read_dir(empty).unwrap().count(), 0);
    assert_eq!(fixture.requests(), "POST\nGET\n");
}

#[test]
fn recovery_cannot_replace_a_confirmed_binding_revision() {
    let fixture = Fixture::new("revision-changed");
    let registered = fixture
        .prepare()
        .register_once(fixture.enrollment(), &metadata(), None, |id| {
            fixture.mark(id)
        })
        .unwrap();
    assert_eq!(
        fixture.recover(&fixture.marked_id()),
        Err(RegistrationError::OutcomeUnknown("IDENTITY_MISMATCH"))
    );
    let state = IdentityStore::open(&fixture.identity, &fixture.target).unwrap();
    assert_eq!(state.status(), Status::Uncertain);
    assert_eq!(state.operation_id(), fixture.marked_id());
    assert_eq!(state.binding(), Some(&registered.binding()));
    assert_eq!(fixture.requests(), "POST\nGET\n");
}
