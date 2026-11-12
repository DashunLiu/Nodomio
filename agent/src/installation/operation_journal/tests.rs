use super::*;
use crate::{
    identity::{Enrollment, Target},
    installation::{
        control_record::{advance_record, publish_claimed},
        registration::{PreparedRegistration, RegistrationAttemptError},
    },
    protocol::{Architecture, Capabilities, Capability, RegistrationMetadata},
};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
};

const DOMAIN: &str = "11111111-1111-4111-8111-111111111111";
const OPERATION: &str = "22222222-2222-4222-8222-222222222222";
const KEY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const INSTALLATION: &str = "55555555-5555-4555-8555-555555555555";
const NOW: u64 = 1_794_304_800_000;

struct Fixture {
    home: tempfile::TempDir,
    directory: File,
    ready: ControlRecord,
}

impl Fixture {
    fn new() -> Self {
        Self::with_target(Target::new("https://management.invalid", "server").unwrap())
    }

    fn with_target(target: Target) -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(home.path()).unwrap();
        let ready = ControlRecord::claimed(
            DOMAIN.into(),
            PreparationClaim {
                operation_id: OPERATION.into(),
                idempotency_key: KEY.into(),
                plan_id: PLAN.into(),
                plan_digest: "1".repeat(64),
                installation_id: INSTALLATION.into(),
                target,
            },
        )
        .unwrap();
        publish_claimed(&directory, &ready).unwrap();
        let ready = advance_record(&directory, &ready, ControlPhase::LockCreatePossible).unwrap();
        let ready = advance_record(&directory, &ready, ControlPhase::Ready).unwrap();
        Self {
            home,
            directory,
            ready,
        }
    }

    fn start(&self) -> OperationJournal<'_> {
        let Admission::New(journal) =
            OperationJournal::begin(&self.directory, &self.ready, &original_intent(), NOW).unwrap()
        else {
            panic!("new admission required");
        };
        journal
    }

    fn original_bytes(&self) -> Vec<u8> {
        fs::read(self.home.path().join("control.json")).unwrap()
    }
}

fn original_intent() -> InstallIntent {
    InstallIntent::new(PLAN, &"1".repeat(64), INSTALLATION, KEY).unwrap()
}

#[test]
fn ready_preparation_is_not_business_and_original_apply_replays_read_only() {
    let fixture = Fixture::new();
    let directory = &fixture.directory;
    assert_eq!(lookup_apply(directory, &original_intent()), Ok(None));
    assert_eq!(lookup_status(directory, OPERATION, INSTALLATION), Ok(None));
    let journal = fixture.start();
    assert_eq!(journal.phase(), BusinessPhase::Accepted);
    let after = fixture.original_bytes();
    let upper_key = InstallIntent::new(
        PLAN,
        &"1".repeat(64),
        INSTALLATION,
        &KEY.to_ascii_uppercase(),
    )
    .unwrap();
    let original = lookup_apply(directory, &upper_key).unwrap().unwrap();
    assert_eq!(original.operation_id(), OPERATION);
    assert_eq!(original.exit_code(), 6);
    assert_eq!(
        lookup_status(directory, OPERATION, INSTALLATION),
        Ok(Some(original.clone()))
    );
    assert!(matches!(
        OperationJournal::begin(directory, &fixture.ready, &upper_key, u64::MAX),
        Ok(Admission::Replay(result)) if result == original
    ));
    assert_eq!(fixture.original_bytes(), after);
}

#[test]
fn conflicts_and_missing_or_corrupt_records_do_not_create_authority() {
    let fixture = Fixture::new();
    let directory = &fixture.directory;
    let changed = InstallIntent::new(PLAN, &"2".repeat(64), INSTALLATION, KEY).unwrap();
    assert_eq!(
        lookup_apply(directory, &changed),
        Err(JournalError::IdempotencyConflict)
    );
    let other = InstallIntent::new(PLAN, &"1".repeat(64), INSTALLATION, DOMAIN).unwrap();
    assert_eq!(
        lookup_apply(directory, &other),
        Err(JournalError::OtherIntent)
    );
    assert_eq!(lookup_status(directory, DOMAIN, INSTALLATION), Ok(None));
    let path = fixture.home.path().join("control.json");
    fs::remove_file(&path).unwrap();
    assert_eq!(
        lookup_apply(directory, &original_intent()),
        Err(JournalError::Storage(ControlRecordError::NotFound))
    );
    assert!(!path.exists());
    fs::write(&path, b"{}").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        lookup_apply(directory, &original_intent()),
        Err(JournalError::Storage(ControlRecordError::InvalidRecord))
    );
    assert_eq!(fs::read(path).unwrap(), b"{}");
}

#[test]
fn effects_require_order_and_interruption_retains_original_phase() {
    let fixture = Fixture::new();
    let mut journal = fixture.start();
    let accepted = fixture.original_bytes();
    assert_eq!(
        journal.advance(BusinessPhase::RegistrationPossible, NOW + 1),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.settle_success(NOW + 1),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(fixture.original_bytes(), accepted);
    journal
        .advance(BusinessPhase::LocalPublicationPossible, NOW + 1)
        .unwrap();
    assert_eq!(
        journal.settle_failed_before_effects(InstallFailureCode::ApplyFailed, NOW + 2),
        Err(JournalError::InvalidTransition)
    );
    journal.mark_unknown(NOW + 2).unwrap();
    assert_eq!(
        journal.advance(BusinessPhase::LocalPublished, NOW + 3),
        Err(JournalError::InvalidTransition)
    );
    let record = read_record(&fixture.directory).unwrap();
    let business = record.business().unwrap();
    assert_eq!(business.phase(), BusinessPhase::LocalPublicationPossible);
    assert_eq!(business.revision(), 3);
    let result = lookup_status(&fixture.directory, OPERATION, INSTALLATION)
        .unwrap()
        .unwrap();
    assert_eq!(result.exit_code(), 6);
    assert_eq!(
        serde_json::to_value(result).unwrap()["errorCode"],
        "OUTCOME_UNKNOWN"
    );
}

#[test]
fn terminal_results_replay_exact_original_bytes() {
    let fixture = Fixture::new();
    let mut journal = fixture.start();
    for (index, phase) in [
        BusinessPhase::LocalPublicationPossible,
        BusinessPhase::LocalPublished,
        BusinessPhase::SupervisorLockCreatePossible,
        BusinessPhase::SupervisorLockReady,
        BusinessPhase::RegistrationPossible,
        BusinessPhase::IdentityConfirmed,
        BusinessPhase::ServiceStartPossible,
        BusinessPhase::Verifying,
    ]
    .into_iter()
    .enumerate()
    {
        journal.advance(phase, NOW + index as u64 + 1).unwrap();
    }
    let original = journal.settle_success(NOW + 9).unwrap();
    let before = fixture.original_bytes();
    assert_eq!(original.exit_code(), 0);
    assert_eq!(
        journal.mark_unknown(NOW + 10),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(fixture.original_bytes(), before);
    let replay = lookup_apply(&fixture.directory, &original_intent())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    let json = serde_json::to_value(replay).unwrap();
    assert_eq!(json["stage"], "COMPLETE");
    assert_eq!(json["targetId"], INSTALLATION);
    assert_eq!(json["errorCode"], serde_json::Value::Null);
}

#[test]
fn proven_failure_before_effects_is_final() {
    let fixture = Fixture::new();
    let mut journal = fixture.start();
    let failed = journal
        .settle_failed_before_effects(InstallFailureCode::ApplyFailed, NOW + 1)
        .unwrap();
    assert_eq!(failed.exit_code(), 5);
    assert_eq!(
        lookup_apply(&fixture.directory, &original_intent()),
        Ok(Some(failed))
    );
    assert_eq!(
        journal.advance(BusinessPhase::LocalPublicationPossible, NOW + 2),
        Err(JournalError::InvalidTransition)
    );
}

#[test]
fn stale_writer_is_fenced_instead_of_overwriting_newer_generation() {
    let fixture = Fixture::new();
    let mut journal = fixture.start();
    let accepted = read_record(&fixture.directory).unwrap();
    let mut newer = accepted.business().unwrap().clone();
    newer.phase = BusinessPhase::LocalPublicationPossible;
    newer.revision += 1;
    replace_business_record(&fixture.directory, &accepted, newer).unwrap();
    let after = fixture.original_bytes();
    assert!(matches!(
        journal.advance(BusinessPhase::LocalPublicationPossible, NOW + 1),
        Err(JournalError::Storage(ControlRecordError::Conflict))
    ));
    assert_eq!(
        journal.mark_unknown(NOW + 2),
        Err(JournalError::WriterFenced)
    );
    assert_eq!(fixture.original_bytes(), after);
}

#[test]
fn canonical_record_with_impossible_business_outcome_fails_closed() {
    let fixture = Fixture::new();
    let _journal = fixture.start();
    let accepted = String::from_utf8(fixture.original_bytes()).unwrap();
    let invalid = accepted
        .replacen("\"revision\":4", "\"revision\":5", 1)
        .replacen(
            "\"business\":{\"revision\":1",
            "\"business\":{\"revision\":2",
            1,
        )
        .replacen("\"state\":\"PENDING\"", "\"state\":\"SUCCEEDED\"", 1);
    assert_ne!(invalid, accepted);
    let path = fixture.home.path().join("control.json");
    fs::write(&path, &invalid).unwrap();
    assert_eq!(
        lookup_status(&fixture.directory, OPERATION, INSTALLATION),
        Err(JournalError::Storage(ControlRecordError::InvalidRecord))
    );
    assert_eq!(fs::read_to_string(path).unwrap(), invalid);
}

#[test]
fn cold_takeover_requires_original_registration_phase_and_never_writes_on_rejection() {
    let fixture = Fixture::new();
    let _journal = fixture.start();
    let current = read_record(&fixture.directory).unwrap();
    let before = fixture.original_bytes();
    assert!(matches!(
        confirm_recovered_registration(
            &fixture.directory,
            &current,
            &fixture.directory,
            None,
            std::time::Duration::from_secs(1),
            || NOW,
        ),
        Err(RegistrationTakeoverError::Recovery(
            RegistrationRecoveryError::InvalidPhase
        ))
    ));
    assert_eq!(fixture.original_bytes(), before);
}

struct RegistrationServer(Child);

impl RegistrationServer {
    fn launch(directory: &Path) -> (Self, Target) {
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/installation/registration/https_fixture.py",
            ))
            .arg(directory)
            .arg("committed")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut port = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        let target = Target::new(
            &format!("https://localhost:{}", port.trim().parse::<u16>().unwrap()),
            "server-1",
        )
        .unwrap();
        (Self(child), target)
    }
}

impl Drop for RegistrationServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cold_takeover_get_proof_advances_both_pending_and_persisted_unknown() {
    const CA: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
    const TIMEOUT: Duration = Duration::from_secs(2);
    for interrupted_unknown in [false, true] {
        let state_home = tempfile::tempdir().unwrap();
        fs::set_permissions(state_home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = File::open(state_home.path()).unwrap();
        let identity_path = state_home.path().join("identity");
        fs::create_dir(&identity_path).unwrap();
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o700)).unwrap();
        state.sync_all().unwrap();
        let (_server, target) = RegistrationServer::launch(state_home.path());
        let fixture = Fixture::with_target(target.clone());
        let marker = state_home.path().join("registration-possible");
        {
            let mut journal = fixture.start();
            for phase in [
                BusinessPhase::LocalPublicationPossible,
                BusinessPhase::LocalPublished,
                BusinessPhase::SupervisorLockCreatePossible,
                BusinessPhase::SupervisorLockReady,
            ] {
                journal.advance(phase, NOW + 1).unwrap();
            }
            let prepared =
                PreparedRegistration::initialize(&identity_path, target, Some(CA), TIMEOUT)
                    .unwrap();
            let input = state_home.path().join("enrollment-fixture");
            fs::write(&input, format!("ndme_{}", "A".repeat(43))).unwrap();
            fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
            let enrollment = Enrollment::from_private_file(&input).unwrap();
            fs::remove_file(input).unwrap();
            let metadata = RegistrationMetadata {
                version: "0.1.0".into(),
                architecture: Architecture::Arm64,
                distribution: "debian".into(),
                distribution_version: "12".into(),
                hostname: "recovery-fixture".into(),
                capabilities: Capabilities {
                    system: Capability::Available,
                    processes: Capability::Unsupported,
                    containers: Capability::Unsupported,
                    ssh_events: Capability::Unsupported,
                },
            };
            assert_eq!(
                prepared.register_once(
                    enrollment,
                    &metadata,
                    None,
                    |id| -> Result<(), JournalError> {
                        journal.mark_registration_possible(id, NOW + 2)?;
                        fs::write(&marker, id).unwrap();
                        Ok(())
                    }
                ),
                Err(RegistrationAttemptError::OutcomeUnknown(
                    "NETWORK_OR_TLS_ERROR"
                ))
            );
            if interrupted_unknown {
                journal.mark_unknown(NOW + 3).unwrap();
                assert_eq!(
                    journal.confirm_registration(
                        Binding {
                            agent_id: "agent:registration-fixture".into(),
                            server_id: "server-1".into(),
                            binding_revision: 2,
                        },
                        NOW + 4,
                    ),
                    Err(JournalError::InvalidTransition)
                );
            }
        }
        let expected = read_record(&fixture.directory).unwrap();
        let prior_revision = expected.revision();
        let expected_id = fs::read_to_string(&marker).unwrap();
        assert!(
            !fixture
                .original_bytes()
                .windows(b"recoveredFromUnknown".len())
                .any(|window| window == b"recoveredFromUnknown")
        );
        let (observed, mut journal) = confirm_recovered_registration(
            &fixture.directory,
            &expected,
            &state,
            Some(CA),
            TIMEOUT,
            || NOW + 5,
        )
        .unwrap();
        assert_eq!(observed.server_id, "server-1");
        assert_eq!(journal.phase(), BusinessPhase::IdentityConfirmed);
        assert_eq!(
            journal.registration_operation_id(),
            Some(expected_id.as_str())
        );
        let confirmed = read_record(&fixture.directory).unwrap();
        assert_eq!(confirmed.claim(), expected.claim());
        assert_eq!(confirmed.revision(), prior_revision + 1);
        assert_eq!(
            confirmed
                .business()
                .unwrap()
                .registration
                .as_ref()
                .unwrap()
                .recovered_from_unknown,
            interrupted_unknown
        );
        assert_eq!(
            lookup_apply(&fixture.directory, &original_intent())
                .unwrap()
                .unwrap()
                .exit_code(),
            6
        );
        assert!(matches!(
            confirm_recovered_registration(
                &fixture.directory,
                &expected,
                &state,
                Some(CA),
                TIMEOUT,
                || NOW + 6,
            ),
            Err(RegistrationTakeoverError::Recovery(
                RegistrationRecoveryError::ControlChanged
            ))
        ));
        assert_eq!(
            fs::read_to_string(state_home.path().join("requests")).unwrap(),
            "POST\nGET\n"
        );
        journal
            .advance(BusinessPhase::ServiceStartPossible, NOW + 7)
            .unwrap();
        let later = read_record(&fixture.directory).unwrap();
        assert_eq!(later.revision(), prior_revision + 2);
        assert_eq!(
            later
                .business()
                .unwrap()
                .registration
                .as_ref()
                .unwrap()
                .recovered_from_unknown,
            interrupted_unknown
        );
    }
}
