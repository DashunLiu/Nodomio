use super::*;
use crate::{
    identity::Target,
    installation::{
        control_record::{PreparationClaim, advance_record, publish_claimed},
        operation_journal::{Admission, BusinessPhase, InstallIntent, OperationJournal},
        registration::PreparedRegistration,
    },
};
use std::{
    fs::{self, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

const DOMAIN: &str = "11111111-1111-4111-8111-111111111111";
const OPERATION: &str = "22222222-2222-4222-8222-222222222222";
const KEY: &str = "33333333-3333-4333-8333-333333333333";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const INSTALLATION: &str = "55555555-5555-4555-8555-555555555555";
const IDENTITY: &str = "66666666-6666-4666-8666-666666666666";
const TIMEOUT: Duration = Duration::from_secs(1);
const NOW: u64 = 1_794_304_800_000;

struct Fixture {
    _temporary: tempfile::TempDir,
    control_path: PathBuf,
    state_path: PathBuf,
    control: File,
    state: File,
    ready: ControlRecord,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let control_path = temporary.path().join("control");
        let state_path = temporary.path().join("state");
        let control = private_directory(&control_path);
        let state = private_directory(&state_path);
        let claim = PreparationClaim {
            operation_id: OPERATION.into(),
            idempotency_key: KEY.into(),
            plan_id: PLAN.into(),
            plan_digest: "1".repeat(64),
            installation_id: INSTALLATION.into(),
            target: Target::new("https://127.0.0.1:1", "server-1").unwrap(),
        };
        let claimed = ControlRecord::claimed(DOMAIN.into(), claim).unwrap();
        publish_claimed(&control, &claimed).unwrap();
        let possible =
            advance_record(&control, &claimed, ControlPhase::LockCreatePossible).unwrap();
        let ready = advance_record(&control, &possible, ControlPhase::Ready).unwrap();
        Self {
            _temporary: temporary,
            control_path,
            state_path,
            control,
            state,
            ready,
        }
    }

    fn pending(&self) -> OperationJournal<'_> {
        let intent = InstallIntent::new(PLAN, &"1".repeat(64), INSTALLATION, KEY).unwrap();
        let Admission::New(mut journal) =
            OperationJournal::begin(&self.control, &self.ready, &intent, NOW).unwrap()
        else {
            panic!("expected original admission");
        };
        for phase in [
            BusinessPhase::LocalPublicationPossible,
            BusinessPhase::LocalPublished,
            BusinessPhase::SupervisorLockCreatePossible,
            BusinessPhase::SupervisorLockReady,
        ] {
            journal.advance(phase, NOW).unwrap();
        }
        journal.mark_registration_possible(IDENTITY, NOW).unwrap();
        journal
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.control_path.join("control.json")).unwrap()
    }
}

fn private_directory(path: &Path) -> File {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
    File::open(path).unwrap()
}

#[test]
fn recovery_requires_the_exact_current_original_marker() {
    let fixture = Fixture::new();
    assert_eq!(
        recover_original_registration(
            &fixture.control,
            &fixture.ready,
            &fixture.state,
            None,
            TIMEOUT
        ),
        Err(RegistrationRecoveryError::InvalidPhase)
    );
    let _journal = fixture.pending();
    let before = fixture.bytes();
    assert_eq!(
        recover_original_registration(
            &fixture.control,
            &fixture.ready,
            &fixture.state,
            None,
            TIMEOUT
        ),
        Err(RegistrationRecoveryError::ControlChanged)
    );
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fs::read_dir(&fixture.state_path).unwrap().count(), 0);
}

#[test]
fn unsafe_or_missing_identity_cannot_be_created_or_followed() {
    let fixture = Fixture::new();
    let _journal = fixture.pending();
    let expected = read_record(&fixture.control).unwrap();
    let before = fixture.bytes();
    for state in [&fixture.control, &fixture.state] {
        assert_eq!(
            recover_original_registration(&fixture.control, &expected, state, None, TIMEOUT),
            Err(RegistrationRecoveryError::InvalidState)
        );
    }
    assert_eq!(fs::read_dir(&fixture.state_path).unwrap().count(), 0);
    symlink(&fixture.control_path, fixture.state_path.join("identity")).unwrap();
    assert_eq!(
        recover_original_registration(&fixture.control, &expected, &fixture.state, None, TIMEOUT),
        Err(RegistrationRecoveryError::InvalidState)
    );
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn unknown_registration_phase_cannot_recover_a_substituted_credential() {
    let fixture = Fixture::new();
    let mut journal = fixture.pending();
    journal.mark_unknown(NOW + 1).unwrap();
    let identity_path = fixture.state_path.join("identity");
    private_directory(&identity_path);
    drop(
        PreparedRegistration::initialize(
            &identity_path,
            fixture.ready.claim().target.clone(),
            None,
            TIMEOUT,
        )
        .unwrap(),
    );
    let expected = read_record(&fixture.control).unwrap();
    let before = fixture.bytes();
    let identity_before = fs::read(identity_path.join("identity.json")).unwrap();
    assert_eq!(
        recover_original_registration(&fixture.control, &expected, &fixture.state, None, TIMEOUT),
        Err(RegistrationRecoveryError::Identity(
            RegistrationError::InvalidOriginalIdentity
        ))
    );
    assert_eq!(fixture.bytes(), before);
    assert!(identity_before == fs::read(identity_path.join("identity.json")).unwrap());
}
