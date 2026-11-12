use nodomi_agent::identity::{IdentityStore, Status, Target};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn target() -> Target {
    Target::new("https://localhost:9443", "server-1").unwrap()
}
#[test]
fn credential_and_operation_are_durable_and_one_writer_owns_state() {
    let dir = directory();
    let first = IdentityStore::initialize(dir.path(), target()).unwrap();
    assert_eq!(first.status(), Status::Prepared);
    assert!(IdentityStore::open(dir.path(), &target()).is_err());
    let operation = first.operation_id().to_owned();
    let bytes = fs::read(dir.path().join("identity.json")).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["credential"].as_str().unwrap().len(), 48);
    assert!(json["credential"].as_str().unwrap().starts_with("ndma_"));
    assert_eq!(
        fs::metadata(dir.path().join("identity.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(first);
    let again = IdentityStore::open(dir.path(), &target()).unwrap();
    assert_eq!(again.operation_id(), operation);
    assert_eq!(fs::read(dir.path().join("identity.json")).unwrap(), bytes);
    assert!(IdentityStore::initialize(dir.path(), target()).is_err());
}
#[test]
fn unsafe_partial_unknown_or_different_target_state_is_never_reinitialized() {
    for entry in ["trust", "maintenance.json", "identity.next"] {
        let dir = directory();
        fs::write(dir.path().join(entry), "evidence").unwrap();
        assert!(IdentityStore::initialize(dir.path(), target()).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join(entry)).unwrap(),
            "evidence"
        );
    }
    let dir = directory();
    drop(IdentityStore::initialize(dir.path(), target()).unwrap());
    let other = Target::new("https://localhost:9443", "server-2").unwrap();
    assert!(IdentityStore::open(dir.path(), &other).is_err());
    fs::write(dir.path().join("identity.json"), "{broken").unwrap();
    assert!(IdentityStore::open(dir.path(), &target()).is_err());
    assert!(IdentityStore::initialize(dir.path(), target()).is_err());
}
#[test]
fn private_directory_and_nofollow_entries_are_required() {
    let dir = directory();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(IdentityStore::initialize(dir.path(), target()).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let outside = directory();
    fs::write(outside.path().join("secret"), "untouched").unwrap();
    symlink(
        outside.path().join("secret"),
        dir.path().join("identity.json"),
    )
    .unwrap();
    assert!(IdentityStore::initialize(dir.path(), target()).is_err());
    assert_eq!(
        fs::read_to_string(outside.path().join("secret")).unwrap(),
        "untouched"
    );
}
#[test]
fn private_secret_input_rejects_unsafe_modes_links_and_extra_bytes() {
    use nodomi_agent::identity::Enrollment;
    let dir = directory();
    let secret = dir.path().join("enrollment");
    fs::write(&secret, format!("ndme_{}\n", "A".repeat(43))).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(Enrollment::from_private_file(&secret).is_ok());
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Enrollment::from_private_file(&secret).is_err());
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    symlink(&secret, dir.path().join("linked")).unwrap();
    assert!(Enrollment::from_private_file(&dir.path().join("linked")).is_err());
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&secret, format!("ndme_{}\nEXTRA", "A".repeat(43))).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(Enrollment::from_private_file(&secret).is_err());
}
#[test]
fn lock_only_or_unsafe_existing_files_preserve_partial_evidence() {
    let dir = directory();
    fs::write(dir.path().join("protocol.lock"), "").unwrap();
    fs::set_permissions(
        dir.path().join("protocol.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(IdentityStore::open(dir.path(), &target()).is_err());
    assert!(IdentityStore::initialize(dir.path(), target()).is_err());
    let fresh = directory();
    drop(IdentityStore::initialize(fresh.path(), target()).unwrap());
    fs::set_permissions(
        fresh.path().join("identity.json"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(IdentityStore::open(fresh.path(), &target()).is_err());
}
#[test]
fn other_process_cannot_open_held_identity() {
    let dir = directory();
    let _held = IdentityStore::initialize(dir.path(), target()).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lock_process_helper"])
        .env("NODOMI_TEST_LOCK", dir.path())
        .output()
        .unwrap();
    assert!(result.status.success());
}
#[test]
fn lock_process_helper() {
    let Ok(path) = std::env::var("NODOMI_TEST_LOCK") else {
        return;
    };
    assert!(IdentityStore::open(std::path::Path::new(&path), &target()).is_err());
}
#[test]
fn directory_symlinks_and_hardlinked_credentials_are_refused() {
    let dir = directory();
    let parent = directory();
    symlink(dir.path(), parent.path().join("alias")).unwrap();
    assert!(IdentityStore::initialize(&parent.path().join("alias"), target()).is_err());
    drop(IdentityStore::initialize(dir.path(), target()).unwrap());
    fs::hard_link(dir.path().join("identity.json"), parent.path().join("copy")).unwrap();
    assert!(IdentityStore::open(dir.path(), &target()).is_err());
}
#[cfg(target_os = "linux")]
#[test]
fn root_cannot_adopt_foreign_owned_credentials() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = directory();
    drop(IdentityStore::initialize(dir.path(), target()).unwrap());
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let name = CString::new(dir.path().join("identity.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: NUL-terminated pathname; this root-only test owns the file and directory.
    assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
    assert!(IdentityStore::open(dir.path(), &target()).is_err());
}
