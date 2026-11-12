use nodomi_agent::trust_storage::*;
use ring::digest::{SHA256, digest};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
};

const INSTALLATION: &str = "d1068b94-754c-4aa3-8b70-2dd4f04fbe3d";
const OPERATION: &str = "a12378e9-2248-46aa-8826-965b75bd260a";
const PAYLOAD: &[u8] = b"opaque-fixture-not-a-trusted-root";
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions or memory access.
    unsafe { libc::geteuid() }
}
fn context(path: &Path) -> ExpectedInstallation {
    ExpectedInstallation::new(path, INSTALLATION, "github-test-source-v1", uid()).unwrap()
}
fn intent(path: &Path) -> NewInstallationIntent {
    NewInstallationIntent::new(context(path), OPERATION).unwrap()
}
fn directory() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn fixture(path: &Path) {
    // The literal record's field order is the v1 checksum order, independently built.
    let record = format!(
        "{{\"schemaVersion\":1,\"purpose\":\"UNVERIFIED_STORAGE_BOUNDARY\",\"installationId\":\"{INSTALLATION}\",\"sourceConfigId\":\"github-test-source-v1\",\"stateLocation\":{},\"ownerUid\":{},\"initializationOperationId\":\"{OPERATION}\",\"generation\":1,\"payloadBase64\":\"b3BhcXVlLWZpeHR1cmUtbm90LWEtdHJ1c3RlZC1yb290\"}}",
        serde_json::to_string(path.to_str().unwrap()).unwrap(),
        uid()
    );
    let checksum: String = digest(&SHA256, record.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write(
        &path.join("authority.json"),
        format!("{{\"record\":{record},\"checksumSha256\":\"{checksum}\"}}").as_bytes(),
    );
}
fn fingerprint(path: &Path) -> Vec<String> {
    fn visit(path: &Path, relative: &str, output: &mut Vec<String>) {
        let m = fs::symlink_metadata(path).unwrap();
        output.push(format!(
            "{relative}|{}|{}|{}|{}|{}|{}|{}|{}|{:?}",
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            if m.is_file() {
                fs::read(path).unwrap()
            } else {
                vec![]
            }
        ));
        if m.is_dir() {
            let mut entries: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            entries.sort();
            for child in entries {
                visit(
                    &child,
                    &format!(
                        "{relative}/{}",
                        child.file_name().unwrap().to_string_lossy()
                    ),
                    output,
                );
            }
        }
    }
    let mut output = vec![];
    visit(path, "", &mut output);
    output
}

#[test]
fn inspector_reads_unverified_fixture_without_mutating_directory() {
    let d = directory();
    fixture(d.path());
    let before = fingerprint(d.path());
    let snapshot = inspect_existing(&context(d.path()))
        .expect("valid bounded opaque fixture must be readable without a verifier");
    assert_eq!(snapshot.generation(), 1);
    assert_eq!(snapshot.opaque_payload(), PAYLOAD);
    assert_eq!(snapshot.initialization_operation_id(), OPERATION);
    assert_eq!(before, fingerprint(d.path()));
}
#[test]
fn explicit_initialization_publishes_once_and_never_clobbers_existing_bytes() {
    let d = directory();
    let snapshot = initialize_new(&intent(d.path()), PAYLOAD)
        .expect("explicit empty-target intent must publish an opaque envelope");
    assert_eq!(snapshot.generation(), 1);
    let before = fingerprint(d.path());
    assert!(matches!(
        initialize_new(&intent(d.path()), b"replacement"),
        Err(StorageError::Conflict)
    ));
    assert_eq!(before, fingerprint(d.path()));
    assert_eq!(
        inspect_original_intent(&intent(d.path()))
            .unwrap()
            .opaque_payload(),
        PAYLOAD
    );
}
#[test]
fn invalid_independent_contexts_are_rejected_before_filesystem_access() {
    let d = directory();
    for (p, id, source) in [
        (Path::new("relative"), INSTALLATION, "source"),
        (d.path(), "broken-id", "source"),
        (d.path(), INSTALLATION, ""),
        (Path::new("/tmp/../other"), INSTALLATION, "source"),
        (Path::new("/tmp/./state"), INSTALLATION, "source"),
        (Path::new("/tmp//state"), INSTALLATION, "source"),
    ] {
        assert!(matches!(
            ExpectedInstallation::new(p, id, source, uid()),
            Err(StorageError::InvalidContext)
        ));
    }
    assert!(matches!(
        NewInstallationIntent::new(context(d.path()), "not-an-operation-id"),
        Err(StorageError::InvalidContext)
    ));
}
#[test]
fn opened_handle_pins_generation_and_never_recreates_lost_authority() {
    let d = directory();
    fixture(d.path());
    let store = open_existing(&context(d.path())).unwrap();
    assert_eq!(
        store
            .read()
            .expect("an existing handle must reread its checked generation")
            .opaque_payload(),
        PAYLOAD
    );
    let original = fs::read(d.path().join("authority.json")).unwrap();
    fs::remove_file(d.path().join("authority.json")).unwrap();
    let before = fingerprint(d.path());
    assert!(matches!(store.read(), Err(StorageError::MissingAuthority)));
    assert_eq!(before, fingerprint(d.path()));
    let mut altered = original.clone();
    altered.push(b' ');
    write(&d.path().join("authority.json"), &altered);
    assert!(matches!(store.read(), Err(StorageError::RecoveryRequired)));
    write(&d.path().join("authority.json"), &original);
    assert!(matches!(store.read(), Err(StorageError::RecoveryRequired)));
    assert_eq!(
        open_existing(&context(d.path()))
            .unwrap()
            .read()
            .unwrap()
            .opaque_payload(),
        PAYLOAD
    );
}
#[test]
fn moved_directory_and_replacement_path_cannot_redirect_opened_handle() {
    let outer = directory();
    let original = outer.path().join("state");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    fixture(&original);
    let store = open_existing(&context(&original)).unwrap();
    let moved = outer.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    fixture(&original);
    let before = fingerprint(outer.path());
    assert!(matches!(store.read(), Err(StorageError::GenerationChanged)));
    assert_eq!(before, fingerprint(outer.path()));
}
#[test]
fn missing_existing_state_and_residual_files_never_initialize_or_cleanup() {
    let outer = directory();
    let missing = outer.path().join("not-created");
    let before = fingerprint(outer.path());
    assert!(matches!(
        inspect_existing(&context(&missing)),
        Err(StorageError::MissingDirectory)
    ));
    assert!(matches!(
        open_existing(&context(&missing)),
        Err(StorageError::MissingDirectory)
    ));
    assert_eq!(before, fingerprint(outer.path()));
    for residual in [
        None,
        Some("authority.next"),
        Some("backup.json"),
        Some("identity.json"),
    ] {
        let d = directory();
        if let Some(name) = residual {
            write(&d.path().join(name), b"preserved evidence");
        }
        let before = fingerprint(d.path());
        let expected_error = if residual.is_some() {
            StorageError::RecoveryRequired
        } else {
            StorageError::MissingAuthority
        };
        assert!(matches!(inspect_existing(&context(d.path())),Err(e) if e==expected_error));
        assert!(matches!(open_existing(&context(d.path())),Err(e) if e==expected_error));
        assert_eq!(before, fingerprint(d.path()));
    }
}
#[test]
fn independent_installation_source_location_and_owner_bindings_are_required() {
    let d = directory();
    fixture(d.path());
    let other_id = "efcd633b-0b77-45c4-88d4-37fe4d545500";
    for (id, source) in [
        (other_id, "github-test-source-v1"),
        (INSTALLATION, "different-source"),
    ] {
        let expected = ExpectedInstallation::new(d.path(), id, source, uid()).unwrap();
        assert!(matches!(
            inspect_existing(&expected),
            Err(StorageError::BindingMismatch)
        ));
    }
    let other = directory();
    write(
        &other.path().join("authority.json"),
        &fs::read(d.path().join("authority.json")).unwrap(),
    );
    assert!(matches!(
        inspect_existing(&context(other.path())),
        Err(StorageError::BindingMismatch)
    ));
    let owner = ExpectedInstallation::new(
        d.path(),
        INSTALLATION,
        "github-test-source-v1",
        uid().wrapping_add(1),
    )
    .unwrap();
    assert!(matches!(
        inspect_existing(&owner),
        Err(StorageError::UnsafeFilesystem)
    ));
}
#[test]
fn strict_format_duplicate_fields_and_bad_checksum_are_preserved_and_rejected() {
    for change in [
        "bad-json",
        "duplicate-record-field",
        "duplicate-envelope-field",
        "unknown-record-field",
        "unknown-envelope-field",
        "tamper",
        "trailing",
    ] {
        let d = directory();
        fixture(d.path());
        let original = fs::read_to_string(d.path().join("authority.json")).unwrap();
        let changed = match change {
            "bad-json" => "{".into(),
            "duplicate-record-field" => {
                original.replace("\"generation\":1", "\"generation\":1,\"generation\":1")
            }
            "duplicate-envelope-field" => original.replace(
                "\"checksumSha256\":",
                "\"checksumSha256\":\"x\",\"checksumSha256\":",
            ),
            "unknown-record-field" => {
                original.replace("\"generation\":1", "\"futureThing\":1,\"generation\":1")
            }
            "unknown-envelope-field" => {
                original.replace("{\"record\":", "{\"extra\":null,\"record\":")
            }
            "tamper" => original.replace("b3BhcXVl", "b3BhcXVm"),
            "trailing" => format!("{original}{{}}"),
            _ => unreachable!(),
        };
        write(&d.path().join("authority.json"), changed.as_bytes());
        let before = fingerprint(d.path());
        assert!(
            matches!(
                inspect_existing(&context(d.path())),
                Err(StorageError::InvalidEnvelope)
            ),
            "{change}"
        );
        assert_eq!(before, fingerprint(d.path()), "{change}");
    }
}
fn rewrite_record(path: &Path, edit: impl FnOnce(String) -> String) {
    let envelope = fs::read_to_string(path.join("authority.json")).unwrap();
    let record = envelope
        .strip_prefix("{\"record\":")
        .unwrap()
        .split_once(",\"checksumSha256\":")
        .unwrap()
        .0;
    let record = edit(record.to_owned());
    let checksum: String = digest(&SHA256, record.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write(
        &path.join("authority.json"),
        format!("{{\"record\":{record},\"checksumSha256\":\"{checksum}\"}}").as_bytes(),
    );
}
#[test]
fn malformed_phase_and_encoded_payload_are_not_treated_as_missing() {
    for change in [
        "version",
        "purpose",
        "generation",
        "operation",
        "invalid-base64",
        "empty-payload",
    ] {
        let d = directory();
        fixture(d.path());
        rewrite_record(d.path(), |r| match change {
            "version" => r.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            "purpose" => r.replace("UNVERIFIED_STORAGE_BOUNDARY", "READY"),
            "generation" => r.replace("\"generation\":1", "\"generation\":0"),
            "operation" => r.replace(OPERATION, "invalid"),
            "invalid-base64" => r.replace("b3BhcXVlLWZpeHR1cmUtbm90LWEtdHJ1c3RlZC1yb290", "%%%"),
            "empty-payload" => r.replace("b3BhcXVlLWZpeHR1cmUtbm90LWEtdHJ1c3RlZC1yb290", ""),
            _ => unreachable!(),
        });
        assert!(
            matches!(
                inspect_existing(&context(d.path())),
                Err(StorageError::InvalidEnvelope)
            ),
            "{change}"
        );
        assert!(matches!(
            initialize_new(&intent(d.path()), PAYLOAD),
            Err(StorageError::Conflict)
        ));
    }
}
#[test]
fn bounded_payload_and_sparse_oversized_envelope_stop_before_parsing() {
    let d = directory();
    let payload = vec![42; MAX_PAYLOAD_BYTES];
    initialize_new(&intent(d.path()), &payload).unwrap();
    assert_eq!(
        inspect_existing(&context(d.path()))
            .unwrap()
            .opaque_payload()
            .len(),
        MAX_PAYLOAD_BYTES
    );
    let empty = directory();
    let before = fingerprint(empty.path());
    assert!(matches!(
        initialize_new(&intent(empty.path()), &vec![0; MAX_PAYLOAD_BYTES + 1]),
        Err(StorageError::ReadBudgetExceeded)
    ));
    assert!(matches!(
        initialize_new(&intent(empty.path()), &[]),
        Err(StorageError::InvalidEnvelope)
    ));
    assert_eq!(before, fingerprint(empty.path()));
    let sparse = directory();
    let f = fs::File::create(sparse.path().join("authority.json")).unwrap();
    fs::set_permissions(
        sparse.path().join("authority.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    f.set_len((MAX_ENVELOPE_BYTES + 1) as u64).unwrap();
    let before = fingerprint(sparse.path());
    assert!(matches!(
        inspect_existing(&context(sparse.path())),
        Err(StorageError::ReadBudgetExceeded)
    ));
    assert_eq!(before, fingerprint(sparse.path()));
}
#[test]
fn symlinks_hardlinks_and_wrong_modes_never_get_repaired() {
    for variant in [
        "file-symlink",
        "directory-symlink",
        "hardlink",
        "file-mode",
        "directory-mode",
    ] {
        let outer = directory();
        let d = outer.path().join("state");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        fixture(&d);
        match variant {
            "file-symlink" => {
                let moved = outer.path().join("saved");
                fs::rename(d.join("authority.json"), &moved).unwrap();
                symlink(moved, d.join("authority.json")).unwrap();
            }
            "directory-symlink" => {
                let moved = outer.path().join("saved");
                fs::rename(&d, &moved).unwrap();
                symlink(moved, &d).unwrap();
            }
            "hardlink" => {
                fs::hard_link(d.join("authority.json"), outer.path().join("alias")).unwrap()
            }
            "file-mode" => {
                fs::set_permissions(d.join("authority.json"), fs::Permissions::from_mode(0o640))
                    .unwrap()
            }
            "directory-mode" => fs::set_permissions(&d, fs::Permissions::from_mode(0o750)).unwrap(),
            _ => unreachable!(),
        }
        let before = fingerprint(outer.path());
        assert!(inspect_existing(&context(&d)).is_err(), "{variant}");
        assert_eq!(before, fingerprint(outer.path()));
    }
}
#[test]
fn fifo_and_socket_are_rejected_without_waiting_for_a_writer() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, net::UnixListener},
        time::{Duration, Instant},
    };
    let d = directory();
    let name = d.path().join("authority.json");
    let c = CString::new(name.as_os_str().as_bytes()).unwrap();
    // SAFETY: c is a terminated test path, mode is valid and path is unique.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let start = Instant::now();
    assert!(inspect_existing(&context(d.path())).is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    fs::remove_file(&name).unwrap();
    let _socket = UnixListener::bind(&name).unwrap();
    assert!(inspect_existing(&context(d.path())).is_err());
}
#[test]
fn original_intent_inspection_cannot_resume_a_different_operation_or_remove_residuals() {
    let d = directory();
    fixture(d.path());
    let other =
        NewInstallationIntent::new(context(d.path()), "efcd633b-0b77-45c4-88d4-37fe4d545500")
            .unwrap();
    assert!(matches!(
        inspect_original_intent(&other),
        Err(StorageError::Conflict)
    ));
    write(
        &d.path().join("authority.next"),
        b"same-intent partial bytes",
    );
    let before = fingerprint(d.path());
    assert!(matches!(
        inspect_original_intent(&intent(d.path())),
        Err(StorageError::RecoveryRequired)
    ));
    assert_eq!(before, fingerprint(d.path()));
}
#[test]
fn inspection_ignores_writer_lock_and_initialization_respects_it_without_lock_files() {
    use std::os::fd::AsRawFd;
    let d = directory();
    let file = fs::File::open(d.path()).unwrap();
    // SAFETY: file is a live directory descriptor and this test owns its lock.
    let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(acquired, 0);
    let before = fingerprint(d.path());
    assert!(matches!(
        initialize_new(&intent(d.path()), PAYLOAD),
        Err(StorageError::WriterBusy)
    ));
    assert_eq!(before, fingerprint(d.path()));
    fixture(d.path());
    let before = fingerprint(d.path());
    assert!(inspect_existing(&context(d.path())).is_ok());
    assert_eq!(before, fingerprint(d.path()));
    // SAFETY: file still owns the lock acquired above.
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
}
#[test]
fn actual_foreign_uid_file_is_rejected_when_running_as_root() {
    if uid() != 0 {
        return;
    }
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let d = directory();
    fixture(d.path());
    let name = CString::new(d.path().join("authority.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: terminated unique test path and root changes only its own disposable fixture.
    assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
    let before = fingerprint(d.path());
    assert!(matches!(
        inspect_existing(&context(d.path())),
        Err(StorageError::UnsafeFilesystem)
    ));
    assert_eq!(before, fingerprint(d.path()));
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Explicit nobody run required; root bypasses mode denial"]
fn linux_unprivileged_denied_open_is_read_only() {
    assert_ne!(uid(), 0);
    let d = directory();
    fixture(d.path());
    fs::set_permissions(
        d.path().join("authority.json"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let before = fingerprint_metadata(d.path());
    assert!(matches!(
        inspect_existing(&context(d.path())),
        Err(StorageError::PermissionDenied)
    ));
    assert_eq!(before, fingerprint_metadata(d.path()));
    fs::set_permissions(
        d.path().join("authority.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}
#[cfg(target_os = "linux")]
fn fingerprint_metadata(path: &Path) -> Vec<(u32, u32, u32, u64, i64, i64)> {
    [path.to_owned(), path.join("authority.json")]
        .iter()
        .map(|p| {
            let m = fs::metadata(p).unwrap();
            (m.mode(), m.uid(), m.gid(), m.nlink(), m.mtime(), m.ctime())
        })
        .collect()
}
#[test]
fn initial_publication_process_helper() {
    let Ok(root) = std::env::var("NODOMI_TRUST_TEST_CHILD_ROOT") else {
        return;
    };
    let label = std::env::var("NODOMI_TRUST_TEST_CHILD_LABEL").unwrap();
    let root = Path::new(&root);
    write(&root.join(format!("ready-{label}")), b"ready");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !root.join("start").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let result = initialize_new(&intent(&root.join("state")), label.as_bytes());
    let value = match result {
        Ok(_) => "WIN",
        Err(StorageError::WriterBusy) => "BUSY",
        Err(StorageError::Conflict) => "CONFLICT",
        Err(_) => "UNEXPECTED",
    };
    write(&root.join(format!("result-{label}")), value.as_bytes());
}
#[test]
fn two_processes_publish_one_initial_envelope_and_keep_winner_payload() {
    use std::process::Command;
    let outer = directory();
    let state = outer.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut children = vec![];
    for label in ["writer-a", "writer-b"] {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "initial_publication_process_helper"])
                .env("NODOMI_TRUST_TEST_CHILD_ROOT", outer.path())
                .env("NODOMI_TRUST_TEST_CHILD_LABEL", label)
                .spawn()
                .unwrap(),
        );
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !["writer-a", "writer-b"]
        .iter()
        .all(|label| outer.path().join(format!("ready-{label}")).exists())
    {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    write(&outer.path().join("start"), b"start");
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let results: Vec<_> = ["writer-a", "writer-b"]
        .iter()
        .map(|label| {
            (
                *label,
                fs::read_to_string(outer.path().join(format!("result-{label}"))).unwrap(),
            )
        })
        .collect();
    assert_eq!(results.iter().filter(|(_, r)| r == "WIN").count(), 1);
    assert!(
        results
            .iter()
            .all(|(_, r)| ["WIN", "BUSY", "CONFLICT"].contains(&r.as_str()))
    );
    let winner = results.iter().find(|(_, r)| r == "WIN").unwrap().0;
    assert_eq!(
        inspect_existing(&context(&state)).unwrap().opaque_payload(),
        winner.as_bytes()
    );
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
}

#[test]
fn writer_cannot_initialize_for_a_foreign_owner_even_with_root_access() {
    if uid() != 0 {
        return;
    }
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let d = directory();
    let name = CString::new(d.path().as_os_str().as_bytes()).unwrap();
    // SAFETY: unique disposable test directory; this root-only branch owns it.
    assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
    let expected = ExpectedInstallation::new(d.path(), INSTALLATION, "test-source", 65534).unwrap();
    let intent = NewInstallationIntent::new(expected, OPERATION).unwrap();
    let before = fingerprint(d.path());
    assert!(matches!(
        initialize_new(&intent, PAYLOAD),
        Err(StorageError::InvalidContext)
    ));
    assert_eq!(before, fingerprint(d.path()));
}
#[test]
fn decoder_refuses_a_checksummed_payload_over_its_decoded_budget() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let d = directory();
    fixture(d.path());
    let encoded = STANDARD.encode(vec![1; MAX_PAYLOAD_BYTES + 1]);
    rewrite_record(d.path(), |r| {
        r.replace("b3BhcXVlLWZpeHR1cmUtbm90LWEtdHJ1c3RlZC1yb290", &encoded)
    });
    assert!(
        fs::metadata(d.path().join("authority.json")).unwrap().len() < MAX_ENVELOPE_BYTES as u64
    );
    assert!(matches!(
        inspect_existing(&context(d.path())),
        Err(StorageError::ReadBudgetExceeded)
    ));
}
#[test]
fn same_content_authority_replacement_is_detected_on_existing_handle() {
    let outer = directory();
    let state = outer.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fixture(&state);
    let store = open_existing(&context(&state)).unwrap();
    assert!(store.read().is_ok());
    let bytes = fs::read(state.join("authority.json")).unwrap();
    fs::rename(
        state.join("authority.json"),
        outer.path().join("retained-original"),
    )
    .unwrap();
    write(&state.join("authority.json"), &bytes);
    assert!(
        matches!(store.read(), Err(StorageError::GenerationChanged)),
        "same bytes in a substituted inode must not silently replace a checked file"
    );
}
#[cfg(target_os = "linux")]
#[test]
fn actual_tmpfs_enospc_preserves_partial_initialization_without_retry() {
    use std::io::Write;
    let Ok(root) = std::env::var("NODOMI_TRUST_ENOSPC_DIR") else {
        return;
    };
    let d = tempfile::tempdir_in(root).unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = d.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut filler = fs::File::create(d.path().join("filler")).unwrap();
    filler.write_all(&vec![0; 900 * 1024]).unwrap();
    filler.sync_all().unwrap();
    let full = filler.write_all(&vec![0; 512 * 1024]).unwrap_err();
    assert_eq!(full.raw_os_error(), Some(libc::ENOSPC));
    filler.set_len(900 * 1024).unwrap();
    filler.sync_all().unwrap();
    assert!(matches!(
        initialize_new(&intent(&state), &vec![1; MAX_PAYLOAD_BYTES]),
        Err(StorageError::CommitOutcomeUnknown)
    ));
    let next = state.join("authority.next");
    assert!(next.exists());
    assert!(fs::metadata(&next).unwrap().len() > 0);
    assert!(!state.join("authority.json").exists());
    let before = fingerprint(&state);
    assert!(matches!(
        initialize_new(&intent(&state), PAYLOAD),
        Err(StorageError::Conflict)
    ));
    assert!(matches!(
        inspect_original_intent(&intent(&state)),
        Err(StorageError::RecoveryRequired)
    ));
    assert_eq!(before, fingerprint(&state));
}
