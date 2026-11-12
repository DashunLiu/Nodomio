use nodomi_agent::trust_storage::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
};
const INSTALLATION: &str = "d1068b94-754c-4aa3-8b70-2dd4f04fbe3d";
fn args(path: &std::path::Path) -> Vec<String> {
    // SAFETY: geteuid has no preconditions or memory access.
    let uid = unsafe { libc::geteuid() };
    vec![
        "--state-dir".into(),
        path.to_str().unwrap().into(),
        "--installation-id".into(),
        INSTALLATION.into(),
        "--source-config-id".into(),
        "test-source".into(),
        "--owner-uid".into(),
        uid.to_string(),
    ]
}
type EntryFingerprint = (String, u32, u32, u64, i64, i64, Vec<u8>);
fn fingerprint(path: &std::path::Path) -> Vec<EntryFingerprint> {
    let mut paths = vec![path.to_owned()];
    paths.extend(fs::read_dir(path).unwrap().map(|e| e.unwrap().path()));
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let m = fs::metadata(p).unwrap();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                m.mode(),
                m.uid(),
                m.nlink(),
                m.mtime(),
                m.ctime(),
                if m.is_file() {
                    fs::read(p).unwrap()
                } else {
                    vec![]
                },
            )
        })
        .collect()
}
#[test]
fn diagnostic_is_read_only_and_never_prints_opaque_contents_or_trust_success() {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: geteuid has no preconditions or memory access.
    let uid = unsafe { libc::geteuid() };
    let expected = ExpectedInstallation::new(d.path(), INSTALLATION, "test-source", uid).unwrap();
    let intent =
        NewInstallationIntent::new(expected, "a12378e9-2248-46aa-8826-965b75bd260a").unwrap();
    initialize_new(&intent, b"DO-NOT-PRINT-THIS-OPAQUE-MATERIAL").unwrap();
    let before = fingerprint(d.path());
    let output = Command::new(env!("CARGO_BIN_EXE_nodomi-agent-trust-inspect"))
        .args(args(d.path()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "valid envelope should produce an unverified diagnostic result"
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["diagnosticOnly"], true);
    assert_eq!(value["storageEnvelope"], "STRUCTURALLY_VALID_UNVERIFIED");
    assert_eq!(value["verifier"], "NOT_CONNECTED");
    assert_eq!(value["generation"], 1);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("DO-NOT-PRINT")
    );
    assert!(output.stderr.is_empty());
    assert_eq!(before, fingerprint(d.path()));
}
#[test]
fn diagnostic_rejects_missing_context_and_never_exposes_init_reset_or_cleanup() {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for options in [
        Vec::<String>::new(),
        vec!["--init".into()],
        vec!["--reset".into()],
        vec!["--cleanup".into()],
        vec!["--state-dir".into()],
    ] {
        let before = fingerprint(d.path());
        let output = Command::new(env!("CARGO_BIN_EXE_nodomi-agent-trust-inspect"))
            .args(options)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(before, fingerprint(d.path()));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_nodomi-agent-trust-inspect"))
        .args(args(d.path()))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "MISSING_AUTHORITY\n"
    );
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
}
