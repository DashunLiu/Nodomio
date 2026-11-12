use std::{fs, os::unix::fs::PermissionsExt, process::Command};
#[test]
fn internal_tool_prepares_public_status_and_rejects_secret_argv_without_echo() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let bin = env!("CARGO_BIN_EXE_nodomi-agent-protocol");
    let args = [
        "prepare",
        "--state-dir",
        dir.path().to_str().unwrap(),
        "--origin",
        "https://localhost:9443",
        "--server-id",
        "server-1",
    ];
    let out = Command::new(bin).args(args).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let status: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(status["status"], "PREPARED");
    assert!(status.get("credential").is_none());
    assert!(!text.contains("ndma_"));
    let out = Command::new(bin)
        .args(["status", "--enrollment-token", "ndme_DO_NOT_ECHO"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !String::from_utf8(out.stderr)
            .unwrap()
            .contains("DO_NOT_ECHO")
    );
    let out = Command::new(bin).args(args).output().unwrap();
    assert!(!out.status.success());
}
#[test]
fn fifo_lock_state_is_refused_without_blocking() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fifo = CString::new(dir.path().join("protocol.lock").as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is NUL-terminated and mode is a valid POSIX permission mask.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nodomi-agent-protocol"))
        .args([
            "status",
            "--state-dir",
            dir.path().to_str().unwrap(),
            "--origin",
            "https://localhost:9443",
            "--server-id",
            "server-1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let result = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(1) {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        result.is_some_and(|status| !status.success()),
        "FIFO lock blocked the private-state preflight"
    );
}
