use std::process::Command;

#[test]
fn service_rejects_operator_supplied_configuration() {
    let result = Command::new(env!("CARGO_BIN_EXE_nodomi-agent"))
        .args(["serve", "--origin", "https://127.0.0.1:1"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"INVALID_SERVICE_ARGUMENTS\n");
}

#[cfg(target_os = "linux")]
#[test]
fn service_without_supervisor_fails_closed() {
    let result = Command::new(env!("CARGO_BIN_EXE_nodomi-agent"))
        .args(["serve", "--supervisor-lock-fd", "3"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"INVALID_SUPERVISOR_LOCK\n");
}

#[cfg(target_os = "linux")]
#[test]
fn existing_diagnostic_arguments_still_emit_finite_json() {
    let result = Command::new(env!("CARGO_BIN_EXE_nodomi-agent"))
        .args(["--samples", "2", "--interval-ms", "10"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let stdout = String::from_utf8(result.stdout).unwrap();
    let snapshots: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|sample| sample["diagnosticOnly"] == true)
    );
}
