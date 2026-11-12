use nodomi_agent::{
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Status, Target},
    protocol::*,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Server(Child, String);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn server(scenario: &str, dir: &Path) -> Server {
    let mut child = Command::new("python3")
        .args([
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/https_protocol.py"
            ),
            scenario,
            dir.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(
        line.trim().parse::<u16>().is_ok(),
        "protocol fixture failed to start"
    );
    Server(child, format!("https://localhost:{}", line.trim()))
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn ca() -> Vec<u8> {
    fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/ca.pem"
    ))
    .unwrap()
}
fn metadata() -> RegistrationMetadata {
    RegistrationMetadata {
        version: "0.1.0".into(),
        architecture: Architecture::Arm64,
        distribution: "debian".into(),
        distribution_version: "12".into(),
        hostname: "protocol-fixture".into(),
        capabilities: Capabilities {
            system: Capability::Available,
            processes: Capability::Unsupported,
            containers: Capability::Unsupported,
            ssh_events: Capability::Unsupported,
        },
    }
}
fn enrollment(dir: &Path) -> Enrollment {
    let path = dir.parent().unwrap().join(format!(
        "{}.enrollment",
        dir.file_name().unwrap().to_str().unwrap()
    ));
    fs::write(&path, format!("ndme_{}", "A".repeat(43))).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let token = Enrollment::from_private_file(&path).unwrap();
    fs::remove_file(path).unwrap();
    token
}
fn client(target: &Target) -> ProtocolClient {
    ProtocolClient::new(target.clone(), Some(&ca()), Duration::from_secs(2)).unwrap()
}
fn heartbeat(epoch: &str) -> Heartbeat {
    let updater:UpdaterRuntime=serde_json::from_value(serde_json::json!({"platform":"linux-aarch64","kernelVersion":"6.12","currentReleaseId":null,"binarySha256":"a".repeat(64),"protocolVersion":1,"selfUpdate":"UNSUPPORTED_INSTALLATION","localPhase":"IDLE","mode":"MANUAL","source":"GITHUB_RELEASES","localAttemptId":null,"trigger":null,"targetVersion":null,"lastCheckAt":null,"availableVersion":null,"errorCode":null,"availableIsSecurityUpdate":null,"resultRecordedAt":null,"updateEventsDroppedTotal":0,"buildOrigin":"SELF_COMPILED"})).unwrap();
    Heartbeat {
        boot_id: epoch.into(),
        version: "0.1.0".into(),
        capabilities: metadata().capabilities,
        buffered_bytes: 0,
        discarded_samples_total: "0".into(),
        collector_epoch: epoch.into(),
        updater,
        ssh_source_diagnostics: None,
    }
}
#[test]
fn lost_registration_response_queries_same_durable_credential_and_never_posts_again() {
    let dir = directory();
    let server = server("lost", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    let token = enrollment(dir.path());
    assert!(client.register(&mut state, &token, &metadata()).is_err());
    assert_eq!(state.status(), Status::Uncertain);
    let saved = fs::read(dir.path().join("identity.json")).unwrap();
    drop(state);
    let mut state = IdentityStore::open(dir.path(), &target).unwrap();
    assert!(client.register(&mut state, &token, &metadata()).is_err());
    assert_eq!(fs::read(dir.path().join("identity.json")).unwrap(), saved);
    let identity = client.query_identity(&mut state).unwrap();
    assert_eq!(identity.agent_id, "agent:fixture");
    assert_eq!(state.status(), Status::Bound);
}
#[test]
fn complete_https_protocol_and_truthful_unsupported_configuration_receipt() {
    let dir = directory();
    let server = server("ok", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    client
        .register(&mut state, &enrollment(dir.path()), &metadata())
        .unwrap();
    let config = client.configuration(&mut state).unwrap();
    assert_eq!(config.target.configuration.sampling_interval_seconds, 30);
    let epoch = "123e4567-e89b-42d3-a456-426614174001";
    let heartbeat = heartbeat(epoch);
    assert_eq!(
        client
            .heartbeat(&mut state, &heartbeat)
            .unwrap()
            .heartbeat_interval_seconds,
        30
    );
    client
        .report_unsupported_configuration(&mut state, &config, epoch, 1)
        .unwrap();
}
#[test]
fn adverse_https_responses_cannot_bind_or_replace_identity() {
    for scenario in [
        "target",
        "expired",
        "malformed",
        "oversize",
        "oversize-stream",
        "redirect",
        "headers",
    ] {
        let dir = directory();
        let server = server(scenario, dir.path());
        let target = Target::new(&server.1, "server-1").unwrap();
        let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
        let client = client(&target);
        let _ = client.register(&mut state, &enrollment(dir.path()), &metadata());
        let before = fs::read(dir.path().join("identity.json")).unwrap();
        let error = client.query_identity(&mut state).unwrap_err();
        if scenario == "redirect" {
            assert_eq!(error, "REDIRECT_REFUSED");
        }
        assert_eq!(
            fs::read(dir.path().join("identity.json")).unwrap(),
            before,
            "{scenario}"
        );
    }
}
#[test]
fn revoked_bound_identity_requires_explicit_reconnect_and_pending_rejection_stays_uncertain() {
    let dir = directory();
    let server = server("revoked", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    client
        .register(&mut state, &enrollment(dir.path()), &metadata())
        .unwrap();
    assert!(client.query_identity(&mut state).is_err());
    assert_eq!(state.status(), Status::NeedsReconnect);
    assert!(
        client
            .register(&mut state, &enrollment(dir.path()), &metadata())
            .is_err()
    );
}
#[test]
fn untrusted_tls_and_timeout_keep_original_identity_and_do_not_retry() {
    for trusted in [false, true] {
        let dir = directory();
        let server = server("slow", dir.path());
        let target = Target::new(&server.1, "server-1").unwrap();
        let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
        let ca = ca();
        let client = ProtocolClient::new(
            target,
            if trusted { Some(&ca) } else { None },
            Duration::from_millis(150),
        )
        .unwrap();
        let before = fs::read(dir.path().join("identity.json")).unwrap();
        let now = std::time::Instant::now();
        assert!(client.query_identity(&mut state).is_err());
        assert!(now.elapsed() < Duration::from_secs(2));
        assert_eq!(fs::read(dir.path().join("identity.json")).unwrap(), before);
    }
    // Unlike the header-only delay above, each body read can make progress inside
    // the configured wait while the complete HTTPS exchange exceeds its budget.
    let dir = directory();
    let server = server("delayed-headers-drip", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("identity.json")).unwrap()).unwrap();
    let client =
        ProtocolClient::new(target.clone(), Some(&ca()), Duration::from_millis(250)).unwrap();
    let token = enrollment(dir.path());
    let started = std::time::Instant::now();
    assert_eq!(
        client
            .register(&mut state, &token, &metadata())
            .unwrap_err(),
        "NETWORK_OR_TLS_ERROR"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "aggregate request exceeded its deadline tolerance"
    );
    assert_eq!(state.status(), Status::Uncertain);
    assert!(IdentityStore::open(dir.path(), &target).is_err());
    let uncertain = fs::read(dir.path().join("identity.json")).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&uncertain).unwrap();
    assert!(
        original["credential"] == persisted["credential"],
        "timeout replaced the credential"
    );
    assert_eq!(original["operationId"], persisted["operationId"]);
    drop(state);
    let mut state = IdentityStore::open(dir.path(), &target).unwrap();
    assert_eq!(state.status(), Status::Uncertain);
    assert_eq!(
        client
            .register(&mut state, &token, &metadata())
            .unwrap_err(),
        "REGISTRATION_ALREADY_ATTEMPTED"
    );
    assert!(
        fs::read(dir.path().join("identity.json")).unwrap() == uncertain,
        "second POST changed uncertain evidence"
    );
    let started = std::time::Instant::now();
    assert!(client.query_identity(&mut state).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "identity resume exceeded aggregate deadline tolerance"
    );
    assert!(
        fs::read(dir.path().join("identity.json")).unwrap() == uncertain,
        "resume timeout changed uncertain evidence"
    );
}
#[test]
fn changed_binding_config_cannot_be_accepted_or_receipted() {
    let dir = directory();
    let server = server("binding", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    client
        .register(&mut state, &enrollment(dir.path()), &metadata())
        .unwrap();
    assert!(client.configuration(&mut state).is_err());
    assert!(client.query_identity(&mut state).is_err());
    assert_eq!(state.binding().unwrap().binding_revision, 2);
    assert_eq!(state.status(), Status::Uncertain);
}
#[test]
fn process_exit_after_lost_response_preserves_credential_and_releases_only_os_lock() {
    let dir = directory();
    let server = server("lost", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    drop(IdentityStore::initialize(dir.path(), target.clone()).unwrap());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_death_helper", "--nocapture"])
        .env("NODOMI_TEST_STATE", dir.path())
        .env("NODOMI_TEST_ORIGIN", &server.1)
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(79));
    let mut state = IdentityStore::open(dir.path(), &target).unwrap();
    assert_eq!(state.status(), Status::Uncertain);
    client(&target).query_identity(&mut state).unwrap();
    assert_eq!(state.status(), Status::Bound);
}
#[test]
fn process_death_helper() {
    let Ok(path) = std::env::var("NODOMI_TEST_STATE") else {
        return;
    };
    let target = Target::new(&std::env::var("NODOMI_TEST_ORIGIN").unwrap(), "server-1").unwrap();
    let mut state = IdentityStore::open(Path::new(&path), &target).unwrap();
    assert!(
        client(&target)
            .register(&mut state, &enrollment(Path::new(&path)), &metadata())
            .is_err()
    );
    std::process::exit(79); // Test-only abrupt process exit: destructors do not run.
}
#[test]
fn trusted_ca_does_not_disable_hostname_validation() {
    let dir = directory();
    let server = server("ok", dir.path());
    let origin = server.1.replace("localhost", "127.0.0.1");
    let target = Target::new(&origin, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    assert_eq!(
        client(&target).query_identity(&mut state).unwrap_err(),
        "NETWORK_OR_TLS_ERROR"
    );
    assert_eq!(state.status(), Status::Prepared);
}
#[test]
fn rejected_malformed_auth_body_still_locks_bound_credential() {
    let dir = directory();
    let server = server("revoked-malformed", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    client
        .register(&mut state, &enrollment(dir.path()), &metadata())
        .unwrap();
    assert!(client.query_identity(&mut state).is_err());
    assert_eq!(state.status(), Status::NeedsReconnect);
}
#[test]
fn lost_heartbeat_response_cannot_change_epoch_or_confirm_configuration() {
    let dir = directory();
    let server = server("lost-heartbeat", dir.path());
    let target = Target::new(&server.1, "server-1").unwrap();
    let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    let client = client(&target);
    client
        .register(&mut state, &enrollment(dir.path()), &metadata())
        .unwrap();
    let config = client.configuration(&mut state).unwrap();
    let epoch = "123e4567-e89b-42d3-a456-426614174001";
    assert!(client.heartbeat(&mut state, &heartbeat(epoch)).is_err());
    assert_eq!(
        client
            .heartbeat(
                &mut state,
                &heartbeat("123e4567-e89b-42d3-a456-426614174002")
            )
            .unwrap_err(),
        "COLLECTOR_EPOCH_CHANGED"
    );
    assert!(
        client
            .report_unsupported_configuration(&mut state, &config, epoch, 1)
            .is_err()
    );
}

fn ssh_fixture(scenario: &str) -> (tempfile::TempDir, Server, ProtocolClient, IdentityStore) {
    let dir = directory();
    let identity_dir = dir.path().join("identity");
    fs::create_dir(&identity_dir).unwrap();
    fs::set_permissions(&identity_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let server = server(scenario, &identity_dir);
    let target = Target::new(&server.1, "server-1").unwrap();
    let client = client(&target);
    let mut state = IdentityStore::initialize(&identity_dir, target).unwrap();
    client
        .register(&mut state, &enrollment(&identity_dir), &metadata())
        .unwrap();
    (dir, server, client, state)
}

fn ssh_body(count: usize) -> Vec<u8> {
    let events: Vec<_> = (0..count)
        .map(|index| {
            serde_json::json!({
                "eventId": format!("123e4567-e89b-42d3-a456-{index:012x}"),
                "bootId": "123e4567-e89b-42d3-a456-426614174001",
                "occurredAt": "2026-11-10T00:00:00Z",
                "eventType": "SSH_AUTH_FAILED",
                "sourceIp": "192.0.2.1",
                "username": "fixture"
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({"events": events})).unwrap()
}

fn ssh_attempts(dir: &Path) -> Vec<String> {
    serde_json::from_slice(&fs::read(dir.join("ssh-attempts.json")).unwrap()).unwrap()
}

#[test]
fn ssh_lost_response_requires_explicit_byte_identical_retry() {
    use ring::digest::{SHA256, digest};

    let (dir, _server, client, mut state) = ssh_fixture("ssh-lost-retry");
    let mut body = b" \n".to_vec();
    body.extend_from_slice(&ssh_body(1));
    body.extend_from_slice(b"\n ");
    let hash: String = digest(&SHA256, &body)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        client.security_events(&mut state, &body, 1).unwrap_err(),
        "NETWORK_OR_TLS_ERROR"
    );
    assert_eq!(
        ssh_attempts(dir.path()).as_slice(),
        std::slice::from_ref(&hash)
    );
    assert_eq!(state.status(), Status::Bound);

    let ack = client.security_events(&mut state, &body, 1).unwrap();
    assert_eq!(
        (ack.accepted_count, ack.duplicate_count, ack.expired_count),
        (0, 1, 0)
    );
    assert_eq!(ssh_attempts(dir.path()).as_slice(), [hash.clone(), hash]);
}

#[test]
fn ssh_batch_preserves_separate_ack_categories() {
    let (_dir, _server, client, mut state) = ssh_fixture("ssh-mixed");
    let ack = client.security_events(&mut state, &ssh_body(3), 3).unwrap();
    assert_eq!(
        (ack.accepted_count, ack.duplicate_count, ack.expired_count),
        (1, 1, 1)
    );
}

#[test]
fn ssh_batch_enforces_count_and_inclusive_wire_byte_limits_before_network() {
    const EVENT_LIMIT: usize = 1000;
    const BODY_LIMIT: usize = 1_048_576;

    let (dir, _server, client, mut state) = ssh_fixture("ssh-ok");
    for (body, count, expected) in [
        (ssh_body(0), 0, "INVALID_SECURITY_EVENT_BATCH"),
        (ssh_body(1), 2, "INVALID_SECURITY_EVENT_BATCH"),
        (
            ssh_body(EVENT_LIMIT + 1),
            EVENT_LIMIT + 1,
            "INVALID_SECURITY_EVENT_BATCH",
        ),
        (
            b"{\"events\":[{}],\"events\":[{}]}".to_vec(),
            1,
            "INVALID_SECURITY_EVENT_BATCH",
        ),
        (
            b"{\"samples\":[{}]}".to_vec(),
            1,
            "INVALID_SECURITY_EVENT_BATCH",
        ),
        (b"[[{}]]".to_vec(), 1, "INVALID_SECURITY_EVENT_BATCH"),
        (vec![b' '; BODY_LIMIT + 1], 1, "REQUEST_TOO_LARGE"),
    ] {
        assert_eq!(
            client
                .security_events(&mut state, &body, count)
                .unwrap_err(),
            expected
        );
    }
    assert!(!dir.path().join("ssh-attempts.json").exists());

    let mut body = ssh_body(EVENT_LIMIT);
    body.resize(BODY_LIMIT, b' ');
    let ack = client
        .security_events(&mut state, &body, EVENT_LIMIT)
        .unwrap();
    assert_eq!(ack.accepted_count, EVENT_LIMIT as u64);
    assert_eq!(ssh_attempts(dir.path()).len(), 1);
}

#[test]
fn ssh_batch_does_not_accept_malformed_acks_or_non_200_responses() {
    for (scenario, error, status) in [
        ("ssh-bad-total", "INVALID_SECURITY_EVENT_ACK", Status::Bound),
        (
            "ssh-malformed-ack",
            "INVALID_SECURITY_EVENT_ACK",
            Status::Bound,
        ),
        ("ssh-array-ack", "INVALID_SECURITY_EVENT_ACK", Status::Bound),
        ("ssh-wrong-success", "INVALID_PROTOCOL", Status::Bound),
        ("ssh-conflict", "REMOTE_REQUEST_REJECTED", Status::Bound),
        ("ssh-revoked", "CREDENTIAL_REJECTED", Status::NeedsReconnect),
        ("ssh-redirect", "REDIRECT_REFUSED", Status::Bound),
    ] {
        let (dir, _server, client, mut state) = ssh_fixture(scenario);
        assert_eq!(
            client
                .security_events(&mut state, &ssh_body(1), 1)
                .unwrap_err(),
            error
        );
        assert_eq!(state.status(), status);
        assert_eq!(ssh_attempts(dir.path()).len(), 1);
    }
}
