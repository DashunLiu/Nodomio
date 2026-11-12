use nodomi_agent::{
    buffer::{QueueTime, SourcePosition, SshQueue},
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Status, Target},
    protocol::{Architecture, Capabilities, Capability, RegistrationMetadata},
    reporting::{SecurityEventPreparation, SecurityEventSender, SecurityEventStep},
};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const BOOT: &str = "90000000-0000-4000-8000-000000000001";

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    _server: Server,
    home: tempfile::TempDir,
    target: Target,
    client: ProtocolClient,
}

impl Fixture {
    fn start(scenario: &str) -> (Self, IdentityStore) {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = home.path().join("state");
        let queue = home.path().join("queue");
        for path in [&state, &queue] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut server = Server(
            Command::new("python3")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/https_protocol.py"
                ))
                .arg(scenario)
                .arg(&state)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line.trim().parse::<u16>().expect("TLS fixture port");
        let target = Target::new(&format!("https://localhost:{port}"), "server-1").unwrap();
        let ca = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/ca.pem"
        ))
        .unwrap();
        let client =
            ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(2)).unwrap();
        let fixture = Self {
            _server: server,
            home,
            target,
            client,
        };
        let mut identity = IdentityStore::initialize(&state, fixture.target.clone()).unwrap();
        let token_path = fixture.home.path().join("enrollment");
        fs::write(&token_path, format!("ndme_{}", "A".repeat(43))).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o400)).unwrap();
        let token = Enrollment::from_private_file(&token_path).unwrap();
        fs::remove_file(token_path).unwrap();
        fixture
            .client
            .register(
                &mut identity,
                &token,
                &RegistrationMetadata {
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
                },
            )
            .unwrap();
        (fixture, identity)
    }

    fn state_path(&self) -> PathBuf {
        self.home.path().join("state")
    }

    fn queue(&self, identity: &IdentityStore) -> SshQueue {
        SshQueue::open(&self.home.path().join("queue"), identity, 3600, 1_000_000).unwrap()
    }

    fn attempts(&self) -> Vec<String> {
        serde_json::from_slice(&fs::read(self.home.path().join("ssh-attempts.json")).unwrap())
            .unwrap()
    }
}

fn clock(seconds: u64) -> QueueTime {
    QueueTime {
        boot_id: BOOT.into(),
        monotonic_ns: seconds * 1_000_000_000,
        unix_seconds: 1_794_303_000 + seconds as i64,
    }
}

fn position(sequence: u64) -> SourcePosition {
    SourcePosition {
        stream: "reporting.1".into(),
        sequence,
        cursor: sequence.to_be_bytes().to_vec(),
    }
}

fn event(sequence: u64) -> Vec<u8> {
    format!(r#" {{"eventId":"70000000-0000-4000-8000-{sequence:012x}","bootId":"{BOOT}","occurredAt":"2026-11-10T12:00:00Z","eventType":"SSH_AUTH_FAILED","sourceIp":null,"username":null}} "#).into_bytes()
}

#[test]
fn prepared_upload_can_be_cancelled_and_retries_without_absorbing_new_event() {
    let (fixture, mut identity) = Fixture::start("ssh-lost-retry");
    let mut queue = fixture.queue(&identity);
    let mut sender = SecurityEventSender::new();
    let at = Instant::now();
    let a = event(1);
    let b = event(2);
    queue.enqueue(&position(1), &a, &clock(0)).unwrap();

    let SecurityEventPreparation::Ready(unsent) = sender
        .prepare(&fixture.client, &identity, &mut queue, &clock(1), at)
        .unwrap()
    else {
        panic!("expected a prepared upload");
    };
    assert!(matches!(
        sender.prepare(&fixture.client, &identity, &mut queue, &clock(4000), at),
        Err("SSH_ATTEMPT_ACTIVE")
    ));
    queue.enqueue(&position(2), &b, &clock(2)).unwrap();
    sender.cancel(&mut queue, unsent).unwrap();
    assert!(!fixture.home.path().join("ssh-attempts.json").exists());

    let SecurityEventPreparation::Ready(request) = sender
        .prepare(&fixture.client, &identity, &mut queue, &clock(3), at)
        .unwrap()
    else {
        panic!("expected the frozen upload");
    };
    let completed = std::thread::spawn(move || request.send()).join().unwrap();
    let first = sender
        .complete(
            &fixture.client,
            &mut identity,
            &mut queue,
            completed,
            at + Duration::from_secs(4),
        )
        .unwrap();
    let SecurityEventStep::RetryScheduled {
        code: "NETWORK_OR_TLS_ERROR",
        remaining,
    } = first
    else {
        panic!("expected retry for lost response, got {first:?}");
    };
    assert!((Duration::from_secs(5)..=Duration::from_millis(5250)).contains(&remaining));
    // An intentionally advanced residence clock would expire both records if a
    // premature poll touched SQLite. The retry delay starts at completion.
    assert!(matches!(
        sender.step(
            &fixture.client,
            &mut identity,
            &mut queue,
            &clock(4000),
            at + Duration::from_secs(6)
        ),
        Ok(SecurityEventStep::Waiting { .. })
    ));
    assert_eq!(fixture.attempts().len(), 1);
    assert_eq!(
        queue.queued_payload_bytes().unwrap(),
        (a.len() + b.len()) as u64
    );
    assert_eq!(
        sender.step(
            &fixture.client,
            &mut identity,
            &mut queue,
            &clock(20),
            at + Duration::from_secs(20)
        ),
        Ok(SecurityEventStep::Acknowledged {
            accepted: 0,
            duplicate: 1,
            expired: 0
        })
    );
    let attempts = fixture.attempts();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], attempts[1]);
    assert_eq!(queue.queued_payload_bytes().unwrap(), b.len() as u64);
    assert_eq!(queue.checkpoint("reporting.1").unwrap(), Some(position(2)));
    let next = queue.prepare(&clock(21)).unwrap().unwrap();
    assert_eq!(next.body, [b"{\"events\":[".as_slice(), &b, b"]}"].concat());
}

#[test]
fn revocation_requires_the_original_queue_and_preserves_frozen_flight() {
    let (fixture, mut identity) = Fixture::start("ssh-revoked");
    let mut queue = fixture.queue(&identity);
    let mut sender = SecurityEventSender::new();
    let at = Instant::now();
    let body = event(1);
    queue.enqueue(&position(1), &body, &clock(0)).unwrap();

    let other_path = fixture.home.path().join("other-queue");
    fs::create_dir(&other_path).unwrap();
    fs::set_permissions(&other_path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut other_queue = SshQueue::open(&other_path, &identity, 3600, 1_000_000).unwrap();
    let SecurityEventPreparation::Ready(request) = sender
        .prepare(&fixture.client, &identity, &mut queue, &clock(1), at)
        .unwrap()
    else {
        panic!("expected a prepared upload");
    };
    assert_eq!(
        sender.complete(
            &fixture.client,
            &mut identity,
            &mut other_queue,
            request.send(),
            Instant::now(),
        ),
        Err("STALE_SSH_ATTEMPT")
    );
    assert_eq!(identity.status(), Status::Bound);
    assert!(matches!(
        queue.prepare(&clock(1)),
        Err("SSH_ATTEMPT_ACTIVE")
    ));
    drop(queue);
    let mut queue = fixture.queue(&identity);
    let mut sender = SecurityEventSender::new();
    assert_eq!(
        sender.step(&fixture.client, &mut identity, &mut queue, &clock(1), at),
        Ok(SecurityEventStep::Stopped {
            code: "CREDENTIAL_REJECTED"
        })
    );
    drop(identity);
    let mut identity = IdentityStore::open(&fixture.state_path(), &fixture.target).unwrap();
    assert_eq!(identity.status(), Status::NeedsReconnect);
    assert_eq!(
        sender.step(
            &fixture.client,
            &mut identity,
            &mut queue,
            &clock(2),
            at + Duration::from_secs(60)
        ),
        Ok(SecurityEventStep::Stopped {
            code: "CREDENTIAL_REJECTED"
        })
    );
    let attempts = fixture.attempts();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], attempts[1]);
    assert_eq!(queue.quarantined_count().unwrap(), 0);
    assert_eq!(queue.checkpoint("reporting.1").unwrap(), Some(position(1)));
    let pending = queue.prepare(&clock(3)).unwrap().unwrap();
    assert_eq!(
        pending.body,
        [b"{\"events\":[".as_slice(), &body, b"]}"].concat()
    );
}

#[test]
fn explicit_conflict_splits_then_retains_each_rejected_original_across_reopen() {
    let (fixture, mut identity) = Fixture::start("ssh-conflict");
    let mut queue = fixture.queue(&identity);
    let mut sender = SecurityEventSender::new();
    let a = event(1);
    let b = event(2);
    queue.enqueue(&position(1), &a, &clock(0)).unwrap();
    queue.enqueue(&position(2), &b, &clock(0)).unwrap();
    assert_eq!(
        sender.step(
            &fixture.client,
            &mut identity,
            &mut queue,
            &clock(1),
            Instant::now()
        ),
        Ok(SecurityEventStep::Split)
    );
    drop(queue);

    let mut queue = fixture.queue(&identity);
    let mut sender = SecurityEventSender::new();
    for second in [2, 3] {
        assert_eq!(
            sender.step(
                &fixture.client,
                &mut identity,
                &mut queue,
                &clock(second),
                Instant::now()
            ),
            Ok(SecurityEventStep::Quarantined)
        );
    }
    assert_eq!(
        sender.step(
            &fixture.client,
            &mut identity,
            &mut queue,
            &clock(4),
            Instant::now()
        ),
        Ok(SecurityEventStep::Empty { quarantined: 2 })
    );
    assert_eq!(fixture.attempts().len(), 3);
    assert_eq!(
        queue.queued_payload_bytes().unwrap(),
        (a.len() + b.len()) as u64
    );
    assert_eq!(queue.checkpoint("reporting.1").unwrap(), Some(position(2)));
}
