//! Synthetic events through the real queue, sender, and HTTPS PostgreSQL receiver.
use nodomi_agent::{
    buffer::{QueueTime, SourcePosition, SshQueue},
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Target},
    protocol::{Architecture, Capabilities, Capability, RegistrationMetadata},
    reporting::{SecurityEventSender, SecurityEventStep},
};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    time::{Duration, Instant},
};

const BOOT: &str = "dc6f272f-e17f-4a5a-ae56-f2760279d423";
const STREAM: &str = "synthetic-ssh-isolation";
const BAD_ID: &str = "f8b44045-33c3-4a95-af75-000000000002";
const ISOLATED_EXIT: i32 = 24;

fn event(sequence: u8, occurred_at: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "eventId": format!("f8b44045-33c3-4a95-af75-{sequence:012x}"),
        "bootId": BOOT,
        "occurredAt": occurred_at,
        "eventType": "SSH_AUTH_FAILED",
        "sourceIp": "192.0.2.42",
        "username": "synthetic-user"
    }))
    .unwrap()
}

fn append(queue: &mut SshQueue, sequence: u8, timestamp: &str, now: &QueueTime) {
    queue
        .enqueue(
            &SourcePosition {
                stream: STREAM.into(),
                sequence: u64::from(sequence),
                cursor: vec![sequence],
            },
            &event(sequence, timestamp),
            now,
        )
        .expect("persist synthetic event and checkpoint");
}

fn checkpoint(queue: &SshQueue, sequence: u8) {
    let position = queue.checkpoint(STREAM).unwrap().expect("checkpoint");
    assert_eq!(position.sequence, u64::from(sequence));
    assert_eq!(position.cursor, [sequence]);
}

fn drain(
    sender: &mut SecurityEventSender,
    client: &ProtocolClient,
    identity: &mut IdentityStore,
    queue: &mut SshQueue,
    now: &QueueTime,
) -> u64 {
    let mut accepted_count = 0;
    for _ in 0..12 {
        match sender
            .step(client, identity, queue, now, Instant::now())
            .unwrap()
        {
            SecurityEventStep::Empty { quarantined: 1 } => return accepted_count,
            SecurityEventStep::Acknowledged {
                accepted,
                duplicate: 0,
                expired: 0,
            } => {
                accepted_count += accepted;
            }
            SecurityEventStep::Split => {}
            _ => panic!("unexpected delivery state after restart"),
        }
    }
    panic!("bounded drain exceeded");
}

#[test]
#[ignore = "requires a standalone local HTTPS relay, test backend and rejection fixture inputs"]
fn https_ssh_rejection_isolation() {
    let step = env::var("NODOMI_DELIVERY_TEST_STEP").expect("fixture step");
    let wall = env::var("NODOMI_DELIVERY_TEST_UNIX_SECONDS")
        .unwrap()
        .parse()
        .unwrap();
    let current = env::var("NODOMI_DELIVERY_TEST_EVENT_AT").expect("fixture timestamp");
    let future = env::var("NODOMI_DELIVERY_TEST_FUTURE_AT").expect("future fixture timestamp");
    let now = QueueTime {
        boot_id: BOOT.into(),
        monotonic_ns: match step.as_str() {
            "send" => 1_000_000_000,
            "retry" => 2_000_000_000,
            "verify" => 3_000_000_000,
            _ => panic!("invalid fixture step"),
        },
        unix_seconds: wall,
    };
    let target = Target::new(
        &env::var("NODOMI_DELIVERY_TEST_RELAY_ORIGIN").unwrap(),
        &env::var("NODOMI_DELIVERY_TEST_SERVER_ID").unwrap(),
    )
    .unwrap();
    let ca = fs::read("/input/ca.pem").unwrap();
    let client = ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(8)).unwrap();
    let root = Path::new("/evidence");
    let identity_path = root.join("identity");
    let queue_path = root.join("ssh-queue");
    let mut identity = if step == "send" {
        let mut state = IdentityStore::initialize(&identity_path, target).unwrap();
        let token_file = root.join("enrollment");
        let enrollment = Enrollment::from_private_file(&token_file).unwrap();
        client
            .register(
                &mut state,
                &enrollment,
                &RegistrationMetadata {
                    version: env!("CARGO_PKG_VERSION").into(),
                    architecture: match env::consts::ARCH {
                        "aarch64" => Architecture::Arm64,
                        "x86_64" => Architecture::X86_64,
                        _ => panic!("unsupported fixture architecture"),
                    },
                    distribution: "Nodomi isolated Linux test".into(),
                    distribution_version: "1".into(),
                    hostname: "fixture-ssh-isolation".into(),
                    capabilities: Capabilities {
                        system: Capability::Unsupported,
                        processes: Capability::Unsupported,
                        containers: Capability::Unsupported,
                        ssh_events: Capability::Unsupported,
                    },
                },
            )
            .expect("real registration");
        fs::remove_file(token_file).unwrap();
        state
    } else {
        IdentityStore::open(&identity_path, &target).unwrap()
    };
    let mut queue = SshQueue::open(&queue_path, &identity, 86_400, 1_000_000).unwrap();
    let mut sender = SecurityEventSender::new();
    match step.as_str() {
        "send" => {
            append(&mut queue, 1, &current, &now);
            append(&mut queue, 2, &future, &now);
            append(&mut queue, 3, &current, &now);
            for _ in 0..12 {
                match sender
                    .step(&client, &mut identity, &mut queue, &now, Instant::now())
                    .unwrap()
                {
                    SecurityEventStep::Quarantined => {
                        assert_eq!(queue.quarantined_count().unwrap(), 1);
                        checkpoint(&queue, 3);
                        // Reopen from disk without dropping the SQLite connection in Rust.
                        std::process::exit(ISOLATED_EXIT);
                    }
                    SecurityEventStep::Split | SecurityEventStep::Acknowledged { .. } => {}
                    _ => panic!("unexpected delivery state during isolation"),
                }
            }
            panic!("bad event was not isolated within the request bound");
        }
        "retry" => {
            assert_eq!(queue.quarantined_count().unwrap(), 1);
            checkpoint(&queue, 3);
            assert!(drain(&mut sender, &client, &mut identity, &mut queue, &now) >= 1);
            append(&mut queue, 4, &current, &now);
            assert_eq!(
                drain(&mut sender, &client, &mut identity, &mut queue, &now),
                1
            );
        }
        "verify" => {
            checkpoint(&queue, 4);
            assert!(matches!(
                sender
                    .step(&client, &mut identity, &mut queue, &now, Instant::now())
                    .unwrap(),
                SecurityEventStep::Empty { quarantined: 1 }
            ));
            let original = event(2, &future);
            assert_eq!(queue.queued_payload_bytes().unwrap(), original.len() as u64);
            let readback = Connection::open_with_flags(
                queue_path.join("ssh-buffer.sqlite3"),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let (stored, reason): (Vec<u8>, String) = readback
                .query_row(
                    "SELECT body,quarantine_code FROM ssh_events WHERE event_id=?1",
                    [BAD_ID],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(stored, original);
            assert_eq!(reason, "INVALID");
        }
        _ => unreachable!(),
    }
}
