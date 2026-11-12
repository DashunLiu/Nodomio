//! Isolated HTTPS/PostgreSQL acceptance using synthetic events and the real queue and client.
use nodomi_agent::{
    buffer::{QueueTime, SourcePosition, SshQueue},
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Target},
    protocol::{Architecture, Capabilities, Capability, RegistrationMetadata},
};
use serde_json::json;
use std::{env, fs, path::Path, time::Duration};

const BOOT: &str = "dc6f272f-e17f-4a5a-ae56-f2760279d423";
const STREAM: &str = "synthetic-ssh-acceptance";
const NETWORK_RESULT_UNKNOWN: i32 = 23;

fn clock(unix_seconds: i64, step: u64) -> QueueTime {
    QueueTime {
        boot_id: BOOT.into(),
        monotonic_ns: step * 1_000_000_000,
        unix_seconds,
    }
}

#[test]
#[ignore = "requires a standalone local HTTPS relay, test backend and replay fixture inputs"]
fn https_ssh_replay() {
    let step = env::var("NODOMI_DELIVERY_TEST_STEP").expect("fixture step");
    let origin = env::var("NODOMI_DELIVERY_TEST_RELAY_ORIGIN").expect("fixture relay origin");
    let server = env::var("NODOMI_DELIVERY_TEST_SERVER_ID").expect("fixture server ID");
    let wall = env::var("NODOMI_DELIVERY_TEST_UNIX_SECONDS")
        .expect("fixture wall clock")
        .parse()
        .expect("fixture epoch seconds");
    let root = Path::new("/evidence");
    let state_path = root.join("identity");
    let queue_path = root.join("ssh-queue");
    let prior_token = root.join("first-attempt");
    let target = Target::new(&origin, &server).expect("valid fixture target");
    let ca = fs::read("/input/ca.pem").expect("fixture CA");
    let client = ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(8))
        .expect("trusted HTTPS client");
    let mut identity = if step == "send" {
        let mut state = IdentityStore::initialize(&state_path, target).expect("private identity");
        let token = root.join("enrollment");
        let enrollment = Enrollment::from_private_file(&token).expect("private enrollment file");
        let architecture = match env::consts::ARCH {
            "aarch64" => Architecture::Arm64,
            "x86_64" => Architecture::X86_64,
            _ => panic!("unsupported Linux test architecture"),
        };
        client
            .register(
                &mut state,
                &enrollment,
                &RegistrationMetadata {
                    version: env!("CARGO_PKG_VERSION").into(),
                    architecture,
                    distribution: "Nodomi isolated Linux test".into(),
                    distribution_version: "1".into(),
                    hostname: "fixture-ssh-replay".into(),
                    capabilities: Capabilities {
                        system: Capability::Unsupported,
                        processes: Capability::Unsupported,
                        containers: Capability::Unsupported,
                        ssh_events: Capability::Unsupported,
                    },
                },
            )
            .expect("real Agent registration");
        fs::remove_file(token).expect("delete consumed enrollment file");
        state
    } else {
        IdentityStore::open(&state_path, &target).expect("reopen persisted identity")
    };
    let mut queue = SshQueue::open(&queue_path, &identity, 86_400, 1_000_000)
        .expect("open bound durable queue");
    queue
        .check_identity(&identity)
        .expect("same queue authority");

    match step.as_str() {
        "send" => {
            let current = env::var("NODOMI_DELIVERY_TEST_EVENT_AT").expect("fixture timestamp");
            let expired =
                env::var("NODOMI_DELIVERY_TEST_EXPIRED_AT").expect("expired fixture timestamp");
            for (index, occurred_at) in [current.as_str(), &current, &expired]
                .into_iter()
                .enumerate()
            {
                let sequence = u64::try_from(index + 1).unwrap();
                let body = serde_json::to_vec(&json!({
                    "eventId": format!("f8b44045-33c3-4a95-af75-{sequence:012x}"),
                    "bootId": BOOT,
                    "occurredAt": occurred_at,
                    "eventType": "SSH_AUTH_FAILED",
                    "sourceIp": "192.0.2.42",
                    "username": "synthetic-user"
                }))
                .unwrap();
                queue
                    .enqueue(
                        &SourcePosition {
                            stream: STREAM.into(),
                            sequence,
                            cursor: vec![sequence as u8],
                        },
                        &body,
                        &clock(wall, 1),
                    )
                    .expect("commit event and position");
            }
            let attempt = queue
                .prepare(&clock(wall, 1))
                .expect("prepare")
                .expect("batch");
            assert_eq!(attempt.event_count, 3);
            fs::write(prior_token, &attempt.token).expect("fixture attempt correlation");
            assert_eq!(
                client
                    .security_events(&mut identity, &attempt.body, attempt.event_count)
                    .unwrap_err(),
                "NETWORK_OR_TLS_ERROR"
            );
            // Leave the persisted attempt as it is. No Drop handler or finish call runs.
            std::process::exit(NETWORK_RESULT_UNKNOWN);
        }
        "retry" => {
            let previous = fs::read_to_string(prior_token).expect("prior fixture attempt");
            let attempt = queue
                .prepare(&clock(wall, 2))
                .expect("recover")
                .expect("pending batch");
            assert_ne!(previous, attempt.token);
            assert_eq!(attempt.event_count, 3);
            let ack = client
                .security_events(&mut identity, &attempt.body, attempt.event_count)
                .expect("real replay confirmation");
            assert_eq!(
                (ack.accepted_count, ack.duplicate_count, ack.expired_count),
                (0, 2, 1)
            );
            assert!(queue.finish(&previous, Some(&ack)).is_err());
            queue
                .finish(&attempt.token, Some(&ack))
                .expect("commit current confirmation");
        }
        "verify" => {
            assert!(
                queue
                    .prepare(&clock(wall, 3))
                    .expect("read confirmed queue")
                    .is_none()
            );
            let position = queue
                .checkpoint(STREAM)
                .expect("read checkpoint")
                .expect("checkpoint");
            assert_eq!((position.sequence, position.cursor), (3, vec![3]));
        }
        _ => panic!("unknown isolated fixture step"),
    }
}
