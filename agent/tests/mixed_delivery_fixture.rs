//! Real Linux captures and synthetic SSH events through one HTTPS delivery lane.
#![cfg(target_os = "linux")]

use nodomi_agent::{
    buffer::{QueueTime, SharedBuffer, SharedBufferPaths, SourcePosition},
    client::{ConfigurationFailure, MetricUploadOutcome, ProtocolClient},
    identity::{Enrollment, IdentityStore, Target, new_collector_epoch},
    model::RawSnapshot,
    protocol::{
        AgentConfiguration, Architecture, Capabilities, Capability, Heartbeat,
        RegistrationMetadata, UpdaterRuntime,
    },
    reporting::{
        SecurityEventPreparation, SecurityEventSender, SecurityEventStep,
        dispatcher::{
            DeliveryCompletion, DeliveryDispatcher, DeliveryKind, with_delivery_dispatcher,
        },
    },
    runtime::HostCollector,
    source::LinuxSource,
};
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = "/evidence";
const STREAM: &str = "synthetic-mixed-dispatch";
const RETRY_AFTER: Duration = Duration::from_secs(6);

struct Owner {
    client: ProtocolClient,
    identity: IdentityStore,
    buffer: SharedBuffer,
    collector: HostCollector,
    sender: SecurityEventSender,
    heartbeat: Heartbeat,
}

fn queue_time(raw: &RawSnapshot) -> QueueTime {
    QueueTime {
        boot_id: raw.boot_id.clone(),
        monotonic_ns: raw.monotonic_ns,
        unix_seconds: (raw.observed_unix_ns / 1_000_000_000).try_into().unwrap(),
    }
}

impl Owner {
    fn add_host(&mut self) {
        self.buffer
            .host
            .admit(
                self.collector
                    .collect(LinuxSource.capture_host().unwrap())
                    .unwrap(),
            )
            .unwrap();
    }

    fn add_ssh(&mut self, sequence: u8) {
        self.add_ssh_padded(sequence, 0);
    }

    fn add_ssh_padded(&mut self, sequence: u8, minimum_bytes: usize) {
        let mut event = serde_json::to_vec(&json!({
            "eventId": format!("08e34971-13f8-4e1d-9577-{sequence:012x}"),
            "bootId": self.heartbeat.boot_id,
            "occurredAt": env::var("NODOMI_DELIVERY_TEST_EVENT_AT").unwrap(),
            "eventType": "SSH_AUTH_FAILED",
            "sourceIp": "192.0.2.42",
            "username": "synthetic-mixed-dispatch",
        }))
        .unwrap();
        event.resize(event.len().max(minimum_bytes), b' ');
        self.buffer
            .ssh
            .enqueue(
                &SourcePosition {
                    stream: STREAM.into(),
                    sequence: u64::from(sequence),
                    cursor: vec![sequence],
                },
                &event,
                &queue_time(&LinuxSource.capture_host().unwrap()),
            )
            .unwrap();
    }

    fn send_heartbeat(&mut self) {
        self.heartbeat.buffered_bytes = self.buffer.allocated_bytes().unwrap();
        self.heartbeat.discarded_samples_total =
            self.buffer.host.discarded_samples_total().to_string();
        self.client
            .heartbeat(&mut self.identity, &self.heartbeat)
            .unwrap();
    }

    fn start_next(&mut self, lane: &mut DeliveryDispatcher) -> Option<DeliveryKind> {
        if lane.active_kind().is_some() {
            return None;
        }
        let raw = LinuxSource.capture_host().unwrap();
        for kind in lane.preferred_order() {
            match kind {
                DeliveryKind::Host if self.buffer.host.has_pending_sample() => {
                    if let Some(sample) = self
                        .buffer
                        .host
                        .begin(&raw.boot_id, raw.cpu_observed.monotonic_ns)
                        .unwrap()
                    {
                        lane.submit_host(&self.client, &self.identity, sample)
                            .unwrap();
                        return Some(kind);
                    }
                }
                DeliveryKind::Ssh => match self
                    .sender
                    .prepare(
                        &self.client,
                        &self.identity,
                        &mut self.buffer.ssh,
                        &queue_time(&raw),
                        Instant::now(),
                    )
                    .unwrap()
                {
                    SecurityEventPreparation::Ready(request) => {
                        lane.submit_ssh(request).unwrap();
                        return Some(kind);
                    }
                    SecurityEventPreparation::Progress(
                        SecurityEventStep::Waiting { .. }
                        | SecurityEventStep::Empty { quarantined: 0 },
                    ) => {}
                    _ => panic!("unexpected SSH preparation state"),
                },
                DeliveryKind::Host => {}
            }
        }
        None
    }

    fn finish(&mut self, lane: &mut DeliveryDispatcher) -> Option<SecurityEventStep> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(completion) = lane.take_completion().unwrap() {
                return match completion {
                    DeliveryCompletion::Host {
                        sample_id,
                        completion,
                        ..
                    } => {
                        let MetricUploadOutcome::Acknowledged(ack) = self
                            .client
                            .finish_metric_upload(&mut self.identity, completion)
                            .unwrap()
                        else {
                            panic!("unconfirmed HOST sample")
                        };
                        assert_eq!(
                            (ack.accepted_count, ack.duplicate_count, ack.expired_count),
                            (1, 0, 0)
                        );
                        self.buffer.host.acknowledge(&sample_id).unwrap();
                        None
                    }
                    DeliveryCompletion::Ssh {
                        finished_at,
                        completion,
                    } => Some(
                        self.sender
                            .complete(
                                &self.client,
                                &mut self.identity,
                                &mut self.buffer.ssh,
                                completion,
                                finished_at,
                            )
                            .unwrap(),
                    ),
                };
            }
            assert!(Instant::now() < deadline, "data completion timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn accept_ssh(owner: &mut Owner, lane: &mut DeliveryDispatcher) {
    assert_eq!(
        owner.finish(lane),
        Some(SecurityEventStep::Acknowledged {
            accepted: 1,
            duplicate: 0,
            expired: 0
        })
    );
}

fn open_owner() -> (Owner, AgentConfiguration) {
    let root = Path::new(ROOT);
    let target = Target::new(
        &env::var("NODOMI_DELIVERY_TEST_RELAY_ORIGIN").unwrap(),
        &env::var("NODOMI_DELIVERY_TEST_SERVER_ID").unwrap(),
    )
    .unwrap();
    let client = ProtocolClient::new(
        target.clone(),
        Some(&fs::read("/input/ca.pem").unwrap()),
        Duration::from_secs(8),
    )
    .unwrap();
    let mut identity = IdentityStore::initialize(&root.join("identity"), target).unwrap();
    let token = root.join("enrollment");
    let architecture = match env::consts::ARCH {
        "aarch64" => Architecture::Arm64,
        "x86_64" => Architecture::X86_64,
        _ => panic!("unsupported fixture architecture"),
    };
    let capabilities = Capabilities {
        system: Capability::Available,
        processes: Capability::Unsupported,
        containers: Capability::Unsupported,
        ssh_events: Capability::Unsupported,
    };
    client
        .register(
            &mut identity,
            &Enrollment::from_private_file(&token).unwrap(),
            &RegistrationMetadata {
                version: env!("CARGO_PKG_VERSION").into(),
                architecture,
                distribution: "Nodomi isolated Linux test".into(),
                distribution_version: "1".into(),
                hostname: "fixture-mixed-dispatch".into(),
                capabilities: capabilities.clone(),
            },
        )
        .unwrap();
    fs::remove_file(token).unwrap();
    let raw = LinuxSource.capture_host().unwrap();
    let epoch = new_collector_epoch().unwrap();
    let config = client.configuration(&mut identity).unwrap();
    let buffer = SharedBuffer::open(
        SharedBufferPaths {
            host: &root.join("runtime"),
            ssh: &root.join("ssh-queue"),
        },
        &identity,
        &epoch,
        &config,
        &queue_time(&raw),
    )
    .unwrap();
    let owner = Owner {
        client,
        identity,
        buffer,
        collector: HostCollector::new(&epoch).unwrap(),
        sender: SecurityEventSender::new(),
        heartbeat: Heartbeat {
            boot_id: raw.boot_id,
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities,
            buffered_bytes: 0,
            discarded_samples_total: "0".into(),
            collector_epoch: epoch,
            ssh_source_diagnostics: None,
            updater: UpdaterRuntime {
                platform: format!("linux-{}", env::consts::ARCH),
                kernel_version: fs::read_to_string("/proc/sys/kernel/osrelease")
                    .unwrap()
                    .trim()
                    .into(),
                binary_sha256: env::var("NODOMI_DELIVERY_TEST_BINARY_SHA256").unwrap(),
                protocol_version: 1,
                self_update: "UNSUPPORTED_INSTALLATION".into(),
                local_phase: "IDLE".into(),
                mode: "MANUAL".into(),
                source: "GITHUB_RELEASES".into(),
                build_origin: "SELF_COMPILED".into(),
                current_release_id: None,
                local_attempt_id: None,
                trigger: None,
                target_version: None,
                last_check_at: None,
                available_version: None,
                error_code: None,
                available_is_security_update: None,
                result_recorded_at: None,
                update_events_dropped_total: 0,
            },
        },
    };

    (owner, config)
}

#[test]
#[ignore = "requires a standalone local HTTPS relay, test backend and mixed-delivery fixture inputs"]
fn https_mixed_delivery() {
    let (mut owner, _) = open_owner();
    let root = Path::new(ROOT);
    owner.send_heartbeat();
    owner.add_host();
    owner.add_ssh(1);
    with_delivery_dispatcher(|lane| {
        assert_eq!(owner.start_next(lane), Some(DeliveryKind::Host));
        assert_eq!(owner.finish(lane), None);
        owner.add_host();
        // Both are ready. A new HOST sample cannot overtake pending SSH.
        assert_eq!(owner.start_next(lane), Some(DeliveryKind::Ssh));
        let Some(SecurityEventStep::RetryScheduled { remaining, .. }) = owner.finish(lane) else {
            panic!("SSH Retry-After was not scheduled")
        };
        assert_eq!(remaining, RETRY_AFTER);
        assert!(matches!(
            owner
                .sender
                .prepare(
                    &owner.client,
                    &owner.identity,
                    &mut owner.buffer.ssh,
                    &queue_time(&LinuxSource.capture_host().unwrap()),
                    Instant::now()
                )
                .unwrap(),
            SecurityEventPreparation::Progress(SecurityEventStep::Waiting { .. })
        ));
        assert_eq!(owner.start_next(lane), Some(DeliveryKind::Host));
        assert_eq!(owner.finish(lane), None);
        assert_eq!(owner.start_next(lane), None);

        let deadline = Instant::now() + RETRY_AFTER + Duration::from_secs(2);
        loop {
            if let Some(kind) = owner.start_next(lane) {
                assert_eq!(kind, DeliveryKind::Ssh);
                break;
            }
            assert!(Instant::now() < deadline, "SSH retry timed out");
            thread::sleep(Duration::from_millis(30));
        }
        // Relay signals only after PostgreSQL has accepted the SSH request;
        // the response is withheld until this owner sends an independent heartbeat.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.join("ssh-response-held").exists() {
            assert!(
                Instant::now() < deadline,
                "relay did not hold committed SSH response"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(lane.active_kind(), Some(DeliveryKind::Ssh));
        assert!(lane.take_completion().unwrap().is_none());
        owner.add_host();
        owner.add_ssh(2);
        assert_eq!(owner.start_next(lane), None);
        owner.send_heartbeat();
        accept_ssh(&mut owner, lane);
        // Both are ready again. SSH must give the next turn to HOST.
        assert_eq!(owner.start_next(lane), Some(DeliveryKind::Host));
        assert_eq!(owner.finish(lane), None);
        assert_eq!(owner.start_next(lane), Some(DeliveryKind::Ssh));
        accept_ssh(&mut owner, lane);
        assert_eq!(owner.start_next(lane), None);
        assert!(!owner.buffer.host.has_pending_sample());
        assert_eq!(owner.buffer.ssh.queued_payload_bytes().unwrap(), 0);
        assert_eq!(
            owner
                .buffer
                .ssh
                .checkpoint(STREAM)
                .unwrap()
                .unwrap()
                .sequence,
            2
        );
        Ok(())
    })
    .unwrap();
}

fn fetch_resize_target(owner: &mut Owner, generation: u64, cap: u64) -> AgentConfiguration {
    let root = Path::new(ROOT);
    fs::write(root.join(format!("resize-ready-{generation}")), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join(format!("resize-published-{generation}")).exists() {
        assert!(
            Instant::now() < deadline,
            "resize fixture did not publish the desired target"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let target = owner.client.configuration(&mut owner.identity).unwrap();
    assert_eq!(target.target.generation, generation);
    assert_eq!(target.target.configuration.buffer_max_bytes, cap);
    target
}

#[test]
#[ignore = "requires a standalone local HTTPS relay, test backend and mixed-delivery fixture inputs"]
fn https_live_buffer_resize() {
    let (mut owner, initial) = open_owner();
    let epoch = owner.heartbeat.collector_epoch.clone();
    assert_eq!(initial.target.generation, 1);
    assert_eq!(initial.target.configuration.buffer_max_bytes, 100_000_000);
    owner.send_heartbeat();
    owner
        .client
        .report_applied_configuration(&mut owner.identity, &initial, &epoch, 1)
        .unwrap();

    owner.add_host();
    owner.add_ssh_padded(1, 32_000);
    let now = queue_time(&LinuxSource.capture_host().unwrap());
    let host = owner
        .buffer
        .host
        .begin(&now.boot_id, now.monotonic_ns)
        .unwrap()
        .unwrap();
    let ssh = owner.buffer.ssh.prepare(&now).unwrap().unwrap();

    let smaller = fetch_resize_target(&mut owner, 2, 4_000_000);
    assert_eq!(
        smaller.target.configuration.sampling_interval_seconds,
        initial.target.configuration.sampling_interval_seconds
    );
    owner.buffer.apply_configuration(&smaller).unwrap();
    assert_eq!(owner.buffer.host.configuration(), Some(&smaller));
    owner
        .client
        .report_applied_configuration(&mut owner.identity, &smaller, &epoch, 2)
        .unwrap();
    for sequence in 2..=40 {
        owner.add_ssh_padded(sequence, 32_000);
    }
    let queued = owner.buffer.ssh.queued_payload_bytes().unwrap();
    assert_eq!(queued, 40 * 32_000);
    assert!((1_000_001..=4_000_000).contains(&owner.buffer.allocated_bytes().unwrap()));

    let too_small = fetch_resize_target(&mut owner, 3, 1_000_000);
    assert_eq!(
        owner.buffer.apply_configuration(&too_small),
        Err("RESOURCE_LIMIT")
    );
    assert!(owner.buffer.safely_reportable());
    assert_eq!(owner.buffer.host.configuration(), Some(&smaller));
    owner
        .client
        .report_configuration_failure(
            &mut owner.identity,
            &too_small,
            &epoch,
            3,
            Some(&smaller),
            ConfigurationFailure::ResourceLimit,
        )
        .unwrap();

    // Both attempts still refer to the originals, including the first SSH batch
    // prepared before the successful shrink and the later queue growth.
    owner.buffer.host.attempt_finished(&host.sample_id).unwrap();
    owner.buffer.ssh.finish(&ssh.token, None).unwrap();
    let now = queue_time(&LinuxSource.capture_host().unwrap());
    assert_eq!(
        owner
            .buffer
            .host
            .begin(&now.boot_id, now.monotonic_ns)
            .unwrap(),
        Some(host)
    );
    let retry = owner.buffer.ssh.prepare(&now).unwrap().unwrap();
    assert_eq!(retry.body, ssh.body);
    assert_eq!(retry.event_count, 1);
    assert_eq!(owner.buffer.ssh.queued_payload_bytes().unwrap(), queued);
    assert_eq!(
        owner
            .buffer
            .ssh
            .checkpoint(STREAM)
            .unwrap()
            .unwrap()
            .sequence,
        40
    );

    owner.add_host();
    owner.add_ssh_padded(41, 32_000);
    assert_eq!(
        owner
            .buffer
            .ssh
            .checkpoint(STREAM)
            .unwrap()
            .unwrap()
            .sequence,
        41
    );
    owner.send_heartbeat();
}

#[test]
#[ignore = "requires a standalone local HTTPS relay, test backend and mixed-delivery fixture inputs"]
fn https_capacity_eviction() {
    const TOTAL: u8 = 24;
    let (mut owner, initial) = open_owner();
    let epoch = owner.heartbeat.collector_epoch.clone();
    owner.send_heartbeat();
    owner
        .client
        .report_applied_configuration(&mut owner.identity, &initial, &epoch, 1)
        .unwrap();
    let minimum = fetch_resize_target(&mut owner, 2, 1_000_000);
    owner.buffer.apply_configuration(&minimum).unwrap();
    owner
        .client
        .report_applied_configuration(&mut owner.identity, &minimum, &epoch, 2)
        .unwrap();

    owner.add_host();
    owner.add_ssh_padded(1, 32_000);
    let now = queue_time(&LinuxSource.capture_host().unwrap());
    let first = owner.buffer.ssh.prepare(&now).unwrap().unwrap();
    assert_eq!(first.event_count, 1);
    for sequence in 2..=TOTAL {
        owner.add_ssh_padded(sequence, 32_000);
    }
    let discarded = owner.buffer.ssh.capacity_discarded_events_total().unwrap();
    assert!((1..u64::from(TOTAL - 1)).contains(&discarded));
    let queued = u64::from(TOTAL) - discarded;
    assert_eq!(
        owner.buffer.ssh.queued_payload_bytes().unwrap(),
        queued * 32_000
    );
    let checkpoint = owner.buffer.ssh.checkpoint(STREAM).unwrap().unwrap();
    assert_eq!(checkpoint.sequence, u64::from(TOTAL));
    let allocated = owner.buffer.allocated_bytes().unwrap();

    owner.buffer.ssh.finish(&first.token, None).unwrap();
    let now = queue_time(&LinuxSource.capture_host().unwrap());
    let retry = owner.buffer.ssh.prepare(&now).unwrap().unwrap();
    assert_eq!(retry.body, first.body);
    owner.buffer.ssh.finish(&retry.token, None).unwrap();

    with_delivery_dispatcher(|lane| {
        let mut sent = 0;
        for _ in 0..=TOTAL {
            match owner.start_next(lane) {
                Some(DeliveryKind::Host) => assert_eq!(owner.finish(lane), None),
                Some(DeliveryKind::Ssh) => {
                    let Some(SecurityEventStep::Acknowledged {
                        accepted,
                        duplicate: 0,
                        expired: 0,
                    }) = owner.finish(lane)
                    else {
                        panic!("unexpected SSH result after capacity recovery");
                    };
                    sent += accepted;
                }
                None => break,
            }
        }
        assert_eq!(sent, queued);
        assert!(!owner.buffer.host.has_pending_sample());
        assert_eq!(owner.buffer.ssh.queued_payload_bytes().unwrap(), 0);
        Ok(())
    })
    .unwrap();
    let allocated_after_drain = owner.buffer.allocated_bytes().unwrap();
    let compacted = owner
        .buffer
        .compact_ssh()
        .unwrap()
        .expect("drained SSH queue has free pages");
    let allocated_after_compaction = owner.buffer.allocated_bytes().unwrap();
    assert!(compacted.allocated_bytes_after < compacted.allocated_bytes_before);
    assert!(allocated_after_compaction < allocated_after_drain);
    assert_eq!(
        owner.buffer.ssh.capacity_discarded_events_total().unwrap(),
        discarded
    );
    assert_eq!(
        owner.buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(checkpoint)
    );
    owner.send_heartbeat();

    fs::write(
        Path::new(ROOT).join("capacity-summary.json"),
        serde_json::to_vec(&json!({
            "admittedCount": TOTAL,
            "capacityDiscardedCount": discarded,
            "queuedCount": queued,
            "allocatedBytesBeforeDrain": allocated,
            "allocatedBytesAfterDrain": allocated_after_drain,
            "allocatedBytesAfterCompaction": allocated_after_compaction,
            "sqliteAllocatedBytesBeforeCompaction": compacted.allocated_bytes_before,
            "sqliteAllocatedBytesAfterCompaction": compacted.allocated_bytes_after,
            "checkpointSequence": TOTAL,
        }))
        .unwrap(),
    )
    .unwrap();
}
