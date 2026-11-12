use crate::{
    buffer::{
        Admission, QueueTime, RejectionProgress, SharedBuffer, SharedBufferPaths, SourcePosition,
        SshQueue, SshRejection,
    },
    identity::{Binding, IdentityStore, Target},
    model::{Availability, ObservationTime, RawSnapshot},
    protocol::{AgentConfiguration, IngestionResult},
    runtime::{HostCollector, StoredSample},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const BOOT: &str = "90000000-0000-4000-8000-000000000010";
const EPOCH: &str = "90000000-0000-4000-8000-000000000020";
const CONFIG: &str = "90000000-0000-4000-8000-000000000030";
const STREAM: &str = "shared-budget-test";
const OCCURRED_AT: &str = "2026-11-10T12:00:00Z";
const MIN_BYTES: u64 = 1_000_000;
const DEFAULT_BYTES: u64 = 100_000_000;
const MAX_BYTES: u64 = 1_000_000_000;

struct Fixture {
    identity: IdentityStore,
    _identity_root: tempfile::TempDir,
    cache_root: tempfile::TempDir,
}

impl Fixture {
    fn new(cache_parent: Option<&Path>) -> Self {
        let cache_root = match cache_parent {
            Some(parent) => tempfile::tempdir_in(parent).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let identity_root = tempfile::tempdir().unwrap();
        let private_dir = |path: std::path::PathBuf| {
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        let target = Target::new("https://localhost:9443", "server-budget").unwrap();
        let mut identity =
            IdentityStore::initialize(&private_dir(identity_root.path().join("identity")), target)
                .unwrap();
        identity
            .confirm(Binding {
                agent_id: "agent-budget".into(),
                server_id: "server-budget".into(),
                binding_revision: 2,
            })
            .unwrap();
        private_dir(cache_root.path().join("host"));
        private_dir(cache_root.path().join("ssh"));
        Self {
            identity,
            _identity_root: identity_root,
            cache_root,
        }
    }

    fn open(&self, limit: u64, now: u64) -> SharedBuffer {
        self.open_config(&configuration(limit), now)
            .expect("open HOST and SSH under one budget")
    }

    fn open_config(
        &self,
        config: &AgentConfiguration,
        now: u64,
    ) -> crate::identity::Result<SharedBuffer> {
        SharedBuffer::open(
            SharedBufferPaths {
                host: &self.cache_root.path().join("host"),
                ssh: &self.cache_root.path().join("ssh"),
            },
            &self.identity,
            EPOCH,
            config,
            &clock(now),
        )
    }

    fn recover(&self) -> SharedBuffer {
        SharedBuffer::recover(
            SharedBufferPaths {
                host: &self.cache_root.path().join("host"),
                ssh: &self.cache_root.path().join("ssh"),
            },
            &self.identity,
            EPOCH,
        )
        .unwrap()
    }

    fn assert_allocation(&self, buffer: &SharedBuffer, limit: u64) -> u64 {
        let bytes = |path: &Path| fs::symlink_metadata(path).unwrap().blocks() * 512;
        let allocated = ["host", "ssh"]
            .into_iter()
            .map(|name| {
                let dir = self.cache_root.path().join(name);
                bytes(&dir)
                    + fs::read_dir(&dir)
                        .unwrap()
                        .map(|entry| bytes(&entry.unwrap().path()))
                        .sum::<u64>()
            })
            .sum::<u64>();
        assert_eq!(buffer.allocated_bytes().unwrap(), allocated);
        assert!(
            allocated <= limit,
            "committed allocation {allocated} exceeds {limit}"
        );
        let peak = buffer.observed_peak_bytes().unwrap();
        assert!(
            (allocated..=limit).contains(&peak),
            "measured peak {peak} must cover allocation {allocated} within {limit}"
        );
        allocated
    }
}

fn configuration(limit: u64) -> AgentConfiguration {
    AgentConfiguration::decode(
        &serde_json::to_vec(&json!({
            "agentId": "agent-budget",
            "bindingRevision": 2,
            "schemaVersion": 1,
            "target": {
                "configId": CONFIG,
                "generation": 1,
                "configuration": {
                    "samplingIntervalSeconds": 30,
                    "bufferMaxAgeSeconds": 3600,
                    "bufferMaxBytes": limit,
                },
            },
        }))
        .unwrap(),
    )
    .unwrap()
}

fn clock(seconds: u64) -> QueueTime {
    QueueTime {
        boot_id: BOOT.into(),
        monotonic_ns: seconds * 1_000_000_000,
        unix_seconds: 1_794_304_800 + i64::try_from(seconds).unwrap(),
    }
}

fn position(sequence: u64) -> SourcePosition {
    SourcePosition {
        stream: STREAM.into(),
        sequence,
        cursor: sequence.to_be_bytes().to_vec(),
    }
}

fn event(sequence: u64, bytes: usize) -> Vec<u8> {
    let mut body = serde_json::to_vec(&json!({
        "eventId": format!("91000000-0000-4000-8000-{sequence:012x}"),
        "bootId": BOOT,
        "occurredAt": OCCURRED_AT,
        "eventType": "SSH_AUTH_FAILED",
        "sourceIp": "192.0.2.42",
        "username": "synthetic-budget-test",
    }))
    .unwrap();
    assert!(body.len() <= bytes);
    body.resize(bytes, b' ');
    body
}

fn sample(seconds: u64, bytes: usize) -> StoredSample {
    let now = clock(seconds);
    let observed = ObservationTime {
        monotonic_ns: now.monotonic_ns,
        observed_unix_ns: u128::try_from(now.unix_seconds).unwrap() * 1_000_000_000,
    };
    let mut sample = HostCollector::new(EPOCH)
        .unwrap()
        .collect(RawSnapshot {
            boot_id: now.boot_id,
            monotonic_ns: observed.monotonic_ns,
            observed_unix_ns: observed.observed_unix_ns,
            cpu_observed: observed,
            memory_observed: observed,
            load_observed: observed,
            swap_observed: observed,
            page_size: Ok(4096),
            cpu: Err(Availability::Unsupported),
            memory: Ok(BTreeMap::from([
                ("MemTotal".into(), Ok(100)),
                ("MemAvailable".into(), Ok(60)),
                ("Cached".into(), Ok(20)),
                ("SwapTotal".into(), Ok(0)),
                ("SwapFree".into(), Ok(0)),
            ])),
            load: Ok([1.0, 0.5, 0.1]),
            swap: Err(Availability::Unsupported),
        })
        .unwrap();
    // Whitespace changes the exact stored body size while keeping the sample valid.
    assert!(sample.body.len() <= bytes);
    sample
        .body
        .extend(std::iter::repeat_n(' ', bytes - sample.body.len()));
    sample
}

fn batch(events: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"{\"events\":[".to_vec();
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(event);
    }
    bytes.extend_from_slice(b"]}");
    bytes
}

fn ack(count: usize) -> IngestionResult {
    IngestionResult {
        accepted_count: u64::try_from(count).unwrap(),
        duplicate_count: 0,
        expired_count: 0,
        received_at: OCCURRED_AT.into(),
    }
}

fn queued_bodies(queue: &SshQueue) -> Vec<Vec<u8>> {
    queue
        .connection
        .prepare("SELECT body FROM ssh_events ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn database_pages(queue: &SshQueue) -> u32 {
    queue
        .connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn shared_budget_handles_minimum_default_and_maximum_without_eager_allocation() {
    for limit in [MIN_BYTES, DEFAULT_BYTES, MAX_BYTES] {
        let fixture = Fixture::new(None);
        let mut buffer = fixture.open(limit, 1);
        let host = sample(1, 8_192);
        buffer.host.admit(host.clone()).unwrap();
        let event = event(1, 4096);
        assert_eq!(
            buffer.ssh.enqueue(&position(1), &event, &clock(1)),
            Ok(Admission::Stored)
        );
        assert_eq!(buffer.host.configuration(), Some(&configuration(limit)));
        assert!(fixture.assert_allocation(&buffer, limit) < MIN_BYTES);
        assert!(buffer.observed_peak_bytes().unwrap() < MIN_BYTES);
        assert_eq!(
            buffer.host.begin(BOOT, clock(1).monotonic_ns).unwrap(),
            Some(host)
        );
        let attempt = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
        assert_eq!(attempt.body, batch(&[event]));
    }
}

#[test]
fn shared_budget_contention_keeps_committed_data_and_allows_drain() {
    let old = sample(1, 16_384);
    let control = Fixture::new(None);
    let mut host_only = control.open(MIN_BYTES, 1);
    host_only.host.admit(old.clone()).unwrap();
    host_only
        .host
        .begin(BOOT, clock(1).monotonic_ns)
        .unwrap()
        .unwrap();
    let candidate = [
        450_000, 375_000, 300_000, 225_000, 192_000, 160_000, 120_000, 96_000,
    ]
    .into_iter()
    .find_map(|bytes| {
        let candidate = sample(2, bytes);
        match host_only.host.admit(candidate.clone()) {
            Ok(()) => Some(candidate),
            Err("RESOURCE_LIMIT") => None,
            Err(error) => panic!("unexpected control HOST admission error: {error}"),
        }
    })
    .expect("a large HOST sample fits under the cap when SSH is empty");
    host_only.host.attempt_finished(&old.sample_id).unwrap();
    assert_eq!(
        host_only.host.begin(BOOT, clock(2).monotonic_ns).unwrap(),
        Some(candidate.clone())
    );
    let stable = control.assert_allocation(&host_only, MIN_BYTES);
    let host_peak = host_only.observed_peak_bytes().unwrap();
    assert!(
        host_peak > stable,
        "the HOST temporary and committed manifests must both be charged"
    );
    host_only.host.acknowledge(&candidate.sample_id).unwrap();
    drop(host_only);

    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(MIN_BYTES, 1);
    buffer.host.admit(old.clone()).unwrap();
    assert_eq!(
        buffer.host.begin(BOOT, clock(1).monotonic_ns).unwrap(),
        Some(old.clone())
    );
    let mut events = Vec::new();
    let admitted = (1..=64)
        .find(|&sequence| {
            let original = event(sequence, 32_000);
            assert_eq!(
                buffer
                    .ssh
                    .enqueue(&position(sequence), &original, &clock(1)),
                Ok(Admission::Stored)
            );
            let discarded = buffer.ssh.capacity_discarded_events_total().unwrap() as usize;
            events.drain(..discarded);
            events.push(original);
            fixture.assert_allocation(&buffer, MIN_BYTES);
            discarded > 0
        })
        .expect("SSH must reuse space at the shared limit");
    assert!(events.len() >= 2);
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(admitted))
    );

    assert_eq!(buffer.host.admit(candidate), Err("RESOURCE_LIMIT"));
    assert_eq!(
        buffer.host.admit(sample(2, 1_100_000)),
        Err("RESOURCE_LIMIT")
    );
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(admitted))
    );
    assert_eq!(
        buffer.ssh.queued_payload_bytes().unwrap(),
        events.len() as u64 * 32_000
    );

    let flight = buffer.ssh.prepare(&clock(2)).unwrap().unwrap();
    let expected = batch(&events);
    assert_eq!(flight.event_count, events.len());
    assert_eq!(flight.body, expected);
    let discarded = buffer.ssh.capacity_discarded_events_total().unwrap();
    let incoming = admitted + 1;
    assert_eq!(
        buffer
            .ssh
            .enqueue(&position(incoming), &event(incoming, 300_000), &clock(2)),
        Err("SSH_QUEUE_RESOURCE_LIMIT"),
    );
    assert_eq!(queued_bodies(&buffer.ssh), events);
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(admitted))
    );
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
    let stable_before_drain = fixture.assert_allocation(&buffer, MIN_BYTES);
    let peak = buffer.observed_peak_bytes().unwrap();
    let journal_peak = buffer.observed_journal_peak_bytes().unwrap();
    assert!(
        journal_peak > 0,
        "the measurement must observe the live SQLite rollback journal"
    );
    drop(buffer);

    let mut buffer = fixture.open(MIN_BYTES, 2);
    assert_eq!(
        buffer.host.begin(BOOT, clock(2).monotonic_ns).unwrap(),
        Some(old.clone())
    );
    let mut resumed = buffer.ssh.prepare(&clock(2)).unwrap().unwrap();
    assert_eq!(resumed.body, expected);
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(admitted))
    );
    while resumed.event_count > 1 {
        assert_eq!(
            buffer.ssh.reject(&resumed.token, SshRejection::Invalid),
            Ok(RejectionProgress::Split)
        );
        resumed = buffer.ssh.prepare(&clock(2)).unwrap().unwrap();
    }
    assert_eq!(resumed.body, batch(&events[..1]));
    assert_eq!(
        buffer.ssh.reject(&resumed.token, SshRejection::Invalid),
        Ok(RejectionProgress::Quarantined)
    );
    let mut sent = 1;
    while let Some(attempt) = buffer.ssh.prepare(&clock(2)).unwrap() {
        let end = sent + attempt.event_count;
        assert_eq!(attempt.body, batch(&events[sent..end]));
        buffer
            .ssh
            .finish(&attempt.token, Some(&ack(attempt.event_count)))
            .unwrap();
        sent = end;
    }
    assert_eq!(sent, events.len());
    assert_eq!(buffer.ssh.quarantined_count(), Ok(1));
    let stored: (Vec<u8>, String) = buffer
        .ssh
        .connection
        .query_row(
            "SELECT body, quarantine_code FROM ssh_events WHERE quarantine_code='INVALID'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, (events[0].clone(), "INVALID".into()));
    buffer.host.acknowledge(&old.sample_id).unwrap();
    assert!(!buffer.host.has_pending_sample());
    assert_eq!(
        buffer.ssh.queued_payload_bytes(),
        Ok(events[0].len() as u64)
    );
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(admitted))
    );
    let stable_after_drain = fixture.assert_allocation(&buffer, MIN_BYTES);
    println!(
        "shared cap {MIN_BYTES} bytes, admitted {admitted} SSH events, \
         HOST control peak {host_peak} bytes, mixed peak {peak} bytes, \
         live journal peak {journal_peak} bytes, \
         settled allocation before drain {stable_before_drain} bytes and after drain {stable_after_drain} bytes"
    );
}

#[test]
fn capacity_eviction_reuses_pages_and_keeps_exact_frozen_prefix() {
    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(MIN_BYTES, 1);
    let first = event(1, 32_000);
    buffer.ssh.enqueue(&position(1), &first, &clock(1)).unwrap();
    let pinned = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(pinned.body, batch(std::slice::from_ref(&first)));
    let mut expected = vec![first];
    let mut discarded = 0;
    let mut reused = 0;
    for sequence in 2..=40 {
        let original = event(sequence, 32_000);
        let previous_pages = database_pages(&buffer.ssh);
        assert_eq!(
            buffer
                .ssh
                .enqueue(&position(sequence), &original, &clock(1)),
            Ok(Admission::Stored),
        );
        let new_total = buffer.ssh.capacity_discarded_events_total().unwrap();
        let removed = usize::try_from(new_total.checked_sub(discarded).unwrap()).unwrap();
        assert!(
            removed < expected.len(),
            "the protected first record cannot be a victim"
        );
        expected.drain(1..1 + removed);
        expected.push(original);
        assert_eq!(queued_bodies(&buffer.ssh), expected);
        assert_eq!(
            buffer.ssh.checkpoint(STREAM).unwrap(),
            Some(position(sequence))
        );
        fixture.assert_allocation(&buffer, MIN_BYTES);
        if removed > 0 && database_pages(&buffer.ssh) == previous_pages {
            reused += 1;
        }
        discarded = new_total;
    }
    assert!(discarded > 1 && reused > 1);
    assert_eq!(discarded, 40 - expected.len() as u64);
    println!(
        "1 MB shared budget retained {} of 40 SSH events, discarded {discarded}, reused pages in {reused} commits",
        expected.len()
    );
    buffer.ssh.finish(&pinned.token, None).unwrap();
    drop(buffer);

    let mut buffer = fixture.recover();
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
    assert_eq!(queued_bodies(&buffer.ssh), expected);
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(40)));
    assert_eq!(
        buffer
            .ssh
            .enqueue(&position(40), expected.last().unwrap(), &clock(1)),
        Ok(Admission::AlreadyCheckpointed)
    );
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
    let retried = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_ne!(retried.token, pinned.token);
    assert_eq!(retried.body, pinned.body);
    buffer.ssh.finish(&retried.token, Some(&ack(1))).unwrap();
    let next = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(next.body, batch(&expected[1..]));
    buffer
        .ssh
        .finish(&next.token, Some(&ack(expected.len() - 1)))
        .unwrap();
    assert!(buffer.ssh.prepare(&clock(1)).unwrap().is_none());
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(40)));
}

#[test]
fn capacity_eviction_rolls_back_when_a_protected_batch_prevents_admission() {
    let incoming = event(6, 300_000);
    let control = Fixture::new(None);
    let mut control_buffer = control.open(MIN_BYTES, 1);
    assert_eq!(
        control_buffer
            .ssh
            .enqueue(&position(6), &incoming, &clock(1)),
        Ok(Admission::Stored),
    );

    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(MIN_BYTES, 1);
    let first = event(1, 200_000);
    buffer.ssh.enqueue(&position(1), &first, &clock(1)).unwrap();
    let flight = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(flight.body, batch(std::slice::from_ref(&first)));
    for sequence in 2..=5 {
        buffer
            .ssh
            .enqueue(&position(sequence), &event(sequence, 32_000), &clock(1))
            .unwrap();
    }
    let previous = queued_bodies(&buffer.ssh);
    let prior_bytes = buffer.ssh.queued_payload_bytes();
    let previous_pages = database_pages(&buffer.ssh);
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(0));
    assert_eq!(
        buffer.ssh.enqueue(&position(6), &incoming, &clock(1)),
        Err("SSH_QUEUE_RESOURCE_LIMIT"),
    );
    assert_eq!(queued_bodies(&buffer.ssh), previous);
    assert_eq!(database_pages(&buffer.ssh), previous_pages);
    assert_eq!(buffer.ssh.queued_payload_bytes(), prior_bytes);
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(0));
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(5)));
    drop(buffer);

    let mut buffer = fixture.recover();
    assert_eq!(queued_bodies(&buffer.ssh), previous);
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(5)));
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(0));
    let retried = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(retried.body, flight.body);
    buffer.ssh.finish(&retried.token, Some(&ack(1))).unwrap();
    let rest = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(rest.body, batch(&previous[1..]));
}

#[test]
fn capacity_eviction_preserves_quarantine_and_unfinished_isolation() {
    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(MIN_BYTES, 1);
    let protected: Vec<_> = (1..=4).map(|sequence| event(sequence, 32_000)).collect();
    buffer
        .ssh
        .enqueue(&position(1), &protected[0], &clock(1))
        .unwrap();
    let bad = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(
        buffer.ssh.reject(&bad.token, SshRejection::Invalid),
        Ok(RejectionProgress::Quarantined)
    );
    for (sequence, body) in (2..=4).zip(&protected[1..]) {
        buffer
            .ssh
            .enqueue(&position(sequence), body, &clock(1))
            .unwrap();
    }
    let rejected = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(rejected.body, batch(&protected[1..]));
    assert_eq!(
        buffer.ssh.reject(&rejected.token, SshRejection::Invalid),
        Ok(RejectionProgress::Split)
    );
    for sequence in 5..=30 {
        buffer
            .ssh
            .enqueue(&position(sequence), &event(sequence, 32_000), &clock(1))
            .unwrap();
    }
    let discarded = buffer.ssh.capacity_discarded_events_total().unwrap();
    assert!(discarded > 0);
    assert_eq!(buffer.ssh.quarantined_count(), Ok(1));
    let rows = queued_bodies(&buffer.ssh);
    assert_eq!(rows[..4], protected);
    assert_eq!(rows.len() as u64, 30 - discarded);
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(30)));
    drop(buffer);

    let mut buffer = fixture.recover();
    let retry = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(retry.body, batch(&protected[1..3]));
    buffer.ssh.finish(&retry.token, Some(&ack(2))).unwrap();
    let isolated_tail = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(isolated_tail.body, batch(&protected[3..]));
    buffer
        .ssh
        .finish(&isolated_tail.token, Some(&ack(1)))
        .unwrap();
    let newer = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(newer.body, batch(&rows[4..]));
    assert_eq!(buffer.ssh.quarantined_count(), Ok(1));
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
}

#[test]
fn interrupted_capacity_replacement_keeps_previous_records_and_cursor() {
    use std::process::Command;

    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(MIN_BYTES, 1);
    let first_host = sample(1, 8_192);
    buffer.host.admit(first_host.clone()).unwrap();
    let first = event(1, 32_000);
    buffer.ssh.enqueue(&position(1), &first, &clock(1)).unwrap();
    let pinned = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(pinned.body, batch(std::slice::from_ref(&first)));
    buffer.ssh.finish(&pinned.token, None).unwrap();
    drop(buffer);

    let Fixture {
        identity,
        _identity_root: identity_root,
        cache_root,
    } = fixture;
    let identity_path = identity_root.path().join("identity");
    drop(identity);
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "buffer::budget::tests::interrupt_capacity_replacement_child",
        ])
        .env("NODOMI_TEST_CAPACITY_IDENTITY", &identity_path)
        .env("NODOMI_TEST_CAPACITY_CACHE", cache_root.path())
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(74),
        "capacity fixture failed before the transaction checkpoint: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let candidate: u64 = fs::read_to_string(cache_root.path().join("candidate"))
        .unwrap()
        .parse()
        .unwrap();
    let previous: Vec<_> = (1..candidate)
        .map(|sequence| event(sequence, 32_000))
        .collect();
    let identity = IdentityStore::open(
        &identity_path,
        &Target::new("https://localhost:9443", "server-budget").unwrap(),
    )
    .unwrap();
    let fixture = Fixture {
        identity,
        _identity_root: identity_root,
        cache_root,
    };
    let mut buffer = fixture.recover();
    assert_eq!(queued_bodies(&buffer.ssh), previous);
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(0));
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(candidate - 1))
    );
    assert_eq!(
        buffer.host.begin(BOOT, clock(1).monotonic_ns).unwrap(),
        Some(first_host)
    );
    let retried = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(retried.body, pinned.body);
    assert_eq!(
        buffer
            .ssh
            .enqueue(&position(candidate), &event(candidate, 32_000), &clock(1)),
        Ok(Admission::Stored),
    );
    let discarded = buffer.ssh.capacity_discarded_events_total().unwrap();
    assert!(discarded > 0 && discarded < previous.len() as u64);
    let mut expected = previous;
    expected.drain(1..1 + usize::try_from(discarded).unwrap());
    expected.push(event(candidate, 32_000));
    assert_eq!(queued_bodies(&buffer.ssh), expected);
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(candidate))
    );
    drop(buffer);

    let buffer = fixture.recover();
    assert_eq!(queued_bodies(&buffer.ssh), expected);
    assert_eq!(buffer.ssh.capacity_discarded_events_total(), Ok(discarded));
    assert_eq!(
        buffer.ssh.checkpoint(STREAM).unwrap(),
        Some(position(candidate))
    );
}

#[test]
#[ignore = "spawned by interrupted_capacity_replacement_keeps_previous_records_and_cursor"]
fn interrupt_capacity_replacement_child() {
    let identity_path = std::env::var_os("NODOMI_TEST_CAPACITY_IDENTITY").unwrap();
    let cache_root =
        std::path::PathBuf::from(std::env::var_os("NODOMI_TEST_CAPACITY_CACHE").unwrap());
    let identity = IdentityStore::open(
        Path::new(&identity_path),
        &Target::new("https://localhost:9443", "server-budget").unwrap(),
    )
    .unwrap();
    let mut buffer = SharedBuffer::recover(
        SharedBufferPaths {
            host: &cache_root.join("host"),
            ssh: &cache_root.join("ssh"),
        },
        &identity,
        EPOCH,
    )
    .unwrap();
    fn exit_before_commit() {
        std::process::exit(74);
    }
    crate::buffer::BEFORE_CAPACITY_COMMIT.with(|hook| hook.set(Some(exit_before_commit)));
    for sequence in 2..=64 {
        fs::write(cache_root.join("candidate"), sequence.to_string()).unwrap();
        assert_eq!(
            buffer
                .ssh
                .enqueue(&position(sequence), &event(sequence, 32_000), &clock(1)),
            Ok(Admission::Stored),
        );
    }
    panic!("the pressure fixture never reached a capacity replacement");
}

#[test]
fn live_shrink_enforces_both_limits_and_keeps_active_attempts() {
    let fixture = Fixture::new(None);
    let mut initial = configuration(DEFAULT_BYTES);
    initial.target.configuration.buffer_max_age_seconds = 86_400;
    let mut buffer = fixture.open_config(&initial, 1).unwrap();
    let first_host = sample(1, 8_192);
    let first_ssh = event(1, 4_096);
    buffer.host.admit(first_host.clone()).unwrap();
    buffer
        .ssh
        .enqueue(&position(1), &first_ssh, &clock(1))
        .unwrap();
    assert_eq!(
        buffer.host.begin(BOOT, clock(1).monotonic_ns).unwrap(),
        Some(first_host.clone())
    );
    let attempt = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(attempt.body, batch(&[first_ssh]));
    buffer.host.admit(sample(2, 8_192)).unwrap();
    buffer
        .ssh
        .enqueue(&position(2), &event(2, 4_096), &clock(2))
        .unwrap();

    let mut smaller = configuration(MIN_BYTES);
    smaller.target.config_id = "90000000-0000-4000-8000-000000000031".into();
    smaller.target.generation = 2;
    buffer.apply_configuration(&smaller).unwrap();
    assert_eq!(buffer.host.configuration(), Some(&smaller));
    assert_eq!(buffer.host.admit(sample(3, 300_000)), Err("RESOURCE_LIMIT"));
    assert_eq!(
        buffer
            .ssh
            .enqueue(&position(3), &event(3, 600_000), &clock(3)),
        Err("SSH_QUEUE_RESOURCE_LIMIT"),
    );
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(2)));
    buffer.host.acknowledge(&first_host.sample_id).unwrap();
    buffer.ssh.finish(&attempt.token, Some(&ack(1))).unwrap();

    assert!(buffer.host.has_pending_sample());
    assert_eq!(buffer.ssh.queued_payload_bytes(), Ok(4_096));
    assert!(
        buffer
            .host
            .begin(BOOT, clock(3603).monotonic_ns)
            .unwrap()
            .is_none()
    );
    assert!(buffer.ssh.prepare(&clock(3603)).unwrap().is_none());
    assert_eq!(buffer.ssh.queued_payload_bytes(), Ok(0));
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(2)));
    drop(buffer);
    let recovered = fixture.recover();
    assert_eq!(recovered.host.configuration(), Some(&smaller));
    assert!(!recovered.host.has_pending_sample());
    assert_eq!(recovered.ssh.checkpoint(STREAM).unwrap(), Some(position(2)));
}

#[test]
fn shared_budget_rejected_shrink_preserves_previous_configuration_and_data() {
    let fixture = Fixture::new(None);
    let mut buffer = fixture.open(DEFAULT_BYTES, 1);
    let host = sample(1, 550_000);
    let ssh = event(1, 500_000);
    buffer.host.admit(host.clone()).unwrap();
    buffer.ssh.enqueue(&position(1), &ssh, &clock(1)).unwrap();
    assert!(fixture.assert_allocation(&buffer, DEFAULT_BYTES) > MIN_BYTES);
    let mut smaller = configuration(MIN_BYTES);
    smaller.target.config_id = "90000000-0000-4000-8000-000000000031".into();
    smaller.target.generation = 2;
    assert_eq!(buffer.apply_configuration(&smaller), Err("RESOURCE_LIMIT"));
    assert!(buffer.safely_reportable());
    assert_eq!(
        buffer.host.configuration(),
        Some(&configuration(DEFAULT_BYTES))
    );
    drop(buffer);
    assert_eq!(
        fixture.open_config(&smaller, 2).err(),
        Some("RESOURCE_LIMIT")
    );

    let mut buffer = fixture.recover();
    assert_eq!(
        buffer.host.configuration(),
        Some(&configuration(DEFAULT_BYTES))
    );
    assert_eq!(
        buffer.host.begin(BOOT, clock(2).monotonic_ns).unwrap(),
        Some(host)
    );
    let flight = buffer.ssh.prepare(&clock(2)).unwrap().unwrap();
    assert_eq!(flight.body, batch(&[ssh]));
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(1)));
}

#[test]
fn shared_budget_accounting_preserves_sqlite_write_lock() {
    let fixture = Fixture::new(None);
    let buffer = fixture.open(DEFAULT_BYTES, 1);
    let db = fixture
        .cache_root
        .path()
        .join("ssh")
        .join(crate::buffer::directory::DB);
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();

    let competing_writer_is_busy = || {
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r#"
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)
try:
    db.execute("BEGIN IMMEDIATE")
except sqlite3.OperationalError as error:
    if error.sqlite_errorcode != sqlite3.SQLITE_BUSY:
        raise
else:
    db.rollback()
    sys.exit("competing connection acquired the write lock")
finally:
    db.close()
"#,
            ])
            .arg(&db)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    competing_writer_is_busy();
    buffer.allocated_bytes().unwrap();
    competing_writer_is_busy();
    writer.execute_batch("ROLLBACK").unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a dedicated 1MiB tmpfs in NODOMI_SHARED_ENOSPC_DIR"]
fn shared_budget_kernel_enospc_preserves_both_stores() {
    use std::io::Write;

    let parent = std::env::var_os("NODOMI_SHARED_ENOSPC_DIR")
        .expect("set NODOMI_SHARED_ENOSPC_DIR to a dedicated 1MiB tmpfs");
    let fixture = Fixture::new(Some(Path::new(&parent)));
    // The app budget leaves ample room. The kernel must produce the failure.
    let mut buffer = fixture.open(DEFAULT_BYTES, 1);
    let old = sample(1, 16_384);
    let first = event(1, 32_000);
    buffer.host.admit(old.clone()).unwrap();
    buffer.ssh.enqueue(&position(1), &first, &clock(1)).unwrap();
    fixture.assert_allocation(&buffer, DEFAULT_BYTES);

    let filler_path = fixture.cache_root.path().join("filler");
    let mut filler = fs::File::create(&filler_path).unwrap();
    let full = (0..=256)
        .find_map(|_| filler.write_all(&[0; 4096]).err())
        .expect("the isolated 1MiB mount must fill");
    assert_eq!(full.raw_os_error(), Some(libc::ENOSPC));
    let filler_bytes = filler.metadata().unwrap().blocks() * 512;
    let later = sample(2, 65_536);
    let second = event(2, 32_000);
    assert_eq!(buffer.host.admit(later.clone()), Err("LOCAL_STORAGE_ERROR"));
    assert!(
        buffer
            .ssh
            .enqueue(&position(2), &second, &clock(2))
            .is_err()
    );
    drop(filler);
    fs::remove_file(filler_path).unwrap();
    drop(buffer);

    let mut buffer = fixture.open(DEFAULT_BYTES, 2);
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(1)));
    assert_eq!(
        buffer.host.begin(BOOT, clock(2).monotonic_ns).unwrap(),
        Some(old.clone())
    );
    let flight = buffer.ssh.prepare(&clock(2)).unwrap().unwrap();
    assert_eq!(flight.body, batch(&[first]));
    buffer.ssh.finish(&flight.token, Some(&ack(1))).unwrap();
    buffer.host.acknowledge(&old.sample_id).unwrap();
    assert_eq!(buffer.host.admit(later.clone()), Ok(()));
    assert_eq!(
        buffer.ssh.enqueue(&position(2), &second, &clock(2)),
        Ok(Admission::Stored)
    );
    assert_eq!(
        buffer.host.begin(BOOT, clock(2).monotonic_ns).unwrap(),
        Some(later)
    );
    assert_eq!(buffer.ssh.checkpoint(STREAM).unwrap(), Some(position(2)));
    fixture.assert_allocation(&buffer, DEFAULT_BYTES);
    println!(
        "kernel ENOSPC with {filler_bytes} allocated filler bytes. \
         Both original records and the old SSH checkpoint survived, and both writes succeeded after freeing space"
    );
}

#[path = "compaction_tests.rs"]
mod compaction_tests;
