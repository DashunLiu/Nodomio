use super::*;
use crate::identity::{Binding, Target};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    process::Command,
};

#[path = "source_position_tests.rs"]
mod source_position_tests;

const BOOT: &str = "90000000-0000-4000-8000-000000000001";
const WALL: i64 = 1_794_303_000;
const AT: &str = "2026-11-10T12:00:00Z";

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn target() -> Target {
    Target::new("https://localhost:9443", "server-a").unwrap()
}

fn bound(path: &Path) -> IdentityStore {
    let mut identity = IdentityStore::initialize(path, target()).unwrap();
    identity
        .confirm(Binding {
            agent_id: "agent-a".into(),
            server_id: "server-a".into(),
            binding_revision: 2,
        })
        .unwrap();
    identity
}

fn clock(seconds: u64) -> QueueTime {
    QueueTime {
        boot_id: BOOT.into(),
        monotonic_ns: seconds * 1_000_000_000,
        unix_seconds: WALL + seconds as i64,
    }
}

fn position(sequence: u64) -> SourcePosition {
    SourcePosition {
        stream: "journal.1".into(),
        sequence,
        cursor: sequence.to_be_bytes().to_vec(),
    }
}

fn event_id(id: u32) -> String {
    format!("70000000-0000-4000-8000-{id:012x}")
}

fn event(id: u32) -> Vec<u8> {
    format!(r#" {{ "eventId":"{}","bootId":"{BOOT}","occurredAt":"{AT}","eventType":"SSH_AUTH_FAILED","sourceIp":"2001:db8::4","username":null }} "#, event_id(id)).into_bytes()
}

fn ack(duplicates: u64) -> IngestionResult {
    IngestionResult {
        accepted_count: 0,
        duplicate_count: duplicates,
        expired_count: 0,
        received_at: AT.into(),
    }
}

fn open(path: &Path, identity: &IdentityStore) -> SshQueue {
    SshQueue::open(path, identity, 3600, 2_000_000).unwrap()
}

fn open_shared(host: &Path, ssh: &Path, identity: &IdentityStore, now: &QueueTime) -> SharedBuffer {
    use crate::protocol::{AgentConfiguration, CollectionConfiguration, ConfigurationTarget};

    SharedBuffer::open(
        SharedBufferPaths { host, ssh },
        identity,
        "90000000-0000-4000-8000-000000000020",
        &AgentConfiguration {
            agent_id: "agent-a".into(),
            binding_revision: 2,
            schema_version: 1,
            target: ConfigurationTarget {
                config_id: "90000000-0000-4000-8000-000000000030".into(),
                generation: 1,
                configuration: CollectionConfiguration {
                    sampling_interval_seconds: 30,
                    buffer_max_age_seconds: 3600,
                    buffer_max_bytes: 1_000_000,
                },
            },
        },
        now,
    )
    .unwrap()
}

fn expected_batch(ids: &[u32]) -> Vec<u8> {
    let mut body = PREFIX.to_vec();
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        body.extend(event(*id));
    }
    body.extend(SUFFIX);
    body
}

fn recreate_pre_isolation_schema(queue: &SshQueue) {
    recreate_v4_source_schema(queue);
    queue
        .connection
        .execute_batch(
            "DROP INDEX ssh_events_ready;
             ALTER TABLE ssh_events DROP COLUMN quarantine_code;
             ALTER TABLE queue_state DROP COLUMN isolation_last;
             ALTER TABLE queue_state DROP COLUMN batch_limit;
             ALTER TABLE queue_state DROP COLUMN quarantined_count;
             ALTER TABLE queue_state DROP COLUMN capacity_discarded_count;
             PRAGMA user_version=2;",
        )
        .unwrap();
}

fn recreate_v4_source_schema(queue: &SshQueue) {
    queue
        .connection
        .execute_batch(
            "ALTER TABLE source_checkpoints RENAME TO source_checkpoints_new;
         CREATE TABLE source_checkpoints (
             stream TEXT PRIMARY KEY,
             sequence INTEGER NOT NULL CHECK (sequence >= 0),
             cursor BLOB NOT NULL CHECK (length(cursor) BETWEEN 1 AND 4096),
             last_event_id TEXT NOT NULL UNIQUE,
             last_body_sha256 BLOB NOT NULL CHECK (length(last_body_sha256) = 32)
         ) STRICT;
         INSERT INTO source_checkpoints SELECT stream,sequence,cursor,last_event_id,last_outcome
             FROM source_checkpoints_new;
         DROP TABLE source_checkpoints_new;
         ALTER TABLE queue_state DROP COLUMN source_counter_epoch;
         ALTER TABLE queue_state DROP COLUMN unknown_format_records_total;
         ALTER TABLE queue_state DROP COLUMN oversized_records_total;
         PRAGMA user_version=4;",
        )
        .unwrap();
}

#[test]
fn checkpoints_and_frozen_bodies_survive_restart_and_old_ack_cannot_clear_newer_event() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let a = event(1);
    let b = String::from_utf8(event(2))
        .unwrap()
        .replace(AT, &AT.to_ascii_lowercase())
        .into_bytes();
    let mut queue = open(queue_dir.path(), &identity);
    assert_eq!(
        queue.enqueue(&position(1), &a, &clock(0)),
        Ok(Admission::Stored)
    );
    let first = queue.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(first.body, [PREFIX, &a, SUFFIX].concat());
    assert_eq!(queue.prepare(&clock(1)).err(), Some("SSH_ATTEMPT_ACTIVE"));
    assert_eq!(
        queue.enqueue(&position(2), &b, &clock(2)),
        Ok(Admission::Stored)
    );
    assert_eq!(
        queue.finish(&first.token, Some(&ack(2))),
        Err("INVALID_SSH_ACK")
    );
    drop(queue);
    let mut queue = open(queue_dir.path(), &identity);
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(2)));
    assert_eq!(
        queue.enqueue(&position(1), &a, &clock(3)),
        Err("SSH_SOURCE_POSITION_STALE")
    );
    assert_eq!(
        queue.enqueue(&position(2), &b, &clock(3)),
        Ok(Admission::AlreadyCheckpointed)
    );
    let second = queue.prepare(&clock(3)).unwrap().unwrap();
    assert_ne!(first.token, second.token);
    assert_eq!(first.body, second.body);
    assert_eq!(
        queue.finish(&first.token, Some(&ack(1))),
        Err("STALE_SSH_ATTEMPT")
    );
    queue.finish(&second.token, None).unwrap();
    let third = queue.prepare(&clock(4)).unwrap().unwrap();
    assert_ne!(third.token, second.token);
    assert_eq!(third.body, first.body);
    queue.finish(&third.token, Some(&ack(1))).unwrap();
    let later = queue.prepare(&clock(5)).unwrap().unwrap();
    assert_eq!(later.body, [PREFIX, &b, SUFFIX].concat());
    queue.finish(&later.token, Some(&ack(1))).unwrap();
    assert_eq!(queue.queued_payload_bytes(), Ok(0));
    assert!(queue.prepare(&clock(6)).unwrap().is_none());
    assert_eq!(
        queue.enqueue(&position(2), &a, &clock(6)),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    assert_eq!(
        queue.enqueue(&position(3), &b, &clock(6)),
        Err("SSH_EVENT_CONFLICT")
    );
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(2)));
}

#[test]
fn split_restarts_without_enlarging_the_rejected_range() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    for id in 1..=5 {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(0))
            .unwrap();
    }
    let rejected = queue.prepare(&clock(0)).unwrap().unwrap();
    assert_eq!(rejected.body, expected_batch(&[1, 2, 3, 4, 5]));
    for id in 6..=7 {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(1))
            .unwrap();
    }
    assert_eq!(
        queue.reject(&rejected.token, SshRejection::TooLarge),
        Ok(RejectionProgress::Split)
    );
    drop(queue);

    let mut queue = open(queue_dir.path(), &identity);
    let prefix = queue.prepare(&clock(2)).unwrap().unwrap();
    assert_eq!(prefix.body, expected_batch(&[1, 2, 3]));
    assert_eq!(
        queue.reject(&rejected.token, SshRejection::Conflict),
        Err("STALE_SSH_ATTEMPT")
    );
    assert_eq!(
        queue.finish(&rejected.token, Some(&ack(5))),
        Err("STALE_SSH_ATTEMPT")
    );
    queue.finish(&prefix.token, Some(&ack(3))).unwrap();
    let tail = queue.prepare(&clock(3)).unwrap().unwrap();
    assert_eq!(tail.body, expected_batch(&[4, 5]));
    queue.finish(&tail.token, Some(&ack(2))).unwrap();
    let newer = queue.prepare(&clock(4)).unwrap().unwrap();
    assert_eq!(newer.body, expected_batch(&[6, 7]));
    queue.finish(&newer.token, Some(&ack(2))).unwrap();
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(7)));
    assert_eq!(queue.quarantined_count(), Ok(0));
    assert_eq!(queue.queued_payload_bytes(), Ok(0));
}

#[test]
fn completed_isolation_clears_before_new_records_can_reuse_rowids() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    for id in 1..=3 {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(0))
            .unwrap();
    }
    for _ in 0..2 {
        let batch = queue.prepare(&clock(0)).unwrap().unwrap();
        assert_eq!(
            queue.reject(&batch.token, SshRejection::Invalid),
            Ok(RejectionProgress::Split)
        );
    }
    let bad = queue.prepare(&clock(0)).unwrap().unwrap();
    assert_eq!(bad.body, expected_batch(&[1]));
    assert_eq!(
        queue.reject(&bad.token, SshRejection::Invalid),
        Ok(RejectionProgress::Quarantined)
    );
    for id in [2, 3] {
        let good = queue.prepare(&clock(0)).unwrap().unwrap();
        assert_eq!(good.body, expected_batch(&[id]));
        queue.finish(&good.token, Some(&ack(1))).unwrap();
    }
    drop(queue);

    let mut queue = open(queue_dir.path(), &identity);
    // Keep the quarantined row, so an empty-payload reset cannot mask a stale
    // range. The first two new events reuse the rowids of the accepted events.
    for id in 4..=6 {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(1))
            .unwrap();
    }
    let ids: Vec<i64> = queue
        .connection
        .prepare("SELECT id FROM ssh_events WHERE quarantine_code IS NULL ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ids, [2, 3, 4]);
    let later = queue.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(later.body, expected_batch(&[4, 5, 6]));
    assert_eq!(queue.quarantined_count(), Ok(1));
}

#[test]
fn expiration_completes_isolation_before_selecting_newer_records() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    for id in [1, 2] {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(0))
            .unwrap();
    }
    let rejected = queue.prepare(&clock(0)).unwrap().unwrap();
    queue
        .reject(&rejected.token, SshRejection::Invalid)
        .unwrap();
    for id in [3, 4] {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(3600))
            .unwrap();
    }
    let frozen = queue.prepare(&clock(3600)).unwrap().unwrap();
    assert_eq!(frozen.body, expected_batch(&[1]));
    queue.finish(&frozen.token, None).unwrap();
    let later = queue.prepare(&clock(3601)).unwrap().unwrap();
    assert_eq!(later.body, expected_batch(&[3, 4]));
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(4)));
    queue.finish(&later.token, Some(&ack(2))).unwrap();
    assert_eq!(queue.queued_payload_bytes(), Ok(0));
}

#[test]
fn singleton_quarantine_keeps_original_and_budget_until_expiry() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = SshQueue::open(queue_dir.path(), &identity, 3600, 1_000_000).unwrap();
    let mut original = event(1);
    original.resize(900_000, b' ');
    queue.enqueue(&position(1), &original, &clock(0)).unwrap();
    let first = queue.prepare(&clock(0)).unwrap().unwrap();
    assert_eq!(
        queue.reject(&first.token, SshRejection::Conflict),
        Ok(RejectionProgress::Quarantined)
    );
    assert_eq!(queue.quarantined_count(), Ok(1));
    assert_eq!(queue.queued_payload_bytes(), Ok(900_000));
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    assert_eq!(
        queue.enqueue(&position(2), &original, &clock(100)),
        Err("SSH_EVENT_CONFLICT")
    );
    let mut oversized = event(2);
    oversized.resize(200_000, b' ');
    assert_eq!(
        queue.enqueue(&position(2), &oversized, &clock(100)),
        Err("SSH_QUEUE_RESOURCE_LIMIT")
    );
    queue.enqueue(&position(2), &event(2), &clock(100)).unwrap();
    let good = queue.prepare(&clock(100)).unwrap().unwrap();
    assert_eq!(good.body, expected_batch(&[2]));
    queue.finish(&good.token, None).unwrap();
    drop(queue);

    let mut queue = SshQueue::open(queue_dir.path(), &identity, 3600, 1_000_000).unwrap();
    let stored: (Vec<u8>, String) = queue
        .connection
        .query_row(
            "SELECT body,quarantine_code FROM ssh_events WHERE event_id=?1",
            [event_id(1)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, (original, "CONFLICT".into()));
    assert_eq!(queue.quarantined_count(), Ok(1));
    let retry = queue.prepare(&clock(3601)).unwrap().unwrap();
    assert_eq!(retry.body, good.body);
    assert_eq!(queue.quarantined_count(), Ok(0));
    queue.finish(&retry.token, Some(&ack(1))).unwrap();
    assert_eq!(queue.queued_payload_bytes(), Ok(0));
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(2)));
}

#[test]
fn malformed_or_oversized_events_cannot_advance_checkpoint() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    let mut first = event(1);
    first.resize(MAX_REQUEST - PREFIX.len() - SUFFIX.len(), b' ');
    queue.enqueue(&position(1), &first, &clock(0)).unwrap();
    let exact = queue.prepare(&clock(0)).unwrap().unwrap();
    assert_eq!(exact.body.len(), MAX_REQUEST);
    let mut over_budget = event(2);
    over_budget.resize(975_000, b' ');
    assert_eq!(
        queue.enqueue(&position(2), &over_budget, &clock(0)),
        Err("SSH_QUEUE_RESOURCE_LIMIT")
    );
    first.push(b' ');
    assert_eq!(
        queue.enqueue(&position(2), &first, &clock(0)),
        Err("SSH_QUEUE_RESOURCE_LIMIT")
    );
    let object = String::from_utf8(event(2)).unwrap();
    for invalid in [
        object.replace(AT, "2026-10-31T23:59:60Z"),
        object.replace(AT, "2026-11-10 12:00:00Z"),
        object.replace("\"SSH_AUTH_FAILED\"", "{\"SSH_AUTH_FAILED\":null}"),
        object.replace(",\"username\":null", ""),
        object.replace("\"username\":null", "\"username\":null,\"username\":null"),
        object.replace("\"username\":null", "\"username\":\"bad\\u0000name\""),
        object.replace(
            "\"username\":null",
            "\"username\":null,\"rawLog\":\"unexpected\"",
        ),
        format!(
            r#"["{}","{BOOT}","{AT}","SSH_AUTH_FAILED",null,null]"#,
            event_id(2)
        ),
    ] {
        assert_eq!(
            queue.enqueue(&position(2), invalid.as_bytes(), &clock(0)),
            Err("INVALID_SSH_EVENT")
        );
    }
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    assert_eq!(
        queue.queued_payload_bytes().unwrap(),
        (MAX_REQUEST - PREFIX.len() - SUFFIX.len()) as u64
    );
}

#[test]
fn expiration_uses_monotonic_residence_and_preserves_source_checkpoint() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    queue
        .enqueue(&position(2), &event(2), &clock(3599))
        .unwrap();
    let frozen = queue.prepare(&clock(3600)).unwrap().unwrap();
    assert_eq!(frozen.event_count, 2);
    queue.finish(&frozen.token, None).unwrap();
    let rollback = QueueTime {
        unix_seconds: WALL - 30,
        ..clock(3601)
    };
    let reboot = QueueTime {
        boot_id: "90000000-0000-4000-8000-000000000002".into(),
        monotonic_ns: 1,
        unix_seconds: WALL - 1,
    };
    assert_eq!(
        queue.prepare(&reboot).err(),
        Some("SSH_QUEUE_CLOCK_UNCERTAIN")
    );
    assert_eq!(
        queue.prepare(&clock(3500)).err(),
        Some("SSH_QUEUE_CLOCK_UNCERTAIN")
    );
    let fresh = queue.prepare(&rollback).unwrap().unwrap();
    assert_eq!(fresh.body, [PREFIX, &event(2), SUFFIX].concat());
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(2)));
    assert_eq!(
        queue.finish(&frozen.token, Some(&ack(2))),
        Err("STALE_SSH_ATTEMPT")
    );
}

#[test]
fn observed_wall_rollback_blocks_cross_boot_replay_until_pending_events_drain() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    let rollback = QueueTime {
        unix_seconds: WALL - 1800,
        ..clock(1800)
    };
    let first = queue.prepare(&rollback).unwrap().unwrap();
    queue.finish(&first.token, None).unwrap();
    drop(queue);

    let mut queue = open(queue_dir.path(), &identity);
    let reboot = QueueTime {
        boot_id: "90000000-0000-4000-8000-000000000002".into(),
        monotonic_ns: 1,
        unix_seconds: WALL + 1,
    };
    assert_eq!(
        queue.prepare(&reboot).err(),
        Some("SSH_QUEUE_CLOCK_UNCERTAIN")
    );
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    let same_boot = QueueTime {
        unix_seconds: WALL + 2,
        ..clock(1801)
    };
    let again = queue.prepare(&same_boot).unwrap().unwrap();
    assert_eq!(again.body, first.body);
    queue.finish(&again.token, Some(&ack(1))).unwrap();
    assert!(queue.prepare(&reboot).unwrap().is_none());
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    assert_eq!(
        queue.enqueue(&position(2), &event(2), &reboot),
        Ok(Admission::Stored)
    );
}

#[test]
fn migration_preserves_v1_pending_batch_and_only_ages_it_on_original_boot() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    let batch = queue.prepare(&clock(1)).unwrap().unwrap();
    queue.finish(&batch.token, None).unwrap();
    // Recreate the v1 table shape in place, keeping the prior owner, inode,
    // record, source checkpoint, and frozen membership.
    recreate_pre_isolation_schema(&queue);
    queue
        .connection
        .execute_batch("ALTER TABLE queue_state DROP COLUMN wall_uncertain; PRAGMA user_version=1;")
        .unwrap();
    drop(queue);

    let mut queue = open(queue_dir.path(), &identity);
    let reboot = QueueTime {
        boot_id: "90000000-0000-4000-8000-000000000002".into(),
        monotonic_ns: 1,
        unix_seconds: WALL + 2,
    };
    assert_eq!(
        queue.prepare(&reboot).err(),
        Some("SSH_QUEUE_CLOCK_UNCERTAIN")
    );
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    let retry = queue.prepare(&clock(2)).unwrap().unwrap();
    assert_eq!(retry.body, batch.body);
    queue.finish(&retry.token, Some(&ack(1))).unwrap();
    assert!(queue.prepare(&reboot).unwrap().is_none());
}

#[test]
fn shared_migration_preserves_v2_wall_rollback_and_frozen_membership() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let host_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    let rollback = QueueTime {
        unix_seconds: WALL - 1,
        ..clock(1)
    };
    let first = queue.prepare(&rollback).unwrap().unwrap();
    queue.finish(&first.token, None).unwrap();
    queue.enqueue(&position(2), &event(2), &clock(2)).unwrap();
    recreate_pre_isolation_schema(&queue);
    drop(queue);

    let mut shared = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(2));
    let queue = &mut shared.ssh;
    let version: u32 = queue
        .connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    let reboot = QueueTime {
        boot_id: "90000000-0000-4000-8000-000000000002".into(),
        monotonic_ns: 1,
        unix_seconds: WALL + 3,
    };
    assert_eq!(
        queue.prepare(&reboot).err(),
        Some("SSH_QUEUE_CLOCK_UNCERTAIN")
    );
    let retry = queue.prepare(&clock(3)).unwrap().unwrap();
    assert_eq!(retry.body, first.body);
    queue.finish(&retry.token, Some(&ack(1))).unwrap();
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(2)));
    let later = queue.prepare(&clock(4)).unwrap().unwrap();
    assert_eq!(later.body, expected_batch(&[2]));
    queue.finish(&later.token, Some(&ack(1))).unwrap();
    assert_eq!(queue.quarantined_count(), Ok(0));
    assert!(shared.allocated_bytes().unwrap() <= 1_000_000);
}

#[test]
fn shared_migration_preserves_v3_quarantine_cursor_and_frozen_membership() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let host_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    let rejected = queue.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(
        queue.reject(&rejected.token, SshRejection::Invalid),
        Ok(RejectionProgress::Quarantined)
    );
    for id in [2, 3] {
        queue
            .enqueue(&position(id.into()), &event(id), &clock(2))
            .unwrap();
    }
    let original = queue.prepare(&clock(3)).unwrap().unwrap();
    assert_eq!(original.body, expected_batch(&[2, 3]));
    queue.finish(&original.token, None).unwrap();
    queue.enqueue(&position(4), &event(4), &clock(4)).unwrap();
    // Recreate v3 in place, preserving its owner, inode, and queue data.
    recreate_v4_source_schema(&queue);
    queue
        .connection
        .execute_batch(
            "ALTER TABLE queue_state DROP COLUMN capacity_discarded_count;
             PRAGMA user_version=3;",
        )
        .unwrap();
    drop(queue);

    let mut shared = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(5));
    let queue = &mut shared.ssh;
    let version: u32 = queue
        .connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    assert_eq!(queue.capacity_discarded_events_total(), Ok(0));
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(4)));
    assert_eq!(queue.quarantined_count(), Ok(1));
    let stored: (Vec<u8>, String) = queue
        .connection
        .query_row(
            "SELECT body,quarantine_code FROM ssh_events WHERE event_id=?1",
            [event_id(1)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, (event(1), "INVALID".into()));
    let retry = queue.prepare(&clock(5)).unwrap().unwrap();
    assert_eq!(retry.body, original.body);
    queue.finish(&retry.token, Some(&ack(2))).unwrap();
    let later = queue.prepare(&clock(6)).unwrap().unwrap();
    assert_eq!(later.body, expected_batch(&[4]));
}

#[test]
fn shared_migration_preserves_v4_checkpoint_event_and_capacity_count() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let host_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    let mut saved = position(1);
    saved.cursor = vec![7; MAX_CURSOR];
    queue.enqueue(&saved, &event(1), &clock(0)).unwrap();
    let frozen = queue.prepare(&clock(1)).unwrap().unwrap();
    queue.finish(&frozen.token, None).unwrap();
    queue
        .connection
        .execute("UPDATE queue_state SET capacity_discarded_count=13", [])
        .unwrap();
    recreate_v4_source_schema(&queue);
    let database = queue_dir.path().join(directory::DB);
    let inode = fs::metadata(&database).unwrap().ino();
    // Remove the fixture rebuild's spare pages and rehearse the migration
    // with no additional SQLite page available.
    queue.connection.execute_batch("VACUUM main").unwrap();
    let pages: u32 = queue
        .connection
        .pragma_query_one(None, "page_count")
        .unwrap();
    queue
        .connection
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let transaction = queue.connection.transaction().unwrap();
    migrate_source_checkpoints(&transaction, true).unwrap();
    assert_eq!(
        transaction
            .pragma_query_one::<u32>(None, "page_count")
            .unwrap(),
        pages
    );
    // Leave v4 in place for the real SharedBuffer open below.
    transaction.finish().unwrap();
    assert_eq!(
        queue
            .connection
            .pragma_query_one::<u32>(None, "user_version")
            .unwrap(),
        4
    );
    assert_eq!(
        queue.checkpoint(&saved.stream).unwrap(),
        Some(saved.clone())
    );
    assert_eq!(queue.capacity_discarded_events_total(), Ok(13));
    drop(queue);

    let mut shared = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(2));
    assert_eq!(fs::metadata(database).unwrap().ino(), inode);
    assert_eq!(shared.ssh.capacity_discarded_events_total(), Ok(13));
    assert_eq!(
        shared.ssh.checkpoint(&saved.stream).unwrap(),
        Some(saved.clone())
    );
    assert_eq!(
        shared.ssh.enqueue(&saved, &event(1), &clock(2)),
        Ok(Admission::AlreadyCheckpointed)
    );
    assert!(shared.ssh_source_counters().unwrap().is_complete());
    assert_eq!(
        shared.ssh.prepare(&clock(2)).unwrap().unwrap().body,
        frozen.body
    );
}

fn recreate_v6_source_schema(queue: &SshQueue) {
    queue
        .connection
        .execute_batch(
            "ALTER TABLE source_checkpoints DROP COLUMN gap_recovered_at;
             ALTER TABLE source_checkpoints DROP COLUMN gap_detected_at;
             ALTER TABLE source_checkpoints DROP COLUMN gap_reason;
             ALTER TABLE source_checkpoints DROP COLUMN source_witness;
             PRAGMA user_version=6;",
        )
        .unwrap();
}

#[test]
fn shared_migration_preserves_v5_checkpoint_and_adds_read_observation() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let host_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut buffer = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(0));
    let saved = position(1);
    buffer
        .commit_source_disposition(&saved, SourceDisposition::UnknownFormat)
        .unwrap();
    recreate_v6_source_schema(&buffer.ssh);
    buffer
        .ssh
        .connection
        .execute_batch(
            "ALTER TABLE source_checkpoints DROP COLUMN last_read_at; PRAGMA user_version=5;",
        )
        .unwrap();
    drop(buffer);

    let mut buffer = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(0));
    assert_eq!(
        buffer.ssh.checkpoint(&saved.stream).unwrap(),
        Some(saved.clone())
    );
    assert_eq!(
        buffer
            .ssh_source_counters()
            .unwrap()
            .unknown_format_records_total,
        Some(1)
    );
    assert_eq!(buffer.ssh.source_read_at(&saved.stream), Ok(None));
    buffer.ssh.record_source_read(&saved, WALL).unwrap();
    assert_eq!(buffer.ssh.source_read_at(&saved.stream), Ok(Some(WALL)));
    assert_eq!(
        buffer.ssh.record_source_read(&position(2), WALL + 1),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    buffer
        .commit_source_disposition(&position(2), SourceDisposition::Ignored)
        .unwrap();
    assert_eq!(buffer.ssh.source_read_at(&saved.stream), Ok(None));
}

#[test]
fn shared_v6_checkpoint_recovery_is_atomic_and_preserves_gap_after_restart() {
    use crate::protocol::SshGapReason;

    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let host_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut buffer = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(0));
    let (saved, rebased, unconfirmed) = (position(1), position(2), position(3));
    let stream = &saved.stream;
    let reason = SshGapReason::FileTruncation;
    assert_eq!(
        buffer.ssh.enqueue(&saved, &event(1), &clock(0)),
        Ok(Admission::Stored)
    );
    let attempt = buffer.ssh.prepare(&clock(0)).unwrap().unwrap();
    buffer.ssh.finish(&attempt.token, Some(&ack(1))).unwrap();
    buffer.ssh.record_source_read(&saved, WALL).unwrap();
    recreate_v6_source_schema(&buffer.ssh);
    drop(buffer);

    let mut buffer = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(1));
    assert_eq!(buffer.ssh.source_read_at(stream), Ok(Some(WALL)));
    assert_eq!(
        buffer.ssh.source_recovery(stream),
        Ok(SourceRecovery::default())
    );
    assert_eq!(
        buffer
            .ssh
            .record_source_witness(&saved, &vec![0; MAX_CURSOR + 1]),
        Err("INVALID_SSH_SOURCE_POSITION")
    );
    let wrong_cursor = SourcePosition {
        cursor: vec![1],
        ..saved.clone()
    };
    assert_eq!(
        buffer.ssh.record_source_witness(&wrong_cursor, b"unread"),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    buffer.ssh.record_source_witness(&saved, b"unread").unwrap();
    buffer
        .ssh
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER reject_rebase BEFORE UPDATE OF gap_reason ON source_checkpoints
         BEGIN SELECT RAISE(ABORT, 'rebase rejected'); END;",
        )
        .unwrap();
    assert!(
        buffer
            .ssh
            .rebase_source(&saved, &rebased, WALL + 1, Some(reason))
            .is_err()
    );
    assert_eq!(buffer.ssh.checkpoint(stream), Ok(Some(saved.clone())));
    assert_eq!(
        buffer.ssh.source_recovery(stream),
        Ok(SourceRecovery {
            witness: Some(b"unread".to_vec()),
            gap: None
        })
    );
    buffer
        .ssh
        .connection
        .execute_batch("DROP TRIGGER reject_rebase;")
        .unwrap();
    buffer
        .ssh
        .rebase_source(&saved, &rebased, WALL + 1, Some(reason))
        .unwrap();
    assert_eq!(buffer.ssh.checkpoint(stream), Ok(Some(rebased.clone())));
    assert_eq!(buffer.ssh.source_read_at(stream), Ok(Some(WALL)));
    assert_eq!(
        buffer.ssh.rebase_source(&saved, &rebased, WALL + 2, None),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    assert_eq!(
        buffer.ssh.enqueue(&unconfirmed, &event(1), &clock(2)),
        Err("SSH_EVENT_CONFLICT")
    );
    let mut gap = SourceGap {
        reason,
        detected_at: WALL + 1,
        recovered_at: None,
    };
    assert_eq!(
        buffer.ssh.source_recovery(stream),
        Ok(SourceRecovery {
            witness: None,
            gap: Some(gap)
        })
    );
    buffer.ssh.record_source_read(&rebased, WALL + 2).unwrap();
    gap.recovered_at = Some(WALL + 2);
    buffer.ssh.record_source_read(&rebased, WALL + 3).unwrap();
    buffer
        .ssh
        .rebase_source(&rebased, &unconfirmed, WALL + 4, None)
        .unwrap();
    buffer
        .ssh
        .record_source_witness(&unconfirmed, b"next unread")
        .unwrap();
    buffer
        .commit_source_disposition(&position(4), SourceDisposition::Ignored)
        .unwrap();
    drop(buffer);

    let mut buffer = open_shared(host_dir.path(), queue_dir.path(), &identity, &clock(5));
    assert_eq!(buffer.ssh.checkpoint(stream), Ok(Some(position(4))));
    assert_eq!(
        buffer.ssh.source_recovery(stream),
        Ok(SourceRecovery {
            witness: None,
            gap: Some(gap)
        })
    );
    assert!(buffer.ssh.prepare(&clock(5)).unwrap().is_none());
}

#[test]
fn first_creation_write_failure_leaves_empty_directory_and_can_retry() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    drop(bound(identity_dir.path()));
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "buffer::tests::creation_write_limit_child"])
        .env("NODOMI_TEST_LIMIT_SSH_IDENTITY", identity_dir.path())
        .env("NODOMI_TEST_LIMIT_SSH_QUEUE", queue_dir.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "fixture child failed: {}",
        String::from_utf8_lossy(&child.stdout)
    );
    assert_eq!(fs::read_dir(queue_dir.path()).unwrap().count(), 0);
    let identity = IdentityStore::open(identity_dir.path(), &target()).unwrap();
    assert_eq!(
        open(queue_dir.path(), &identity).queued_payload_bytes(),
        Ok(0)
    );
    let orphan = private_dir();
    let path = orphan.path().join("ssh-buffer.sqlite3");
    fs::write(&path, b"preexisting state").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(SshQueue::open(orphan.path(), &identity, 3600, 1_000_000).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preexisting state");
}

#[test]
fn creation_write_limit_child() {
    let Ok(identity_dir) = std::env::var("NODOMI_TEST_LIMIT_SSH_IDENTITY") else {
        return;
    };
    let queue_dir = std::env::var("NODOMI_TEST_LIMIT_SSH_QUEUE").unwrap();
    let identity = IdentityStore::open(Path::new(&identity_dir), &target()).unwrap();
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: Only this fixture child changes its file size limit and signal
    // handler. The initialized rlimit is writable and valid for both calls.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit), 0);
        assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
        limit.rlim_cur = 0;
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
    assert_eq!(
        SshQueue::open(Path::new(&queue_dir), &identity, 3600, 1_000_000).err(),
        Some("SSH_QUEUE_STORAGE_ERROR")
    );
}

#[test]
fn rejected_directory_paths_and_foreign_binding_preserve_files() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let alias_dir = private_dir();
    let alias = alias_dir.path().join("link");
    symlink(queue_dir.path(), &alias).unwrap();
    assert!(SshQueue::preflight(&alias, &identity).is_err());
    assert!(SshQueue::preflight(identity_dir.path(), &identity).is_err());
    assert_eq!(fs::read_dir(identity_dir.path()).unwrap().count(), 2);
    assert_eq!(fs::read_dir(queue_dir.path()).unwrap().count(), 0);
    let foreign = private_dir();
    let second = bound(foreign.path());
    let queue = open(queue_dir.path(), &identity);
    assert!(queue.check_identity(&second).is_err());
    assert_eq!(
        SshQueue::preflight(queue_dir.path(), &identity).err(),
        Some("SSH_QUEUE_LOCKED")
    );
    drop(queue);
    let files = || -> Vec<_> {
        let mut files = fs::read_dir(queue_dir.path())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let metadata = fs::metadata(&path).unwrap();
                assert_eq!(metadata.mode() & 0o777, 0o600);
                let bytes = fs::read(&path).unwrap();
                assert!(!bytes.windows(5).any(|w| w == b"ndma_"));
                (path, metadata.mtime(), metadata.ctime(), bytes)
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    };
    let before = files();
    assert_eq!(
        SshQueue::preflight(queue_dir.path(), &second).err(),
        Some("SSH_QUEUE_BINDING_MISMATCH")
    );
    assert_eq!(
        SshQueue::open(queue_dir.path(), &second, 3600, 1_000_000).err(),
        Some("SSH_QUEUE_BINDING_MISMATCH")
    );
    assert_eq!(before, files());
}

#[test]
fn sqlite_engine_and_durability_are_verified() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let queue = open(queue_dir.path(), &identity);
    let (version, source, journal, sync): (String, String, String, i64) = queue.connection.query_row(
        "SELECT sqlite_version(), sqlite_source_id(), journal_mode, synchronous FROM pragma_journal_mode, pragma_synchronous",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    let mut statement = queue.connection.prepare("PRAGMA compile_options").unwrap();
    let options = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        (&*version, &*source, &*journal, sync),
        ("3.54.1", SQLITE_SOURCE_ID, "delete", 3)
    );
    println!("SQLite {version}, {source}, journal={journal}, synchronous={sync}; {options:?}");
}

#[test]
fn sqlite_rollback_restores_previous_checkpoint_and_payload() {
    let identity_dir = private_dir();
    let queue_dir = private_dir();
    let identity = bound(identity_dir.path());
    let mut queue = open(queue_dir.path(), &identity);
    queue.enqueue(&position(1), &event(1), &clock(0)).unwrap();
    drop(queue);
    drop(identity);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "buffer::tests::interrupt_sqlite_write_child"])
        .env("NODOMI_TEST_SSH_IDENTITY", identity_dir.path())
        .env("NODOMI_TEST_SSH_QUEUE", queue_dir.path())
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(73));
    assert!(
        queue_dir
            .path()
            .join("ssh-buffer.sqlite3-journal")
            .is_file()
    );
    let identity = IdentityStore::open(identity_dir.path(), &target()).unwrap();
    let mut queue = open(queue_dir.path(), &identity);
    assert_eq!(queue.checkpoint("journal.1").unwrap(), Some(position(1)));
    assert_eq!(queue.queued_payload_bytes(), Ok(event(1).len() as u64));
    assert_eq!(
        queue.prepare(&clock(1)).unwrap().unwrap().body,
        [PREFIX, &event(1), SUFFIX].concat()
    );
}

#[test]
fn interrupt_sqlite_write_child() {
    let Ok(identity_dir) = std::env::var("NODOMI_TEST_SSH_IDENTITY") else {
        return;
    };
    let queue_dir = std::env::var("NODOMI_TEST_SSH_QUEUE").unwrap();
    let identity = IdentityStore::open(Path::new(&identity_dir), &target()).unwrap();
    let mut queue = open(Path::new(&queue_dir), &identity);
    queue
        .connection
        .pragma_update(None, "cache_size", 8)
        .unwrap();
    let transaction = queue.connection.transaction().unwrap();
    transaction
        .execute(
            "UPDATE source_checkpoints SET sequence=2 WHERE stream='journal.1'",
            [],
        )
        .unwrap();
    let mut body = event(2);
    body.resize(900_000, b' ');
    transaction
        .execute(
            "INSERT INTO ssh_events(event_id,admitted_ns,body) VALUES(?1,1,?2)",
            params![event_id(2), body],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE queue_state SET payload_bytes=900000 WHERE singleton=1",
            [],
        )
        .unwrap();
    // Exit without dropping the SQLite transaction or connection. The parent
    // verifies the durable journal is recovered before it reads the queue.
    std::process::exit(73);
}
