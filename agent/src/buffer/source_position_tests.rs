use super::*;

const EPOCH: &str = "90000000-0000-4000-8000-000000000020";
const NEXT_EPOCH: &str = "90000000-0000-4000-8000-000000000021";

struct Fixture {
    identity: IdentityStore,
    _identity_dir: tempfile::TempDir,
    host: tempfile::TempDir,
    ssh: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let identity_dir = private_dir();
        Self {
            identity: bound(identity_dir.path()),
            _identity_dir: identity_dir,
            host: private_dir(),
            ssh: private_dir(),
        }
    }

    fn open(&self) -> SharedBuffer {
        open_shared(self.host.path(), self.ssh.path(), &self.identity, &clock(0))
    }

    fn recover(&self, epoch: &str) -> SharedBuffer {
        SharedBuffer::recover(
            SharedBufferPaths {
                host: self.host.path(),
                ssh: self.ssh.path(),
            },
            &self.identity,
            epoch,
        )
        .unwrap()
    }
}

fn assert_counts(buffer: &SharedBuffer, unknown: Option<u64>, oversized: Option<u64>) {
    let counters = buffer.ssh_source_counters().unwrap();
    assert_eq!(counters.unknown_format_records_total, unknown);
    assert_eq!(counters.oversized_records_total, oversized);
    assert_eq!(
        counters.is_complete(),
        unknown.is_some() && oversized.is_some()
    );
}

#[test]
fn dispositions_and_events_share_one_checkpoint_without_fabricating_events() {
    use SourceDisposition::{Ignored, Oversized, UnknownFormat};

    let fixture = Fixture::new();
    let mut buffer = fixture.open();
    assert_eq!(
        buffer.commit_source_disposition(&position(1), Ignored),
        Ok(Admission::Stored)
    );
    assert_eq!(
        buffer.commit_source_disposition(&position(1), Ignored),
        Ok(Admission::AlreadyCheckpointed)
    );
    assert_eq!(
        buffer.commit_source_disposition(&position(1), UnknownFormat),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    assert_eq!(
        buffer.ssh.enqueue(&position(1), &event(1), &clock(0)),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    assert!(buffer.ssh.prepare(&clock(0)).unwrap().is_none());
    assert_counts(&buffer, Some(0), Some(0));

    assert_eq!(
        buffer.ssh.enqueue(&position(2), &event(2), &clock(0)),
        Ok(Admission::Stored)
    );
    assert_eq!(
        buffer.commit_source_disposition(&position(2), Ignored),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    let batch = buffer.ssh.prepare(&clock(0)).unwrap().unwrap();
    assert_eq!(batch.body, expected_batch(&[2]));
    buffer.ssh.finish(&batch.token, Some(&ack(1))).unwrap();

    assert_eq!(
        buffer.commit_source_disposition(&position(3), UnknownFormat),
        Ok(Admission::Stored)
    );
    assert_eq!(
        buffer.commit_source_disposition(&position(1), Ignored),
        Err("SSH_SOURCE_POSITION_STALE")
    );
    assert_eq!(
        buffer.commit_source_disposition(
            &SourcePosition {
                cursor: position(3).cursor,
                ..position(4)
            },
            Oversized,
        ),
        Err("SSH_SOURCE_POSITION_CONFLICT")
    );
    assert_eq!(
        buffer.ssh.enqueue(&position(4), &event(2), &clock(0)),
        Err("SSH_EVENT_CONFLICT")
    );
    assert_eq!(
        buffer.ssh.checkpoint("journal.1").unwrap(),
        Some(position(3))
    );
    assert_counts(&buffer, Some(1), Some(0));
    assert!(buffer.ssh.prepare(&clock(0)).unwrap().is_none());
}

#[test]
fn event_and_disposition_streams_share_the_checkpoint_limit() {
    let fixture = Fixture::new();
    let mut buffer = fixture.open();
    let stream_position = |stream| SourcePosition {
        stream: format!("journal.test.{stream}"),
        ..position(1)
    };
    for stream in 0..32 {
        assert_eq!(
            buffer
                .ssh
                .enqueue(&stream_position(stream), &event(stream + 1), &clock(0)),
            Ok(Admission::Stored)
        );
    }
    for stream in 32..64 {
        assert_eq!(
            buffer.commit_source_disposition(&stream_position(stream), SourceDisposition::Ignored),
            Ok(Admission::Stored)
        );
    }
    let extra = stream_position(64);
    assert_eq!(
        buffer.commit_source_disposition(&extra, SourceDisposition::Oversized),
        Err("SSH_QUEUE_RESOURCE_LIMIT")
    );
    assert_eq!(
        buffer.ssh.enqueue(&extra, &event(65), &clock(0)),
        Err("SSH_QUEUE_RESOURCE_LIMIT")
    );
    assert_eq!(buffer.ssh.checkpoint(&extra.stream), Ok(None));
    assert_counts(&buffer, Some(0), Some(0));
}

#[test]
fn source_counts_survive_same_epoch_reopen_without_recounting_old_replays() {
    use SourceDisposition::{Oversized, UnknownFormat};

    let fixture = Fixture::new();
    let mut buffer = fixture.open();
    buffer
        .commit_source_disposition(&position(1), UnknownFormat)
        .unwrap();
    buffer
        .commit_source_disposition(&position(2), Oversized)
        .unwrap();
    drop(buffer);

    let mut buffer = fixture.recover(EPOCH);
    assert_counts(&buffer, Some(1), Some(1));
    assert_eq!(
        buffer.commit_source_disposition(&position(2), Oversized),
        Ok(Admission::AlreadyCheckpointed)
    );
    assert_counts(&buffer, Some(1), Some(1));
    drop(buffer);

    let mut buffer = fixture.recover(NEXT_EPOCH);
    assert_eq!(
        buffer.ssh.checkpoint("journal.1").unwrap(),
        Some(position(2))
    );
    assert_counts(&buffer, Some(0), Some(0));
    assert_eq!(
        buffer.commit_source_disposition(&position(2), Oversized),
        Ok(Admission::AlreadyCheckpointed)
    );
    assert_counts(&buffer, Some(0), Some(0));
    buffer
        .commit_source_disposition(&position(3), Oversized)
        .unwrap();
    drop(buffer);

    let buffer = fixture.recover(NEXT_EPOCH);
    assert_eq!(
        buffer.ssh.checkpoint("journal.1").unwrap(),
        Some(position(3))
    );
    assert_counts(&buffer, Some(0), Some(1));
}

#[test]
fn failed_disposition_mutation_preserves_the_previous_checkpoint_and_epoch_counts() {
    use SourceDisposition::{Oversized, UnknownFormat};

    let fixture = Fixture::new();
    let mut buffer = fixture.open();
    buffer
        .commit_source_disposition(&position(1), UnknownFormat)
        .unwrap();
    drop(buffer);

    let mut buffer = fixture.recover(NEXT_EPOCH);
    // Exercise both statements so one failure necessarily follows the other
    // staged write, regardless of whether the implementation updates the
    // checkpoint or the counter first.
    for table in ["source_checkpoints", "queue_state"] {
        buffer
            .ssh
            .connection
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER fail_insert BEFORE INSERT ON {table}
                   BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;
                 CREATE TEMP TRIGGER fail_update BEFORE UPDATE ON {table}
                   BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;"
            ))
            .unwrap();
        assert!(
            buffer
                .commit_source_disposition(&position(2), Oversized)
                .is_err()
        );
        buffer
            .ssh
            .connection
            .execute_batch("DROP TRIGGER fail_insert; DROP TRIGGER fail_update;")
            .unwrap();
        assert_eq!(
            buffer.ssh.checkpoint("journal.1").unwrap(),
            Some(position(1))
        );
        assert_counts(&buffer, Some(0), Some(0));
    }
    drop(buffer);

    let mut buffer = fixture.recover(EPOCH);
    assert_counts(&buffer, Some(1), Some(0));
    assert_eq!(
        buffer.ssh.checkpoint("journal.1").unwrap(),
        Some(position(1))
    );
    assert_eq!(
        buffer.commit_source_disposition(&position(2), Oversized),
        Ok(Admission::Stored)
    );
    assert_counts(&buffer, Some(1), Some(1));
}

#[test]
fn source_count_overflow_becomes_unknown_only_for_the_affected_counter() {
    use SourceDisposition::{Oversized, UnknownFormat};

    let fixture = Fixture::new();
    let mut buffer = fixture.open();
    buffer
        .commit_source_disposition(&position(1), UnknownFormat)
        .unwrap();
    let max = u64::MAX.to_be_bytes();
    assert_eq!(
        buffer
            .ssh
            .connection
            .execute(
                "UPDATE queue_state SET unknown_format_records_total=?1 WHERE source_counter_epoch=?2",
                params![max.as_slice(), EPOCH],
            )
            .unwrap(),
        1
    );
    assert_counts(&buffer, Some(u64::MAX), Some(0));
    assert_eq!(
        buffer.commit_source_disposition(&position(2), UnknownFormat),
        Ok(Admission::Stored)
    );
    buffer
        .commit_source_disposition(&position(3), UnknownFormat)
        .unwrap();
    buffer
        .commit_source_disposition(&position(4), Oversized)
        .unwrap();
    drop(buffer);

    let buffer = fixture.recover(EPOCH);
    assert_eq!(
        buffer.ssh.checkpoint("journal.1").unwrap(),
        Some(position(4))
    );
    assert_counts(&buffer, None, Some(1));
}

#[test]
fn process_exit_recovers_checkpoint_and_counters_as_one_commit() {
    let mut fixture = Fixture::new();
    let mut buffer = fixture.open();
    buffer
        .commit_source_disposition(&position(1), SourceDisposition::UnknownFormat)
        .unwrap();
    drop(buffer);

    for (phase, exit_code, committed) in [("staged", 79, false), ("committed", 80, true)] {
        let Fixture {
            identity,
            _identity_dir: identity_dir,
            host,
            ssh,
        } = fixture;
        drop(identity);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "buffer::tests::source_position_tests::source_disposition_exit_child",
            ])
            .env("NODOMI_TEST_SOURCE_EXIT_PHASE", phase)
            .env("NODOMI_TEST_SOURCE_EXIT_IDENTITY", identity_dir.path())
            .env("NODOMI_TEST_SOURCE_EXIT_HOST", host.path())
            .env("NODOMI_TEST_SOURCE_EXIT_SSH", ssh.path())
            .output()
            .unwrap();
        assert_eq!(
            child.status.code(),
            Some(exit_code),
            "{phase}: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        fixture = Fixture {
            identity: IdentityStore::open(identity_dir.path(), &target()).unwrap(),
            _identity_dir: identity_dir,
            host,
            ssh,
        };
        if committed {
            let mut buffer = fixture.recover(NEXT_EPOCH);
            assert_eq!(
                buffer.ssh.checkpoint("journal.1").unwrap(),
                Some(position(2))
            );
            assert_counts(&buffer, Some(0), Some(1));
            assert_eq!(
                buffer.commit_source_disposition(&position(2), SourceDisposition::Oversized),
                Ok(Admission::AlreadyCheckpointed)
            );
            assert_counts(&buffer, Some(0), Some(1));
        } else {
            let buffer = fixture.recover(EPOCH);
            assert_eq!(
                buffer.ssh.checkpoint("journal.1").unwrap(),
                Some(position(1))
            );
            assert_counts(&buffer, Some(1), Some(0));
        }
    }
}

fn exit_before_source_commit() {
    // SAFETY: This fixture child intentionally exits without running destructors.
    unsafe { libc::_exit(79) }
}

#[test]
#[ignore = "spawned by process_exit_recovers_checkpoint_and_counters_as_one_commit"]
fn source_disposition_exit_child() {
    let path = |name: &str| std::path::PathBuf::from(std::env::var_os(name).unwrap());
    let identity =
        IdentityStore::open(&path("NODOMI_TEST_SOURCE_EXIT_IDENTITY"), &target()).unwrap();
    let mut buffer = SharedBuffer::recover(
        SharedBufferPaths {
            host: &path("NODOMI_TEST_SOURCE_EXIT_HOST"),
            ssh: &path("NODOMI_TEST_SOURCE_EXIT_SSH"),
        },
        &identity,
        NEXT_EPOCH,
    )
    .unwrap();
    if std::env::var("NODOMI_TEST_SOURCE_EXIT_PHASE").as_deref() == Ok("staged") {
        super::super::source_position::BEFORE_SOURCE_COMMIT
            .with(|hook| hook.set(Some(exit_before_source_commit)));
        buffer
            .commit_source_disposition(&position(2), SourceDisposition::Oversized)
            .unwrap();
        panic!("disposition returned before the exit hook");
    }
    buffer
        .commit_source_disposition(&position(2), SourceDisposition::Oversized)
        .unwrap();
    // SAFETY: The commit has returned and the fixture child must exit abruptly.
    unsafe { libc::_exit(80) }
}
