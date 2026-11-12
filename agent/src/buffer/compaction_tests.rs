use super::{
    Admission, Fixture, MIN_BYTES, RejectionProgress, SharedBuffer, SourcePosition, SshQueue,
    SshRejection, StoredSample, ack, batch, clock, configuration, database_pages, event, position,
    sample,
};
use crate::buffer::directory::{DB, OWNER};
use rusqlite::types::Value;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{fs, os::unix::fs::MetadataExt};

const ROOMY_BYTES: u64 = 4_000_000;

type QueueRows = [Vec<Vec<Value>>; 3];

struct Fragmented {
    buffer: SharedBuffer,
    host: StoredSample,
    frozen: Vec<u8>,
    position: SourcePosition,
}

fn rows(queue: &SshQueue) -> QueueRows {
    [
        "SELECT * FROM queue_state ORDER BY singleton",
        "SELECT * FROM source_checkpoints ORDER BY stream",
        "SELECT * FROM ssh_events ORDER BY id",
    ]
    .map(|sql| {
        let mut statement = queue.connection.prepare(sql).unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    })
}

fn fragmented(fixture: &Fixture, grow: bool) -> Fragmented {
    let mut buffer = fixture.open(MIN_BYTES, 1);
    let host = sample(1, 8_192);
    buffer.host.admit(host.clone()).unwrap();
    buffer
        .ssh
        .enqueue(&position(1), &event(1, 32_000), &clock(1))
        .unwrap();
    let protected = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(protected.event_count, 1);
    for sequence in 2..=24 {
        assert_eq!(
            buffer
                .ssh
                .enqueue(&position(sequence), &event(sequence, 32_000), &clock(1)),
            Ok(Admission::Stored)
        );
    }
    assert!(buffer.ssh.capacity_discarded_events_total().unwrap() > 0);
    assert_eq!(
        buffer.ssh.reject(&protected.token, SshRejection::Invalid),
        Ok(RejectionProgress::Quarantined)
    );
    let last_drained = if grow {
        let mut larger = configuration(ROOMY_BYTES);
        larger.target.config_id = "90000000-0000-4000-8000-000000000031".into();
        larger.target.generation = 2;
        buffer.apply_configuration(&larger).unwrap();
        for sequence in 25..=56 {
            buffer
                .ssh
                .enqueue(&position(sequence), &event(sequence, 32_000), &clock(1))
                .unwrap();
        }
        56
    } else {
        24
    };
    while let Some(attempt) = buffer.ssh.prepare(&clock(1)).unwrap() {
        buffer
            .ssh
            .finish(&attempt.token, Some(&ack(attempt.event_count)))
            .unwrap();
    }
    assert_eq!(buffer.ssh.quarantined_count(), Ok(1));
    assert_eq!(buffer.ssh.queued_payload_bytes(), Ok(32_000));

    let last = last_drained + 2;
    let pending = [event(last - 1, 32_000), event(last, 32_000)];
    for (sequence, body) in (last - 1..=last).zip(&pending) {
        buffer
            .ssh
            .enqueue(&position(sequence), body, &clock(1))
            .unwrap();
    }
    let frozen = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(frozen.body, batch(&pending));
    buffer.ssh.finish(&frozen.token, None).unwrap();
    Fragmented {
        buffer,
        host,
        frozen: frozen.body,
        position: position(last),
    }
}

fn db_path(fixture: &Fixture) -> std::path::PathBuf {
    fixture.cache_root.path().join("ssh").join(DB)
}

#[cfg(target_os = "linux")]
fn allocated(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().blocks() * 512
}

#[test]
fn compaction_releases_space_for_shrink_and_preserves_live_ack() {
    let fixture = Fixture::new(None);
    let Fragmented {
        mut buffer,
        host,
        frozen,
        position: checkpoint,
    } = fragmented(&fixture, true);
    let active = buffer.ssh.prepare(&clock(1)).unwrap().unwrap();
    assert_eq!(active.body, frozen);
    let before = rows(&buffer.ssh);
    let pages_before = database_pages(&buffer.ssh);
    let before_configuration = buffer.host.configuration().unwrap().clone();
    let database = db_path(&fixture);
    let metadata = fs::symlink_metadata(&database).unwrap();
    let marker = database.with_file_name(OWNER);
    let before_owner = fs::read(&marker).unwrap();
    let shared_before = fixture.assert_allocation(&buffer, ROOMY_BYTES);
    assert!(shared_before > MIN_BYTES);

    let mut smaller = configuration(MIN_BYTES);
    smaller.target.config_id = "90000000-0000-4000-8000-000000000032".into();
    smaller.target.generation = 3;
    assert_eq!(buffer.apply_configuration(&smaller), Err("RESOURCE_LIMIT"));

    let report = buffer
        .compact_ssh()
        .unwrap()
        .expect("fragmented main file shrinks");
    let after = fs::symlink_metadata(&database).unwrap();
    assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
    assert_eq!(fs::read(marker).unwrap(), before_owner);
    assert_eq!(report.allocated_bytes_before, metadata.blocks() * 512);
    assert_eq!(report.allocated_bytes_after, after.blocks() * 512);
    assert!(report.allocated_bytes_after < report.allocated_bytes_before);
    assert!(database_pages(&buffer.ssh) < pages_before);
    assert_eq!(rows(&buffer.ssh), before);
    assert_eq!(buffer.host.configuration(), Some(&before_configuration));
    let shared_after = buffer.allocated_bytes().unwrap();
    assert!(shared_after < MIN_BYTES);
    assert_eq!(buffer.compact_ssh(), Ok(None));
    assert_eq!(buffer.allocated_bytes(), Ok(shared_after));
    println!(
        "SSH main allocated {} -> {} bytes, shared {shared_before} -> {shared_after} bytes",
        report.allocated_bytes_before, report.allocated_bytes_after
    );

    buffer.apply_configuration(&smaller).unwrap();
    buffer
        .ssh
        .finish(&active.token, Some(&ack(active.event_count)))
        .unwrap();
    assert!(buffer.ssh.prepare(&clock(1)).unwrap().is_none());
    let discard_count = buffer.ssh.capacity_discarded_events_total().unwrap();
    let confirmed = rows(&buffer.ssh);
    drop(buffer);

    let mut recovered = fixture.recover();
    assert_eq!(recovered.host.configuration(), Some(&smaller));
    assert_eq!(rows(&recovered.ssh), confirmed);
    assert_eq!(
        recovered.ssh.checkpoint(super::STREAM).unwrap(),
        Some(checkpoint)
    );
    assert_eq!(
        recovered.ssh.capacity_discarded_events_total(),
        Ok(discard_count)
    );
    assert_eq!(recovered.ssh.quarantined_count(), Ok(1));
    assert_eq!(
        recovered
            .host
            .begin(super::BOOT, clock(1).monotonic_ns)
            .unwrap(),
        Some(host)
    );
}

#[cfg(target_os = "linux")]
fn fill_tmpfs(path: &Path) -> u64 {
    use std::io::Write;

    let mut file = fs::File::create(path).unwrap();
    let error = (0..=256)
        .find_map(|_| file.write_all(&[0; 4096]).err())
        .expect("the isolated 1 MiB tmpfs must fill");
    assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    file.metadata().unwrap().blocks() * 512
}

#[cfg(target_os = "linux")]
fn tmpfs_fixture() -> Fixture {
    let parent = std::env::var_os("NODOMI_SHARED_ENOSPC_DIR")
        .expect("set NODOMI_SHARED_ENOSPC_DIR to a dedicated 1 MiB tmpfs");
    Fixture::new(Some(Path::new(&parent)))
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a dedicated 1 MiB tmpfs in NODOMI_SHARED_ENOSPC_DIR"]
fn compaction_space_preflight_leaves_both_stores_usable() {
    let fixture = tmpfs_fixture();
    let Fragmented { mut buffer, .. } = fragmented(&fixture, false);
    let database = db_path(&fixture);
    let before_bytes = allocated(&database);
    let before = rows(&buffer.ssh);
    let filler = fixture.cache_root.path().join("filler");
    let filled = fill_tmpfs(&filler);
    assert_eq!(buffer.compact_ssh().err(), Some("RESOURCE_LIMIT"));
    assert!(buffer.safely_reportable());
    assert_eq!(rows(&buffer.ssh), before);
    assert_eq!(allocated(&database), before_bytes);
    assert!(
        !database
            .with_file_name(crate::buffer::directory::JOURNAL)
            .exists()
    );
    fs::remove_file(filler).unwrap();
    assert!(buffer.compact_ssh().unwrap().is_some());
    assert_eq!(rows(&buffer.ssh), before);
    println!("compaction preflight refused with {filled} filler bytes on 1 MiB tmpfs");
}

#[cfg(target_os = "linux")]
thread_local! {
    static COMPACTION_FILLER: std::cell::RefCell<Option<std::path::PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(target_os = "linux")]
fn fill_after_preflight() {
    let path = COMPACTION_FILLER.with(|path| path.take()).unwrap();
    println!(
        "actual tmpfs ENOSPC after compaction preflight, filler bytes {}",
        fill_tmpfs(&path)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a dedicated 1 MiB tmpfs in NODOMI_SHARED_ENOSPC_DIR"]
fn compaction_kernel_enospc_after_preflight_fences_and_recovers() {
    let fixture = tmpfs_fixture();
    let Fragmented {
        mut buffer,
        host,
        frozen,
        position: checkpoint,
    } = fragmented(&fixture, false);
    let before = rows(&buffer.ssh);
    let filler = fixture.cache_root.path().join("filler");
    assert!(COMPACTION_FILLER.with(|path| path.replace(Some(filler.clone())).is_none()));
    crate::buffer::BEFORE_COMPACTION.with(|hook| hook.set(Some(fill_after_preflight)));
    assert_eq!(
        buffer.compact_ssh().err(),
        Some("SSH_QUEUE_RECOVERY_REQUIRED")
    );
    assert!(COMPACTION_FILLER.with(|path| path.borrow().is_none()));
    assert!(!buffer.safely_reportable());
    assert_eq!(buffer.allocated_bytes(), Err("BUFFER_RECOVERY_REQUIRED"));
    assert_eq!(
        buffer.host.admit(sample(2, 8_192)),
        Err("BUFFER_RECOVERY_REQUIRED")
    );
    assert_eq!(
        buffer.ssh.prepare(&clock(1)).err(),
        Some("SSH_QUEUE_RECOVERY_REQUIRED")
    );
    fs::remove_file(filler).unwrap();
    drop(buffer);

    let mut recovered = fixture.recover();
    assert_eq!(rows(&recovered.ssh), before);
    assert_eq!(
        recovered.ssh.checkpoint(super::STREAM).unwrap(),
        Some(checkpoint)
    );
    assert_eq!(
        recovered.ssh.prepare(&clock(1)).unwrap().unwrap().body,
        frozen
    );
    assert_eq!(
        recovered
            .host
            .begin(super::BOOT, clock(1).monotonic_ns)
            .unwrap(),
        Some(host)
    );
    assert!(recovered.compact_ssh().unwrap().is_some());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the Linux compaction trace shim in NODOMI_COMPACTION_TRACE_SO"]
fn compaction_process_exit_recovers_at_sqlite_commit_boundary() {
    use crate::{
        buffer::directory::JOURNAL,
        identity::{IdentityStore, Target},
    };
    use std::process::Command;

    let shim = std::env::var_os("NODOMI_COMPACTION_TRACE_SO").expect("set trace shim path");
    for (phase, exit_code) in [("before-unlink", 76), ("after-truncate", 77)] {
        let fixture = Fixture::new(None);
        let Fragmented {
            buffer,
            host,
            frozen,
            position: checkpoint,
        } = fragmented(&fixture, false);
        let before = rows(&buffer.ssh);
        let database = db_path(&fixture);
        let before_allocated = allocated(&database);
        let before_len = fs::symlink_metadata(&database).unwrap().len();
        let journal = database.with_file_name(JOURNAL);
        drop(buffer);
        let Fixture {
            identity,
            _identity_root: identity_root,
            cache_root,
        } = fixture;
        let identity_path = identity_root.path().join("identity");
        drop(identity);
        let run_child = |stage| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "buffer::budget::tests::compaction_tests::compaction_crash_child",
                ])
                .env("LD_PRELOAD", &shim)
                .env("NODOMI_TEST_COMPACTION_CRASH", stage)
                .env("NODOMI_TEST_COMPACTION_IDENTITY", &identity_path)
                .env("NODOMI_TEST_COMPACTION_CACHE", cache_root.path())
                .output()
                .unwrap()
        };
        let child = run_child(phase);
        assert_eq!(
            child.status.code(),
            Some(exit_code),
            "{phase} hook did not exit at the commit boundary: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        if phase == "before-unlink" {
            assert!(journal.is_file());
            assert_eq!(fs::symlink_metadata(&database).unwrap().len(), before_len);
        } else {
            assert!(!journal.exists());
            assert!(fs::symlink_metadata(&database).unwrap().len() < before_len);
            let refused = run_child("recovery-sync-fails");
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert!(
                refused.status.success(),
                "recovery should refuse the SSH main-file sync failure: {} {stderr}",
                String::from_utf8_lossy(&refused.stdout)
            );
            assert!(stderr.contains("injected recovery SSH main sync EIO"));
            assert!(!journal.exists());
        }
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
        let mut recovered = fixture.recover();
        assert_eq!(rows(&recovered.ssh), before);
        assert_eq!(
            recovered.ssh.checkpoint(super::STREAM).unwrap(),
            Some(checkpoint)
        );
        assert_eq!(
            recovered.ssh.prepare(&clock(1)).unwrap().unwrap().body,
            frozen
        );
        assert_eq!(
            recovered
                .host
                .begin(super::BOOT, clock(1).monotonic_ns)
                .unwrap(),
            Some(host)
        );
        if phase == "before-unlink" {
            assert_eq!(allocated(&database), before_allocated);
        } else {
            assert!(allocated(&database) < before_allocated);
        }
        println!("{phase}: reopened with exact HOST, SSH and checkpoint state");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "spawned by compaction_process_exit_recovers_at_sqlite_commit_boundary"]
fn compaction_crash_child() {
    use crate::{
        buffer::SharedBufferPaths,
        identity::{IdentityStore, Target},
    };
    let identity = std::env::var_os("NODOMI_TEST_COMPACTION_IDENTITY").unwrap();
    let cache = std::path::PathBuf::from(std::env::var_os("NODOMI_TEST_COMPACTION_CACHE").unwrap());
    let identity = IdentityStore::open(
        Path::new(&identity),
        &Target::new("https://localhost:9443", "server-budget").unwrap(),
    )
    .unwrap();
    let recovered = SharedBuffer::recover(
        SharedBufferPaths {
            host: &cache.join("host"),
            ssh: &cache.join("ssh"),
        },
        &identity,
        super::EPOCH,
    );
    if std::env::var("NODOMI_TEST_COMPACTION_CRASH").as_deref() == Ok("recovery-sync-fails") {
        assert_eq!(recovered.err(), Some("SSH_QUEUE_STORAGE_ERROR"));
        return;
    }
    let mut buffer = recovered.unwrap();
    buffer.compact_ssh().unwrap();
    panic!("compaction returned before the crash hook");
}
