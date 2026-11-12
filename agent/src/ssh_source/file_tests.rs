//! Real auth-file acceptance. Run each invocation in the same isolated Linux
//! file source and cache, with real SSH connections between invocations.

use super::{AUTH_FILE_STREAM, JOURNAL_STREAM, SourceRead, SshSourceReader, queue_time};
use crate::{
    buffer::{SharedBuffer, SharedBufferPaths},
    identity::{Binding, IdentityStore, Target, new_collector_epoch, uuid},
    protocol::{Capability, SshContinuity, SshGapReason, SshSource},
};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn records(queue: &Path) -> Vec<Value> {
    let database = rusqlite::Connection::open_with_flags(
        queue.join("ssh-buffer.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut select = database
        .prepare("SELECT body FROM ssh_events ORDER BY id")
        .unwrap();
    select
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|body| serde_json::from_slice(&body.unwrap()).expect("invalid queued event"))
        .collect()
}

#[test]
#[ignore = "requires isolated OpenSSH and a trusted local rsyslog auth file"]
fn ssh_auth_file_fixture_advances() {
    let root = PathBuf::from(std::env::var_os("NODOMI_SSH_SOURCE_TEST_CACHE").unwrap());
    let expected = std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECTED").unwrap();
    let expected: Vec<_> = expected
        .split(',')
        .filter(|name| !name.is_empty())
        .collect();
    let paths = ["identity", "host", "ssh"].map(|name| {
        let path = root.join(name);
        if !path.exists() {
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    });
    let target = Target::new("https://localhost:8443", "fixture-server").unwrap();
    let mut identity = if paths[0].join("identity.json").exists() {
        IdentityStore::open(&paths[0], &target).unwrap()
    } else {
        IdentityStore::initialize(&paths[0], target).unwrap()
    };
    if identity.binding().is_none() {
        identity
            .confirm(Binding {
                agent_id: "fixture-agent".into(),
                server_id: "fixture-server".into(),
                binding_revision: 1,
            })
            .unwrap();
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let boot = boot.trim();
    let event_boot =
        std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_BOOT_ID").unwrap_or_else(|_| boot.to_owned());
    let epoch = new_collector_epoch().unwrap();
    let config = serde_json::from_value(json!({
        "agentId": "fixture-agent",
        "bindingRevision": 1,
        "schemaVersion": 1,
        "target": {
            "configId": "90000000-0000-4000-8000-000000000001",
            "generation": 1,
            "configuration": {
                "samplingIntervalSeconds": 30,
                "bufferMaxAgeSeconds": 3600,
                "bufferMaxBytes": 1000000
            }
        }
    }))
    .unwrap();
    let mut buffer = SharedBuffer::open(
        SharedBufferPaths {
            host: &paths[1],
            ssh: &paths[2],
        },
        &identity,
        &epoch,
        &config,
        &queue_time(boot).unwrap(),
    )
    .unwrap();
    let before = buffer.ssh.checkpoint(AUTH_FILE_STREAM).unwrap();
    let prior_records = records(&paths[2]);
    let previous_report = root.join("file-test-report.json");
    let prior_report: Option<Value> = match fs::read(&previous_report) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).unwrap()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => panic!("cannot read prior fixture heartbeat"),
    };
    assert_eq!(before.is_some(), prior_report.is_some());

    let mode = std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_FILE_STATE")
        .unwrap_or_else(|_| "caught-up".into());
    let expected_state = match mode.as_str() {
        "caught-up" => SourceRead::CaughtUp,
        "waiting" => SourceRead::WaitingForRotation,
        "witnessed" => SourceRead::More,
        "rebased" | "rebased-unconfirmed" => SourceRead::Rebased,
        _ => panic!("invalid expected file state"),
    };
    let witnessed_before = buffer
        .ssh
        .source_recovery(AUTH_FILE_STREAM)
        .unwrap()
        .witness
        .is_some();
    let mut reader = SshSourceReader::default();
    let result = if mode == "witnessed" {
        // Observe a real unread record and exit before admitting it.
        reader
            .poll_bounded(&mut buffer, &queue_time(boot).unwrap(), 0)
            .unwrap()
    } else {
        let mut result = SourceRead::More;
        for _ in 0..100 {
            result = reader
                .poll(&mut buffer, &queue_time(boot).unwrap())
                .unwrap();
            if result != SourceRead::More {
                break;
            }
        }
        result
    };
    assert_eq!(result, expected_state);
    let after = buffer.ssh.checkpoint(AUTH_FILE_STREAM).unwrap().unwrap();
    let witnessed_after = buffer
        .ssh
        .source_recovery(AUTH_FILE_STREAM)
        .unwrap()
        .witness
        .is_some();
    assert!(buffer.ssh.checkpoint(JOURNAL_STREAM).unwrap().is_none());
    let (capability, diagnostic) = reader.heartbeat_report(&mut buffer).unwrap();
    let diagnostic = diagnostic.unwrap();
    assert_eq!(diagnostic.source, Some(SshSource::AuthLogFile));
    assert!(diagnostic.initialized_at.is_some());
    assert!(matches!(capability, Capability::Available));
    if let Some(previous) = &prior_report {
        assert_eq!(json!(diagnostic.initialized_at), previous["initializedAt"]);
    }
    match expected_state {
        SourceRead::More | SourceRead::Rebased => {
            let before = before.as_ref().unwrap();
            if expected_state == SourceRead::More {
                assert!(witnessed_after, "unread observation was not saved");
                assert_eq!(before, &after, "an observation moved the cursor");
            } else {
                assert_eq!(witnessed_before, mode == "rebased");
                assert!(!witnessed_after, "reset retained a stale witness");
                assert_eq!(after.sequence, before.sequence + 1);
                assert_ne!(after.cursor, before.cursor);
            }
            assert_eq!(
                json!(diagnostic.last_read_at),
                prior_report.as_ref().unwrap()["lastReadAt"]
            );
            assert_eq!(diagnostic.is_caught_up, None);
        }
        SourceRead::WaitingForRotation => assert_eq!(diagnostic.is_caught_up, None),
        SourceRead::CaughtUp => {
            assert_eq!(diagnostic.is_caught_up, Some(true));
            assert!(diagnostic.last_read_at.is_some());
        }
        _ => unreachable!(),
    }
    let prior_gap = prior_report
        .as_ref()
        .map(|report| &report["lastGap"])
        .filter(|gap| !gap.is_null());
    if mode == "rebased" || prior_gap.is_some() {
        assert_eq!(diagnostic.continuity, SshContinuity::Gapped);
        let gap = diagnostic.last_gap.as_ref().unwrap();
        assert_eq!(gap.reason, SshGapReason::FileTruncation);
        assert!(OffsetDateTime::parse(&gap.detected_at, &Rfc3339).is_ok());
        if mode == "rebased" {
            assert!(prior_gap.is_none());
            assert!(gap.recovered_at.is_none());
        } else {
            let prior_gap = prior_gap.unwrap();
            assert_eq!(json!(gap.detected_at), prior_gap["detectedAt"]);
            if expected_state == SourceRead::CaughtUp && prior_gap["recoveredAt"].is_null() {
                let recovered_at = gap.recovered_at.as_deref().unwrap();
                assert!(OffsetDateTime::parse(recovered_at, &Rfc3339).is_ok());
            } else {
                assert_eq!(json!(gap.recovered_at), prior_gap["recoveredAt"]);
            }
        }
    } else {
        assert_eq!(diagnostic.continuity, SshContinuity::Unknown);
        assert!(diagnostic.last_gap.is_none());
    }
    drop(buffer);

    let records = records(&paths[2]);
    assert!(
        records.starts_with(&prior_records),
        "restart changed a previously queued event"
    );
    assert_eq!(
        records.len(),
        expected.len(),
        "unexpected number of queued events"
    );
    if matches!(expected_state, SourceRead::More | SourceRead::Rebased) {
        assert_eq!(records.len(), prior_records.len());
    }
    let expected_types = std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_EVENT_TYPES").ok();
    let types = records
        .iter()
        .map(|record| record["eventType"].as_str().unwrap());
    if let Some(expected_types) = expected_types.as_deref() {
        assert!(
            types
                .clone()
                .eq(expected_types.split(',').filter(|kind| !kind.is_empty())),
            "unexpected event types or ordering"
        );
    }
    for (record, username) in records.iter().zip(expected) {
        let fields = record.as_object().unwrap();
        assert_eq!(fields.len(), 6);
        assert!(fields.contains_key("sourceIp"));
        assert!(
            record["username"] == username,
            "unexpected event username or ordering"
        );
        assert_eq!(record["bootId"], event_boot);
        assert!(OffsetDateTime::parse(record["occurredAt"].as_str().unwrap(), &Rfc3339).is_ok());
        assert!(matches!(
            record["eventType"].as_str(),
            Some("SSH_LOGIN_SUCCEEDED" | "SSH_AUTH_FAILED")
        ));
    }
    let ids: Vec<_> = records
        .iter()
        .map(|record| record["eventId"].as_str().unwrap())
        .collect();
    assert!(ids.iter().all(|id| uuid(id)));
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
    let report = json!({
        "beforeSequence": before.map(|position| position.sequence),
        "afterSequence": after.sequence,
        "eventIds": ids,
        "eventTypes": types.collect::<Vec<_>>(),
        "source": diagnostic.source,
        "initializedAt": diagnostic.initialized_at,
        "lastReadAt": diagnostic.last_read_at,
        "isCaughtUp": diagnostic.is_caught_up,
        "continuity": diagnostic.continuity,
        "lastGap": diagnostic.last_gap,
        "witnessed": witnessed_after,
    });
    fs::write(previous_report, report.to_string()).unwrap();
    println!("{report}");
}
