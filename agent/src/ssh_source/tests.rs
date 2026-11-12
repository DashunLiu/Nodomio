//! Real local journal acceptance. Run each invocation in the same isolated
//! Linux journal and cache, with real SSH connections between invocations.
#![cfg(target_os = "linux")]

use crate::{
    buffer::{SharedBuffer, SharedBufferPaths},
    identity::{Binding, IdentityStore, Target, new_collector_epoch},
    protocol::{Capability, IngestionResult, SshContinuity, SshSource},
    ssh_source::{JOURNAL_STREAM, SourceRead, SshSourceReader, queue_time},
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

#[test]
#[ignore = "requires an isolated real sshd and local system journal"]
fn ssh_journal_fixture_advances() {
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
    let epoch = new_collector_epoch().unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let boot = boot.trim();
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
    if std::env::var_os("NODOMI_SSH_SOURCE_TEST_ACK_EXISTING").is_some() {
        let now = queue_time(boot).unwrap();
        while let Some(attempt) = buffer.ssh.prepare(&now).unwrap() {
            let ack = IngestionResult {
                accepted_count: attempt.event_count as u64,
                duplicate_count: 0,
                expired_count: 0,
                received_at: super::observation_timestamp(now.unix_seconds).unwrap(),
            };
            buffer.ssh.finish(&attempt.token, Some(&ack)).unwrap();
        }
    }
    let before = buffer.ssh.checkpoint(JOURNAL_STREAM).unwrap();
    let report_path = root.join("journal-test-report.json");
    let prior: Option<Value> = match fs::read(&report_path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).unwrap()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read fixture report: {error}"),
    };
    assert_eq!(prior.is_some(), before.is_some());
    let expected_state =
        std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_STATE").unwrap_or_else(|_| "caught-up".into());
    let mut reader = SshSourceReader::default();
    let result = if expected_state == "witnessed" {
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
    assert_eq!(
        result,
        match expected_state.as_str() {
            "witnessed" => SourceRead::More,
            "rebased" => SourceRead::Rebased,
            "caught-up" => SourceRead::CaughtUp,
            _ => panic!("unsupported journal fixture state"),
        }
    );
    let after = buffer.ssh.checkpoint(JOURNAL_STREAM).unwrap().unwrap();
    let expected_gap = std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_GAP").ok();
    if expected_state == "caught-up" && expected_gap.is_some() {
        // Simulate exiting before sending a heartbeat. A successful poll
        // itself must have made recovery durable.
        assert!(
            buffer
                .ssh
                .source_recovery(JOURNAL_STREAM)
                .unwrap()
                .gap
                .unwrap()
                .recovered_at
                .is_some()
        );
    }
    let (capability, diagnostic) = reader.heartbeat_report(&mut buffer).unwrap();
    let diagnostic = diagnostic.unwrap();
    assert_eq!(diagnostic.source, Some(SshSource::Journald));
    assert!(diagnostic.initialized_at.is_some());
    assert!(matches!(capability, Capability::Available));
    if let Some(previous) = &prior {
        assert_eq!(json!(diagnostic.initialized_at), previous["initializedAt"]);
    }
    let gap = json!(diagnostic.last_gap);
    if let Some(reason) = expected_gap {
        assert_eq!(diagnostic.continuity, SshContinuity::Gapped);
        assert_eq!(gap["reason"], reason);
        assert!(gap["detectedAt"].is_string());
        if let Some(previous) = prior.as_ref().filter(|prior| prior["lastGap"].is_object()) {
            assert_eq!(gap["detectedAt"], previous["lastGap"]["detectedAt"]);
            if previous["lastGap"]["recoveredAt"].is_string() {
                assert_eq!(gap, previous["lastGap"]);
            }
        }
    } else {
        assert_eq!(diagnostic.continuity, SshContinuity::Unknown);
        assert!(gap.is_null());
    }
    if expected_state == "witnessed" {
        assert_eq!(before.as_ref(), Some(&after));
        assert_eq!(diagnostic.is_caught_up, None);
        assert!(
            buffer
                .ssh
                .source_recovery(JOURNAL_STREAM)
                .unwrap()
                .witness
                .is_some()
        );
    } else if expected_state == "rebased" {
        assert_eq!(after.sequence, before.as_ref().unwrap().sequence + 1);
        assert_eq!(diagnostic.is_caught_up, None);
        let prior = prior.as_ref().unwrap();
        assert_eq!(json!(diagnostic.last_read_at), prior["lastReadAt"]);
        if prior["lastGap"].is_null() && gap.is_object() {
            assert!(gap["recoveredAt"].is_null());
        }
        assert!(
            buffer
                .ssh
                .source_recovery(JOURNAL_STREAM)
                .unwrap()
                .witness
                .is_none()
        );
    } else {
        assert_eq!(diagnostic.is_caught_up, Some(true));
        assert!(diagnostic.last_read_at.is_some());
        if gap.is_object() {
            assert!(gap["recoveredAt"].is_string());
        }
    }
    drop(buffer);
    let database = rusqlite::Connection::open_with_flags(
        paths[2].join("ssh-buffer.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut select = database
        .prepare("SELECT body FROM ssh_events ORDER BY id")
        .unwrap();
    let records = select
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|body| serde_json::from_slice::<serde_json::Value>(&body.unwrap()).unwrap())
        .collect::<Vec<_>>();
    let actual = records
        .iter()
        .map(|value| value["username"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    for record in &records {
        assert_eq!(record.as_object().unwrap().len(), 6);
        assert_eq!(record["bootId"], boot);
    }
    let ids = records
        .iter()
        .map(|value| value["eventId"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids.iter().collect::<std::collections::HashSet<_>>().len(),
        ids.len()
    );
    let report = json!({
        "beforeSequence": before.map(|position| position.sequence),
        "afterSequence": after.sequence,
        "eventIds": ids,
        "eventTypes": records.iter().map(|record| &record["eventType"]).collect::<Vec<_>>(),
        "state": expected_state,
        "initializedAt": diagnostic.initialized_at,
        "lastReadAt": diagnostic.last_read_at,
        "lastGap": gap,
    });
    fs::write(report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    println!("{report}");
}
