use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

const OP: &str = "11111111-1111-4111-8111-111111111111";
const EPOCH: &str = "22222222-2222-4222-8222-222222222222";
const SAMPLE: &str = "33333333-3333-4333-8333-333333333333";
fn context() -> HealthContext {
    HealthContext::new(
        Target::new("https://management.example", "server:test").unwrap(),
        Binding {
            agent_id: "agent:test".into(),
            server_id: "server:test".into(),
            binding_revision: 1,
        },
        OP,
        EPOCH,
    )
    .unwrap()
}
fn configuration() -> AgentConfiguration {
    AgentConfiguration::decode(br#"{"agentId":"agent:test","bindingRevision":1,"schemaVersion":1,"target":{"configId":"44444444-4444-4444-8444-444444444444","generation":1,"configuration":{"samplingIntervalSeconds":30,"bufferMaxAgeSeconds":3600,"bufferMaxBytes":1000000}}}"#).unwrap()
}
fn ack(accepted: u64) -> IngestionResult {
    IngestionResult {
        accepted_count: accepted,
        duplicate_count: 1 - accepted,
        expired_count: 0,
        received_at: "2026-11-11T00:00:00Z".into(),
    }
}
fn sample(tracker: &HealthTracker) -> StoredSample {
    let ns = health_boottime_ns().unwrap();
    let seconds: serde_json::Value =
        serde_json::from_str(&format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)).unwrap();
    StoredSample { sample_id:SAMPLE.into(), boot_id:tracker.boot_id.clone(), monotonic_ns:ns, body:serde_json::json!({"sampleId":SAMPLE,"bootId":tracker.boot_id,"monotonicSeconds":seconds,"collectorEpoch":EPOCH,"clockEpoch":EPOCH,"collectionGroup":{"kind":"HOST","subjectId":null},"collectionStatus":"PARTIAL","observedAt":"2026-11-11T00:00:00Z","points":[{"metric":"load.1m","availability":"AVAILABLE","value":1}]}).to_string() }
}
fn complete() -> HealthTracker {
    let ctx = context();
    let mut tracker = HealthTracker::new(ctx.clone()).unwrap();
    tracker.record_heartbeat(&ctx).unwrap();
    tracker.record_applied(&ctx, &configuration()).unwrap();
    tracker
        .record_host_accepted(&ctx, &sample(&tracker), &ack(1))
        .unwrap();
    tracker
}
fn store() -> (tempfile::TempDir, HealthConfirmationStore) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = HealthConfirmationStore::open(File::open(dir.path()).unwrap()).unwrap();
    (dir, store)
}
#[test]
fn only_complete_same_epoch_real_acceptance_is_persistable() {
    let (_dir, store) = store();
    let ctx = context();
    let mut tracker = HealthTracker::new(ctx.clone()).unwrap();
    assert_eq!(tracker.persist(&store), Err(HealthError::Incomplete));
    assert_eq!(
        tracker.record_applied(&ctx, &configuration()),
        Err(HealthError::Incomplete)
    );
    tracker.record_heartbeat(&ctx).unwrap();
    tracker.record_applied(&ctx, &configuration()).unwrap();
    assert_eq!(
        tracker.record_host_accepted(&ctx, &sample(&tracker), &ack(0)),
        Err(HealthError::NotAccepted)
    );
    assert_eq!(tracker.persist(&store), Err(HealthError::Incomplete));
    let mut unavailable = sample(&tracker);
    unavailable.body = unavailable.body.replace("AVAILABLE", "COLLECTION_ERROR");
    assert_eq!(
        tracker.record_host_accepted(&ctx, &unavailable, &ack(1)),
        Err(HealthError::Incomplete)
    );
    tracker
        .record_host_accepted(&ctx, &sample(&tracker), &ack(1))
        .unwrap();
    let proof = tracker.persist(&store).unwrap();
    assert_eq!(
        store
            .verify_for_install(
                &ctx.target,
                &ctx.binding,
                OP,
                tracker.started_ns,
                Duration::from_secs(30)
            )
            .unwrap(),
        proof
    );
    assert_eq!(proof.collector_epoch(), EPOCH);
    assert!(proof.supervisor_pid() > 1);
}
#[test]
fn rejects_identity_epoch_origin_and_old_sample() {
    let ctx = context();
    let mut tracker = HealthTracker::new(ctx.clone()).unwrap();
    let mut wrong = ctx.clone();
    wrong.binding.binding_revision += 1;
    assert_eq!(
        tracker.record_heartbeat(&wrong),
        Err(HealthError::ContextMismatch)
    );
    tracker.record_heartbeat(&ctx).unwrap();
    let old = sample(&tracker);
    tracker.record_applied(&ctx, &configuration()).unwrap();
    assert_eq!(
        tracker.record_host_accepted(&ctx, &old, &ack(1)),
        Err(HealthError::Stale)
    );
    let mut wrong_sample = sample(&tracker);
    let mut body: serde_json::Value = serde_json::from_str(&wrong_sample.body).unwrap();
    body["collectorEpoch"] = serde_json::json!(OP);
    wrong_sample.body = body.to_string();
    assert_eq!(
        tracker.record_host_accepted(&ctx, &wrong_sample, &ack(1)),
        Err(HealthError::ContextMismatch)
    );
    let (_dir, store) = store();
    let proof = complete().persist(&store).unwrap();
    let other = Target::new("https://other.example", "server:test").unwrap();
    assert_eq!(
        store.verify_for_install(&other, &ctx.binding, OP, 0, Duration::from_secs(30)),
        Err(HealthError::ContextMismatch)
    );
    assert_eq!(
        store.verify_for_install(&ctx.target, &wrong.binding, OP, 0, Duration::from_secs(30)),
        Err(HealthError::ContextMismatch)
    );
    assert_eq!(
        store.verify_for_install(&ctx.target, &ctx.binding, EPOCH, 0, Duration::from_secs(30)),
        Err(HealthError::ContextMismatch)
    );
    assert_eq!(
        store.verify_for_install(
            &ctx.target,
            &ctx.binding,
            OP,
            proof.started_ns + 1,
            Duration::from_secs(30)
        ),
        Err(HealthError::Stale)
    );
    assert_eq!(
        store.verify_for_install(&ctx.target, &ctx.binding, OP, 0, Duration::ZERO),
        Err(HealthError::Stale)
    );
}
#[test]
fn protected_file_rejects_symlinks_hardlinks_bad_mode_and_oversized_records() {
    let (dir, store) = store();
    let tracker = complete();
    tracker.persist(&store).unwrap();
    let path = dir.path().join("health-confirmation.json");
    let saved = fs::read(&path).unwrap();
    fs::hard_link(&path, dir.path().join("linked")).unwrap();
    assert_eq!(store.read(), Err(HealthError::UnsafeStorage));
    fs::remove_file(dir.path().join("linked")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.read(), Err(HealthError::UnsafeStorage));
    fs::remove_file(&path).unwrap();
    symlink("elsewhere", &path).unwrap();
    assert_eq!(tracker.persist(&store), Err(HealthError::UnsafeStorage));
    fs::remove_file(&path).unwrap();
    fs::write(&path, vec![b' '; MAX_HEALTH_BYTES + 1]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.read(), Err(HealthError::InvalidRecord));
    fs::write(&path, &saved).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    value["bootId"] = serde_json::json!(OP);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let ctx = context();
    assert_eq!(
        store.verify_for_install(&ctx.target, &ctx.binding, OP, 0, Duration::from_secs(30)),
        Err(HealthError::Stale)
    );
}
#[test]
fn missing_and_incomplete_records_never_become_success() {
    let (dir, store) = store();
    assert_eq!(store.read(), Err(HealthError::NotFound));
    let path = dir.path().join("health-confirmation.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.read(), Err(HealthError::InvalidRecord));
}

#[test]
fn parent_sync_failure_is_unknown_and_retry_can_confirm_same_exact_proof() {
    let (_dir, store) = store();
    let tracker = complete();
    let proof = tracker.persist(&store).unwrap();
    assert_eq!(
        store.save(&proof, |_| Err(io::Error::other(
            "injected parent sync failure"
        ))),
        Err(HealthError::CommitOutcomeUnknown)
    );
    assert_eq!(tracker.persist(&store).unwrap(), proof);
    let lock = open_at(&store.directory, c".", libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
    // SAFETY: lock owns an independent live directory descriptor.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert_eq!(tracker.persist(&store), Err(HealthError::Busy));
    drop(lock);
    assert_eq!(tracker.persist(&store).unwrap(), proof);
}

#[test]
fn rejects_inconsistent_future_unknown_and_duplicate_fields() {
    let (dir, store) = store();
    let tracker = complete();
    let proof = tracker.persist(&store).unwrap();
    let path = dir.path().join("health-confirmation.json");
    let original = serde_json::to_value(&proof).unwrap();
    for mutate in ["schemaVersion", "heartbeatNs", "extra"] {
        let mut value = original.clone();
        value[mutate] = serde_json::json!(u64::MAX);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(store.read(), Err(HealthError::InvalidRecord));
    }
    let mut value = original.clone();
    value["host"]["acceptedNs"] = serde_json::json!(u64::MAX);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let ctx = context();
    assert_eq!(
        store.verify_for_install(&ctx.target, &ctx.binding, OP, 0, Duration::from_secs(30)),
        Err(HealthError::Stale)
    );
    let bytes = serde_json::to_string(&proof).unwrap();
    fs::write(&path, format!("{{\"schemaVersion\":1,{}", &bytes[1..])).unwrap();
    assert_eq!(store.read(), Err(HealthError::InvalidRecord));
}

#[test]
fn held_directory_rename_cannot_redirect_writes() {
    let outer = tempfile::tempdir().unwrap();
    let original = outer.path().join("health");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let store = HealthConfirmationStore::open(File::open(&original).unwrap()).unwrap();
    let renamed = outer.path().join("held");
    fs::rename(&original, &renamed).unwrap();
    fs::create_dir(&original).unwrap();
    let canary = original.join("health-confirmation.json");
    fs::write(&canary, b"untouched").unwrap();
    let tracker = complete();
    tracker.persist(&store).unwrap();
    assert_eq!(fs::read(canary).unwrap(), b"untouched");
    assert!(renamed.join("health-confirmation.json").is_file());
}

#[test]
fn newer_configuration_requires_new_post_applied_host_evidence() {
    let ctx = context();
    let mut tracker = complete();
    let (_dir, store) = store();
    let mut newer = configuration();
    newer.target.generation = 2;
    newer.target.config_id = OP.into();
    tracker.record_applied(&ctx, &newer).unwrap();
    assert_eq!(tracker.persist(&store), Err(HealthError::Incomplete));
    assert_eq!(
        tracker.record_applied(&ctx, &configuration()),
        Err(HealthError::ContextMismatch)
    );
    tracker
        .record_host_accepted(&ctx, &sample(&tracker), &ack(1))
        .unwrap();
    assert_eq!(tracker.persist(&store).unwrap().config_id(), OP);
}
