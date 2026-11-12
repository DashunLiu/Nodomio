//! Finite development-run behavior across real TLS, without an installed daemon.
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[cfg(not(target_os = "linux"))]
#[test]
fn protocol_run_refuses_to_invent_linux_runtime_on_other_hosts() {
    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let bin = env!("CARGO_BIN_EXE_nodomi-agent-protocol");
    let common = [
        "--state-dir",
        state.path().to_str().unwrap(),
        "--origin",
        "https://localhost:1",
        "--server-id",
        "server-1",
    ];
    assert!(
        Command::new(bin)
            .arg("prepare")
            .args(common)
            .output()
            .unwrap()
            .status
            .success()
    );
    let before = fs::read(state.path().join("identity.json")).unwrap();
    let output = Command::new(bin).arg("run").args(common).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "UNSUPPORTED_HOST"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read(state.path().join("identity.json")).unwrap(),
        before
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn collect_refuses_non_linux_before_sending_identity_or_runtime_requests() {
    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let common = [
        "--state-dir",
        state.path().to_str().unwrap(),
        "--origin",
        "https://localhost:1",
        "--server-id",
        "server-1",
    ];
    let binary = env!("CARGO_BIN_EXE_nodomi-agent-protocol");
    assert!(
        Command::new(binary)
            .arg("prepare")
            .args(common)
            .output()
            .unwrap()
            .status
            .success()
    );
    let before = fs::read(state.path().join("identity.json")).unwrap();
    let output = Command::new(binary)
        .arg("collect")
        .args(common)
        .args([
            "--runtime-dir",
            state.path().to_str().unwrap(),
            "--samples",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "UNSUPPORTED_HOST"
    );
    assert_eq!(
        fs::read(state.path().join("identity.json")).unwrap(),
        before
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nodomi_agent::{
        client::ProtocolClient,
        identity::{Enrollment, IdentityStore, Target},
        protocol::RegistrationMetadata,
    };
    use std::{
        io::{BufRead, BufReader},
        path::PathBuf,
        process::{Child, Output, Stdio},
        time::Duration,
    };
    struct Fixture {
        child: Child,
        directory: tempfile::TempDir,
        state: PathBuf,
        origin: String,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl Fixture {
        fn new(scenario: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let state = directory.path().join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            let mut child = Command::new("python3")
                .args([
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/fixtures/https_protocol.py"
                    ),
                    scenario,
                    state.to_str().unwrap(),
                    env!("CARGO_BIN_EXE_nodomi-agent-protocol"),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.trim().parse::<u16>().is_ok());
            let origin = format!("https://localhost:{}", line.trim());
            let target = Target::new(&origin, "server-1").unwrap();
            let mut identity = IdentityStore::initialize(&state, target.clone()).unwrap();
            let token = directory.path().join("enrollment");
            fs::write(&token, format!("ndme_{}", "A".repeat(43))).unwrap();
            fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
            let metadata: RegistrationMetadata = serde_json::from_value(serde_json::json!({"version":"0.1.0","architecture":"ARM64","distribution":"debian","distributionVersion":"12","hostname":"protocol-fixture","capabilities":{"system":"AVAILABLE","processes":"UNSUPPORTED","containers":"UNSUPPORTED","sshEvents":"UNSUPPORTED"}})).unwrap();
            ProtocolClient::new(
                target,
                Some(
                    &fs::read(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/fixtures/tls/ca.pem"
                    ))
                    .unwrap(),
                ),
                Duration::from_secs(2),
            )
            .unwrap()
            .register(
                &mut identity,
                &Enrollment::from_private_file(&token).unwrap(),
                &metadata,
            )
            .unwrap();
            drop(identity);
            fs::remove_file(token).unwrap();
            Self {
                child,
                directory,
                state,
                origin,
            }
        }
        fn run(&self) -> Output {
            Command::new(env!("CARGO_BIN_EXE_nodomi-agent-protocol"))
                .args([
                    "run",
                    "--state-dir",
                    self.state.to_str().unwrap(),
                    "--origin",
                    &self.origin,
                    "--server-id",
                    "server-1",
                    "--ca-file",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/ca.pem"),
                ])
                .output()
                .unwrap()
        }
        fn collect(&self, samples: usize) -> Output {
            self.collect_at(samples, &self.directory.path().join("runtime"))
        }
        fn collect_at(&self, samples: usize, runtime: &std::path::Path) -> Output {
            if !runtime.exists() {
                fs::create_dir(runtime).unwrap();
                fs::set_permissions(runtime, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Command::new(env!("CARGO_BIN_EXE_nodomi-agent-protocol"))
                .args([
                    "collect",
                    "--state-dir",
                    self.state.to_str().unwrap(),
                    "--runtime-dir",
                    runtime.to_str().unwrap(),
                    "--samples",
                    &samples.to_string(),
                    "--origin",
                    &self.origin,
                    "--server-id",
                    "server-1",
                    "--ca-file",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/ca.pem"),
                ])
                .output()
                .unwrap()
        }
        fn observations(&self) -> serde_json::Value {
            serde_json::from_slice(
                &fs::read(self.directory.path().join("observations.json")).unwrap(),
            )
            .unwrap()
        }
        fn runtime_manifest(&self) -> serde_json::Value {
            serde_json::from_slice(
                &fs::read(self.directory.path().join("runtime/runtime.json")).unwrap(),
            )
            .unwrap()
        }
    }
    #[test]
    fn finite_run_fetches_defaults_reports_real_facts_and_never_claims_applied() {
        let fixture = Fixture::new("runtime");
        let output = fixture.run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("ndma_") && !text.contains("ndme_"));
        let result: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(result["tool"], "INTERNAL_PROTOCOL_DEVELOPMENT");
        assert_eq!(result["status"], "BOUND");
        assert_eq!(
            result["configuration"]["target"]["configuration"],
            serde_json::json!({"samplingIntervalSeconds":30,"bufferMaxAgeSeconds":86400,"bufferMaxBytes":100000000})
        );
        assert_eq!(
            result["receipt"],
            serde_json::json!({"result":"FAILED","appliedConfigId":null,"errorCode":"UNSUPPORTED_CONFIGURATION","sequence":1,"acknowledged":true})
        );
        let observations = fixture.observations();
        assert_eq!(
            observations["calls"],
            serde_json::json!(["identity", "configuration", "heartbeat", "receipt"])
        );
        assert_eq!(result["runtime"], observations["heartbeat"]["updater"]);
        assert_eq!(
            result["collectorEpoch"],
            observations["receipt"]["collectorEpoch"]
        );
        assert_eq!(result["runtime"]["buildOrigin"], "SELF_COMPILED");
        assert_eq!(
            result["runtime"]["currentReleaseId"],
            serde_json::Value::Null
        );
        assert_eq!(result["runtime"]["selfUpdate"], "UNSUPPORTED_INSTALLATION");
        assert_eq!(result["runtime"]["mode"], "MANUAL");
        let first_epoch = result["collectorEpoch"].clone();
        assert!(fixture.run().status.success());
        assert_ne!(
            fixture.observations()["heartbeat"]["collectorEpoch"],
            first_epoch
        );
        assert_eq!(
            fs::read_dir(&fixture.state).unwrap().count(),
            2,
            "no fake config/application files"
        );
    }
    #[test]
    fn lost_live_heartbeat_stops_before_receipt_and_keeps_identity() {
        let fixture = Fixture::new("runtime-lost-heartbeat");
        let before = fs::read(fixture.state.join("identity.json")).unwrap();
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "NETWORK_OR_TLS_ERROR"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            fixture.observations()["calls"],
            serde_json::json!(["identity", "configuration", "heartbeat"])
        );
        assert_eq!(
            fs::read(fixture.state.join("identity.json")).unwrap(),
            before
        );
    }
    #[test]
    fn receipt_rejection_is_not_reported_as_acknowledged() {
        let fixture = Fixture::new("runtime-receipt-rejected");
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "REMOTE_REQUEST_REJECTED"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            fixture.observations()["calls"],
            serde_json::json!(["identity", "configuration", "heartbeat", "receipt"])
        );
    }
    #[test]
    fn mismatched_configuration_stops_before_runtime_report_or_receipt() {
        let fixture = Fixture::new("runtime-config-binding");
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "CONFIGURATION_BINDING_MISMATCH"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            fixture.observations()["calls"],
            serde_json::json!(["identity", "configuration"])
        );
    }
    #[test]
    fn finite_collect_activates_durable_defaults_and_transports_original_host_sample() {
        let fixture = Fixture::new("runtime-collect");
        let output = fixture.collect(1);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["receipt"]["result"], "APPLIED");
        assert_eq!(result["collectedRounds"], 1);
        let observations = fixture.observations();
        assert_eq!(
            observations["receipt"]["appliedConfigId"],
            result["configuration"]["target"]["configId"]
        );
        assert_eq!(observations["metricBodies"].as_array().unwrap().len(), 1);
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture.directory.path().join("runtime/runtime.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["configuration"], result["configuration"]);
        assert_eq!(manifest["latest"], serde_json::Value::Null);
        assert_eq!(manifest["inflight"], serde_json::Value::Null);
        assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 2);
    }
    #[test]
    fn invalid_aggregate_ack_preserves_exact_durable_inflight() {
        let fixture = Fixture::new("runtime-collect-invalid-ack");
        let output = fixture.collect(1);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "INVALID_METRIC_ACK"
        );
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture.directory.path().join("runtime/runtime.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["latest"], manifest["inflight"]);
        let sent = &fixture.observations()["metricBodies"][0]["samples"][0];
        assert_eq!(manifest["latest"]["sampleId"], sent["sampleId"]);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(manifest["latest"]["body"].as_str().unwrap())
                .unwrap(),
            *sent
        );
    }
    #[test]
    fn rate_limited_slow_upload_does_not_block_heartbeat_or_latest_admission() {
        let fixture = Fixture::new("runtime-collect-slow-metric");
        let output = fixture.collect(2);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["collectedRounds"], 2);
        assert_eq!(result["acknowledgedSamples"], 2);
        let observed = fixture.observations();
        let attempts = observed["metricAttempts"].as_array().unwrap();
        let bodies = observed["metricBodies"].as_array().unwrap();
        let heartbeats = observed["heartbeatTimes"].as_array().unwrap();
        assert_eq!(
            attempts.len(),
            3,
            "one rate limit, the same body retried, then the new sample"
        );
        assert_eq!(heartbeats.len(), 2);
        let limited_response = attempts[0]["responseAt"].as_f64().unwrap();
        let retry_start = attempts[1]["startedAt"].as_f64().unwrap();
        let retry_response = attempts[1]["responseAt"].as_f64().unwrap();
        let next_start = attempts[2]["startedAt"].as_f64().unwrap();
        let heartbeat_start = heartbeats[0].as_f64().unwrap();
        let heartbeat_during_retry = heartbeats[1].as_f64().unwrap();
        assert!(
            retry_start - limited_response >= 25.0,
            "rate-limited retry started after {:.3}s, before Retry-After=25",
            retry_start - limited_response
        );
        assert_eq!(attempts[0]["bodySHA256"], attempts[1]["bodySHA256"]);
        assert!(
            retry_start < heartbeat_during_retry && heartbeat_during_retry < retry_response,
            "the second heartbeat must reach the TLS receiver while the retry is still awaiting its response"
        );
        assert!((29.0..35.0).contains(&(heartbeat_during_retry - heartbeat_start)));
        assert!(
            next_start >= retry_response,
            "data requests must not overlap"
        );
        let next_sample = &bodies[2]["samples"][0];
        let next_id = &next_sample["sampleId"];
        let retry_id = &bodies[1]["samples"][0]["sampleId"];
        assert!(next_id.is_string());
        assert_ne!(next_id, retry_id);
        assert_eq!(
            &attempts[1]["latestBeforeAck"], next_id,
            "the newer sample was durable before the retry's ACK and survived it"
        );
        assert_eq!(&next_sample["continuity"]["previousSampleId"], retry_id);
        assert_eq!(next_sample["continuity"]["isContinuous"], true);
        let total_cpu = next_sample["points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["metric"] == "cpu.executionPercent" && p["labels"]["cpu"] == "total")
            .expect("HOST sample has total CPU execution percentage");
        assert_eq!(total_cpu["availability"], "AVAILABLE");
        let manifest = fixture.runtime_manifest();
        assert!(manifest["latest"].is_null() && manifest["inflight"].is_null());
        eprintln!(
            "Slow TLS evidence retry_after_s={:.3} heartbeat_interval_s={:.3} retry_response_hold_s={:.3}",
            retry_start - limited_response,
            heartbeat_during_retry - heartbeat_start,
            retry_response - retry_start
        );
    }
    #[test]
    fn metric_array_ack_cannot_remove_original_pending_sample() {
        let fixture = Fixture::new("runtime-collect-array-ack");
        let output = fixture.collect(1);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "INVALID_METRIC_ACK"
        );
        assert!(output.stdout.is_empty());
        assert_one_original_pending(&fixture);
    }
    #[test]
    fn expired_metric_ack_clears_queue_and_reports_no_ingestion() {
        let fixture = Fixture::new("runtime-collect-expired-ack");
        let output = fixture.collect(1);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["acknowledgedSamples"], 1);
        assert_eq!(result["acceptedSamples"], 0);
        assert_eq!(result["duplicateSamples"], 0);
        assert_eq!(result["expiredSamples"], 1);
        assert_eq!(
            fixture.observations()["metricBodies"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let manifest = fixture.runtime_manifest();
        assert!(manifest["latest"].is_null() && manifest["inflight"].is_null());
    }
    #[test]
    fn metric_revocation_stops_collection_and_keeps_original_pending_sample() {
        let fixture = Fixture::new("runtime-collect-revoked");
        let started = std::time::Instant::now();
        let output = fixture.collect(2);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "CREDENTIAL_REJECTED"
        );
        assert!(output.stdout.is_empty());
        assert!(started.elapsed() < Duration::from_secs(25));
        let identity: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.state.join("identity.json")).unwrap())
                .unwrap();
        assert_eq!(identity["status"], "NEEDS_RECONNECT");
        assert_one_original_pending(&fixture);
    }
    fn assert_one_original_pending(fixture: &Fixture) {
        let manifest = fixture.runtime_manifest();
        let observed = fixture.observations();
        let bodies = observed["metricBodies"].as_array().unwrap();
        assert_eq!(bodies.len(), 1);
        let sent = &bodies[0]["samples"][0];
        assert_eq!(manifest["latest"], manifest["inflight"]);
        assert_eq!(manifest["inflight"]["sampleId"], sent["sampleId"]);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                manifest["inflight"]["body"].as_str().unwrap()
            )
            .unwrap(),
            *sent
        );
    }
    #[test]
    fn lost_response_restart_retries_original_body_before_new_epoch_sample() {
        let fixture = Fixture::new("runtime-collect-retry");
        let first = fixture.collect(1);
        assert_eq!(first.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(first.stderr).unwrap().trim(),
            "NETWORK_OR_TLS_ERROR"
        );
        let second = fixture.collect(1);
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
        assert_eq!(result["acknowledgedSamples"], 2);
        let observations = fixture.observations();
        let bodies = observations["metricBodies"].as_array().unwrap();
        assert_eq!(bodies.len(), 3);
        assert_eq!(bodies[0], bodies[1]);
        assert_ne!(
            bodies[1]["samples"][0]["sampleId"],
            bodies[2]["samples"][0]["sampleId"]
        );
        assert_ne!(
            bodies[1]["samples"][0]["collectorEpoch"],
            bodies[2]["samples"][0]["collectorEpoch"]
        );
        assert_eq!(
            bodies[2]["samples"][0]["continuity"],
            serde_json::json!({"previousSampleId":null,"isContinuous":false})
        );
        assert!(
            bodies[2]["samples"][0]["points"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["metric"].as_str().unwrap().starts_with("cpu."))
                .all(|p| p["availability"] == "NO_BASELINE")
        );
    }
    #[test]
    fn actual_config_write_failure_sends_failed_and_never_applied() {
        use std::io::Write;
        let Ok(root) = std::env::var("NODOMI_RUNTIME_ENOSPC_DIR") else {
            return;
        };
        let fixture = Fixture::new("runtime-collect-write-failed");
        let runtime = tempfile::tempdir_in(&root).unwrap();
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(runtime.path().join("runtime.lock"), "").unwrap();
        fs::set_permissions(
            runtime.path().join("runtime.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let filler_path =
            std::path::Path::new(&root).join(format!("runtime-cli-fill-{}", std::process::id()));
        let mut filler = fs::File::create(&filler_path).unwrap();
        let error = loop {
            if let Err(error) = filler.write_all(&[0u8; 4096]) {
                break error;
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        let output = fixture.collect_at(1, runtime.path());
        fs::remove_file(filler_path).unwrap();
        drop(filler);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "LOCAL_STORAGE_ERROR"
        );
        assert!(output.stdout.is_empty());
        let observed = fixture.observations();
        assert_eq!(observed["receipt"]["result"], "FAILED");
        assert_eq!(
            observed["receipt"]["appliedConfigId"],
            serde_json::Value::Null
        );
        assert_eq!(observed["receipt"]["errorCode"], "LOCAL_STORAGE_ERROR");
        assert!(observed.get("metrics").is_none());
        assert!(!runtime.path().join("runtime.json").exists());
    }

    #[test]
    fn collect_rejects_configuration_below_retained_capacity_with_exact_receipt() {
        use nodomi_agent::{
            identity::new_collector_epoch,
            runtime::{HostCollector, RuntimeStore},
            source::LinuxSource,
        };

        let fixture = Fixture::new("runtime-collect-resource-limit");
        let target = Target::new(&fixture.origin, "server-1").unwrap();
        let mut identity = IdentityStore::open(&fixture.state, &target).unwrap();
        let ca = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/ca.pem"
        ))
        .unwrap();
        let client = ProtocolClient::new(target, Some(&ca), Duration::from_secs(2)).unwrap();
        let mut old = client.configuration(&mut identity).unwrap();
        old.target.generation = 1;
        old.target.config_id = "123e4567-e89b-42d3-a456-426614174001".into();
        old.target.configuration.buffer_max_bytes = 100_000_000;
        let directory = fixture.directory.path().join("runtime");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let epoch = new_collector_epoch().unwrap();
        let mut store = RuntimeStore::open(&directory, &identity, &epoch).unwrap();
        let raw = LinuxSource.capture_host().unwrap();
        store
            .apply(&old, &raw.boot_id, raw.cpu_observed.monotonic_ns)
            .unwrap();
        let mut sample = HostCollector::new(&epoch).unwrap().collect(raw).unwrap();
        // Valid JSON whitespace makes the retained sample and atomic replacement
        // coexist above the target without fabricating host metric values.
        sample.body.extend(std::iter::repeat_n(' ', 600_000));
        store.admit(sample).unwrap();
        drop(store);
        drop(identity);
        let manifest = directory.join("runtime.json");
        let original = fs::read(&manifest).unwrap();

        let output = fixture.collect_at(1, &directory);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "RESOURCE_LIMIT"
        );
        assert!(output.stdout.is_empty());
        let observed = fixture.observations();
        assert_eq!(observed["receipt"]["result"], "FAILED");
        assert_eq!(observed["receipt"]["errorCode"], "RESOURCE_LIMIT");
        assert!(observed["receipt"]["appliedConfigId"].is_null());
        assert_eq!(observed["receipt"]["generation"], 2);
        assert_eq!(observed["receipt"]["sequence"], 1);
        assert!(observed.get("metricBodies").is_none());
        assert_eq!(fs::read(manifest).unwrap(), original);
        assert!(!directory.join("runtime.next").exists());
    }

    #[test]
    fn collect_runtime_alias_rejects_before_identity_http_or_file_publication() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new("runtime-collect");
        let identity_file = fixture.state.join("identity.json");
        let before = fs::read(&identity_file).unwrap();
        let metadata = fs::metadata(&identity_file).unwrap();
        let output = fixture.collect_at(1, &fixture.state);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "RUNTIME_DIRECTORY_NOT_SEPARATE"
        );
        assert_eq!(fs::read(&identity_file).unwrap(), before);
        let after = fs::metadata(&identity_file).unwrap();
        assert_eq!(
            (
                after.ino(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
            (
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec()
            )
        );
        assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 2);
        assert!(
            !fixture.directory.path().join("observations.json").exists(),
            "no identity HTTP before runtime preflight"
        );
    }
}
