use super::*;
use nodomi_agent::{
    buffer::SourcePosition,
    identity::{Enrollment, Target},
    protocol::RegistrationMetadata,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    server: Child,
    files: ServiceFiles,
}

impl Fixture {
    fn new(scenario: &str) -> Self {
        Self::with_script(
            scenario,
            Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/https_service.py"
            )),
        )
    }

    fn with_script(scenario: &str, script: &Path) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut server = Command::new("python3")
            .arg(script)
            .arg(directory.path())
            .args(["0", scenario])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut port = String::new();
        BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut port)
            .unwrap();
        let port: u16 = port.trim().parse().unwrap();
        let target = Target::new(&format!("https://localhost:{port}"), "server-1").unwrap();
        let private_dir = |name: &str| -> PathBuf {
            let path = directory.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        let files = ServiceFiles {
            target,
            ca: Some(include_bytes!("../tests/fixtures/tls/ca.pem").to_vec()),
            identity: private_dir("identity"),
            host: private_dir("runtime"),
            ssh: private_dir("ssh-queue"),
            health: None,
            startup_window_required: false,
        };
        Self {
            directory,
            server,
            files,
        }
    }

    fn register(&self) {
        let token = self.directory.path().join("enrollment-fixture");
        fs::write(&token, format!("ndme_{}", "A".repeat(43))).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
        let metadata: RegistrationMetadata = serde_json::from_value(json!({
            "version":"0.1.0","architecture":"ARM64","distribution":"debian",
            "distributionVersion":"12","hostname":"service-fixture",
            "capabilities":{"system":"AVAILABLE","processes":"UNSUPPORTED",
                "containers":"UNSUPPORTED","sshEvents":"UNSUPPORTED"}
        }))
        .unwrap();
        let mut identity =
            IdentityStore::initialize(&self.files.identity, self.files.target.clone()).unwrap();
        ProtocolClient::new(
            self.files.target.clone(),
            self.files.ca.as_deref(),
            Duration::from_secs(2),
        )
        .unwrap()
        .register(
            &mut identity,
            &Enrollment::from_private_file(&token).unwrap(),
            &metadata,
        )
        .unwrap();
        fs::remove_file(token).unwrap();
    }

    fn entries(&self, kind: &str) -> Vec<Value> {
        let path = self.directory.path().join("service-observations.json");
        let all: Vec<Value> = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("{error}"),
        };
        all.into_iter()
            .filter(|item| item["kind"] == kind)
            .collect()
    }

    fn observations(&self, kind: &str) -> Vec<Value> {
        self.entries(kind)
            .into_iter()
            .map(|item| item["body"].clone())
            .collect()
    }

    fn wait_for(&self, kind: &str, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let events = self.observations(kind);
            if events.len() >= count {
                return events;
            }
            assert!(Instant::now() < deadline, "missing {kind} {count}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_for_caught_up_heartbeat(&self, from: usize) -> Value {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(heartbeat) = self
                .observations("heartbeat")
                .into_iter()
                .skip(from)
                .find(|heartbeat| heartbeat["sshSourceDiagnostics"]["isCaughtUp"] == true)
            {
                return heartbeat;
            }
            assert!(Instant::now() < deadline, "missing caught-up SSH heartbeat");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn manifest(&self) -> Value {
        serde_json::from_slice(&fs::read(self.files.host.join("runtime.json")).unwrap()).unwrap()
    }

    fn run(&self, stop: &AtomicBool) -> Result<()> {
        run_service(
            &self.files,
            None,
            stop,
            Duration::from_millis(400),
            Duration::from_secs(2),
        )
        .map(|_| ())
    }

    fn seed_large_queue(&self) {
        let mut state = IdentityStore::open(&self.files.identity, &self.files.target).unwrap();
        let desired = ProtocolClient::new(
            self.files.target.clone(),
            self.files.ca.as_deref(),
            Duration::from_secs(2),
        )
        .unwrap()
        .configuration(&mut state)
        .unwrap();
        let raw = capture().unwrap();
        let clock = QueueTime {
            boot_id: raw.boot_id,
            monotonic_ns: raw.cpu_observed.monotonic_ns,
            unix_seconds: (raw.cpu_observed.observed_unix_ns / 1_000_000_000) as i64,
        };
        let mut buffer = SharedBuffer::open(
            self.files.buffer_paths(),
            &state,
            &new_collector_epoch().unwrap(),
            &desired,
            &clock,
        )
        .unwrap();
        for sequence in 1..=2u64 {
            let mut body = serde_json::to_vec(&json!({
                "eventId": format!("91000000-0000-4000-8000-{sequence:012x}"),
                "bootId": clock.boot_id,
                "occurredAt": "2026-11-11T00:00:00Z",
                "eventType": "SSH_AUTH_FAILED",
                "sourceIp": "192.0.2.42",
                "username": "service-fixture",
            }))
            .unwrap();
            body.resize(600_000, b' ');
            let position = SourcePosition {
                stream: "service-fixture".into(),
                sequence,
                cursor: sequence.to_be_bytes().to_vec(),
            };
            buffer.ssh.enqueue(&position, &body, &clock).unwrap();
        }
        assert!(buffer.allocated_bytes().unwrap() > 1_000_000);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

#[test]
fn managed_first_install_with_missing_startup_record_stops_before_ordinary_work() {
    let mut fixture = Fixture::new("healthy");
    fixture.register();
    fixture.files.startup_window_required = true;
    assert_eq!(
        fixture.run(&AtomicBool::new(false)),
        Err("INVALID_INSTALL_STARTUP")
    );
    assert!(fixture.observations("heartbeat").is_empty());
    assert_eq!(fs::read_dir(&fixture.files.host).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&fixture.files.ssh).unwrap().count(), 0);
}

#[test]
fn service_uses_bound_identity_and_keeps_collecting_after_lost_receipt() {
    let fixture = Fixture::new("lost-first-receipt");
    fixture.register();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let receipts = fixture.wait_for("receipt", 2);
        let heartbeats = fixture.wait_for("heartbeat", 2);
        let samples = fixture.wait_for("metric", 2);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert_eq!(fixture.observations("registration").len(), 1);
        assert_eq!(fixture.observations("identity").len(), 1);
        assert_eq!(receipts[0], receipts[1]);
        let receipt_entries = fixture.entries("receipt");
        assert_eq!(
            receipt_entries[0]["bodySha256"],
            receipt_entries[1]["bodySha256"]
        );
        assert!(receipt_entries[0]["bodySha256"].is_string());
        assert_eq!(receipts[0]["result"], "APPLIED");
        assert_eq!(receipts[0]["sequence"], 1);
        assert_eq!(
            fixture.manifest()["configuration"]["target"]["configId"],
            receipts[0]["configId"]
        );
        assert_eq!(
            heartbeats[0]["collectorEpoch"],
            heartbeats[1]["collectorEpoch"]
        );
        assert_eq!(heartbeats[0]["capabilities"]["system"], "AVAILABLE");
        assert_eq!(heartbeats[0]["capabilities"]["sshEvents"], "UNSUPPORTED");
        assert_eq!(heartbeats[0]["updater"]["buildOrigin"], "UNKNOWN");
        let first = &samples[0]["samples"][0];
        let second = &samples[1]["samples"][0];
        assert_ne!(first["sampleId"], second["sampleId"]);
        assert_eq!(first["collectorEpoch"], heartbeats[0]["collectorEpoch"]);
        assert_eq!(second["collectorEpoch"], heartbeats[0]["collectorEpoch"]);
        assert!(
            first["points"]
                .as_array()
                .is_some_and(|metrics| !metrics.is_empty())
        );
    });
}

#[test]
#[ignore = "requires the isolated native SSH journal fixture"]
fn service_reports_native_ssh_diagnostics_and_resumes_uploads() {
    let fixture = Fixture::with_script(
        "native-journal",
        Path::new(&std::env::var_os("NODOMI_SSH_SOURCE_TEST_HTTPS_FIXTURE").unwrap()),
    );
    let login_script = std::env::var_os("NODOMI_SSH_SOURCE_TEST_LOGIN_SCRIPT").unwrap();
    let expected_source =
        std::env::var("NODOMI_SSH_SOURCE_TEST_EXPECT_SOURCE").unwrap_or_else(|_| "JOURNALD".into());
    let login = |username| {
        assert!(
            Command::new(&login_script)
                .arg(username)
                .status()
                .unwrap()
                .success(),
            "real fixture login failed: {username}"
        );
    };
    let diagnostics = |heartbeat: &Value| {
        assert_eq!(heartbeat["capabilities"]["sshEvents"], "AVAILABLE");
        let diagnostic = &heartbeat["sshSourceDiagnostics"];
        assert_eq!(diagnostic["source"], expected_source.as_str());
        assert!(diagnostic["initializedAt"].is_string());
        assert!(diagnostic["lastReadAt"].is_string());
        assert_eq!(diagnostic["isCaughtUp"], true);
        assert_eq!(diagnostic["counters"]["coverage"], "COMPLETE");
        assert_eq!(diagnostic["counters"]["unknownFormatRecordsTotal"], "0");
        assert_eq!(diagnostic["counters"]["oversizedRecordsTotal"], "0");
        assert!(diagnostic.get("cursor").is_none());
        assert!(diagnostic.get("path").is_none());
        diagnostic["initializedAt"].clone()
    };
    let run_phase = |login_during_service, heartbeat_from, expected_uploads| {
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let service = scope.spawn(|| fixture.run(&stop));
            let _stop_on_failure = StopOnDrop(&stop);
            let heartbeat = fixture.wait_for_caught_up_heartbeat(heartbeat_from);
            if login_during_service {
                login("o04live");
            }
            fixture.wait_for("security-events", expected_uploads);
            stop.store(true, Ordering::Relaxed);
            assert_eq!(service.join().unwrap(), Ok(()));
            heartbeat
        })
    };

    login("o04history");
    fixture.register();
    let first = run_phase(true, 0, 1);
    let initialized_at = diagnostics(&first);
    let prior_heartbeats = fixture.observations("heartbeat").len();
    login("o04offline");
    let restarted = run_phase(false, prior_heartbeats, 2);
    assert_ne!(first["collectorEpoch"], restarted["collectorEpoch"]);
    assert_eq!(initialized_at, diagnostics(&restarted));
    assert_ne!(
        first["sshSourceDiagnostics"]["lastReadAt"],
        restarted["sshSourceDiagnostics"]["lastReadAt"]
    );

    let uploads = fixture.observations("security-events");
    let records: Vec<_> = uploads
        .iter()
        .flat_map(|body| body["events"].as_array().unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["username"], "o04live");
    assert_eq!(records[1]["username"], "o04offline");
    assert_ne!(records[0]["eventId"], records[1]["eventId"]);
    for record in records {
        assert_eq!(record["eventType"], "SSH_LOGIN_SUCCEEDED");
        assert_eq!(record.as_object().unwrap().len(), 6);
    }
    println!("native SSH heartbeat and two ordered uploads passed");
}

#[test]
fn stop_drains_started_request_and_restart_recovers_same_pending_sample() {
    let fixture = Fixture::new("slow-first-metric");
    fixture.register();
    let stop = AtomicBool::new(false);
    let first = std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let metrics = fixture.wait_for("metric", 1);
        let stop_started = Instant::now();
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert!(stop_started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            fixture.manifest()["inflight"]["sampleId"],
            metrics[0]["samples"][0]["sampleId"]
        );
        metrics[0].clone()
    });
    stop.store(false, Ordering::Relaxed);
    std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let metrics = fixture.wait_for("metric", 2);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert_eq!(metrics[1], first);
        let metric_entries = fixture.entries("metric");
        assert_eq!(
            metric_entries[0]["bodySha256"],
            metric_entries[1]["bodySha256"]
        );
        assert!(metric_entries[0]["bodySha256"].is_string());
        assert_eq!(fixture.observations("registration").len(), 1);
        assert_eq!(fixture.observations("identity").len(), 2);
    });
}

#[test]
fn service_refuses_prepared_identity_without_network_or_queue_creation() {
    let fixture = Fixture::new("healthy");
    let state =
        IdentityStore::initialize(&fixture.files.identity, fixture.files.target.clone()).unwrap();
    drop(state);
    assert_eq!(
        fixture.run(&AtomicBool::new(false)),
        Err("IDENTITY_NOT_CONFIRMED")
    );
    assert!(fixture.observations("identity").is_empty());
    assert!(fixture.observations("registration").is_empty());
    assert!(fs::read_dir(&fixture.files.host).unwrap().next().is_none());
    assert!(fs::read_dir(&fixture.files.ssh).unwrap().next().is_none());
}

#[test]
fn service_stops_on_revocation_without_registration_or_reporting() {
    let fixture = Fixture::new("revoked-identity");
    fixture.register();
    assert_eq!(
        fixture.run(&AtomicBool::new(false)),
        Err("CREDENTIAL_REJECTED")
    );
    assert_eq!(fixture.observations("registration").len(), 1);
    assert_eq!(fixture.observations("identity").len(), 1);
    assert!(fixture.observations("heartbeat").is_empty());
    assert!(fixture.observations("metric").is_empty());
    assert_eq!(
        IdentityStore::open(&fixture.files.identity, &fixture.files.target)
            .unwrap()
            .status(),
        Status::NeedsReconnect,
    );
}

#[test]
fn built_in_trust_does_not_accept_fixture_private_ca() {
    let fixture = Fixture::new("healthy");
    fixture.register();
    let mut state = IdentityStore::open(&fixture.files.identity, &fixture.files.target).unwrap();
    let client =
        ProtocolClient::new_for_service(fixture.files.target.clone(), None, Duration::from_secs(2))
            .unwrap();
    assert_eq!(
        client.query_identity(&mut state),
        Err("NETWORK_OR_TLS_ERROR")
    );
    assert_eq!(state.status(), Status::Bound);
    assert!(fixture.observations("identity").is_empty());
}

fn assert_shrink_receipts(receipts: &[Value], manifest: &Value) {
    let [applied, failed] = receipts else {
        panic!("expected recovery and failure")
    };
    assert_eq!(applied["result"], "APPLIED");
    assert_eq!(applied["generation"], 1);
    assert_eq!(applied["sequence"], 1);
    assert_eq!(failed["result"], "FAILED");
    assert_eq!(failed["generation"], 2);
    assert_eq!(failed["sequence"], 2);
    assert_eq!(failed["errorCode"], "RESOURCE_LIMIT");
    assert_eq!(applied["collectorEpoch"], failed["collectorEpoch"]);
    assert_eq!(failed["appliedConfigId"], applied["configId"]);
    assert_eq!(
        manifest["configuration"]["target"]["configId"],
        applied["configId"]
    );
}

#[test]
fn recovered_effective_config_is_confirmed_before_failed_shrink_in_new_epoch() {
    let fixture = Fixture::new("healthy");
    fixture.register();
    fixture.seed_large_queue();
    let stop = AtomicBool::new(false);
    let original_epoch = std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let receipts = fixture.wait_for("receipt", 1);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert_eq!(receipts[0]["result"], "APPLIED");
        receipts[0]["collectorEpoch"].clone()
    });
    fs::write(fixture.directory.path().join("use-smaller"), b"").unwrap();
    stop.store(false, Ordering::Relaxed);
    std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let receipts = fixture.wait_for("receipt", 3);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert!(fixture.observations("rejected-receipt").is_empty());
        assert_ne!(receipts[1]["collectorEpoch"], original_epoch);
        assert_shrink_receipts(&receipts[1..], &fixture.manifest());
    });
}

#[test]
fn lost_applied_ack_replays_exact_receipt_before_failed_shrink() {
    let fixture = Fixture::new("lost-first-receipt-then-shrink");
    fixture.register();
    fixture.seed_large_queue();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let service = scope.spawn(|| fixture.run(&stop));
        let _stop_on_failure = StopOnDrop(&stop);
        let receipts = fixture.wait_for("receipt", 3);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(service.join().unwrap(), Ok(()));
        assert!(fixture.observations("rejected-receipt").is_empty());
        assert_eq!(receipts[0], receipts[1]);
        let entries = fixture.entries("receipt");
        assert_eq!(entries[0]["bodySha256"], entries[1]["bodySha256"]);
        assert_shrink_receipts(&receipts[1..], &fixture.manifest());
    });
}
