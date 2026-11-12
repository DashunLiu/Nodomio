use super::*;
use crate::runtime::StoredSample;
use std::{
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
};

// These keys are the repository's local TLS fixture, not installation material.
const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
const RESPONSES: &str = r#"
import http.server, json, pathlib, ssl, sys

tls = pathlib.Path(sys.argv[1])
responses = iter(json.loads(sys.argv[2]))

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        assert self.path == '/api/agent/v1/metric-batches'
        assert self.headers['Authorization'].startswith('Bearer ndma_')
        request = self.rfile.read(int(self.headers['Content-Length']))
        assert len(json.loads(request)['samples']) == 1
        status, content_type, body, retry_after = next(responses)
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        if retry_after is not None:
            self.send_header('Retry-After', retry_after)
        self.end_headers()
        self.wfile.write(data)

server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(tls / 'server.pem', tls / 'server-key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
"#;

struct Fixture(Child);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Fixture {
    fn start(responses: serde_json::Value) -> (Self, Target, ProtocolClient) {
        let child = Command::new("python3")
            .args(["-c", RESPONSES, TLS, &responses.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut fixture = Self(child);
        let mut line = String::new();
        BufReader::new(fixture.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line.trim().parse::<u16>().expect("TLS fixture port");
        let target = Target::new(&format!("https://localhost:{port}"), "fixture-server").unwrap();
        let ca = std::fs::read(Path::new(TLS).join("ca.pem")).unwrap();
        let client =
            ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(2)).unwrap();
        (fixture, target, client)
    }
}

fn identity(target: &Target) -> (tempfile::TempDir, IdentityStore) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
    store
        .confirm(Binding {
            agent_id: "fixture-agent".into(),
            server_id: target.expected_server_id.clone(),
            binding_revision: 1,
        })
        .unwrap();
    (dir, store)
}

fn sample() -> StoredSample {
    let sample_id = "dc6f272f-e17f-4a5a-ae56-f2760279d423";
    let boot_id = "dc6f272f-e17f-4a5a-ae56-f2760279d424";
    StoredSample {
        sample_id: sample_id.into(),
        boot_id: boot_id.into(),
        monotonic_ns: 1_000_000_000,
        body: serde_json::json!({
            "sampleId":sample_id,"bootId":boot_id,"monotonicSeconds":1,
            "collectionGroup":{"kind":"HOST","subjectId":null},"collectionStatus":"PARTIAL",
            "observedAt":"2026-11-10T00:00:00Z","collectorEpoch":boot_id,"clockEpoch":boot_id,
            "points":[{"metric":"system.load1","labels":{},"value":0,"availability":"AVAILABLE"}]
        })
        .to_string(),
    }
}

#[test]
fn binding_rejection_requires_current_owner_and_authoritative_problem() {
    use serde_json::json;
    let missing = json!({"type":"about:blank","title":"Not found","status":404,
        "code":"RESOURCE_NOT_FOUND","requestId":"fixture-request"});
    let route_missing = json!({"type":"about:blank","title":"Not found","status":404,
        "code":"NOT_FOUND","requestId":"fixture-request"});
    let (_fixture, target, client) = Fixture::start(json!([
        [404, "application/problem+json", route_missing, null],
        [
            404,
            "application/problem+json",
            [
                "about:blank",
                "Not found",
                404,
                null,
                "RESOURCE_NOT_FOUND",
                "fixture-request",
                null
            ],
            null
        ],
        [404, "application/problem+json", missing, null],
        [404, "application/problem+json", missing, null]
    ]));
    let (dir, mut owner) = identity(&target);
    let (_other_dir, mut other) = identity(&target);
    let sample = sample();
    let send = |owner: &IdentityStore| {
        let upload = client.prepare_metric_upload(owner, &sample).unwrap();
        std::thread::spawn(move || upload.send()).join().unwrap()
    };
    for _ in 0..2 {
        let completed = send(&owner);
        assert!(matches!(
            client.finish_metric_upload(&mut owner, completed),
            Ok(MetricUploadOutcome::Failed {
                terminal: false,
                ..
            })
        ));
        assert_eq!(owner.status(), Status::Bound);
    }
    assert!(matches!(
        client.finish_metric_upload(&mut other, send(&owner)),
        Err("IDENTITY_MISMATCH")
    ));
    assert_eq!(other.status(), Status::Bound);
    let completed = send(&owner);
    assert_eq!(owner.status(), Status::Bound);
    assert!(matches!(
        client.finish_metric_upload(&mut owner, completed),
        Ok(MetricUploadOutcome::Failed {
            code: "CREDENTIAL_REJECTED",
            terminal: true,
            ..
        })
    ));
    drop(owner);
    assert_eq!(
        IdentityStore::open(dir.path(), &target).unwrap().status(),
        Status::NeedsReconnect
    );
}

#[test]
fn retry_after_survives_bad_maintenance_body_and_decimal_overflow() {
    use serde_json::json;
    let (_fixture, target, client) = Fixture::start(json!([
        [503, "text/plain", "maintenance", "25"],
        [
            503,
            "application/problem+json",
            null,
            "18446744073709551616"
        ],
        [
            429,
            "application/problem+json",
            null,
            "Tue, 10 Nov 2026 01:00:00 GMT"
        ],
        [413, "text/plain", "body too large", null]
    ]));
    let (_dir, mut owner) = identity(&target);
    for (expected_retry, expected_terminal) in [
        (Some(Duration::from_secs(25)), false),
        (Some(Duration::MAX), false),
        (None, false),
        (None, true),
    ] {
        let completed = client
            .prepare_metric_upload(&owner, &sample())
            .unwrap()
            .send();
        assert!(matches!(
            client.finish_metric_upload(&mut owner, completed),
            Ok(MetricUploadOutcome::Failed { retry_after, terminal, .. })
                if retry_after == expected_retry && terminal == expected_terminal
        ));
        assert_eq!(owner.status(), Status::Bound);
    }
}
