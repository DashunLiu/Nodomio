use super::*;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
};

const BODY: &[u8] = b" {\"events\":[{}, {}, {}]}\n";
const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
const SERVER: &str = r#"
import http.server, json, pathlib, ssl, sys

tls = pathlib.Path(sys.argv[1])
responses = iter(json.loads(sys.argv[2]))
expected = sys.argv[3].encode()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        assert self.path == '/api/agent/v1/security-event-batches'
        assert self.headers['Authorization'].startswith('Bearer ndma_')
        assert self.rfile.read(int(self.headers['Content-Length'])) == expected
        status, mime, body, retry = next(responses)
        if status == 0:
            self.close_connection = True
            return
        data = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        if retry is not None:
            self.send_header('Retry-After', retry)
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

fn fixture(responses: &[Value]) -> (Fixture, Target, ProtocolClient) {
    let mut fixture = Fixture(
        Command::new("python3")
            .args([
                "-c",
                SERVER,
                TLS,
                &serde_json::to_string(responses).unwrap(),
                std::str::from_utf8(BODY).unwrap(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(fixture.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port = line.trim().parse::<u16>().expect("TLS fixture port");
    let target = Target::new(&format!("https://localhost:{port}"), "fixture-server").unwrap();
    let ca = std::fs::read(Path::new(TLS).join("ca.pem")).unwrap();
    let client = ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(2)).unwrap();
    (fixture, target, client)
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

fn problem(status: u16, code: &str) -> Value {
    json!([
        status,
        "application/problem+json",
        json!({"type":"about:blank","title":"Fixture","status":status,"code":code,
            "requestId":"fixture-request"})
        .to_string(),
        null
    ])
}

fn send(client: &ProtocolClient, owner: &IdentityStore) -> SecurityEventUploadCompletion {
    let upload = client
        .prepare_security_event_upload(owner, BODY, 3)
        .unwrap();
    std::thread::spawn(move || upload.send()).join().unwrap()
}

fn assert_failure(
    outcome: SecurityEventUploadOutcome,
    expected: (&str, Option<Duration>, bool, Option<SecurityEventRejection>),
) {
    let SecurityEventUploadOutcome::Failed {
        code,
        retry_after,
        terminal,
        rejection,
    } = outcome
    else {
        panic!("unexpected SSH acknowledgement");
    };
    assert_eq!((code, retry_after, terminal, rejection), expected);
}

#[test]
fn only_known_object_rejections_authorize_isolation() {
    let mut mismatched = problem(400, "JSON_INVALID");
    mismatched[0] = json!(422);
    let array_problem = json!([
        "about:blank",
        "Fixture",
        422,
        null,
        "INPUT_INVALID",
        "fixture-request",
        null
    ]);
    let (_fixture, target, client) = fixture(&[
        problem(400, "JSON_INVALID"),
        problem(422, "INPUT_INVALID"),
        problem(413, "BODY_TOO_LARGE"),
        problem(409, "SECURITY_EVENT_CONFLICT"),
        problem(400, "AUTHENTICATION_AMBIGUOUS"),
        problem(400, "JSON_REQUIRED"),
        json!([
            422,
            "application/problem+json",
            array_problem.to_string(),
            null
        ]),
        mismatched,
        json!([413, "text/html", "proxy error", null]),
    ]);
    let (_dir, mut owner) = identity(&target);
    use SecurityEventRejection::*;
    for (code, reason) in [
        ("REMOTE_REQUEST_REJECTED", Some(Invalid)),
        ("REMOTE_REQUEST_REJECTED", Some(Invalid)),
        ("REMOTE_REQUEST_REJECTED", Some(TooLarge)),
        ("REMOTE_REQUEST_REJECTED", Some(Conflict)),
        ("REMOTE_REQUEST_REJECTED", None),
        ("REMOTE_REQUEST_REJECTED", None),
        ("REMOTE_REQUEST_REJECTED", None),
        ("INVALID_PROTOCOL", None),
        ("INVALID_PROTOCOL", None),
    ] {
        let completed = send(&client, &owner);
        assert_failure(
            client
                .finish_security_event_upload(&mut owner, completed)
                .unwrap(),
            (code, None, false, reason),
        );
        assert_eq!(owner.status(), Status::Bound);
    }
}

#[test]
fn rejection_is_persisted_only_by_the_authorizing_operation() {
    let (_fixture, target, client) = fixture(&[
        problem(404, "NOT_FOUND"),
        problem(404, "RESOURCE_NOT_FOUND"),
        problem(404, "RESOURCE_NOT_FOUND"),
        json!([401, "text/plain", "authorization rejected", null]),
        json!([403, "text/plain", "authorization rejected", null]),
    ]);
    let (dir, mut owner) = identity(&target);
    let (_other_dir, mut other) = identity(&target);
    let route_missing = send(&client, &owner);
    assert_failure(
        client
            .finish_security_event_upload(&mut owner, route_missing)
            .unwrap(),
        ("REMOTE_REQUEST_REJECTED", None, false, None),
    );
    assert!(matches!(
        client.finish_security_event_upload(&mut other, send(&client, &owner)),
        Err("IDENTITY_MISMATCH")
    ));
    assert_eq!(other.status(), Status::Bound);
    let rejected = send(&client, &owner);
    assert_failure(
        client
            .finish_security_event_upload(&mut owner, rejected)
            .unwrap(),
        ("CREDENTIAL_REJECTED", None, true, None),
    );
    drop(owner);
    assert_eq!(
        IdentityStore::open(dir.path(), &target).unwrap().status(),
        Status::NeedsReconnect
    );
    for _ in 0..2 {
        let (_dir, mut owner) = identity(&target);
        let completed = send(&client, &owner);
        assert_failure(
            client
                .finish_security_event_upload(&mut owner, completed)
                .unwrap(),
            ("CREDENTIAL_REJECTED", None, true, None),
        );
        assert_eq!(owner.status(), Status::NeedsReconnect);
    }
}

#[test]
fn bad_ack_and_transport_failures_do_not_authorize_isolation() {
    let valid_ack = json!({"acceptedCount":1,"duplicateCount":1,"expiredCount":1,"receivedAt":"2026-11-11T00:00:00Z"}).to_string();
    let (_fixture, target, client) = fixture(&[
        json!([
            200,
            "application/json",
            "[1,1,1,\"2026-11-11T00:00:00Z\"]",
            null
        ]),
        json!([
            200,
            "application/json",
            "{\"acceptedCount\":3,\"duplicateCount\":1,\"expiredCount\":0,\"receivedAt\":\"2026-11-11T00:00:00Z\"}",
            null
        ]),
        json!([503, "application/problem+json", "invalid JSON", "25"]),
        json!([
            429,
            "application/problem+json",
            "invalid JSON",
            "100000000000000000000"
        ]),
        json!([0, "", "", null]),
        json!([200, "application/json", valid_ack, null]),
    ]);
    let (_dir, mut owner) = identity(&target);
    for (code, retry) in [
        ("INVALID_SECURITY_EVENT_ACK", None),
        ("INVALID_SECURITY_EVENT_ACK", None),
        ("INVALID_PROTOCOL", Some(Duration::from_secs(25))),
        ("INVALID_PROTOCOL", Some(Duration::MAX)),
        ("NETWORK_OR_TLS_ERROR", None),
    ] {
        let completed = send(&client, &owner);
        assert_failure(
            client
                .finish_security_event_upload(&mut owner, completed)
                .unwrap(),
            (code, retry, false, None),
        );
        assert_eq!(owner.status(), Status::Bound);
    }
    assert!(matches!(
        client.prepare_security_event_upload(&owner, BODY, 2),
        Err("INVALID_SECURITY_EVENT_BATCH")
    ));
    let ack = client.security_events(&mut owner, BODY, 3).unwrap();
    assert_eq!(
        (ack.accepted_count, ack.duplicate_count, ack.expired_count),
        (1, 1, 1)
    );
}
