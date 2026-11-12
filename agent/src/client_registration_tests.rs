use super::*;
use std::{
    fs::{self, Permissions},
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
};

const DEPLOYMENT: &str = "6dc0a032-3f68-42ae-9dd9-14dc1a41ab01";
const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
const FIXTURE: &str = r#"
import http.server, json, pathlib, ssl, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        server = body['expectedServerId']
        matches = ((server == 'official' and body.get('expectedDeploymentId') == sys.argv[2])
                   or (server == 'legacy' and 'expectedDeploymentId' not in body))
        if (self.path != '/api/agent/v1/registrations' or not matches
                or self.headers.get_all('Authorization') != ['Bearer ndme_' + 'A' * 43]):
            self.send_error(400)
            return
        result = json.dumps({'agentId': 'fixture-agent', 'serverId': server,
            'samplingIntervalSeconds': 30, 'heartbeatIntervalSeconds': 30,
            'registeredAt': '2026-11-11T00:00:00Z', 'bindingRevision': 2}).encode()
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)

server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
tls = pathlib.Path(sys.argv[1])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(tls / 'server.pem', tls / 'server-key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
"#;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn metadata() -> RegistrationMetadata {
    RegistrationMetadata {
        version: "0.1.0".into(),
        architecture: Architecture::Arm64,
        distribution: "Debian".into(),
        distribution_version: "12".into(),
        hostname: "fixture".into(),
        capabilities: Capabilities {
            system: Capability::Available,
            processes: Capability::Unsupported,
            containers: Capability::Unsupported,
            ssh_events: Capability::Unsupported,
        },
    }
}

#[test]
fn official_registration_sends_exact_deployment_legacy_keeps_its_wire_shape() {
    let child = Command::new("python3")
        .args(["-c", FIXTURE, TLS, DEPLOYMENT])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    let mut line = String::new();
    BufReader::new(server.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port: u16 = line.trim().parse().unwrap();
    let ca = fs::read(Path::new(TLS).join("ca.pem")).unwrap();
    let root = tempfile::tempdir().unwrap();
    let token = root.path().join("token");
    fs::write(&token, format!("ndme_{}", "A".repeat(43))).unwrap();
    fs::set_permissions(&token, Permissions::from_mode(0o400)).unwrap();
    let enrollment = Enrollment::from_private_file(&token).unwrap();
    fs::remove_file(token).unwrap();

    for name in ["official", "legacy"] {
        let target = Target::new(&format!("https://localhost:{port}"), name).unwrap();
        let client =
            ProtocolClient::new(target.clone(), Some(&ca), Duration::from_secs(2)).unwrap();
        let dir = root.path().join(name);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o700)).unwrap();
        let mut state = IdentityStore::initialize(&dir, target).unwrap();
        let metadata = metadata();
        let identity = if name == "official" {
            assert_eq!(
                client.register_for_deployment(
                    &mut state,
                    &enrollment,
                    &metadata,
                    "not-a-deployment"
                ),
                Err("INVALID_DEPLOYMENT_ID")
            );
            assert_eq!(state.status(), Status::Prepared);
            client.register_for_deployment(&mut state, &enrollment, &metadata, DEPLOYMENT)
        } else {
            client.register(&mut state, &enrollment, &metadata)
        }
        .unwrap();
        assert_eq!(identity.server_id, name);
        assert_eq!(state.status(), Status::Bound);
    }
}
