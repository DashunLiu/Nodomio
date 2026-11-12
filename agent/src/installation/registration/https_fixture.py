"""Isolated registration fixture using the repository's public test TLS keys."""

import http.server
import json
import pathlib
import socket
import ssl
import sys

root = pathlib.Path(sys.argv[1])
scenario = sys.argv[2]
tls = pathlib.Path(sys.argv[3])
known_credential = None
identity = {
    "agentId": "agent:registration-fixture",
    "serverId": "foreign-server" if scenario == "wrong-server" else "server-1",
    "samplingIntervalSeconds": 30,
    "heartbeatIntervalSeconds": 30,
    "registeredAt": "2026-11-11T00:00:00Z",
    "bindingRevision": 2,
}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        mime = "application/json" if status < 400 else "application/problem+json"
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def reject(self, status, code):
        self.reply(status, {"type": "about:blank", "title": "Fixture", "status": status, "code": code})

    def record(self, name):
        with (root / "requests").open("a", encoding="utf-8") as log:
            log.write(name + "\n")

    def do_POST(self):
        global known_credential
        self.record("POST")
        if (self.path != "/api/agent/v1/registrations"
                or self.headers.get("Authorization") != "Bearer ndme_" + "A" * 43):
            self.reject(401, "ENROLLMENT_EXPIRED")
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw)
        state = json.loads((root / "identity" / "identity.json").read_bytes())
        marker = (root / "registration-possible").read_text(encoding="utf-8")
        if (body.get("expectedServerId") != "server-1"
                or state["credential"] != body.get("agentCredential")
                or state["status"] != "UNCERTAIN" or state["operationId"] != marker):
            self.reject(422, "FIXTURE_ORDER")
            return
        if scenario != "uncommitted":
            known_credential = body["agentCredential"]
        if scenario in ("committed", "uncommitted"):
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.reply(201, identity)

    def do_GET(self):
        self.record("GET")
        if (self.path != "/api/agent/v1/identity" or known_credential is None
                or self.headers.get("Authorization") != "Bearer " + known_credential):
            self.reject(401, "CREDENTIAL_UNKNOWN")
            return
        current = dict(identity)
        if scenario == "revision-changed":
            current["bindingRevision"] = identity["bindingRevision"] + 1
        self.reply(200, current)


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(tls / "server.pem", tls / "server-key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
