"""Loopback HTTPS fixture for the sustained Linux Agent service tests."""
import copy
import hashlib
import http.server
import json
import os
import pathlib
import socket
import ssl
import sys
import threading
import time

root = pathlib.Path(sys.argv[1])
port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
scenario = sys.argv[3] if len(sys.argv) > 3 else "healthy"
observations = []
lock = threading.Lock()
credential = None
service_start_reboot = scenario in ("reboot-service-start-before", "reboot-service-start-after")
reboot_fixture = scenario == "reboot-registration" or service_start_reboot
fixture_deployment_id = "6dc0a032-3f68-42ae-9dd9-14dc1a41ab01"
credential_path = root / "fixture-backend-credential"
if reboot_fixture and credential_path.exists():
    credential = credential_path.read_text(encoding="ascii")
    observations = json.loads((root / "service-observations.json").read_text(encoding="utf-8"))
identity = dict(agentId="agent:fixture", serverId="server-1", samplingIntervalSeconds=5,
                heartbeatIntervalSeconds=30, registeredAt="2026-11-11T00:00:00Z", bindingRevision=2)
configuration = dict(agentId=identity["agentId"], bindingRevision=2, schemaVersion=1,
                     target=dict(configId="123e4567-e89b-42d3-a456-426614174000", generation=1,
                                 configuration=dict(samplingIntervalSeconds=5,
                                                    bufferMaxAgeSeconds=86400,
                                                    bufferMaxBytes=100_000_000)))
smaller = copy.deepcopy(configuration)
smaller["target"].update(configId="123e4567-e89b-42d3-a456-426614174001", generation=2)
smaller["target"]["configuration"]["bufferMaxBytes"] = 1_000_000
receipt_lock = threading.Lock()
collector_epoch = None
applied_id = None
receipts = {}
use_smaller = False


def record(kind, body=None, body_sha256=None):
    with lock:
        observations.append(dict(kind=kind, body=body, bodySha256=body_sha256))
        next_file = root / "service-observations.next"
        next_file.write_text(json.dumps(observations), encoding="utf-8")
        next_file.replace(root / "service-observations.json")
        return sum(item["kind"] == kind for item in observations)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=None):
        payload = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            mime = "application/json" if status < 400 else "application/problem+json"
            self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def reject(self, status, code):
        self.reply(status, dict(type="about:blank", title="Fixture", status=status, code=code))

    def check_auth(self):
        return credential is not None and self.headers.get("Authorization") == "Bearer " + credential

    def read_body(self):
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size)
        self.body_sha256 = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    def do_GET(self):
        if reboot_fixture and self.path == "/api/agent/v1/enrollment-target?expectedServerId=server-1":
            if credential is not None or self.headers.get("Authorization") != "Bearer ndme_" + "A" * 43:
                self.reject(401, "ENROLLMENT_EXPIRED")
                return
            record("enrollment-target")
            self.reply(200, dict(deploymentId=fixture_deployment_id, serverId="server-1",
                                 bindingRevision=1))
        elif not self.check_auth():
            self.reject(401, "AGENT_REVOKED")
        elif self.path == "/api/agent/v1/identity":
            record("identity")
            if scenario == "revoked-identity":
                self.reject(401, "AGENT_REVOKED")
            else:
                self.reply(200, identity)
        elif self.path == "/api/agent/v1/configuration":
            record("configuration")
            self.reply(200, smaller if use_smaller or (root / "use-smaller").exists() else configuration)
        else:
            self.reject(404, "UNKNOWN_ROUTE")

    def do_POST(self):
        global credential, collector_epoch, applied_id
        if self.path == "/api/agent/v1/registrations":
            if service_start_reboot:
                record("registration-attempt")
                if credential is not None:
                    self.reject(401, "ENROLLMENT_EXPIRED")
                    return
            if self.headers.get("Authorization") != "Bearer ndme_" + "A" * 43:
                self.reject(401, "ENROLLMENT_EXPIRED")
                return
            body = self.read_body()
            if reboot_fixture and body.get("expectedDeploymentId") != fixture_deployment_id:
                self.reject(422, "TARGET_MISMATCH")
                return
            credential = body["agentCredential"]
            if reboot_fixture:
                with os.fdopen(os.open(credential_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="ascii") as saved:
                    saved.write(credential)
                    saved.flush()
                    os.fsync(saved.fileno())
                directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            record("registration")
            if scenario == "lost-registration-response":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if scenario in ("hold-registration-response", "reboot-registration"):
                time.sleep(30)
            self.reply(201, identity)
        elif not self.check_auth():
            self.reject(401, "AGENT_REVOKED")
        elif self.path == "/api/agent/v1/heartbeats":
            body = self.read_body()
            with receipt_lock:
                if collector_epoch != body["collectorEpoch"]:
                    collector_epoch = body["collectorEpoch"]
                    applied_id = None
                    receipts.clear()
            record("heartbeat", body)
            self.reply(200, dict(receivedAt=identity["registeredAt"],
                                 samplingIntervalSeconds=5, heartbeatIntervalSeconds=30))
        elif self.path == "/api/agent/v1/metric-batches":
            body = self.read_body()
            if scenario == "reboot-service-start-before":
                record("held-metric", body, self.body_sha256)
                # The guest is cut with this request visible but without an ACK.
                # Keep the wait bounded in case the host harness stops early.
                time.sleep(30)
                self.reject(503, "FIXTURE_ACK_HELD")
                return
            count = record("metric", body, self.body_sha256)
            if scenario == "slow-first-metric" and count == 1:
                time.sleep(1)
            self.reply(200, dict(acceptedCount=1, duplicateCount=0, expiredCount=0,
                                 receivedAt=identity["registeredAt"]))
        elif (self.path == "/api/agent/v1/security-event-batches"
              and scenario == "native-journal"):
            body = self.read_body()
            record("security-events", body, self.body_sha256)
            self.reply(200, dict(acceptedCount=len(body["events"]), duplicateCount=0, expiredCount=0,
                                 receivedAt=identity["registeredAt"]))
        else:
            self.reject(404, "UNKNOWN_ROUTE")

    def do_PUT(self):
        global applied_id, use_smaller
        if not self.check_auth():
            self.reject(401, "AGENT_REVOKED")
        elif self.path == "/api/agent/v1/configuration-receipts":
            body = self.read_body()
            with receipt_lock:
                target = (configuration, smaller)[body["configId"] == smaller["target"]["configId"]]["target"]
                sequence = body["sequence"]
                actual = body["appliedConfigId"]
                valid = (body["collectorEpoch"] == collector_epoch and
                         body["configId"] == target["configId"] and
                         body["generation"] == target["generation"])
                if sequence in receipts:
                    valid = valid and receipts[sequence] == body
                elif sequence > max(receipts, default=0):
                    if body["result"] == "APPLIED":
                        valid = valid and actual == body["configId"]
                    else:
                        valid = valid and actual == applied_id
                    if valid:
                        applied_id = actual
                if valid:
                    receipts[sequence] = body
                count = record("receipt" if valid else "rejected-receipt", body, self.body_sha256)
                if scenario == "lost-first-receipt-then-shrink" and count == 1:
                    use_smaller = True
            if not valid:
                self.reject(409, "CONFIGURATION_RECEIPT_CONFLICT")
                return
            if scenario in ("lost-first-receipt", "lost-first-receipt-then-shrink") and count == 1:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.reply(204)
        else:
            self.reject(404, "UNKNOWN_ROUTE")


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
tls = pathlib.Path(__file__).parent / "tls"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(tls / "server.pem", tls / "server-key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
