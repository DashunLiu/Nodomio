"""Local HTTPS protocol fixture. No Nodomi Go or PostgreSQL integration.
The checked-in private key is public test material, never an installation key.
"""
import hashlib, http.server, json, pathlib, platform, re, socket, ssl, sys, threading, time, uuid
scenario, state = sys.argv[1], pathlib.Path(sys.argv[2])
runtime = scenario.startswith("runtime")
slow_metric = scenario == "runtime-collect-slow-metric"
observations = dict(calls=[])
observations_lock = threading.Lock()
metric_bodies = []

def save_observations():
    payload = json.dumps(observations).encode()
    if metric_bodies:
        # Bodies were validated before admission. Preserve exact JSON numbers
        # instead of rounding or trimming them through Python's float parser.
        payload = payload[:-1] + b',"metricBodies":[' + b','.join(metric_bodies) + b']}'
    (state.parent / "observations.json").write_bytes(payload)

def record(name, body=None):
    if runtime:
        with observations_lock:
            observations["calls"].append(name)
            if body is not None: observations[name] = body
            if slow_metric and name == "heartbeat":
                observations.setdefault("heartbeatTimes", []).append(time.monotonic())
            save_observations()
identity = dict(agentId="agent:fixture", serverId="server-1", samplingIntervalSeconds=30,
                heartbeatIntervalSeconds=30, registeredAt="2026-11-10T00:00:00Z", bindingRevision=2)
config = dict(agentId="agent:fixture", bindingRevision=2, schemaVersion=1,
              target=dict(configId="123e4567-e89b-42d3-a456-426614174000", generation=1,
                          configuration=dict(samplingIntervalSeconds=30, bufferMaxAgeSeconds=86400,
                                             bufferMaxBytes=100000000)))
if scenario == "runtime-collect-resource-limit":
    config["target"]["generation"] = 2
    config["target"]["configuration"]["bufferMaxBytes"] = 1_000_000
credential = None
current_epoch = None
caps=dict(system="AVAILABLE",processes="UNSUPPORTED",containers="UNSUPPORTED",sshEvents="UNSUPPORTED")
updater=dict(platform="linux-aarch64",kernelVersion="6.12",currentReleaseId=None,binarySha256="a"*64,
             protocolVersion=1,selfUpdate="UNSUPPORTED_INSTALLATION",localPhase="IDLE",mode="MANUAL",
             source="GITHUB_RELEASES",localAttemptId=None,trigger=None,targetVersion=None,lastCheckAt=None,
             availableVersion=None,errorCode=None,availableIsSecurityUpdate=None,resultRecordedAt=None,
             updateEventsDroppedTotal=0,buildOrigin="SELF_COMPILED")
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate field")
        result[key]=value
    return result
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def respond(self, status, data, content="application/json", headers=None):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        if scenario=="delayed-headers-drip": time.sleep(.1)
        self.send_response(status)
        self.send_header("Content-Type", content)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.end_headers()
        try:
            if scenario=="delayed-headers-drip":
                for offset in range(0,len(body),8):
                    self.wfile.write(body[offset:offset+8]); self.wfile.flush(); time.sleep(.075)
            else: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass
    def problem(self, status, code, headers=None):
        self.respond(status, dict(type="about:blank", title="Fixture error", status=status,
                                  code=code, requestId="fixture-request"), "application/problem+json", headers)
    def check_auth(self):
        local=json.loads((state / "identity.json").read_text())
        expected=credential or local["credential"]
        assert self.headers.get("Authorization")=="Bearer "+expected
    def body_bytes(self):
        assert self.headers.get("Content-Type")=="application/json"
        limit = {
            "/api/agent/v1/metric-batches": 4194304,
            "/api/agent/v1/security-event-batches": 1048576,
        }.get(self.path, 16384)
        length = int(self.headers["Content-Length"])
        assert 0 < length <= limit
        return self.rfile.read(length)
    def body(self):
        return json.loads(self.body_bytes(), object_pairs_hook=unique)
    def ssh_batch(self):
        assert scenario.startswith("ssh-")
        self.check_auth()
        raw = self.body_bytes()
        body = json.loads(raw, object_pairs_hook=unique)
        assert set(body) == {"events"} and 1 <= len(body["events"]) <= 1000
        for event in body["events"]:
            assert set(event) == {"eventId", "bootId", "occurredAt", "eventType", "sourceIp", "username"}
            uuid.UUID(event["eventId"])
        attempts = observations.setdefault("sshAttempts", [])
        attempts.append(hashlib.sha256(raw).hexdigest())
        (state.parent / "ssh-attempts.json").write_text(json.dumps(attempts))
        result = dict(acceptedCount=len(body["events"]), duplicateCount=0, expiredCount=0,
                      receivedAt="2026-11-10T00:00:00Z")
        if scenario == "ssh-lost-retry":
            if len(attempts) == 1:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            assert attempts[-1] == attempts[0]
            result.update(acceptedCount=0, duplicateCount=len(body["events"]))
        elif scenario == "ssh-mixed":
            assert len(body["events"]) == 3
            result.update(acceptedCount=1, duplicateCount=1, expiredCount=1)
        elif scenario == "ssh-bad-total":
            result.update(acceptedCount=0)
        elif scenario == "ssh-malformed-ack":
            result["eventIds"] = []
        elif scenario == "ssh-array-ack":
            self.respond(200, list(result.values()))
            return
        elif scenario == "ssh-wrong-success":
            self.respond(201, result)
            return
        elif scenario == "ssh-conflict":
            self.problem(409, "SECURITY_EVENT_CONFLICT")
            return
        elif scenario == "ssh-revoked":
            self.problem(401, "AGENT_REVOKED")
            return
        elif scenario == "ssh-redirect":
            self.respond(307, b"", headers={"Location": self.path})
            return
        self.respond(200, result)
    def slow_metric_response(self, attempt_number, attempt, sample_id, result):
        if attempt_number == 2:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                with observations_lock:
                    heartbeat_during_upload = any(
                        instant > attempt["startedAt"] for instant in observations["heartbeatTimes"]
                    )
                if heartbeat_during_upload:
                    durable = json.loads((state.parent / "runtime" / "runtime.json").read_text())
                    latest, inflight = durable["latest"], durable["inflight"]
                    if inflight and inflight["sampleId"] == sample_id and latest and latest["sampleId"] != sample_id:
                        with observations_lock:
                            attempt["latestBeforeAck"] = latest["sampleId"]
                        break
                time.sleep(.025)
        with observations_lock:
            attempt["responseAt"] = time.monotonic()
            save_observations()
        if attempt_number == 1:
            self.problem(429, "RATE_LIMITED", {"Retry-After": "25"})
        else:
            self.respond(200, result)
    def do_POST(self):
        global credential, current_epoch
        try:
            if self.path=="/api/agent/v1/registrations":
                assert self.headers.get("Authorization")=="Bearer ndme_"+"A"*43
                body=self.body()
                assert re.fullmatch(r"ndma_[A-Za-z0-9_-]{43}",body["agentCredential"])
                assert body==dict(agentCredential=body["agentCredential"],version="0.1.0",architecture="ARM64",
                                  distribution="debian",distributionVersion="12",hostname="protocol-fixture",
                                  capabilities=caps,expectedServerId="server-1")
                local=json.loads((state/"identity.json").read_text())
                assert local["credential"]==body["agentCredential"] and local["status"]=="UNCERTAIN"
                credential=body["agentCredential"]
                if scenario=="lost":
                    self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                if scenario=="expired": self.problem(401,"ENROLLMENT_EXPIRED"); return
                result=dict(identity)
                if scenario=="target": result["serverId"]="foreign-server"
                self.respond(201,result)
            elif self.path=="/api/agent/v1/heartbeats":
                self.check_auth(); body=self.body()
                assert str(uuid.UUID(body["collectorEpoch"]))==body["collectorEpoch"]
                assert str(uuid.UUID(body["bootId"]))==body["bootId"]
                expected_updater=dict(updater)
                if runtime:
                    expected_updater.update(platform={"aarch64":"linux-aarch64", "x86_64":"linux-x86_64"}[platform.machine()],kernelVersion=platform.release(),binarySha256=hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest())
                    assert body["bootId"]==pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                assert body==dict(bootId=body["bootId"],version="0.1.0",capabilities=caps,bufferedBytes=(body["bufferedBytes"] if scenario.startswith("runtime-collect") else 0),
                                  discardedSamplesTotal=(body["discardedSamplesTotal"] if scenario.startswith("runtime-collect") else "0"),collectorEpoch=body["collectorEpoch"],updater=expected_updater)
                record("heartbeat", body)
                current_epoch=body["collectorEpoch"]
                if scenario in ["lost-heartbeat", "runtime-lost-heartbeat"]:
                    self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                self.respond(200,dict(receivedAt="2026-11-10T00:00:00Z",samplingIntervalSeconds=30,heartbeatIntervalSeconds=30))
            elif self.path == "/api/agent/v1/security-event-batches":
                self.ssh_batch()
            elif self.path=="/api/agent/v1/metric-batches":
                started_at = time.monotonic()
                self.check_auth()
                raw = self.body_bytes()
                body = json.loads(raw, object_pairs_hook=unique)
                assert scenario.startswith("runtime-collect") and len(body["samples"])==1
                sample=body["samples"][0]
                assert sample["collectorEpoch"]==current_epoch or (scenario=="runtime-collect-retry" and metric_bodies and metric_bodies[0]==raw)
                assert sample["collectionGroup"]==dict(kind="HOST",subjectId=None)
                assert sample["collectionStatus"]=="PARTIAL"
                assert len(set(p["metric"] for p in sample["points"]))==19
                assert not any(p["metric"].endswith("BytesPerSecond") for p in sample["points"])
                uuid.UUID(sample["sampleId"]); uuid.UUID(sample["clockEpoch"])
                assert sample["bootId"]==pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                record("metrics",body)
                with observations_lock:
                    metric_bodies.append(raw)
                    attempt_number = len(metric_bodies)
                    if slow_metric:
                        attempt = dict(bodySHA256=hashlib.sha256(raw).hexdigest(), startedAt=started_at)
                        observations.setdefault("metricAttempts", []).append(attempt)
                    save_observations()
                if scenario=="runtime-collect-lost" or (scenario=="runtime-collect-retry" and attempt_number==1):
                    self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                result=dict(acceptedCount=1,duplicateCount=0,expiredCount=0,receivedAt="2026-11-10T00:00:00Z")
                if scenario=="runtime-collect-invalid-ack": result["acceptedCount"]=0
                if scenario=="runtime-collect-expired-ack": result.update(acceptedCount=0, expiredCount=1)
                if scenario == "runtime-collect-array-ack":
                    self.respond(200, list(result.values())); return
                if scenario == "runtime-collect-revoked":
                    self.problem(401, "AGENT_REVOKED"); return
                if slow_metric:
                    self.slow_metric_response(attempt_number, attempt, sample["sampleId"], result); return
                self.respond(200,result)
            else: self.problem(404,"UNKNOWN_ROUTE")
        except (AssertionError, ValueError, KeyError): self.problem(422,"FIXTURE_CONTRACT_FAILED")
    def do_GET(self):
        try:
            self.check_auth()
            if scenario=="revoked-malformed": self.respond(401,b"SECRET: malformed auth problem"); return
            if scenario=="revoked" or scenario=="expired": self.problem(401,"AGENT_REVOKED"); return
            if scenario=="redirect": self.respond(307,b"",headers={"Location":"https://127.0.0.1:1/stolen"}); return
            if scenario=="malformed": self.respond(200,b"{broken"); return
            if scenario=="oversize": self.respond(200,b"x"*16385); return
            if scenario=="oversize-stream":
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b"x"*16385); return
            if scenario=="headers": self.respond(200,identity,headers={"X-Large":"x"*500000}); return
            if scenario=="slow": time.sleep(.8)
            if self.path=="/api/agent/v1/configuration":
                record("configuration")
                result=dict(config)
                if scenario in ["binding", "runtime-config-binding"]: result["bindingRevision"]=3
                self.respond(200,result)
            elif self.path=="/api/agent/v1/identity":
                record("identity")
                result=dict(identity)
                if scenario=="binding": result["bindingRevision"]=3
                if scenario=="target": result["serverId"]="foreign-server"
                self.respond(200,result)
            else: self.problem(404,"UNKNOWN_ROUTE")
        except (AssertionError,ValueError,KeyError): self.problem(422,"FIXTURE_CONTRACT_FAILED")
    def do_PUT(self):
        try:
            self.check_auth(); assert self.path=="/api/agent/v1/configuration-receipts"
            body=self.body()
            assert set(body)==set("configId generation bindingRevision collectorEpoch sequence result appliedConfigId errorCode".split())
            assert body["bindingRevision"]==2 and body["generation"]==config["target"]["generation"]
            assert body["configId"]==config["target"]["configId"] and body["collectorEpoch"]==current_epoch
            assert type(body["sequence"]) is int and 1<=body["sequence"]<=9007199254740991
            if scenario=="runtime-collect-write-failed":
                assert body["result"]=="FAILED" and body["appliedConfigId"] is None and body["errorCode"]=="LOCAL_STORAGE_ERROR"
            elif scenario=="runtime-collect-resource-limit":
                assert body["result"]=="FAILED" and body["appliedConfigId"] is None and body["errorCode"]=="RESOURCE_LIMIT"
            elif scenario.startswith("runtime-collect"):
                assert body["result"]=="APPLIED" and body["appliedConfigId"]==config["target"]["configId"] and body["errorCode"] is None
                durable=json.loads((state.parent/"runtime"/"runtime.json").read_text())
                assert durable["configuration"]==config
            else:
                assert body["result"]=="FAILED" and body["appliedConfigId"] is None
                assert body["errorCode"]=="UNSUPPORTED_CONFIGURATION"
            record("receipt", body)
            if scenario=="runtime-receipt-rejected": self.problem(409,"RECEIPT_CONFLICT"); return
            self.respond(204,b"")
        except (AssertionError,ValueError,KeyError): self.problem(422,"FIXTURE_CONTRACT_FAILED")
server_class = http.server.ThreadingHTTPServer if slow_metric else http.server.HTTPServer
server=server_class(("127.0.0.1",0),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls=pathlib.Path(__file__).parent/"tls"
ctx.load_cert_chain(tls/"server.pem",tls/"server-key.pem")
server.socket=ctx.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True)
server.serve_forever()
