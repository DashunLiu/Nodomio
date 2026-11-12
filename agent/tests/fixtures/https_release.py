"""Serve fictional GitHub release responses over local TLS using public test keys."""

import hashlib
import http.server
import json
import pathlib
import ssl
import sys
import threading
import time
import uuid
from urllib.parse import parse_qs, urlsplit

SCENARIO = sys.argv[1]
STATE = pathlib.Path(sys.argv[2])
PLATFORM = sys.argv[3] if len(sys.argv) > 3 else "linux-aarch64"
OWNER = "DashunLiu"
REPOSITORY = "Nodomio"
REPO = f"{OWNER}/{REPOSITORY}"
API = "/repos/" + REPO
CDN = "https://release-assets.githubusercontent.com"
artifact_file = STATE / "artifact.tar.gz"
ARTIFACT = artifact_file.read_bytes() if artifact_file.exists() else b"nodomi arm64 release fixture\n"
COMMIT = (
    "abcdef1234567890abcdef1234567890abcdef12"
    if SCENARIO == "binding-source-commit"
    else "1234567890abcdef1234567890abcdef12345678"
)
TAG_OBJECT = "fedcba0987654321fedcba0987654321fedcba09"
MIME_JSON = "application/json"
MIME_BINARY = "application/octet-stream"
ARTIFACT_IDS = {122: 452, 123: 556 if SCENARIO == "binding-program-id" else 456}
MANIFEST_IDS = {122: 453, 123: 557 if SCENARIO == "binding-manifest-id" else 457}
RELEASE_BY_MANIFEST_ID = {asset_id: release_id for release_id, asset_id in MANIFEST_IDS.items()}
RECORD_LOCK = threading.Lock()
EXACT_READS = {}


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def release(release_id):
    tags = {
        122: "agent-v0.0.9",
        123: "agent-v0.1.0",
        124: "system-v8.0.0",
    }
    return {
        "id": release_id,
        "tag_name": tags[release_id],
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "published_at": "2026-11-11T02:04:05Z",
        "target_commitish": "fixture-main",
    }


def artifact_name(release_id):
    version = release(release_id)["tag_name"].removeprefix("agent-v")
    return f"nodomi-agent-{version}-{PLATFORM}.tar.gz"


def manifest(release_id):
    tag = release(release_id)["tag_name"]
    version = tag.removeprefix("agent-v")
    major, minor, patch = map(int, version.split("."))
    business_id = uuid.uuid5(
        uuid.NAMESPACE_URL, f"https://github.com/{REPO}/releases/{release_id}"
    )
    result = json_bytes({
        "length": len(ARTIFACT),
        "hashes": {"sha256": sha256(ARTIFACT)},
        "custom": {
            "nodomi": {
                "schemaVersion": 1,
                "component": "AGENT",
                "releaseId": str(business_id),
                "sequence": 1 + major * 10_000_000_000 + minor * 100_000 + patch,
                "version": version,
                "channel": "STABLE",
                "platform": PLATFORM,
                "isSecurityUpdate": False,
                "status": "WITHDRAWN" if SCENARIO == "withdrawn" else "ACTIVE",
                "compatibility": {
                    "wireProtocols": [1],
                    "supervisorProtocols": [1],
                    "readConfigFormats": [1],
                    "writeConfigFormat": 1,
                    "readQueueFormats": [1],
                    "writeQueueFormat": 1,
                    "minKernel": (
                        "9.0.0"
                        if SCENARIO == "incompatible" and release_id == 123
                        else "5.4.0"
                    ),
                    "libc": "STATIC",
                    "minLibcVersion": None,
                },
                "github": {
                    "owner": OWNER,
                    "repo": REPOSITORY,
                    "releaseId": release_id,
                    "assetId": ARTIFACT_IDS[release_id] + (SCENARIO == "manifest-mismatch"),
                    "assetName": artifact_name(release_id),
                },
            },
        },
    })
    if SCENARIO == "manifest-too-large":
        return result.ljust(64 * 1024 + 1)
    if SCENARIO == "binding-manifest-bytes":
        # Preserve all parsed values and the byte count while changing the raw digest.
        return json_bytes(dict(reversed(list(json.loads(result).items()))))
    return result


def asset(asset_id, name, data):
    return {
        "id": asset_id,
        "name": name,
        "size": len(data),
        "state": "uploaded",
        "digest": f"sha256:{sha256(data)}",
        "url": f"https://api.github.com{API}/releases/assets/{asset_id}",
    }


def release_assets(release_id, read_number):
    artifact_id = ARTIFACT_IDS[release_id]
    name = artifact_name(release_id)
    package = asset(artifact_id, name, ARTIFACT)
    record = asset(
        MANIFEST_IDS[release_id], name.removesuffix(".tar.gz") + ".release.json", manifest(release_id)
    )
    if SCENARIO == "digest-missing":
        del package["digest"]
    if SCENARIO == "asset-changed" and read_number > 1:
        package = asset(556, name, ARTIFACT)
    assets = [package, record]
    if SCENARIO == "too-many-assets":
        assets.extend(asset(1000 + i, f"extra-{i}.txt", b"x") for i in range(15))
    return assets


def link(page, host="api.github.com", path=API):
    return f'<https://{host}{path}/releases?per_page=100&page={page}>; rel="next"'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def respond(self, status, data=b"", *, mime=MIME_JSON, headers=None, delay=0,
                stall_body=False, trickle=False, chunked=False):
        body = data if isinstance(data, bytes) else json_bytes(data)
        if delay:
            time.sleep(delay)
        try:
            self.send_response(status)
            self.send_header("Content-Type", mime)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if stall_body:
                self.wfile.write(body[:1])
                self.wfile.flush()
                time.sleep(3)
                self.wfile.write(body[1:])
            elif trickle:
                for offset in range(0, len(body), 16):
                    self.wfile.write(body[offset:offset + 16])
                    self.wfile.flush()
                    time.sleep(0.12)
            elif chunked:
                # No Content-Length. Overrun is observable only after reading the stream.
                for chunk in (body[:len(ARTIFACT)], body[len(ARTIFACT):]):
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def redirect(self, location, delay=0):
        self.respond(
            302,
            headers={"Location": location, "Set-Cookie": "fixture=must-not-be-forwarded"},
            delay=delay,
        )

    def record_request(self, path):
        credential_headers = {
            "authorization", "proxy-authorization", "cookie", "x-api-key",
            "x-agent-credential", "x-enrollment-token",
        }
        credentials = sorted(credential_headers.intersection(key.lower() for key in self.headers))
        with RECORD_LOCK:
            with (STATE / "requests.jsonl").open("a") as log:
                log.write(json.dumps({
                    "method": self.command, "path": self.path, "credentials": credentials,
                }) + "\n")
            read_number = EXACT_READS.get(path, 0) + 1
            EXACT_READS[path] = read_number
        return credentials, read_number

    def reject_write(self):
        self.record_request(urlsplit(self.path).path)
        self.respond(405, {"message": "release fixture accepts reads only"})

    do_POST = do_PUT = do_PATCH = do_DELETE = reject_write

    def do_HEAD(self):
        credentials, _ = self.record_request(urlsplit(self.path).path)
        if SCENARIO == "tls-probe" and self.path == "/" and not credentials:
            self.redirect("/fixture/redirect/must-not-follow")
        else:
            self.respond(405)

    def do_GET(self):
        parsed = urlsplit(self.path)
        credentials, read_number = self.record_request(parsed.path)
        if SCENARIO == "authenticated-redirect" and self.path == f"{API}/releases/assets/456":
            if (credentials == ["authorization"]
                    and self.headers.get("Authorization") == "Bearer fixture-read-token"
                    and self.headers.get("Accept") == MIME_BINARY
                    and self.headers.get("Referer") is None):
                self.redirect(f"{CDN}/fixture/redirect/package?signature=fixture")
            else:
                self.respond(401)
            return
        if credentials or self.headers.get("Referer") is not None:
            self.respond(400, {"message": "credential header reached release fixture"})
            return

        path = parsed.path
        if path == API:
            self.respond(200, {
                "id": 987654, "name": REPOSITORY, "full_name": REPO, "private": False,
                "owner": {"login": OWNER},
            })
        elif path == f"{API}/releases":
            self.catalog(parsed.query)
        elif path == f"{API}/releases/latest":
            self.respond(200, release(124))
        elif path in (f"{API}/releases/122", f"{API}/releases/123", f"{API}/releases/124"):
            self.exact_release(int(path.rsplit("/", 1)[-1]), read_number)
        elif path.startswith(f"{API}/releases/") and path.endswith("/assets"):
            release_id = int(path.split("/")[-2])
            if release_id not in ARTIFACT_IDS or parse_qs(parsed.query) != {"per_page": ["100"]}:
                self.respond(404)
            else:
                self.respond(
                    200, release_assets(release_id, read_number),
                    headers=(
                        {"Link": f'<https://api.github.com{path}?per_page=100&page=2>; rel="next"'}
                        if SCENARIO == "asset-list-next"
                        else None
                    ),
                    delay=0.24 if SCENARIO == "control-deadline" else 0,
                )
        elif path.startswith(f"{API}/releases/assets/"):
            self.binary(int(path.rsplit("/", 1)[-1]))
        elif path.startswith(f"{API}/git/ref/tags/"):
            tag = path.rsplit("/", 1)[-1]
            tag_object = (
                {"type": "commit", "sha": COMMIT}
                if tag == "agent-v0.0.9"
                else {"type": "tag", "sha": TAG_OBJECT}
            )
            self.respond(200, {
                "ref": f"refs/tags/{tag}",
                "object": tag_object,
            })
        elif path == f"{API}/git/tags/{TAG_OBJECT}":
            self.respond(200, {
                "sha": TAG_OBJECT,
                "object": {"type": "commit", "sha": COMMIT},
            })
        elif path.startswith("/fixture/redirect/"):
            self.cdn(path)
        else:
            self.respond(404, {"message": "unexpected fixture path"})

    def catalog(self, query):
        params = parse_qs(query)
        if params.get("per_page") != ["100"] or len(params.get("page", [])) != 1:
            self.respond(400, {"message": "unexpected fixture query"})
            return
        page = int(params["page"][0])
        if SCENARIO == "page-not-found" and page == 2:
            self.respond(404)
            return
        if SCENARIO == "too-many-pages":
            entry = release(123) if page == 1 else dict(release(124), id=200 + page)
            self.respond(200, [entry], headers={"Link": link(page + 1)})
            return
        if page == 1:
            next_links = {
                "link-malformed": 'https://api.github.com/releases; rel="next"',
                "link-off-domain": link(2, host="example.invalid"),
                "link-cycle": link(1),
                "link-duplicate": f"{link(2)}, {link(3)}",
            }
            header = next_links.get(SCENARIO, link(2, path="/repositories/987654"))
            self.respond(200, [release(124), release(122)], headers={"Link": header})
        elif page == 2:
            entry = release(123)
            if SCENARIO == "published-field-missing":
                del entry["published_at"]
            self.respond(200, [entry])
        else:
            self.respond(404)

    def exact_release(self, release_id, read_number):
        if SCENARIO == "not-found":
            self.respond(404, {"message": "not found"})
        elif SCENARIO == "unavailable":
            self.respond(503, {"message": "temporarily unavailable"})
        elif SCENARIO == "rate-limited":
            self.respond(429, {"message": "too many requests"}, headers={"Retry-After": "60"})
        else:
            data = release(release_id)
            if SCENARIO == "release-changed" and read_number > 1:
                data["tag_name"] = "agent-v0.1.1"
            if SCENARIO == "prerelease":
                data["prerelease"] = True
            if SCENARIO == "mutable-release":
                data["immutable"] = False
            body = json_bytes(data)
            if SCENARIO == "control-too-large":
                body = body.ljust(2 * 1024 * 1024 + 1)
            delay = {
                "control-stalled-headers": 3,
                "control-deadline": 0.24,
                "control-trickle": 0.18,
            }.get(SCENARIO, 0)
            self.respond(
                200, body, delay=delay, stall_body=SCENARIO == "control-stalled-body",
                trickle=SCENARIO == "control-trickle",
            )

    def binary(self, asset_id):
        if MIME_BINARY not in self.headers.get("Accept", ""):
            self.respond(400, {"message": "octet-stream Accept required"})
            return
        if asset_id in RELEASE_BY_MANIFEST_ID:
            data = manifest(RELEASE_BY_MANIFEST_ID[asset_id])
            if SCENARIO == "manifest-swapped":
                data = data.replace(b'"isSecurityUpdate":false', b'"isSecurityUpdate":true ')
            self.respond(200, data, mime=MIME_BINARY)
        elif asset_id in ARTIFACT_IDS.values():
            self.package()
        else:
            self.respond(404)

    def package(self):
        if SCENARIO in ("redirect", "redirect-deadline"):
            delay = 0.24 if SCENARIO == "redirect-deadline" else 0
            self.redirect(f"{CDN}/fixture/redirect/second", delay=delay)
            return
        bad_redirects = {
            "redirect-off-domain": "https://example.invalid/fixture/redirect/rejected",
            "redirect-http": "http://release-assets.githubusercontent.com/fixture/redirect/rejected",
            "redirect-private-ip": "https://127.0.0.1/fixture/redirect/rejected",
            "redirect-userinfo": "https://fixture@release-assets.githubusercontent.com/fixture/redirect/rejected",
            "redirect-too-many": f"{CDN}/fixture/redirect/1",
        }
        if SCENARIO in bad_redirects:
            self.redirect(bad_redirects[SCENARIO])
            return
        payload = {
            "download-extra-byte": ARTIFACT + b"x",
            "download-short": ARTIFACT[:-1],
            "download-wrong-digest": b"x" + ARTIFACT[1:],
        }.get(SCENARIO, ARTIFACT)
        self.respond(
            200, payload, mime=MIME_BINARY,
            delay=3 if SCENARIO == "download-stalled-headers" else 0,
            stall_body=SCENARIO == "download-stalled-body",
            chunked=SCENARIO in ("download-extra-byte", "download-short"),
        )

    def cdn(self, path):
        step = path.rsplit("/", 1)[-1]
        if step == "second":
            delay = 0.24 if SCENARIO == "redirect-deadline" else 0
            self.redirect(f"{CDN}/fixture/redirect/package?signature=fixture", delay=delay)
        elif step in ("1", "2"):
            self.redirect(f"{CDN}/fixture/redirect/{int(step) + 1}")
        elif step == "3":
            self.redirect(f"{CDN}/fixture/redirect/rejected")
        elif step == "package" and self.path.endswith("?signature=fixture"):
            self.respond(200, ARTIFACT, mime=MIME_BINARY)
        else:
            self.respond(404)


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, ssl.SSLError)):
            super().handle_error(request, client_address)

    def get_request(self):
        connection, address = super().get_request()
        try:
            if SCENARIO == "control-stalled-tls":
                time.sleep(3)
            return self.tls.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise


(STATE / "manifest.json").write_bytes(manifest(123))
with Server(("127.0.0.1", 0), Handler) as server:
    tls = pathlib.Path(__file__).with_name("tls")
    server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.tls.load_cert_chain(tls / "server.pem", tls / "server-key.pem")
    print(server.server_address[1], flush=True)
    server.serve_forever()
