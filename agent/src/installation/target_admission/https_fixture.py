"""Local TLS-only enrollment target fixture. No tokens are written to output."""

import http.server
import json
import pathlib
import ssl
import sys
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        request = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(request.query, strict_parsing=True)
        origin = f"https://localhost:{self.server.server_port}"
        if (
            request.path != "/api/agent/v1/enrollment-target"
            or set(query) != {"expectedServerId"}
            or len(query["expectedServerId"]) != 1
            or self.headers.get_all("Authorization") != ["Bearer ndme_" + "A" * 43]
            or self.headers.get("Origin") != origin
            or self.headers.get("Cache-Control") != "no-store"
        ):
            self.send_error(401)
            return
        expected = query["expectedServerId"][0]
        if expected == "redirect-server":
            self.send_response(302)
            self.send_header("Location", "/unexpected")
            self.end_headers()
            return
        if expected == "different-server":
            self.send_json(422, "application/problem+json", {
                "type": "about:blank",
                "title": "Unprocessable Entity",
                "status": 422,
                "code": "TARGET_MISMATCH",
                "requestId": "fixture",
            })
            return
        self.send_json(200, "application/json", {
            "deploymentId": "6dc0a032-3f68-42ae-9dd9-14dc1a41ab01",
            "serverId": "server-1",
            "bindingRevision": 7,
        })

    def send_json(self, status, content_type, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


tls = pathlib.Path(sys.argv[1])
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(tls / "server.pem", tls / "server-key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
