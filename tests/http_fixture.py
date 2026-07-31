#!/usr/bin/env python3
"""Deterministic local HTTP fixture for httpxer integration checks."""

from __future__ import annotations

import argparse
import json
import signal
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


REQUESTS: dict[str, list[dict[str, object]]] = defaultdict(list)
LOCK = threading.Lock()
SERVERS: dict[str, ThreadingHTTPServer] = {}


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str) -> None:
        self.mode = mode
        super().__init__(("127.0.0.1", 0), FixtureHandler)


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "httpxer-fixture/1"

    @property
    def mode(self) -> str:
        return self.server.mode  # type: ignore[attr-defined]

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _record(self) -> None:
        with LOCK:
            REQUESTS[self.mode].append(
                {
                    "at": time.monotonic(),
                    "method": self.command,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "cookie": self.headers.get("Cookie"),
                    "range": self.headers.get("Range"),
                }
            )

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/html",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        self._record()

        if self.path == "/__stats":
            with LOCK:
                payload = json.dumps(REQUESTS, sort_keys=True).encode()
            self._send(200, payload, "application/json")
            return
        if self.path == "/__reset":
            with LOCK:
                REQUESTS.clear()
            self._send(200, b"reset", "text/plain")
            return

        mode = self.mode
        path = self.path.split("?", 1)[0]

        if mode == "mixed":
            if path == "/real":
                self._send(200, b"REAL dashboard endpoint", "text/plain")
            elif path == "/secret.conf":
                self._send(200, b"REAL_CONFIG=true\nTOKEN=fixture", "text/plain")
            elif path.endswith(".conf"):
                nonce = f"{len(REQUESTS[mode]):032x}".encode()
                self._send(200, b"<html>missing conf request=" + nonce + b"</html>")
            elif path.endswith(".config"):
                self._send(200, b"<html>missing config family</html>")
            elif path.endswith(".log"):
                self._send(200, b"missing log family", "text/plain")
            elif path.endswith(".env"):
                self._send(200, b"missing env family", "text/plain")
            elif path.endswith("/.git/HEAD"):
                self._send(200, b"missing git family", "text/plain")
            else:
                self._send(200, b"<html>generic application shell</html>")
            return

        if mode == "echo":
            if path == "/real":
                self._send(200, b"REAL echo service endpoint", "text/plain")
            elif path == "/blocked/":
                self._send(403, b"forbidden directory", "text/plain")
            else:
                self._send(200, b"not found path=" + path.encode() + b"; end")
            return

        if mode == "status":
            body = b"same response body across statuses"
            if path == "/real":
                self._send(200, body)
            else:
                self._send(302, body, headers={"Location": "/login"})
            return

        if mode == "auth":
            if path == "/protected/child":
                self._send(200, b"REAL protected child", "text/plain")
            elif path.startswith("/protected/"):
                self._send(401, b"protected area", "text/plain")
            elif path == "/real":
                self._send(200, b"REAL public endpoint", "text/plain")
            else:
                self._send(404, b"not found", "text/plain")
            return

        if mode == "cross_a":
            self._send(200, b"<html>shared shell-looking content</html>")
            return

        if mode == "cross_b":
            if path == "/real":
                self._send(200, b"<html>shared shell-looking content</html>")
            else:
                self._send(404, b"not found", "text/plain")
            return

        if mode == "redirect":
            if path == "/redirect-cross":
                capture = SERVERS["capture"].server_address[1]
                self._send(
                    302,
                    b"redirect",
                    headers={"Location": f"http://127.0.0.1:{capture}/capture"},
                )
            else:
                self._send(200, b"redirect source", "text/plain")
            return

        if mode == "capture":
            self._send(200, b"captured", "text/plain")
            return

        self._send(500, b"unknown fixture mode", "text/plain")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--modes",
        default="mixed,echo,status,auth,cross_a,cross_b,redirect,capture",
    )
    args = parser.parse_args()

    for mode in args.modes.split(","):
        server = FixtureServer(mode)
        SERVERS[mode] = server
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print(
        json.dumps({name: server.server_address[1] for name, server in SERVERS.items()}),
        flush=True,
    )

    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_args: done.set())
    signal.signal(signal.SIGINT, lambda *_args: done.set())
    done.wait()
    for server in SERVERS.values():
        server.shutdown()


if __name__ == "__main__":
    main()
