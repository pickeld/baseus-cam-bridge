"""Local still-image HTTP endpoint (bound to 127.0.0.1 by default).

A GET of ``/<slug>.jpg`` or ``/<slug>-right.jpg`` returns the cached still
immediately. On a cache miss a tiny placeholder JPEG is returned so Home
Assistant's Generic Camera still test does not hang. Stills are filled
from live IDR frames; this server does not open a second P2P session.
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from .still_cache import jpeg_for_get, still_slug

_log = print


class StillHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path in ("/", "/health"):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        parsed = urlparse(self.path)
        name = unquote(parsed.path or "").strip("/")
        try:
            slug = still_slug(name)
        except ValueError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data, status = jpeg_for_get(slug)
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        _log(f"[still] GET slug={slug} cache={status}")

    def do_HEAD(self):
        self.do_GET()


def start_still_server(host: str, port: int, *, log=None):
    """Bind and start the still server in a daemon thread. Returns the server."""
    global _log
    if log is not None:
        _log = log
    server = ThreadingHTTPServer((host, int(port)), StillHandler)
    thread = threading.Thread(target=server.serve_forever, name="still-http", daemon=True)
    thread.start()
    if log:
        log(f"[still] listening on {host}:{int(port)} (cache only; no P2P refresh)")
    return server


def main(argv=None) -> int:
    host = os.environ.get("BASEUS_STILL_BIND", "127.0.0.1")
    port = int(os.environ.get("BASEUS_STILL_PORT", "8099") or 8099)

    def log(*a):
        print(*a, file=sys.stderr, flush=True)

    start_still_server(host, port, log=log)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
