"""A filtering forward proxy that all scanner traffic is routed through.

Chromium is started with ``--proxy-server`` pointing here, and the Python link
checker uses it too. For every connection the proxy:

1. checks the destination host and port with ``EgressPolicy``;
2. resolves DNS once and connects to the exact address it validated, which
   closes the gap between "check" and "connect" that DNS rebinding relies on;
3. enforces a byte budget, a connection cap and idle timeouts.

HTTPS is tunnelled with CONNECT and never decrypted. Blocked attempts are
recorded so the report can show them as evidence.

This is still an in-process control. A public deployment needs the same rules
enforced by the network (firewall / egress gateway) around isolated workers.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from urllib.parse import urlsplit

from .security import EgressPolicy

_HOP_BY_HOP = {
    "proxy-connection", "proxy-authorization", "proxy-authenticate",
    "connection", "keep-alive", "te", "trailer", "upgrade",
}
MAX_HEADER_BYTES = 64 * 1024


class EgressProxy:
    def __init__(
        self,
        policy: EgressPolicy,
        max_bytes: int = 80 * 1024 * 1024,
        idle_timeout: float = 20.0,
        connect_timeout: float = 10.0,
        max_connections: int = 96,
    ):
        self.policy = policy
        self.max_bytes = max_bytes
        self.idle_timeout = idle_timeout
        self.connect_timeout = connect_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.port = 0
        self.bytes_transferred = 0
        self.budget_exceeded = False
        self.blocked: list[dict] = []
        self.dns_failures: list[dict] = []
        self.connect_failures: list[dict] = []

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.settimeout(0.5)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, name="egress-proxy", daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stopping.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- bookkeeping -------------------------------------------------------
    def _record_block(self, host: str, port: int, reason: str, target: str) -> None:
        with self._lock:
            if len(self.blocked) < 200:
                self.blocked.append({"host": host, "port": port, "reason": reason, "target": target, "at": time.time()})

    def _add_bytes(self, count: int) -> bool:
        with self._lock:
            self.bytes_transferred += count
            if self.bytes_transferred > self.max_bytes:
                self.budget_exceeded = True
                return False
            return True

    # -- connection handling -----------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                self._reply(client, 503, "Proxy connection limit reached")
                client.close()
                continue
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(self.connect_timeout)
            head, rest = self._read_head(client)
            if head is None:
                return
            request_line, *header_lines = head.split("\r\n")
            parts = request_line.split(" ")
            if len(parts) != 3:
                self._reply(client, 400, "Bad request")
                return
            method, target, version = parts
            if method.upper() == "CONNECT":
                host, port = _split_host_port(target, 443)
                upstream = self._open(client, host, port, target)
                if upstream is None:
                    return
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
            else:
                url = urlsplit(target)
                if url.scheme.lower() != "http" or not url.hostname:
                    self._reply(client, 400, "Only absolute http:// requests or CONNECT are accepted")
                    return
                port = url.port or 80
                upstream = self._open(client, url.hostname, port, target)
                if upstream is None:
                    return
                path = url.path or "/"
                if url.query:
                    path += "?" + url.query
                headers = [line for line in header_lines if line and line.split(":", 1)[0].strip().lower() not in _HOP_BY_HOP]
                if not any(line.lower().startswith("host:") for line in headers):
                    headers.insert(0, f"Host: {url.netloc}")
                out = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
                upstream.sendall(out.encode("latin-1") + rest)
            self._relay(client, upstream)
        except (OSError, ValueError):
            pass
        finally:
            for sock in (upstream, client):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._slots.release()

    def _read_head(self, client: socket.socket) -> tuple[str | None, bytes]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(8192)
            if not chunk:
                return None, b""
            data += chunk
            if len(data) > MAX_HEADER_BYTES:
                self._reply(client, 431, "Request header too large")
                return None, b""
        head, _, rest = data.partition(b"\r\n\r\n")
        return head.decode("latin-1"), rest

    def _open(self, client: socket.socket, host: str, port: int, target: str) -> socket.socket | None:
        if self.budget_exceeded:
            self._reply(client, 509, "Scan data budget exceeded")
            return None
        decision = self.policy.check_destination(host, port)
        if not decision.allowed:
            if decision.code == "dns_failure":
                with self._lock:
                    self.dns_failures.append({"host": host, "port": port})
                self._reply(client, 502, "DNS lookup failed", blocked=False)
            else:
                self._record_block(host, port, decision.reason, target)
                self._reply(client, 403, "Blocked by AdLeak safety policy: " + decision.reason)
            return None
        last_error = None
        for ip_text, ip_port in decision.addresses:
            family = socket.AF_INET6 if ":" in ip_text else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            try:
                sock.connect((ip_text, ip_port))
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        status = 504 if isinstance(last_error, socket.timeout) else 502
        with self._lock:
            self.connect_failures.append({"host": host, "port": port, "error": str(last_error)[:200], "timeout": status == 504})
        self._reply(client, status, "Upstream connection timed out" if status == 504 else "Upstream connection failed", blocked=False)
        return None

    def failure_for(self, host: str) -> dict | None:
        """Explain why the proxy refused or failed a connection to ``host``."""
        host = (host or "").lower()
        with self._lock:
            for item in self.blocked:
                if item["host"].lower() == host:
                    return {"kind": "blocked_by_policy", "detail": item["reason"]}
            for item in self.dns_failures:
                if item["host"].lower() == host:
                    return {"kind": "dns", "detail": "DNS lookup failed"}
            for item in self.connect_failures:
                if item["host"].lower() == host:
                    return {"kind": "timeout" if item["timeout"] else "connection", "detail": item["error"]}
        return None

    def _relay(self, a: socket.socket, b: socket.socket) -> None:
        a.setblocking(False)
        b.setblocking(False)
        peers = {a: b, b: a}
        while not self._stopping.is_set():
            readable, _, errored = select.select([a, b], [], [a, b], self.idle_timeout)
            if errored or not readable:
                return
            for src in readable:
                try:
                    chunk = src.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    return
                if not self._add_bytes(len(chunk)):
                    return
                dst = peers[src]
                dst.setblocking(True)
                dst.settimeout(self.idle_timeout)
                dst.sendall(chunk)
                dst.setblocking(False)

    @staticmethod
    def _reply(client: socket.socket, status: int, reason: str, blocked: bool = True) -> None:
        # X-AdLeak-Proxy marks responses generated here, so the engine never
        # mistakes a proxy refusal for an error returned by the website.
        safe_reason = reason.replace("\r", " ").replace("\n", " ")[:200]
        extra = f"X-AdLeak-Blocked: {safe_reason}\r\n" if blocked and status == 403 else ""
        msg = (
            f"HTTP/1.1 {status} {safe_reason}\r\nX-AdLeak-Proxy: 1\r\n{extra}"
            "Content-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        try:
            client.sendall(msg.encode("latin-1", "replace"))
        except OSError:
            pass


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    host, sep, port = target.rpartition(":")
    if not sep:
        return target, default_port
    return host, int(port)
