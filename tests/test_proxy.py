"""The egress proxy enforces the policy for every connection."""

import socket
import urllib.request

import pytest

from adleak.links import build_opener, check_link
from adleak.proxy import EgressProxy


def raw_request(port, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(data)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def test_allowed_destination_is_forwarded(fixture_site, test_policy):
    with EgressProxy(test_policy) as proxy:
        opener = build_opener(proxy.url)
        with opener.open(fixture_site["base"] + "/about.html", timeout=5) as resp:
            assert resp.status == 200
            assert b"About us" in resp.read()
        assert proxy.bytes_transferred > 0


def test_loopback_on_other_port_is_blocked(fixture_site, test_policy):
    other = fixture_site["port"] + 1
    with EgressProxy(test_policy) as proxy:
        reply = raw_request(proxy.port, f"GET http://127.0.0.1:{other}/ HTTP/1.1\r\nHost: 127.0.0.1:{other}\r\n\r\n".encode())
        assert reply.startswith(b"HTTP/1.1 403")
        assert b"X-AdLeak-Proxy: 1" in reply
        assert proxy.blocked and proxy.blocked[0]["reason"] == "loopback address"


@pytest.mark.parametrize("target", ["169.254.169.254:80", "10.0.0.1:443", "[::1]:443", "192.168.1.1:443"])
def test_connect_to_private_targets_is_blocked(test_policy, target):
    with EgressProxy(test_policy) as proxy:
        reply = raw_request(proxy.port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        assert reply.startswith(b"HTTP/1.1 403"), reply[:80]


def test_non_http_absolute_targets_rejected(test_policy):
    with EgressProxy(test_policy) as proxy:
        reply = raw_request(proxy.port, b"GET ftp://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 400")


def test_byte_budget_stops_transfers(fixture_site, test_policy):
    with EgressProxy(test_policy, max_bytes=200) as proxy:
        opener = build_opener(proxy.url)
        try:
            with opener.open(fixture_site["base"] + "/good.html", timeout=5) as resp:
                resp.read()
        except Exception:
            pass
        assert proxy.budget_exceeded


def test_link_checker_classifies_results(fixture_site, test_policy):
    base = fixture_site["base"]
    with EgressProxy(test_policy) as proxy:
        opener = build_opener(proxy.url)
        assert check_link(opener, base + "/about.html", timeout=4)["outcome"] == "ok"
        assert check_link(opener, base + "/status/404", timeout=4)["outcome"] == "broken"
        assert check_link(opener, base + "/status/403", timeout=4)["outcome"] == "restricted"
        assert check_link(opener, base + "/status/500", timeout=4)["outcome"] == "server_error"
        loop = check_link(opener, base + "/redirect/loop", timeout=4, max_redirects=3)
        assert loop["outcome"] == "redirect_loop"
        redirected = check_link(opener, base + "/redirect/keep?utm_source=x", timeout=4)
        assert redirected["outcome"] == "ok" and redirected["hops"]
        private = check_link(opener, "http://localhost:3000/dev", timeout=4)
        assert private["outcome"] == "blocked_by_policy"
