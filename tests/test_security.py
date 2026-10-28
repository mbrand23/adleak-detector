"""Test plan item 10: unsafe URL rejection."""

import socket

import pytest

from adleak.security import EgressPolicy, UnsafeUrlError, ip_block_reason, validate_url
import ipaddress


def fake_resolver(mapping):
    def resolve(host, port, type=None):
        if host not in mapping:
            raise socket.gaierror("not found")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]
    return resolve


PUBLIC = EgressPolicy(resolver=fake_resolver({
    "shop.example.org": ["93.184.215.14"],
    "rebind.attacker.net": ["93.184.215.14", "10.0.0.5"],
    "inside.attacker.net": ["169.254.169.254"],
    "v6private.attacker.net": ["fd00::1"],
}))


@pytest.mark.parametrize("raw, code", [
    ("javascript:alert(1)", "unsupported_scheme"),
    ("file:///C:/Windows/win.ini", "unsupported_scheme"),
    ("ftp://shop.example.org/", "unsupported_scheme"),
    ("data:text/html,hi", "unsupported_scheme"),
    ("gopher://shop.example.org:70/", "unsupported_scheme"),
    ("http://user:pass@shop.example.org/", "embedded_credentials"),
    ("http://shop.example.org@10.0.0.1/", "embedded_credentials"),
    ("http://localhost/", "blocked_destination"),
    ("http://127.0.0.1/", "blocked_destination"),
    ("http://127.1/", "blocked_destination"),
    ("http://2130706433/", "blocked_destination"),
    ("http://0x7f000001/", "blocked_destination"),
    ("http://[::1]/", "blocked_destination"),
    ("http://[::ffff:127.0.0.1]/", "blocked_destination"),
    ("http://10.1.2.3/", "blocked_destination"),
    ("http://192.168.0.1/", "blocked_destination"),
    ("http://172.16.5.4/", "blocked_destination"),
    ("http://169.254.169.254/latest/meta-data/", "blocked_destination"),
    ("http://100.100.100.200/", "blocked_destination"),
    ("http://100.64.0.1/", "blocked_destination"),
    ("http://0.0.0.0/", "blocked_destination"),
    ("http://224.0.0.1/", "blocked_destination"),
    ("http://240.0.0.1/", "blocked_destination"),
    ("http://metadata.google.internal/", "blocked_destination"),
    ("http://printer.local/", "blocked_destination"),
    ("http://intranet/", "blocked_destination"),
    ("http://inside.attacker.net/", "blocked_destination"),
    ("http://rebind.attacker.net/", "blocked_destination"),
    ("http://v6private.attacker.net/", "blocked_destination"),
    ("http://shop.example.org:22/", "blocked_port"),
    ("http://shop.example.org:6379/", "blocked_port"),
    ("http://shop.example.org:99999/", "invalid_port"),
    ("https://no-such-domain.example.org/", "dns_failure"),
    ("", "invalid_url"),
    ("   ", "invalid_url"),
    ("http://shop.example.org/a b", "invalid_url"),
    ("http://shop.example.org/\r\nX: y", "invalid_url"),
    ("https://" + "a" * 2050 + ".com", "invalid_url"),
    (None, "invalid_url"),
    (12345, "invalid_url"),
])
def test_rejects_unsafe_urls(raw, code):
    with pytest.raises(UnsafeUrlError) as info:
        validate_url(raw, PUBLIC)
    assert info.value.code == code, info.value.message


@pytest.mark.parametrize("raw, expected", [
    ("shop.example.org", "https://shop.example.org/"),
    ("shop.example.org/offer?utm_source=fb&utm_medium=cpc", "https://shop.example.org/offer?utm_source=fb&utm_medium=cpc"),
    ("HTTPS://SHOP.EXAMPLE.ORG/Path", "https://shop.example.org/Path"),
    ("http://shop.example.org:8080/x", "http://shop.example.org:8080/x"),
    ("  https://shop.example.org/  ", "https://shop.example.org/"),
])
def test_accepts_public_urls(raw, expected):
    assert validate_url(raw, PUBLIC).url == expected


def test_every_resolved_address_must_be_public():
    decision = PUBLIC.check_destination("rebind.attacker.net", 443)
    assert not decision.allowed and "10.0.0.5" in decision.reason


def test_ipv6_embedding_private_ipv4_is_blocked():
    assert ip_block_reason(ipaddress.ip_address("64:ff9b::a00:1")) is not None   # NAT64 of 10.0.0.1
    assert ip_block_reason(ipaddress.ip_address("2002:c0a8:0101::1")) is not None  # 6to4 of 192.168.1.1
    assert ip_block_reason(ipaddress.ip_address("2606:4700::1111")) is None


def test_test_allowlist_is_exact():
    policy = EgressPolicy(test_allow=frozenset({("127.0.0.1", 5555)}))
    assert policy.check_destination("127.0.0.1", 5555).allowed
    assert not policy.check_destination("127.0.0.1", 5556).allowed
    assert not EgressPolicy().check_destination("127.0.0.1", 5555).allowed
