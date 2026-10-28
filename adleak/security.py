"""URL and network-destination safety checks.

These are application-level controls. They lower the risk of server-side
request forgery (SSRF) for a prototype that runs on one person's computer.
They do NOT replace isolated browser workers and network-level egress rules,
which are required before any public deployment (see ARCHITECTURE.md).

Every outbound connection the scanner makes (browser traffic and Python link
checks) passes through ``EgressPolicy.check_destination`` inside the egress
proxy, which also pins the connection to the IP address it validated.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_URL_LENGTH = 2048

BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "host.docker.internal",
    "gateway.docker.internal",
})

# Suffixes that only make sense on private networks or are reserved by RFC 2606/6761.
BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".localdomain", ".internal", ".intranet", ".lan",
    ".home", ".home.arpa", ".corp", ".private", ".test", ".example",
    ".invalid", ".onion", ".arpa",
)

CLOUD_METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),   # AWS, Azure, GCP, Oracle, DigitalOcean
    ipaddress.ip_address("169.254.170.2"),     # AWS ECS task metadata
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IPv6 metadata
})

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!\d)")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_LEGACY_IPV4 = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$", re.IGNORECASE)
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class UnsafeUrlError(ValueError):
    """Raised when a submitted URL must not be scanned."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    addresses: tuple[tuple[str, int], ...] = ()
    code: str = ""


@dataclass(frozen=True)
class ValidatedUrl:
    url: str
    scheme: str
    host: str
    port: int


def ip_block_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return why an address must not be contacted, or None when it is public."""
    if ip in CLOUD_METADATA_IPS:
        return "cloud metadata address"
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = []
        if ip.ipv4_mapped:
            embedded.append(ip.ipv4_mapped)
        if ip.sixtofour:
            embedded.append(ip.sixtofour)
        if ip.teredo:
            embedded.extend(ip.teredo)
        if any(ip in net for net in _NAT64):
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        for inner in embedded:
            reason = ip_block_reason(inner)
            if reason:
                return f"IPv6 address embedding a {reason}"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_private:
        return "private network address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_reserved:
        return "reserved address"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return "carrier-grade NAT address"
    if not ip.is_global:
        return "non-public address"
    return None


def normalise_host(host: str) -> str:
    """Lower-case, strip a trailing dot and IDNA-encode a hostname."""
    host = host.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _LEGACY_IPV4.match(host):
        # Shorthand, hex, octal and decimal IPv4 forms ("127.1", "0x7f000001",
        # "2130706433") that some resolvers accept are expanded so they get the
        # same address checks as dotted-quad addresses.
        try:
            return socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeUrlError("invalid_host", "The hostname contains invalid characters.") from exc


def hostname_block_reason(host: str) -> str | None:
    if host in BLOCKED_HOSTNAMES:
        return "local or internal hostname"
    if host.endswith(BLOCKED_SUFFIXES):
        return "reserved or internal domain suffix"
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if "." not in host:
        # Single-label names (e.g. "intranet") resolve via local search domains.
        return "single-label hostname"
    labels = host.split(".")
    if len(host) > 253 or not all(_HOST_LABEL.match(label) for label in labels):
        return "invalid hostname"
    return None


@dataclass
class EgressPolicy:
    """Decides which network destinations the scanner may contact.

    ``test_allow`` and ``test_resolve`` exist only so the automated test suite
    can point the scanner at fixture servers on 127.0.0.1. The application
    server always uses ``EgressPolicy()`` with both empty.
    """

    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    test_allow: frozenset[tuple[str, int]] = frozenset()
    test_resolve: dict[str, tuple[str, int]] = field(default_factory=dict)
    resolver: Callable[..., list] = socket.getaddrinfo

    def resolve(self, host: str, port: int) -> list[tuple[str, int]]:
        if host in self.test_resolve:
            return [self.test_resolve[host]]
        try:
            ipaddress.ip_address(host)
            return [(host, port)]
        except ValueError:
            pass
        infos = self.resolver(host, port, type=socket.SOCK_STREAM)
        seen: list[tuple[str, int]] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            entry = (sockaddr[0].split("%")[0], port)
            if entry not in seen:
                seen.append(entry)
        return seen

    def check_destination(self, host: str, port: int) -> Decision:
        try:
            host = normalise_host(host)
        except UnsafeUrlError as exc:
            return Decision(False, exc.message, code="invalid_host")
        reason = hostname_block_reason(host)
        if reason and host not in self.test_resolve:
            return Decision(False, reason, code="blocked_host")
        try:
            addresses = self.resolve(host, port)
        except (socket.gaierror, UnicodeError, OSError):
            return Decision(False, "DNS lookup failed", code="dns_failure")
        if not addresses:
            return Decision(False, "DNS lookup returned no usable addresses", code="dns_failure")
        for ip_text, target_port in addresses:
            if (ip_text, target_port) in self.test_allow:
                continue
            ip_reason = ip_block_reason(ipaddress.ip_address(ip_text))
            if ip_reason:
                # Every address must be public, so a hostname that mixes public
                # and private records cannot be used to reach the private one.
                if ip_text == host:
                    return Decision(False, ip_reason, code="blocked_address")
                return Decision(False, f"resolves to a {ip_reason} ({ip_text})", code="blocked_address")
            if target_port not in self.allowed_ports:
                return Decision(False, f"port {target_port} is not allowed", code="blocked_port")
        return Decision(True, addresses=tuple(addresses))


def validate_url(raw: object, policy: EgressPolicy | None = None, resolve: bool = True) -> ValidatedUrl:
    """Validate a URL a person submitted for scanning.

    Adds ``https://`` when no scheme was typed. Raises ``UnsafeUrlError`` with a
    message that is safe to show in the interface.
    """
    policy = policy or EgressPolicy()
    if not isinstance(raw, str):
        raise UnsafeUrlError("invalid_url", "Enter a website address as text.")
    text = raw.strip()
    if not text:
        raise UnsafeUrlError("invalid_url", "Enter a website address to scan.")
    if len(text) > MAX_URL_LENGTH:
        raise UnsafeUrlError("invalid_url", f"The address is longer than {MAX_URL_LENGTH} characters.")
    if _CONTROL_OR_SPACE.search(text):
        raise UnsafeUrlError("invalid_url", "The address contains spaces or control characters.")
    if "://" not in text:
        if _SCHEME_PREFIX.match(text):
            raise UnsafeUrlError("unsupported_scheme", "Only http:// and https:// addresses can be scanned.")
        text = "https://" + text

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise UnsafeUrlError("invalid_url", "That is not a valid web address.") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("unsupported_scheme", "Only http:// and https:// addresses can be scanned.")
    if "@" in parts.netloc or parts.username or parts.password:
        raise UnsafeUrlError("embedded_credentials", "Addresses containing a username or password are not accepted.")
    if not parts.hostname:
        raise UnsafeUrlError("invalid_url", "The address has no website name.")
    if "\\" in parts.netloc:
        raise UnsafeUrlError("invalid_url", "The address contains a backslash in the website name.")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeUrlError("invalid_port", "The port number in the address is not valid.") from exc

    host = normalise_host(parts.hostname)
    reason = hostname_block_reason(host)
    if reason and host not in policy.test_resolve:
        raise UnsafeUrlError("blocked_destination", f"This address cannot be scanned: {reason}.")
    if not resolve:
        try:
            ip_reason = ip_block_reason(ipaddress.ip_address(host))
        except ValueError:
            ip_reason = None
        if ip_reason and (host, port) not in policy.test_allow:
            raise UnsafeUrlError("blocked_destination", f"This address cannot be scanned: {ip_reason}.")
        if port not in policy.allowed_ports and (host, port) not in policy.test_allow:
            raise UnsafeUrlError("blocked_port", f"Port {port} is not allowed. Use a standard web port.")
    else:
        decision = policy.check_destination(host, port)
        if not decision.allowed:
            if decision.code == "dns_failure":
                raise UnsafeUrlError(
                    "dns_failure",
                    "This domain could not be found (DNS lookup failed). Check the spelling, "
                    "or check that the domain is registered and pointed at a host.",
                )
            if decision.code == "blocked_port":
                raise UnsafeUrlError("blocked_port", f"Port {port} is not allowed. Use a standard web port.")
            raise UnsafeUrlError("blocked_destination", f"This address cannot be scanned: {decision.reason}.")

    netloc = f"[{host}]" if ":" in host else host
    if parts.port:
        netloc += f":{parts.port}"
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    return ValidatedUrl(url=url, scheme=scheme, host=host, port=port)
