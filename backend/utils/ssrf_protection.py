"""SSRF protection utilities — validate URLs/hosts don't resolve to private IPs."""

import ipaddress
import logging
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_url_not_private(url: str) -> None:
    """Validate that a URL doesn't resolve to a private/reserved IP.
    
    Raises ValueError if the URL host resolves to private, loopback,
    reserved, or link-local addresses.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")
    validate_host_not_private(host)


def validate_host_not_private(host: str) -> list:
    """Validate that a hostname doesn't resolve to a private/reserved IP.

    Raises ValueError if the host is — or resolves to — a private, loopback,
    reserved or link-local address, or if it cannot be resolved at all.

    Returns every validated IP address (deduplicated, in resolver order), so
    a caller can pin its connection to exactly what was checked (see
    pin_host) instead of letting the HTTP client resolve the name a second
    time. The whole set comes back because the loop below rejects the host
    outright if ANY address is forbidden — so on return every address is
    public-safe, and discarding any of them would only cost the caller
    multi-A/dual-stack failover, not security.
    """
    # First check if host is already an IP. A trailing root dot
    # ("169.254.169.254.") names the same address on any resolver that accepts
    # it, so it must not turn the literal into an opaque "hostname".
    # Parsing and policy are decided SEPARATELY: ipaddress.ip_address()
    # embeds its input verbatim in the ValueError it raises ("'<host>' does
    # not appear to be an IPv4 or IPv6 address"), so deciding from the
    # message text would refuse any hostname that merely CONTAINS a policy
    # word — e.g. private-ca.corp.example.com.
    try:
        ip = ipaddress.ip_address(host.rstrip('.') or host)
    except ValueError:
        ip = None  # Not an IP literal — resolve it below.
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            raise ValueError(f"Host {host} is a private/reserved IP address")
        return [str(ip)]

    # Fail CLOSED when the host can be neither parsed nor resolved. Treating
    # that as "not a SSRF risk" was a fail-open: a value like
    # "169.254.169.254:80" or "evil@169.254.169.254" is unresolvable as a
    # HOSTNAME, but requests re-parses it as a URL authority, splits off the
    # port/userinfo and happily connects to the private address behind it.
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host {host}: {e}")

    chosen = []
    for _, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            raise ValueError(f"Host {host} resolves to private/reserved IP {ip}")
        if str(ip) not in chosen:
            chosen.append(str(ip))

    if not chosen:
        raise ValueError(f"Host {host} produced no usable IP addresses")
    return chosen


# Cloud metadata endpoints and loopback — NEVER legitimate targets for
# outbound HTTP from UCM. Unlike validate_url_not_private (which also blocks
# RFC1918 private ranges), this narrow check allows admins to legitimately
# point UCM at internal infrastructure (AD, Keycloak on 10.x, internal ACME
# CAs, on-prem IdP) while still blocking the highest-impact SSRF targets:
# cloud instance metadata services (which leak IAM credentials) and loopback
# (which would let attackers probe UCM's own internal endpoints).
_CLOUD_METADATA_IPS = {
    '169.254.169.254',          # AWS, Azure, DigitalOcean, GCP (also link-local)
    '169.254.170.2',            # AWS ECS/EKS task credentials (see note below)
    '100.100.100.200',          # Alibaba Cloud
    'fd00:ec2::254',            # AWS IPv6
}
# 169.254.170.2 is NOT the instance metadata service, which is why it was missed:
# it is the ECS task-credentials endpoint, reached by appending the container's
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI. It hands out live task-role IAM
# credentials exactly as IMDS does, so the impact is identical even though the
# address is not. Blocked unconditionally with the rest -- a link-local address
# is never a legitimate ACME/webhook/SSO target, whatever allow_private_ips says.
_CLOUD_METADATA_HOSTS = {
    'metadata.google.internal',
    'metadata',                 # GCP short name
    'metadata.goog',
}

# Deny-list as parsed IP objects so an IPv4-mapped IPv6 form (::ffff:a.b.c.d) can't
# evade a string comparison by re-encoding an IPv4 target as IPv6.
_CLOUD_METADATA_IP_OBJS = {ipaddress.ip_address(a) for a in _CLOUD_METADATA_IPS}


def _forbidden_ip_reason(ip, allow_loopback: bool = False):
    """Why `ip` (an ipaddress object) is a forbidden SSRF target — cloud metadata,
    loopback, or unspecified (0.0.0.0 / ::, which route to loopback on most OSes) — or
    None. IPv4-mapped IPv6 is collapsed to IPv4 first so it can't slip past the checks.

    allow_loopback=True permits loopback/unspecified (for a colocated ACME upstream
    such as Pebble/step-ca on 127.0.0.1); cloud metadata stays blocked regardless."""
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    if ip in _CLOUD_METADATA_IP_OBJS:
        return "cloud metadata IP"
    if (ip.is_loopback or ip.is_unspecified) and not allow_loopback:
        return "loopback/unspecified address"
    return None


def validate_url_not_cloud_metadata(url: str, allow_loopback: bool = False) -> None:
    """Validate that a URL doesn't target cloud metadata services or loopback.

    This is a *narrow* SSRF guard — it explicitly ALLOWS RFC1918 private IPs
    (10.x, 192.168.x, 172.16.x) because UCM is commonly configured against
    internal infrastructure (AD, internal Keycloak, on-prem IdP, internal
    ACME CAs). It blocks only the highest-impact SSRF targets:

    - Cloud instance metadata endpoints (credential exfiltration)
    - Loopback (would let a compromised admin probe UCM's own internals)

    allow_loopback=True is an opt-in used only for a colocated ACME upstream
    (Pebble/step-ca on 127.0.0.1); cloud metadata stays blocked regardless.

    Raises ValueError if the URL targets a forbidden endpoint.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")

    host_l = host.lower().rstrip('.')

    # Short-circuit: explicit bad hostnames
    if host_l in _CLOUD_METADATA_HOSTS:
        raise ValueError(f"Host {host} is a cloud metadata endpoint")

    # Check literal IP (host_l has any trailing root dot stripped — "127.0.0.1."
    # reaches the same address wherever the resolver accepts it). Parsing and
    # policy are decided SEPARATELY: ip_address()'s parse error embeds the
    # hostname verbatim, so matching on the exception message would refuse
    # legitimate names that merely CONTAIN "metadata"/"loopback"/"unspecified"
    # — e.g. metadata-db.corp.example.com.
    try:
        ip = ipaddress.ip_address(host_l)
    except ValueError:
        ip = None  # Not a literal IP — fall through to DNS resolution.
    if ip is not None:
        reason = _forbidden_ip_reason(ip, allow_loopback)
        if reason:
            raise ValueError(f"Host {host} is a {reason}")
        return

    # Resolve hostname and check all returned IPs. Fail CLOSED when the host
    # cannot be resolved, the same rule validate_host_not_private applies:
    # "cannot resolve, so cannot reach anything" proved to be a fail-open —
    # the HTTP client re-parses odd values as a URL authority and resolves on
    # its own, and a resolver that answers the fetch but SERVFAILs this check
    # would otherwise switch the guard off entirely.
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host {host}: {e}")
    for _, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        reason = _forbidden_ip_reason(ip, allow_loopback)
        if reason:
            raise ValueError(f"Host {host} resolves to {reason} {ip}")


# ---------------------------------------------------------------------------
# DNS-rebinding-safe outbound HTTP
# ---------------------------------------------------------------------------
#
# validate_url_not_cloud_metadata() resolves the hostname once, but the
# subsequent requests.* call resolves it AGAIN. A hostile / compromised DNS
# server can return a benign IP for the validation lookup and a forbidden
# IP (cloud metadata, loopback, etc.) for the connection lookup — classic
# DNS rebinding.
#
# The standard mitigation is to resolve once, validate the IP, and then
# pin the connection to that exact IP while preserving the original
# hostname for SNI + certificate verification. We implement that by
# installing a thread-local override of urllib3's create_connection.
#
# Caller responsibility: only use safe_request_post() / safe_request_get() /
# safe_request_head() for outbound HTTP whose URL is provided by an authenticated UCM admin
# (webhooks, SSO discovery, etc.). Protocol-driven fetches (ACME challenge
# validation, CDP/OCSP) run their own identifier validation instead — but that
# validation resolves the name and then lets the HTTP client resolve it again,
# so it is only rebinding-safe where the caller pins the connection itself with
# pin_host() (ACME HTTP-01 / TLS-ALPN-01 do, when private IPs are disallowed).

_pinned_resolution = threading.local()


def _patched_create_connection(address, *args, **kwargs):
    """urllib3.util.connection.create_connection wrapper that re-routes
    the connection to a thread-locally pinned IP while keeping the
    original hostname intact for SNI / cert verification.

    A pinned entry may be a single IP or a list of validated IPs; a list is
    tried in order — mirroring urllib3's own getaddrinfo loop — so pinning
    does not silently discard multi-A/dual-stack failover. The original
    hostname is NEVER handed back to the OS resolver while a pin is in
    place, even when every pinned address fails: a rebinding answer outside
    the validated set must stay unreachable."""
    pinned = getattr(_pinned_resolution, 'host_to_ip', None)
    if pinned:
        host, port = address
        ips = pinned.get(host.lower().rstrip('.'))
        if ips:
            if isinstance(ips, str):
                ips = [ips]
            err = None
            for ip in ips:
                try:
                    return _orig_create_connection((ip, port), *args, **kwargs)
                except OSError as e:
                    err = e
            raise err
    return _orig_create_connection(address, *args, **kwargs)


# Lazy import & patch — only when a caller actually wants safe outbound HTTP.
_orig_create_connection = None
_patch_lock = threading.Lock()


def _ensure_urllib3_patched():
    global _orig_create_connection
    if _orig_create_connection is not None:
        return
    with _patch_lock:
        if _orig_create_connection is not None:
            return
        from urllib3.util import connection as urllib3_connection
        _orig_create_connection = urllib3_connection.create_connection
        urllib3_connection.create_connection = _patched_create_connection


@contextmanager
def pin_host(host: str, ip):
    """Within this block, all urllib3 connections to `host` go to `ip` —
    a single IP string, or a list of validated IPs tried in order (see
    _patched_create_connection)."""
    _ensure_urllib3_patched()
    pinned = getattr(_pinned_resolution, 'host_to_ip', None)
    if pinned is None:
        pinned = {}
        _pinned_resolution.host_to_ip = pinned
    key = host.lower().rstrip('.')
    prev = pinned.get(key)
    pinned[key] = ip
    try:
        yield
    finally:
        if prev is None:
            pinned.pop(key, None)
        else:
            pinned[key] = prev


def _resolve_and_validate(url: str, allow_loopback: bool = False) -> tuple:
    """Resolve URL hostname to its safe IPs. Returns (host, [ips]).

    Every validated address comes back (deduplicated, in resolver order),
    exactly as validate_host_not_private does and for the same reason: the
    loop below refuses the host outright if ANY resolved address is
    forbidden, so on return the whole set is public-safe. Returning only the
    first would pin the caller's outbound HTTP to one address and lose
    multi-A/dual-stack failover for zero security benefit.

    Raises ValueError if the URL has no hostname, fails to resolve,
    or any resolved IP is forbidden (cloud metadata / loopback)."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")

    # Already a literal IP — validate and pin to itself. Parse failure must
    # not be conflated with the policy raise: ip_address() embeds the
    # hostname in its parse-error message, so a message sniff would refuse
    # hosts merely containing "metadata"/"loopback"/"unspecified".
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None  # Not a literal IP — resolve below.
    if ip_obj is not None:
        reason = _forbidden_ip_reason(ip_obj, allow_loopback)
        if reason:
            raise ValueError(f"Host {host} is a {reason}")
        return host, [str(ip_obj)]

    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve {host}: {e}")

    chosen = []
    for _, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        reason = _forbidden_ip_reason(ip, allow_loopback)
        if reason:
            raise ValueError(f"Host {host} resolves to {reason} {ip}")
        if str(ip) not in chosen:
            chosen.append(str(ip))

    if not chosen:
        raise ValueError(f"Host {host} produced no usable IPs")

    return host, chosen


def validated_addresses(url: str, allow_loopback: bool = False) -> tuple:
    """The host and the addresses `url` resolves to, once vetted.

    The three helpers below resolve, vet and pin around a single request, and
    that is what most callers want. A caller holding its own
    `requests.Session` cannot use them, and validating on its own leaves the
    name to be resolved a second time when the connection is made: between
    the two, a name answering different addresses in turn reaches whatever it
    likes, with no race to win. This hands back what `pin_host` needs so such
    a caller can vet once and connect to what was vetted.

    The pin must be entered before the session's first connection: a socket
    already in its pool was created outside it.
    """
    return _resolve_and_validate(url, allow_loopback)


def safe_request_post(url, allow_loopback: bool = False, **kwargs):
    """requests.post() with DNS-rebinding protection.

    Resolves the URL hostname once, validates it against the cloud-metadata
    deny-list, and pins the underlying TCP connection to the addresses that
    were actually validated for the duration of the call — the whole set, so
    a multi-A/dual-stack upstream keeps its failover (see pin_host). SNI and
    certificate verification continue to use the original hostname so HTTPS
    works normally.

    allow_loopback=True permits a colocated upstream on 127.0.0.1 (ACME
    Pebble/step-ca); cloud metadata stays blocked. Default keeps loopback denied.
    """
    import requests
    kwargs.setdefault('timeout', 30)  # never hang forever on a stuck/slow upstream
    host, ips = _resolve_and_validate(url, allow_loopback)
    with pin_host(host, ips):
        return requests.post(url, **kwargs)


def safe_request_get(url, allow_loopback: bool = False, **kwargs):
    """requests.get() counterpart of safe_request_post()."""
    import requests
    kwargs.setdefault('timeout', 30)  # never hang forever on a stuck/slow upstream
    host, ips = _resolve_and_validate(url, allow_loopback)
    with pin_host(host, ips):
        return requests.get(url, **kwargs)


def safe_request_head(url, allow_loopback: bool = False, **kwargs):
    """requests.head() with DNS-rebinding protection (e.g. ACME newNonce)."""
    import requests
    kwargs.setdefault('timeout', 30)
    host, ips = _resolve_and_validate(url, allow_loopback)
    with pin_host(host, ips):
        return requests.head(url, **kwargs)
