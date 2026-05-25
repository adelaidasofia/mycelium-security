"""URL hardening helpers for SSRF mitigation.

Defends against:
  - Cloud-metadata exfiltration (AWS / GCP / Azure / Alibaba IMDS endpoints)
  - Redirect-based SSRF bypass (caller wraps fetcher with allow_redirects=False)
  - URL parser confusion (backslash / tab / CR / LF / null / embedded creds)
  - DNS rebinding (caller pins resolved IP via resolve_pinned for fetch lifetime)
  - Private network probing (IPv4 + IPv6 private / link-local / loopback blocked)

Usage:
    from urllib.parse import urlparse
    from mycelium_security import sanitize_or_raise, assert_public_ip, resolve_pinned

    safe_url = sanitize_or_raise(user_supplied_url)
    host = urlparse(safe_url).hostname
    assert_public_ip(host, allowlist_ranges=enterprise_onprem_cidrs)
    pinned_ip = resolve_pinned(host)
    # ...now safe to fetch with allow_redirects=False, optionally using pinned_ip
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlparse


class UnsafeURL(ValueError):
    """A URL or host failed SSRF mitigation checks."""


_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_DANGEROUS_CHARS: frozenset[str] = frozenset({"\\", "\t", "\r", "\n", "\x00"})

_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS IMDSv1/v2, Azure IMDS, OpenStack
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",    # AWS IMDSv2 IPv6
    }
)


def sanitize_or_raise(url: str) -> str:
    """Validate a URL string. Return the (unchanged) URL or raise UnsafeURL.

    Rejects:
      - Non-string / empty input
      - Dangerous chars (backslash / tab / CR / LF / null) — URL parser confusion
      - Schemes outside http / https — file:// + gopher:// + dict:// are SSRF vectors
      - Embedded credentials (user:pass@host)
      - URLs with no resolvable hostname
    """
    if not isinstance(url, str) or not url:
        raise UnsafeURL("URL must be a non-empty string")
    for ch in _DANGEROUS_CHARS:
        if ch in url:
            raise UnsafeURL(f"URL contains banned character: {ch!r}")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURL(
            f"URL scheme {parsed.scheme!r} not in allowlist {sorted(_ALLOWED_SCHEMES)}"
        )
    if parsed.username or parsed.password:
        raise UnsafeURL("URL contains embedded credentials (user:pass@host)")
    if not parsed.hostname:
        raise UnsafeURL("URL has no hostname")
    return url


def _is_metadata_endpoint(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return str(ip) in _METADATA_IPS


def _is_private_or_reserved(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_all(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a host to all A + AAAA records, or treat as a literal IP."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURL(f"Host resolution failed for {host!r}: {exc}") from exc
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not out:
        raise UnsafeURL(f"No usable IPs resolved for {host!r}")
    return out


def assert_public_ip(
    host: str, *, allowlist_ranges: Iterable[str] = ()
) -> None:
    """Resolve host to all IPs; raise UnsafeURL if any are blocked.

    `allowlist_ranges`: optional Enterprise-tier on-prem CIDRs (e.g.
    `["10.0.0.0/8", "192.168.1.0/24"]`) that override the standard
    private-IP block. Allowlist NEVER bypasses cloud-metadata block.
    """
    if not host:
        raise UnsafeURL("Cannot validate empty host")
    allowed_nets = [ipaddress.ip_network(cidr, strict=False) for cidr in allowlist_ranges]
    for ip in _resolve_all(host):
        # Cloud-metadata is blocked regardless of any allowlist
        if _is_metadata_endpoint(ip):
            raise UnsafeURL(
                f"IP {ip} is a cloud-metadata endpoint (always blocked, no allowlist override)"
            )
        # Enterprise on-prem allowlist may override the standard private block
        if any(ip in net for net in allowed_nets):
            continue
        if _is_private_or_reserved(ip):
            raise UnsafeURL(
                f"IP {ip} resolved from {host!r} is in a private / reserved / link-local range"
            )


def resolve_pinned(host: str) -> str:
    """Resolve host once. Return the first IP as a string for pinned-IP fetches.

    Used AFTER assert_public_ip succeeds. Pinning the IP prevents DNS-rebinding
    attacks where the host's DNS re-resolves to a private IP between the
    validation step and the actual fetch.
    """
    ips = _resolve_all(host)
    return str(ips[0])
