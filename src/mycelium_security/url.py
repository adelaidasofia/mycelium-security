"""URL hardening helpers for SSRF mitigation.

Defends against:
  - Cloud-metadata exfiltration (AWS / GCP / Azure / Alibaba IMDS endpoints)
  - Redirect-based SSRF bypass (caller wraps fetcher with allow_redirects=False)
  - URL parser confusion (backslash / tab / CR / LF / null / embedded creds)
  - DNS rebinding (caller pins resolved IP via resolve_pinned for fetch lifetime)
  - Private network probing (IPv4 + IPv6 private / link-local / loopback blocked)
  - Shared address space / CGNAT (100.64.0.0/10, RFC 6598) — routable internal
    space at cloud providers, carrier NATs and overlay networks
  - IPv4 tunnelled inside IPv6 (IPv4-mapped / 6to4 / Teredo / NAT64) — the inner
    address is validated too, so ``::ffff:10.0.0.1`` cannot smuggle a private target

Usage (recommended — single resolution, no rebinding window):
    from urllib.parse import urlparse
    from mycelium_security import sanitize_or_raise, resolve_and_validate, resolve_pinned

    safe_url = sanitize_or_raise(user_supplied_url)
    host = urlparse(safe_url).hostname
    validated = resolve_and_validate(host, allowlist_ranges=enterprise_onprem_cidrs)
    pinned_ip = resolve_pinned(host, validated=validated)
    # `validated` carries `enterprise_onprem_cidrs` inside it (MYC-4650
    # review round 3, F7), so `resolve_pinned` re-validates against that
    # SAME allowlist even though this call passes no `allowlist_ranges` of
    # its own — this recommended snippet now round-trips correctly for an
    # Enterprise on-prem allowlisted host.
    # ...now safe to fetch with allow_redirects=False, using pinned_ip

Deprecated pattern (two INDEPENDENT lookups — do not use for new code):
    assert_public_ip(host, allowlist_ranges=enterprise_onprem_cidrs)
    pinned_ip = resolve_pinned(host, allowlist_ranges=enterprise_onprem_cidrs)
    # `resolve_pinned` still re-validates this single-arg call internally
    # (MYC-4650), so it is safe, but it now does its OWN resolution rather
    # than reusing `assert_public_ip`'s — prefer `resolve_and_validate` +
    # `resolve_pinned(host, validated=...)` so only one DNS lookup happens
    # for the whole validate-then-pin sequence.
    #
    # `allowlist_ranges` must be passed to BOTH calls here (MYC-4650 review
    # round 2): `resolve_pinned`'s legacy one-arg form re-resolves and
    # re-validates on its own, with an EMPTY allowlist by default, so a host
    # that only resolves inside `enterprise_onprem_cidrs` raises `UnsafeURL`
    # if this second call omits it — even though `assert_public_ip` on the
    # line above already accepted that exact host.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import NamedTuple
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

_NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")


class ValidatedResolution(NamedTuple):
    """The result of resolving + validating a host, for reuse without a second lookup.

    ``ips`` is the exact list ``assert_public_ip`` / ``resolve_and_validate``
    already resolved and validated, in resolution order. Pass this object to
    ``resolve_pinned(host, validated=...)`` so the pinned IP comes from THIS
    list rather than a fresh, unvalidated DNS lookup (MYC-4650: reusing the
    validated list is what closes the DNS-rebinding window between "validate"
    and "pin").

    A ``NamedTuple``, not a ``@dataclass`` (MYC-4650 review round 2, F1): a
    consumer (memory-runtime-pro's ``security-audit`` gate) loads this file
    standalone via ``importlib.util.spec_from_file_location`` +
    ``exec_module``, which never registers the module in ``sys.modules``.
    With ``from __future__ import annotations`` active, ``@dataclass`` calls
    ``dataclasses._is_type``, which does ``sys.modules.get(cls.__module__)``
    and then dereferences its ``.__dict__`` — ``None.__dict__`` raises
    ``AttributeError`` on every standalone load. ``NamedTuple`` has no such
    dependency on module registration, so it loads standalone on 3.10+
    (the package floor; measured on 3.12 and 3.14).

    ``allowlist_ranges`` is the (normalised to ``tuple[str, ...]``) set of
    on-prem CIDRs ``assert_public_ip`` / ``resolve_and_validate`` validated
    this resolution against (MYC-4650 review round 3, F7). Carrying it here
    is what lets ``resolve_pinned(host, validated=...)`` re-validate the
    reused list against the SAME allowlist the caller originally used,
    without repeating ``allowlist_ranges`` at the pin call site.

    Residual risk: this is a plain, unchecked ``NamedTuple`` — nothing
    stops a caller from hand-building one that NAMES a private range in
    its own ``allowlist_ranges`` and self-authorising it for whatever
    `resolve_pinned` re-validation runs next. Only trust an
    ``allowlist_ranges`` value on a record this package itself produced.
    Cloud-metadata IPs remain blocked unconditionally by ``_validate_ips``
    regardless of any allowlist, hand-built or not.
    """

    host: str
    ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    allowlist_ranges: tuple[str, ...] = ()


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


# Explicit IANA special-purpose ranges.
#
# WHY AN EXPLICIT LIST AND NOT JUST THE `ipaddress` PROPERTIES:
# the stdlib properties are a moving target. CPython has revised what
# `is_private` / `is_global` mean (notably the CVE-2024-4032 correction to the
# special-purpose registries), so the SAME code can classify an address
# differently across the Python versions this package supports (>=3.10).
# A security blocklist must not silently change shape with the interpreter.
#
# Concretely: `100.64.0.0/10` (RFC 6598 "Shared Address Space", carrier-grade
# NAT) reports `is_private=False` on current CPython, so a property-only check
# ALLOWED it — verified on 3.12.13 and 3.14.6. That range is routable internal
# space at cloud providers, carrier NATs, and overlay networks (Tailscale uses
# exactly it), which makes it a live SSRF target rather than dead space.
#
# These entries are deterministic and auditable. The property checks below are
# KEPT as defence-in-depth, so anything the list misses still has a second net.
_BLOCKED_V4_NETWORKS: tuple[str, ...] = (
    "0.0.0.0/8",          # "this network" (RFC 1122)
    "10.0.0.0/8",         # RFC 1918 private
    "100.64.0.0/10",      # RFC 6598 shared address space / CGNAT  <- the gap
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local (incl. cloud metadata)
    "172.16.0.0/12",      # RFC 1918 private
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # TEST-NET-1
    "192.168.0.0/16",     # RFC 1918 private
    "198.18.0.0/15",      # benchmarking (RFC 2544)
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved (class E), incl. 255.255.255.255
)

_BLOCKED_V6_NETWORKS: tuple[str, ...] = (
    "::/128",             # unspecified
    "::1/128",            # loopback
    "100::/64",           # discard-only
    "2001:db8::/32",      # documentation
    "fc00::/7",           # unique-local
    "fe80::/10",          # link-local
    "ff00::/8",           # multicast
)

_BLOCKED_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(c) for c in (*_BLOCKED_V4_NETWORKS, *_BLOCKED_V6_NETWORKS)
)


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Extract the IPv4 address tunnelled inside an IPv6 address, if any.

    IPv4-mapped (``::ffff:10.0.0.1``), 6to4 (``2002:a00:1::``) and Teredo all
    carry an IPv4 address inside an IPv6 one. Checking only the outer IPv6
    form can miss a private target, so callers must validate the INNER address
    too. This is the bypass shape a property-only check cannot see.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    for attr in ("ipv4_mapped", "sixtofour"):
        inner = getattr(ip, attr, None)
        if inner is not None:
            return inner
    teredo = getattr(ip, "teredo", None)
    if teredo:
        # (server, client) — the client address is the interesting half.
        return teredo[1]
    if ip in _NAT64_NETWORK:
        return ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return None


def _is_metadata_endpoint(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # IPv6 zone identifiers select an interface, not a different address.
    # Strip them before policy comparison so ``fd00:ec2::254%eth0`` cannot
    # evade the non-overridable metadata check and fall through an allowlist.
    policy_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ip
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
        policy_ip = ipaddress.IPv6Address(ip.packed)
    if str(policy_ip) in _METADATA_IPS:
        return True
    inner = _embedded_ipv4(policy_ip)
    return inner is not None and str(inner) in _METADATA_IPS


def _is_private_or_reserved(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    inner = _embedded_ipv4(ip)
    # NAT64 is a transport encoding whose standard outer prefix is classified
    # reserved by the stdlib even when the embedded destination is public.
    # Validate that actual IPv4 destination instead; metadata is checked above.
    # Other transition formats retain both checks to avoid widening their
    # established policy as a side effect of this NAT64 correction.
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address]
    if inner is not None and isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_NETWORK:
        candidates = [inner]
    else:
        candidates = [ip]
        if inner is not None:
            candidates.append(inner)
    for candidate in candidates:
        if any(candidate in net for net in _BLOCKED_NETS):
            return True
        if (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_multicast
            or candidate.is_reserved
            or candidate.is_unspecified
        ):
            return True
    return False


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


def _validate_ips(
    host: str,
    ips: Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address],
    *,
    allowlist_ranges: Iterable[str] = (),
) -> None:
    """Raise UnsafeURL if any IP in `ips` (already resolved from `host`) is blocked.

    Shared by `assert_public_ip` and `resolve_pinned`'s legacy one-arg path so
    both validate the SAME list of IPs the same way — never two independent
    resolutions validated by two independent code paths.
    """
    allowed_nets = [ipaddress.ip_network(cidr, strict=False) for cidr in allowlist_ranges]
    for ip in ips:
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


def assert_public_ip(
    host: str, *, allowlist_ranges: Iterable[str] = ()
) -> ValidatedResolution:
    """Resolve host to all IPs; raise UnsafeURL if any are blocked.

    `allowlist_ranges`: optional Enterprise-tier on-prem CIDRs (e.g.
    `["10.0.0.0/8", "192.168.1.0/24"]`) that override the standard
    private-IP block. Allowlist NEVER bypasses cloud-metadata block.

    Returns the `ValidatedResolution` (the exact resolved + validated IP
    list) so a caller can hand it to `resolve_pinned(host, validated=...)`
    without triggering a second, unvalidated DNS lookup. Existing callers
    that only relied on the raise-on-failure behavior are unaffected.

    The returned `ValidatedResolution.allowlist_ranges` carries this call's
    `allowlist_ranges`, normalised to `tuple[str, ...]` (MYC-4650 review
    round 3, F7), so `resolve_pinned(host, validated=...)` can re-validate
    against the SAME allowlist without the caller repeating it.
    """
    if not host:
        raise UnsafeURL("Cannot validate empty host")
    normalized_allowlist = tuple(str(cidr) for cidr in allowlist_ranges)
    ips = _resolve_all(host)
    _validate_ips(host, ips, allowlist_ranges=normalized_allowlist)
    return ValidatedResolution(
        host=host, ips=tuple(ips), allowlist_ranges=normalized_allowlist
    )


def resolve_and_validate(
    host: str, *, allowlist_ranges: Iterable[str] = ()
) -> ValidatedResolution:
    """Recommended single entry point: resolve `host` ONCE and validate it.

    Equivalent to `assert_public_ip`, named for the call site that wants the
    validated resolution to hand straight to `resolve_pinned(host, validated=...)`.
    """
    return assert_public_ip(host, allowlist_ranges=allowlist_ranges)


def resolve_pinned(
    host: str,
    *,
    validated: ValidatedResolution | None = None,
    allowlist_ranges: Iterable[str] = (),
) -> str:
    """Return the first validated IP as a string, for pinned-IP fetches.

    Pass `validated` (the `ValidatedResolution` returned by
    `resolve_and_validate` / `assert_public_ip`) to pin from that SAME
    resolution with NO new DNS lookup — the recommended path, since it
    closes the DNS-rebinding window between "validate" and "pin" entirely.
    `validated.host` must match `host`, or this raises `UnsafeURL` — a
    mismatch means the caller is pinning the wrong host's resolution.

    Called with no `validated` (legacy one-arg form), this does its OWN
    single resolution and runs the same validation `assert_public_ip` runs
    on that list before returning — it never returns an unvalidated IP, but
    it is a SECOND, independent lookup versus a prior `assert_public_ip`
    call, so a rebinding resolver could answer differently between the two.
    Prefer the `validated=` form for new code (MYC-4650).

    `allowlist_ranges`: forwarded to whichever validation runs — the legacy
    path's fresh resolution, or the re-validation of a reused `validated`
    list (see below). Pass the SAME ranges used to build `validated` so the
    re-check agrees with the original decision. Without this parameter, an
    Enterprise on-prem caller who validated `host` with
    `allowlist_ranges=[...]` and then pinned via the legacy one-arg form
    would get `UnsafeURL` on their own allowlisted private IP, because the
    legacy path used to re-resolve with an empty allowlist regardless of
    what the caller had validated with (MYC-4650 review round 2, F2).

    When `validated` is passed and `allowlist_ranges` is NOT (the empty
    default), the re-validation uses `validated.allowlist_ranges` instead
    — the ranges `assert_public_ip`/`resolve_and_validate` recorded when
    they built `validated` — so the README-recommended `resolve_and_validate`
    + `resolve_pinned(host, validated=...)` pattern round-trips an
    Enterprise on-prem allowlist with no repeated argument (MYC-4650 review
    round 3, F7). Passing `allowlist_ranges` explicitly here still wins over
    whatever `validated` carries, for a caller that wants to widen or
    narrow the check at the pin site.

    Residual risk of trusting `validated.allowlist_ranges`: a hand-built
    `ValidatedResolution` can name a private range in its own
    `allowlist_ranges` and self-authorise it here. Cloud-metadata IPs stay
    blocked regardless — `_validate_ips` never lets any allowlist override
    that check.
    """
    if not host:
        raise UnsafeURL("Cannot validate empty host")
    if validated is not None:
        if not isinstance(validated, ValidatedResolution):
            raise UnsafeURL(
                f"validated must be a ValidatedResolution, got {type(validated)!r}"
            )
        if validated.host != host:
            raise UnsafeURL(
                f"validated resolution is for {validated.host!r}, not {host!r}"
            )
        if not validated.ips:
            raise UnsafeURL(f"validated resolution for {host!r} has no IPs")
        if not all(
            isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            for ip in validated.ips
        ):
            raise UnsafeURL(
                f"validated resolution for {host!r} contains a non-IP-address element"
            )
        # Re-validate the reused list (pure, no DNS) rather than trusting it
        # unconditionally — a hand-built or duck-typed `ValidatedResolution`
        # may not have been through `_validate_ips` at all (MYC-4650 review
        # round 2, F4/F5), so the returned IP must be validated by
        # construction, not merely by the caller's earlier good behavior.
        # An explicitly-passed `allowlist_ranges` wins; otherwise reuse the
        # allowlist `validated` itself was built with (round 3, F7).
        effective_allowlist = tuple(allowlist_ranges) or validated.allowlist_ranges
        _validate_ips(host, validated.ips, allowlist_ranges=effective_allowlist)
        return str(validated.ips[0])
    ips = _resolve_all(host)
    _validate_ips(host, ips, allowlist_ranges=allowlist_ranges)
    return str(ips[0])
