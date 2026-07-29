"""SSRF mitigation tests covering all five threat-model attacks:

    - Cloud-metadata exfil (AWS / Azure / Alibaba endpoints)
    - Redirect-based bypass (out-of-scope for the helper itself; caller wraps
      its HTTP client with allow_redirects=False — tested separately when wired)
    - URL parser confusion (backslash / tab / CR / LF / null)
    - DNS rebinding (resolve_pinned + assert_public_ip combo)
    - Private IPv6 (link-local fe80::, unique-local fc00::/7, loopback ::1)
"""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from mycelium_security import url as url_module
from mycelium_security import (
    UnsafeURL,
    assert_public_ip,
    resolve_pinned,
    sanitize_or_raise,
)

_SHARED_VECTOR_PATH = Path(__file__).with_name("ssrf_shared_vectors.json")


def _shared_vectors() -> list[dict[str, object]]:
    payload = json.loads(_SHARED_VECTOR_PATH.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    vectors = payload["vectors"]
    assert isinstance(vectors, list)
    return vectors


@pytest.mark.parametrize("vector", _shared_vectors())
def test_shared_ssrf_vector_contract(vector):
    host = vector["host"]
    allowlist_ranges = vector["allowlist_ranges"]
    allowed = vector["allowed"]
    assert isinstance(host, str)
    assert isinstance(allowlist_ranges, list)
    assert all(isinstance(cidr, str) for cidr in allowlist_ranges)
    assert isinstance(allowed, bool)

    try:
        assert_public_ip(host, allowlist_ranges=allowlist_ranges)
        actual_allowed = True
    except UnsafeURL:
        actual_allowed = False

    assert actual_allowed is allowed


def test_shared_contract_covers_every_metadata_representation_under_allowlist():
    covered = {
        (
            vector["host"],
            tuple(vector["allowlist_ranges"]),
        )
        for vector in _shared_vectors()
        if vector["allowed"] is False
    }
    expected: set[tuple[str, tuple[str, ...]]] = set()

    for literal in url_module._METADATA_IPS:
        address = ipaddress.ip_address(literal)
        if isinstance(address, ipaddress.IPv4Address):
            value = int(address)
            high = value >> 16
            low = value & 0xFFFF
            complemented = value ^ 0xFFFFFFFF
            expected.update(
                {
                    (str(address), (f"{address}/32",)),
                    (f"::ffff:{address}", ("::ffff:0:0/96",)),
                    (f"2002:{high:04x}:{low:04x}::", ("2002::/16",)),
                    (f"64:ff9b::{high:04x}:{low:04x}", ("64:ff9b::/96",)),
                    (
                        "2001:0000:4136:e378:8000:63bf:"
                        f"{complemented >> 16:04x}:{complemented & 0xFFFF:04x}",
                        ("2001::/32",),
                    ),
                }
            )
        else:
            expected.update(
                {
                    (str(address), ("fc00::/7",)),
                    (f"{address}%lo0", ("fc00::/7",)),
                    (f"{address}%25lo0", ("fc00::/7",)),
                }
            )

    assert expected <= covered


class TestSanitizeOrRaise:
    def test_accepts_http(self):
        assert sanitize_or_raise("http://example.com/path") == "http://example.com/path"

    def test_accepts_https(self):
        assert sanitize_or_raise("https://example.com/path") == "https://example.com/path"

    def test_accepts_https_with_query(self):
        url = "https://api.example.com/v1/tts?voice=neutral&lang=en"
        assert sanitize_or_raise(url) == url

    @pytest.mark.parametrize(
        "dangerous_url",
        [
            "https://example.com/\\path",     # backslash
            "https://example.com/\tpath",     # tab
            "https://example.com/\rpath",     # CR
            "https://example.com/\npath",     # LF
            "https://example.com/\x00path",   # null
        ],
    )
    def test_rejects_dangerous_chars(self, dangerous_url):
        with pytest.raises(UnsafeURL, match="banned character"):
            sanitize_or_raise(dangerous_url)

    @pytest.mark.parametrize(
        "scheme",
        ["file", "ftp", "gopher", "dict", "ldap", "javascript", "data"],
    )
    def test_rejects_non_http_schemes(self, scheme):
        with pytest.raises(UnsafeURL, match="scheme"):
            sanitize_or_raise(f"{scheme}://example.com/path")

    def test_rejects_embedded_credentials(self):
        with pytest.raises(UnsafeURL, match="credentials"):
            sanitize_or_raise("https://user:pass@example.com/path")

    def test_rejects_empty(self):
        with pytest.raises(UnsafeURL):
            sanitize_or_raise("")

    def test_rejects_non_string(self):
        with pytest.raises(UnsafeURL):
            sanitize_or_raise(None)  # type: ignore[arg-type]

    def test_rejects_no_hostname(self):
        with pytest.raises(UnsafeURL, match="hostname"):
            sanitize_or_raise("https:///path")


class TestAssertPublicIPMetadata:
    @pytest.mark.parametrize(
        "metadata_ip",
        ["169.254.169.254", "100.100.100.200"],
    )
    def test_rejects_cloud_metadata_v4(self, metadata_ip):
        with pytest.raises(UnsafeURL, match="metadata"):
            assert_public_ip(metadata_ip)

    def test_rejects_cloud_metadata_v6(self):
        with pytest.raises(UnsafeURL, match="metadata"):
            assert_public_ip("fd00:ec2::254")

    def test_cloud_metadata_cannot_be_allowlisted(self):
        with pytest.raises(UnsafeURL, match="metadata"):
            assert_public_ip(
                "169.254.169.254",
                allowlist_ranges=["169.254.0.0/16"],
            )

    @pytest.mark.parametrize(
        ("metadata_ip", "allowlist"),
        [
            ("::ffff:169.254.169.254", "::ffff:169.254.0.0/112"),
            ("2002:a9fe:a9fe::", "2002::/16"),
            ("64:ff9b::a9fe:a9fe", "64:ff9b::/96"),
            ("2001:0000:4136:e378:8000:63bf:5601:5601", "2001::/32"),
            ("fd00:ec2::254", "fc00::/7"),
            ("fd00:ec2::254%lo0", "fc00::/7"),
            ("fd00:ec2::254%25lo0", "fc00::/7"),
        ],
    )
    def test_cloud_metadata_representation_cannot_be_allowlisted(
        self, metadata_ip, allowlist
    ):
        with pytest.raises(UnsafeURL, match="metadata"):
            assert_public_ip(metadata_ip, allowlist_ranges=[allowlist])


class TestAssertPublicIPPrivateRanges:
    @pytest.mark.parametrize(
        "private_ip",
        [
            "10.0.0.1",        # RFC1918
            "172.16.0.1",      # RFC1918
            "192.168.1.1",     # RFC1918
            "127.0.0.1",       # Loopback
            "169.254.0.1",     # Link-local (non-metadata)
            "0.0.0.0",         # Unspecified
        ],
    )
    def test_rejects_private_ipv4(self, private_ip):
        with pytest.raises(UnsafeURL):
            assert_public_ip(private_ip)

    @pytest.mark.parametrize(
        "private_v6",
        [
            "::1",          # Loopback
            "fe80::1",      # Link-local
            "fc00::1",      # Unique-local
            "fd00::1",      # Unique-local
        ],
    )
    def test_rejects_private_ipv6(self, private_v6):
        with pytest.raises(UnsafeURL):
            assert_public_ip(private_v6)

    def test_accepts_public_ipv4(self):
        # 8.8.8.8 = Google DNS, definitely public
        assert_public_ip("8.8.8.8")

    def test_accepts_public_ipv6(self):
        # 2606:4700:4700::1111 = Cloudflare DNS, public
        assert_public_ip("2606:4700:4700::1111")

    def test_enterprise_allowlist_overrides_private(self):
        # Enterprise tenant with on-prem 10.x range allowlisted
        assert_public_ip("10.5.5.5", allowlist_ranges=["10.0.0.0/8"])

    def test_enterprise_allowlist_narrow_cidr(self):
        # Allowlist matches a specific subnet only
        assert_public_ip("192.168.1.10", allowlist_ranges=["192.168.1.0/24"])
        with pytest.raises(UnsafeURL):
            assert_public_ip("192.168.2.10", allowlist_ranges=["192.168.1.0/24"])


class TestAssertPublicIPSharedAddressSpace:
    """CGNAT / RFC 6598 — the range a property-only check let through.

    `100.64.0.0/10` reports `is_private=False` on current CPython (verified on
    3.12.13 and 3.14.6), so the original property-only implementation ALLOWED
    it. It is routable internal space at cloud providers, carrier NATs and
    overlay networks (Tailscale uses exactly this range), so it is a live SSRF
    target. Regression test for that gap.
    """

    @pytest.mark.parametrize(
        "cgnat_ip",
        [
            "100.64.0.0",        # first address in the range
            "100.64.0.1",        # the reported case
            "100.100.100.100",   # mid-range
            "100.127.255.255",   # last address in the range
        ],
    )
    def test_rejects_cgnat(self, cgnat_ip):
        with pytest.raises(UnsafeURL):
            assert_public_ip(cgnat_ip)

    @pytest.mark.parametrize(
        "public_neighbour",
        [
            "100.63.255.255",  # one below 100.64.0.0 — must still be allowed
            "100.128.0.0",     # one above 100.127.255.255 — must still be allowed
        ],
    )
    def test_boundary_neighbours_still_allowed(self, public_neighbour):
        """NEGATIVE CONTROL: the block must not bleed past the /10 boundary.

        An over-broad blocklist breaks legitimate fetches and teaches people to
        bypass the guard, so the edges matter as much as the range itself.
        """
        assert_public_ip(public_neighbour)

    def test_allowlist_can_override_cgnat(self):
        """An on-prem/overlay tenant legitimately running CGNAT can opt in."""
        assert_public_ip("100.64.5.5", allowlist_ranges=["100.64.0.0/10"])


class TestAssertPublicIPEmbeddedIPv4:
    """IPv4 tunnelled inside IPv6 must be validated on the INNER address."""

    @pytest.mark.parametrize(
        "tunnelled",
        [
            "::ffff:10.0.0.1",           # IPv4-mapped, RFC1918 inside
            "::ffff:127.0.0.1",          # IPv4-mapped loopback
            "::ffff:100.64.0.1",         # IPv4-mapped CGNAT
            "::ffff:169.254.169.254",    # IPv4-mapped cloud metadata
            "2002:a00:1::",              # 6to4 wrapping 10.0.0.1
            "2002:6440:1::",             # 6to4 wrapping 100.64.0.1
            "64:ff9b::a00:1",            # NAT64 wrapping 10.0.0.1
            "64:ff9b::6440:1",           # NAT64 wrapping 100.64.0.1
        ],
    )
    def test_rejects_private_ipv4_inside_ipv6(self, tunnelled):
        with pytest.raises(UnsafeURL):
            assert_public_ip(tunnelled)

    def test_public_ipv4_mapped_still_allowed(self):
        """NEGATIVE CONTROL: a mapped PUBLIC address is not collateral damage."""
        assert_public_ip("::ffff:8.8.8.8")

    def test_public_nat64_still_allowed(self):
        """NEGATIVE CONTROL: standard NAT64 preserves a public inner address."""
        assert_public_ip("64:ff9b::808:808")


class TestAssertPublicIPSpecialPurposeTable:
    """Table-driven sweep of IANA special-purpose ranges.

    Enumerated so a range cannot be silently forgotten the way CGNAT was. Each
    entry is one representative address from a range that must never be
    fetchable.
    """

    @pytest.mark.parametrize(
        "addr,label",
        [
            ("0.0.0.0", "this-network"),
            ("10.0.0.1", "rfc1918-10"),
            ("100.64.0.1", "cgnat"),
            ("127.0.0.1", "loopback"),
            ("169.254.0.1", "link-local"),
            ("172.16.0.1", "rfc1918-172"),
            ("192.0.0.1", "ietf-protocol"),
            ("192.0.2.1", "test-net-1"),
            ("192.168.0.1", "rfc1918-192"),
            ("198.18.0.1", "benchmarking"),
            ("198.51.100.1", "test-net-2"),
            ("203.0.113.1", "test-net-3"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved-class-e"),
            ("255.255.255.255", "broadcast"),
            ("::", "v6-unspecified"),
            ("::1", "v6-loopback"),
            ("100::1", "v6-discard"),
            ("2001:db8::1", "v6-documentation"),
            ("fc00::1", "v6-unique-local"),
            ("fd00::1", "v6-unique-local-fd"),
            ("fe80::1", "v6-link-local"),
            ("ff02::1", "v6-multicast"),
        ],
    )
    def test_special_purpose_range_is_blocked(self, addr, label):
        with pytest.raises(UnsafeURL):
            assert_public_ip(addr)

    @pytest.mark.parametrize(
        "addr,label",
        [
            ("8.8.8.8", "google-dns"),
            ("1.1.1.1", "cloudflare-dns"),
            ("140.82.121.4", "github-api"),
            ("2606:4700:4700::1111", "cloudflare-dns-v6"),
            ("2001:4860:4860::8888", "google-dns-v6"),
        ],
    )
    def test_genuinely_public_still_allowed(self, addr, label):
        """NEGATIVE CONTROL: real vendor endpoints must keep working.

        A blocklist that also blocks these would break every connector that
        depends on this package.
        """
        assert_public_ip(addr)


class TestAssertPublicIPDNSRebinding:
    def test_hostname_resolving_to_private_ip_blocked(self):
        # Simulate DNS rebinding: a "public" hostname resolves to 10.0.0.1
        with patch("mycelium_security.url.socket.getaddrinfo") as mock_resolver:
            mock_resolver.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
            ]
            with pytest.raises(UnsafeURL):
                assert_public_ip("attacker-controlled.example.com")

    def test_hostname_resolving_to_metadata_blocked(self):
        with patch("mycelium_security.url.socket.getaddrinfo") as mock_resolver:
            mock_resolver.return_value = [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("169.254.169.254", 0),
                )
            ]
            with pytest.raises(UnsafeURL, match="metadata"):
                assert_public_ip("attacker-rebind-to-imds.example.com")

    def test_multi_record_one_private_blocks(self):
        # Resolver returns both a public AND a private IP — block on the private one
        with patch("mycelium_security.url.socket.getaddrinfo") as mock_resolver:
            mock_resolver.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
            ]
            with pytest.raises(UnsafeURL):
                assert_public_ip("dual-record.example.com")


class TestAssertPublicIPEdgeCases:
    def test_rejects_empty_host(self):
        with pytest.raises(UnsafeURL):
            assert_public_ip("")

    def test_raises_on_unresolvable(self):
        with pytest.raises(UnsafeURL, match="resolution failed"):
            assert_public_ip("definitely-not-a-real-tld-zzzzzzzz.invalid")


class TestResolvePinned:
    def test_returns_literal_ip_unchanged(self):
        assert resolve_pinned("8.8.8.8") == "8.8.8.8"

    def test_returns_literal_ipv6_unchanged(self):
        assert resolve_pinned("2606:4700:4700::1111") == "2606:4700:4700::1111"

    def test_raises_on_unresolvable(self):
        with pytest.raises(UnsafeURL):
            resolve_pinned("definitely-not-a-real-tld-zzzzzzzz.invalid")

    def test_uses_first_resolved_ip(self):
        with patch("mycelium_security.url.socket.getaddrinfo") as mock_resolver:
            mock_resolver.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.2", 0)),
            ]
            assert resolve_pinned("multi-record.example.com") == "203.0.113.1"
