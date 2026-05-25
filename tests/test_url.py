"""SSRF mitigation tests covering all five threat-model attacks:

    - Cloud-metadata exfil (AWS / Azure / Alibaba endpoints)
    - Redirect-based bypass (out-of-scope for the helper itself; caller wraps
      its HTTP client with allow_redirects=False — tested separately when wired)
    - URL parser confusion (backslash / tab / CR / LF / null)
    - DNS rebinding (resolve_pinned + assert_public_ip combo)
    - Private IPv6 (link-local fe80::, unique-local fc00::/7, loopback ::1)
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from mycelium_security import (
    UnsafeURL,
    assert_public_ip,
    resolve_pinned,
    sanitize_or_raise,
)


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
