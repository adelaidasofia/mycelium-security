# Changelog

## v0.1.0 — 2026-05-25

Initial release.

- `sanitize_or_raise(url)` — rejects dangerous chars (backslash / tab / CR / LF / null), non-http(s) schemes, embedded credentials, empty / hostless URLs
- `assert_public_ip(host, allowlist_ranges=())` — resolves host, raises on private / loopback / link-local / unspecified / reserved / multicast IPs; always blocks cloud-metadata endpoints (AWS / Azure / Alibaba IMDS, IPv4 + IPv6) regardless of allowlist
- `resolve_pinned(host)` — returns first resolved IP for DNS-rebinding-safe fetch
- `UnsafeURL` exception (subclass of `ValueError`)
- 46-test fixture covering all five threat-model attacks from the OWASP SSRF playbook
- Python 3.10+
- MIT license
