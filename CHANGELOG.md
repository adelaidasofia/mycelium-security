# Changelog

## v0.1.2 — 2026-07-28

### Fixed

- Standard-prefix NAT64 now validates the embedded IPv4 destination without
  blanket-blocking the outer `64:ff9b::/96` representation.
- Public NAT64 destinations such as the encoding of `8.8.8.8` remain reachable,
  while private, CGNAT, and cloud-metadata destinations remain blocked.
- The exported `__version__` now matches the package version.

## v0.1.1 — 2026-07-21

**Security fix.** `assert_public_ip()` allowed carrier-grade NAT.

### Fixed
- **`100.64.0.0/10` (RFC 6598 shared address space / CGNAT) is now blocked.**
  It was previously ALLOWED: the check relied on `ipaddress` properties, and
  `100.64.0.1` reports `is_private=False` on current CPython (verified on
  3.12.13 and 3.14.6). CGNAT is routable internal space at cloud providers,
  carrier NATs and overlay networks — Tailscale uses exactly this range — so it
  was a live SSRF target, not dead space. The failure was silent: the function
  returned cleanly, so no caller logged, alerted, or failed a test.
- **IPv4 tunnelled inside IPv6 is now validated on the inner address.**
  IPv4-mapped (`::ffff:10.0.0.1`), 6to4, Teredo and NAT64 all carry an IPv4
  address; checking only the outer IPv6 form could smuggle a private target
  past the guard. Cloud-metadata detection unwraps these too.

### Changed
- The blocklist is now an **explicit, auditable list of IANA special-purpose
  ranges** rather than only stdlib properties. CPython has revised what
  `is_private` / `is_global` mean (the CVE-2024-4032 registry correction), so a
  property-only blocklist can change shape across the Python versions this
  package supports (>=3.10). The property checks are retained as
  defence-in-depth. Behaviour verified identical on 3.12 and 3.14.

### Compatibility
- No API change. `allowlist_ranges` still overrides the private/CGNAT block, so
  an on-prem or overlay tenant legitimately running on CGNAT can opt in, and
  cloud-metadata remains un-overridable.
- **Not expected to break callers.** Verified that 12 real vendor hosts used
  across the connector fleet (Stripe, Intercom, GitHub, Linear, Notion, Coda,
  RescueTime, Substack, Luma, Zendesk, OpenAI, Google APIs) all still pass, and
  that the block does not bleed past the `/10` boundary — `100.63.255.255` and
  `100.128.0.0` remain allowed.

### Tests
90 passing (was 50). Adds a table-driven sweep over 23 special-purpose ranges so
a range cannot be silently forgotten again, CGNAT boundary tests, embedded
IPv4-in-IPv6 cases, and negative controls asserting genuinely public endpoints
still resolve.

Found by the helpdesk-mcp build, where an SSRF test written against the
documented blocklist failed against this package rather than against the caller.

## v0.1.0 — 2026-05-25

Initial release.

- `sanitize_or_raise(url)` — rejects dangerous chars (backslash / tab / CR / LF / null), non-http(s) schemes, embedded credentials, empty / hostless URLs
- `assert_public_ip(host, allowlist_ranges=())` — resolves host, raises on private / loopback / link-local / unspecified / reserved / multicast IPs; always blocks cloud-metadata endpoints (AWS / Azure / Alibaba IMDS, IPv4 + IPv6) regardless of allowlist
- `resolve_pinned(host)` — returns first resolved IP for DNS-rebinding-safe fetch
- `UnsafeURL` exception (subclass of `ValueError`)
- 46-test fixture covering all five threat-model attacks from the OWASP SSRF playbook
- Python 3.10+
- MIT license
