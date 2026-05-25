# 0001 — Distribution mechanism: PyPI package, git-installable until trusted publisher configured

Date: 2026-05-25
Status: Accepted

## Context

The SSRF mitigation helper originated in `memory-runtime-pro/src/security/url.py` (private repo, shipped 2026-05-24 under MYC-94). MYC-101 scope correction identified that the real user-URL SSRF surface lives across ~7 public MCP repos (`adelaidasofia/parse-mcp`, `github-mcp`, `luma-mcp`, `apollo-mcp`, `substack-mcp`, `rescuetime-mcp`, `linear-mcp`).

Each MCP needs the same four-layer hardening from `Runtime SSRF Mitigations` pattern wired into every outbound fetch. The helper is 150 lines, generic, security-critical.

Three distribution options were considered:

1. **Copy-per-repo.** Vendor the file into each repo. Pros: zero new dep per MCP. Cons: drift across N repos when security helper updates land; updates require N PRs; vendor copy bypasses CVE-tracking on `mycelium-security`.

2. **Git submodule.** Submodule the helper into each repo. Pros: single source of truth. Cons: submodule UX pain (sync friction, CI complexity, end-user install friction); inconsistent with Python ecosystem norms.

3. **PyPI package.** Publish as `mycelium-security`. Pros: industry-standard; semver; one update site; pip-installable; future-proof when helper grows. Cons: requires PyPI account + trusted publisher config (small one-time setup).

## Decision

**Ship as PyPI package (`mycelium-security`)**. Distribute via two install paths:

- **`pip install mycelium-security`** (preferred) — once PyPI trusted publisher is configured on `pypi.org/manage/account/publishing/` for this repo. The `publish.yml` workflow is dormant until then; it will fail loud at first tag-push, which is the trigger to configure.
- **`pip install "mycelium-security @ git+https://github.com/adelaidasofia/mycelium-security.git@v0.1.0"`** (immediate fallback) — works TODAY without PyPI setup. Tag-pinned for reproducibility.

Each MCP repo adds the dep to its `pyproject.toml`:

```toml
dependencies = [
    # ...existing deps...
    "mycelium-security @ git+https://github.com/adelaidasofia/mycelium-security.git@v0.1.0",
]
```

After PyPI publish, MCPs can flip to `mycelium-security>=0.1.0,<0.2`.

## Consequences

**Positive.**
- Single source of truth across the MCP family. CVE in helper → bump one version, propagate via dependabot.
- New MCPs adopt by adding one line to `pyproject.toml`.
- PyPI listing surfaces the helper to the wider community (open-core boundary respected: helper is generic security code, no personal data, no business logic).

**Negative.**
- Git-URL deps don't get dependabot security alerts the way named PyPI deps do. Migration to named PyPI dep is queued as a follow-up once trusted publisher is configured (~5 min one-time Adelaida action on pypi.org).
- Adding any dep is a supply-chain surface. Mitigation: the helper has zero runtime deps (stdlib only — `ipaddress`, `socket`, `urllib.parse`); the only dev dep is `pytest`.

**Trade-off declined.**
- The "copy-per-repo" path was rejected even with the "vendor-copy is fast" framing, because the drift cost on a security helper is unbounded: a CVE in the helper that lands in `mycelium-security` v0.1.1 must propagate to every vendor copy or vendor copies become CVE-stale. Vendor-copy is correct for low-risk one-off scripts, not security primitives shared across a repo family.

## Out of scope

- TLS pinning, CSP, SRI, webhook signature validation, token rotation cadence — separate concerns, separate libs / rules.
- Per-tenant Enterprise allowlist UI / config — the helper supports `allowlist_ranges=` parameter; the runtime layer (memory-runtime-pro) wires it from tenant config.

## References

- `🍄 Mycelium AI/Patterns/Runtime SSRF Mitigations.md` — pattern doc
- `⚙️ Meta/rules/url-input-safety.md` — vault rule that the MCP Build Runbook references
- MYC-94 (closed) — reference impl shipped in memory-runtime-pro
- MYC-101 — this rollout
- open-webui v0.9.5 changelog — original cherry-pick source for the four-layer pattern
