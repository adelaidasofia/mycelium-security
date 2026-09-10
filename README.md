# mycelium-security

SSRF mitigations for outbound HTTP in MCP servers and agentic runtimes.

Defends against five attack classes from the OWASP SSRF threat model:

- **Cloud-metadata exfiltration** — AWS `169.254.169.254`, GCP/Azure IMDS, Alibaba `100.100.100.200`, AWS IMDSv2 IPv6 `fd00:ec2::254`
- **URL parser confusion** — backslash, tab, CR, LF, null byte, embedded credentials
- **DNS rebinding** — multi-record resolution, post-validation re-resolution
- **Private network probing** — RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), loopback (127/8, ::1), unique-local IPv6 (fc00::/7), link-local IPv6 (fe80::/10)
- **Redirect-based bypass** — pair with `allow_redirects=False` on your HTTP client; this library leaves redirect policy to the caller

Designed for any Python service that fetches user-supplied or partially-controlled URLs: MCP servers, web crawlers, webhook receivers, LLM tool implementations.

## Install

```bash
pip install mycelium-security
```

Or pin a tag from git directly:

```bash
pip install "mycelium-security @ git+https://github.com/adelaidasofia/mycelium-security.git@v0.1.0"
```

## Usage

```python
from urllib.parse import urlparse
import httpx

from mycelium_security import sanitize_or_raise, assert_public_ip, UnsafeURL

def safe_fetch(user_url: str) -> str:
    try:
        url = sanitize_or_raise(user_url)
        host = urlparse(url).hostname
        assert_public_ip(host)
    except UnsafeURL as e:
        raise ValueError(f"refused to fetch: {e}") from e

    # allow_redirects=False is critical — a 302 to 169.254.169.254
    # would bypass the IP check above
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        resp = client.get(url)
    return resp.text
```

### Pinned-IP pattern (recommended for high-risk paths)

```python
from mycelium_security import sanitize_or_raise, resolve_and_validate, resolve_pinned

safe_url = sanitize_or_raise(user_url)
host = urlparse(safe_url).hostname
validated = resolve_and_validate(host)          # ONE resolution, fully validated
pinned_ip = resolve_pinned(host, validated=validated)  # pin from that SAME list
# now use a custom transport that fetches `pinned_ip` with the original Host: header
```

`resolve_and_validate` + `resolve_pinned(host, validated=...)` resolve the
host exactly once. Passing `validated` is what makes `resolve_pinned` reuse
that already-validated IP list instead of resolving again — the previous
two-independent-lookups pattern (`assert_public_ip(host)` then
`resolve_pinned(host)`, each resolving DNS on its own) is **deprecated**:
each call was a separate DNS round trip, so a rebinding resolver could
legitimately answer differently between them. `resolve_pinned(host)` called
without `validated` still re-validates internally and will never hand back
a private or metadata IP, but it now does that via its own extra lookup —
prefer the pinned-IP pattern above for new code.

**If you use the deprecated pattern with an Enterprise on-prem allowlist,
pass `allowlist_ranges` to BOTH calls:**

```python
assert_public_ip(host, allowlist_ranges=["10.20.0.0/16"])
pinned_ip = resolve_pinned(host, allowlist_ranges=["10.20.0.0/16"])  # required
```

`resolve_pinned(host)`'s legacy one-arg form re-resolves and re-validates
independently, with an EMPTY allowlist by default — omit `allowlist_ranges`
here and a host that only resolves inside `10.20.0.0/16` raises `UnsafeURL`
on this second call even though `assert_public_ip` just accepted it
(MYC-4650 review round 2). `resolve_pinned(host, validated=...)` does not
have this trap: `ValidatedResolution` carries the `allowlist_ranges` it was
built with, and `resolve_pinned` falls back to that carried allowlist
whenever its own `allowlist_ranges` argument is empty — so the "Pinned-IP
pattern" example above (`resolve_and_validate(host,
allowlist_ranges=enterprise_onprem_cidrs)` then `resolve_pinned(host,
validated=validated)`, with no `allowlist_ranges` repeated at the pin call)
round-trips correctly for an Enterprise on-prem allowlisted host (MYC-4650
review round 3, F7).

### Enterprise on-prem allowlist

```python
# Tenant has on-prem 10.20.0.0/16 they legitimately need to reach
assert_public_ip(
    host,
    allowlist_ranges=["10.20.0.0/16"],
)
# Cloud-metadata IPs are blocked REGARDLESS of any allowlist
```

## What it doesn't do

- **Doesn't fetch.** Bring your own HTTP client (httpx, aiohttp, urllib, requests).
- **Doesn't block redirects.** That's your client's job. Set `allow_redirects=False` (httpx: `follow_redirects=False`).
- **Doesn't TLS-pin.** Use `httpx.Client(verify=...)` with your CA bundle.
- **Doesn't validate webhook signatures.** Separate concern.

## API

| Function | Purpose |
|---|---|
| `sanitize_or_raise(url: str) -> str` | Validate URL string; reject dangerous chars + schemes + embedded creds. Raises `UnsafeURL`. |
| `resolve_and_validate(host: str, *, allowlist_ranges: Iterable[str] = ()) -> ValidatedResolution` | **Recommended entry point.** Resolve host ONCE, raise `UnsafeURL` if any resolved IP is private / metadata / link-local / unspecified, return the validated resolution. |
| `assert_public_ip(host: str, *, allowlist_ranges: Iterable[str] = ()) -> ValidatedResolution` | Same behavior as `resolve_and_validate` (kept as the original name). Existing callers that ignore the return value are unaffected. |
| `resolve_pinned(host: str, *, validated: ValidatedResolution \| None = None, allowlist_ranges: Iterable[str] = ()) -> str` | With `validated=`, returns its first IP with **no new lookup** — pass the result of `resolve_and_validate`/`assert_public_ip`. Re-validates against `allowlist_ranges` if given, else `validated.allowlist_ranges`. Without `validated` (deprecated legacy form), does its own single resolution and validates it against `allowlist_ranges` before returning. |
| `ValidatedResolution` | `NamedTuple` result of a validated resolution: `host: str`, `ips: tuple[ipaddress.IPv4Address \| ipaddress.IPv6Address, ...]`, `allowlist_ranges: tuple[str, ...] = ()`. |
| `UnsafeURL` | `ValueError` subclass raised on any check failure. |

## Tests

```bash
pip install -e ".[dev]"
pytest
```

46 tests cover the five threat-model attacks.

## License

MIT.

## Acknowledgements

URL parser hardening + redirect-block patterns adapted from the open-webui v0.9.5 SSRF mitigations changelog.
