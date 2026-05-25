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

### Three-call pattern (recommended for high-risk paths)

```python
from mycelium_security import sanitize_or_raise, assert_public_ip, resolve_pinned

safe_url = sanitize_or_raise(user_url)
host = urlparse(safe_url).hostname
assert_public_ip(host)
pinned_ip = resolve_pinned(host)   # pin the IP for the fetch lifetime
# now use a custom transport that fetches `pinned_ip` with the original Host: header
```

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
| `assert_public_ip(host: str, *, allowlist_ranges: Iterable[str] = ()) -> None` | Resolve host, raise `UnsafeURL` if any resolved IP is private / metadata / link-local / unspecified. |
| `resolve_pinned(host: str) -> str` | Resolve once, return the first IP as a string. Pair with `assert_public_ip` for DNS-rebinding mitigation. |
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
