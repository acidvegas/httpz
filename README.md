# HTTPZ Web Scanner

![](./.screens/preview.gif)

A high-performance concurrent HTTP recon tool. HTTPZ checks domains for HTTP/HTTPS services and pulls back status codes, titles, body previews, response headers, favicon hashes, TLS certificate info, and resolved IPs — all configurable per scan.

Designed to run as a library inside distributed workers scanning hundreds of millions of domains.

## Requirements

- [Python](https://www.python.org/downloads/) 3.8+
  - [aiodns](https://pypi.org/project/aiodns/)
  - [aiofiles](https://pypi.org/project/aiofiles/)
  - [aiohttp](https://pypi.org/project/aiohttp/)
  - [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)
  - [cryptography](https://pypi.org/project/cryptography/)
  - [dnspython](https://pypi.org/project/dnspython/)
  - [mmh3](https://pypi.org/project/mmh3/)

## Installation

### Via pip *(recommended)*
```bash
pip install httpz_scanner
httpz --help
```

### From source
```bash
git clone https://github.com/acidvegas/httpz
cd httpz
pip install -r requirements.txt
```

## CLI usage

Basic:
```bash
python -m httpz_scanner domains.txt
```

All fields, JSONL output to stdout and a file:
```bash
python -m httpz_scanner domains.txt -all -c 100 -j -o results.jsonl
```

Read from stdin:
```bash
cat domains.txt | python -m httpz_scanner - -all
echo example.com | python -m httpz_scanner - -all
```

Filter by status code:
```bash
python -m httpz_scanner domains.txt -mc 200,301-399 -ec 404,500
```

Specific fields with custom timeout and resolvers:
```bash
python -m httpz_scanner domains.txt -sc -ti -i -tls -to 10 -r resolvers.txt
```

### Distributed scanning

Built-in shard mode splits a file across N workers (line-modulo):
```bash
# Machine 1
httpz domains.txt --shard 1/3
# Machine 2
httpz domains.txt --shard 2/3
# Machine 3
httpz domains.txt --shard 3/3
```
Workers can also handle their own line offsetting and feed domains directly to the library — see below.

## Library usage

```python
import asyncio
from httpz_scanner import HTTPZScanner

async def domain_source():
    # Any of: list, async generator, sync generator, file path string, '-'
    for d in ['example.com', 'github.com', 'cloudflare.com']:
        yield d

async def main():
    scanner = HTTPZScanner(
        concurrent_limit = 100,
        timeout          = 5,
        retries          = 1,
        retry_backoff    = 0.5,
        follow_redirects = True,
        max_body_size    = 1024 * 1024,
        favicon_max_size = 256 * 1024,

        # Feature toggles — all default OFF
        fetch_headers        = True,
        fetch_content_type   = True,
        fetch_content_length = True,
        fetch_title          = True,
        fetch_body           = True,
        fetch_favicon        = True,
        fetch_tls            = True,
        fetch_ips            = True,

        # Optional filters
        match_codes   = None,        # e.g. {200, 301, 302}
        exclude_codes = None,        # e.g. {404, 500}

        # Optional knobs
        custom_headers = None,       # {'X-Foo': 'bar'}
        post_data      = None,
        shard          = None,       # (index, total) — workers usually do this themselves
        resolvers      = None,       # ['1.1.1.1', '8.8.8.8'] for A/AAAA lookups
        dns_timeout    = 2.0,
    )

    async for result in scanner.scan(domain_source()):
        print(result['domain'], result['status'])

asyncio.run(main())
```

The scanner accepts:
- a file path (string)
- `'-'` for stdin
- a list/tuple of domains
- a sync iterator/generator
- an async generator

### Graceful shutdown

Workers receiving SIGTERM (or any orchestrator signal) can drain cleanly:

```python
async def supervisor(scanner, scan_iterator):
    async for result in scan_iterator:
        ...

scanner = HTTPZScanner(...)
scan_task = asyncio.create_task(supervisor(scanner, scanner.scan(domains)))

# Later, on shutdown signal:
await scanner.stop()        # drops queued domains, lets in-flight finish, exits
await scan_task
```

`stop()` is idempotent and async-safe.

## Result schema

Each yielded result is a dict. Fields appear only when their feature toggle is on and data is available.

```jsonc
{
  "domain":      "example.com",
  "url":         "https://example.com/",
  "status":      200,                          // -1 on error
  "protocol":    "https",                      // or "http"

  // -- toggleable fields --
  "response_headers": {"Server": "...", ...},  // fetch_headers
  "content_type":     "text/html; charset=utf-8",
  "content_length":   1234,
  "redirect_chain":   ["https://example.com", "https://www.example.com/"],
  "title":            "Example Domain",        // single line, max 1024 chars
  "body_preview":     "<!doctype html>...",    // first 1024 raw bytes, normalized
  "body_clean":       "Example Domain ...",    // HTML-stripped, max 1024 chars
  "favicon_hash":     "1014476666658474844",   // mmh3 64-bit, capped read
  "ips":              ["93.184.216.34", "..."],
  "tls": {
    "fingerprint": "<sha256 hex>",
    "subject":     "*.example.com",
    "issuer":      "DigiCert TLS RSA SHA256 2020 CA1",
    "email":       null,
    "alt_names":   ["*.example.com", "example.com"],
    "not_before":  "2026-01-15T00:00:00",
    "not_after":   "2027-02-14T23:59:59"
  },

  // -- only on failure --
  "error":      "Connection timed out",
  "error_type": "TIMEOUT"   // CONN | SSL | CERT | TIMEOUT | HTTP | UNKNOWN | PROCESS | TASK | NO_RESPONSE
}
```

## Protocol fallback

- `https://x` → tries https, falls back to http on connection failure
- `http://x`  → tries http, falls back to https on connection failure
- `x` (no scheme) → tries https, falls back to http

Any HTTP response (including 4xx/5xx) is accepted — only connection-level errors trigger fallback.

## Retries

`retries` is per protocol, applied only to transient errors (TIMEOUT, CONN, HTTP). Cert errors, DNS failures, and HTTP responses do not retry. Backoff is linear: `retry_backoff * (attempt + 1)`.

## Performance notes for distributed use

- `force_close=True` on the connector — keep-alive is disabled (you're scanning unique hosts).
- TLS cert is captured from the *original* request's connection via a connector subclass, no second handshake per https domain.
- DNS uses `aiodns` + 5-minute in-process cache.
- Bounded internal queue (`concurrent_limit * 2`) keeps memory flat regardless of input size.
- Ensure your worker's `ulimit -n` is high enough for `concurrent_limit * 2` sockets.

## CLI arguments

| Argument         | Long form               | Description                                  |
|------------------|-------------------------|----------------------------------------------|
| `file`           |                         | Domain file (one per line) or `-` for stdin  |
| `-c N`           | `--concurrent N`        | Concurrent in-flight checks (default 100)    |
| `-to N`          | `--timeout N`           | Request timeout in seconds (default 5)       |
| `-rt N`          | `--retries N`           | Retry attempts per protocol (default 1)      |
| `-rb N`          | `--retry-backoff N`     | Linear backoff base seconds (default 0.5)    |
| `-mb N`          | `--max-body-size N`     | Max body bytes to read (default 1 MB)        |
| `-fm N`          | `--favicon-max-size N`  | Max favicon bytes (default 256 KB)           |
| `-dt N`          | `--dns-timeout N`       | DNS query timeout (default 2.0)              |
| `-fr`            | `--follow-redirects`    | Follow redirects (max 10)                    |
| `-r FILE`        | `--resolvers FILE`      | DNS resolver IP list for IP lookups          |
| `-hd "k: v,..."` | `--headers "k: v,..."`  | Custom request headers                       |
| `-pd DATA`       | `--post-data DATA`      | Send POST with this body                     |
| `-sh N/T`        | `--shard N/T`           | Shard `N` of `T` (line-modulo)               |
| `-mc CODES`      | `--match-codes CODES`   | Only show these status codes                 |
| `-ec CODES`      | `--exclude-codes CODES` | Exclude these status codes                   |
| `-o FILE`        | `--output FILE`         | Append-write JSONL to file                   |
| `-j`             | `--jsonl`               | Print JSONL to stdout                        |
| `-p`             | `--progress`            | Show numeric counter alongside output        |
| `-d`             | `--debug`               | Show error states and debug logs             |
| `-all`           | `--all-flags`           | Enable every output field                    |

### Field flags

| Flag   | Long form           | Description                  |
|--------|---------------------|------------------------------|
| `-sc`  | `--status-code`     | Status code                  |
| `-ct`  | `--content-type`    | Content-Type header          |
| `-cl`  | `--content-length`  | Content-Length header        |
| `-ti`  | `--title`           | Page title (≤1024 chars)     |
| `-b`   | `--body`            | body_preview + body_clean    |
| `-i`   | `--ip`              | A/AAAA records               |
| `-f`   | `--favicon`         | mmh3 favicon hash            |
| `-hr`  | `--show-headers`    | Full response headers        |
| `-tls` | `--tls-info`        | TLS certificate fields       |

---

###### Mirrors: [SuperNETs](https://git.supernets.org/acidvegas/) • [GitHub](https://github.com/acidvegas/) • [GitLab](https://gitlab.com/acidvegas/) • [Codeberg](https://codeberg.org/acidvegas/)
