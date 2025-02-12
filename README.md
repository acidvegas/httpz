# HTTPZ Web Scanner

![](./.screens/preview.gif)

A high-performance concurrent web scanner written in Python. HTTPZ efficiently scans domains for HTTP/HTTPS services, extracting valuable information like status codes, titles, SSL certificates, and more.

## Requirements

- [Python](https://www.python.org/downloads/)
  - [aiohttp](https://pypi.org/project/aiohttp/)
  - [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)
  - [cryptography](https://pypi.org/project/cryptography/)
  - [dnspython](https://pypi.org/project/dnspython/)
  - [mmh3](https://pypi.org/project/mmh3/)
  - [python-dotenv](https://pypi.org/project/python-dotenv/)

## Installation

### Via pip *(recommended)*
```bash
# Install from PyPI
pip install httpz_scanner

# The 'httpz' command will now be available in your terminal
httpz --help
```

### From source
```bash
# Clone the repository
git clone https://github.com/acidvegas/httpz
cd httpz
pip install -r requirements.txt
```

## Usage

### Command Line Interface

Basic usage:
```bash
python -m httpz_scanner domains.txt
```

Scan with all flags enabled and output to JSONL:
```bash
python -m httpz_scanner domains.txt -all -c 100 -o results.jsonl -j -p
```

Read from stdin:
```bash
cat domains.txt | python -m httpz_scanner - -all -c 100
echo "example.com" | python -m httpz_scanner - -all
```

Filter by status codes and follow redirects:
```bash
python -m httpz_scanner domains.txt -mc 200,301-399 -ec 404,500 -fr -p
```

Show specific fields with custom timeout and resolvers:
```bash
python -m httpz_scanner domains.txt -sc -ti -i -tls -to 10 -r resolvers.txt
```

Full scan with all options:
```bash
python -m httpz_scanner domains.txt -c 100 -o output.jsonl -j -all -to 10 -mc 200,301 -ec 404,500 -p -ax -r resolvers.txt
```

### Distributed Scanning
Split scanning across multiple machines using the `--shard` argument:

```bash
# Machine 1
httpz domains.txt --shard 1/3

# Machine 2
httpz domains.txt --shard 2/3

# Machine 3
httpz domains.txt --shard 3/3
```

Each machine will process a different subset of domains without overlap. For example, with 3 shards:
- Machine 1 processes lines 0,3,6,9,...
- Machine 2 processes lines 1,4,7,10,...
- Machine 3 processes lines 2,5,8,11,...

This allows efficient distribution of large scans across multiple machines.

### Python Library
```python
import asyncio
import urllib.request
from httpz_scanner import HTTPZScanner

async def scan_from_list() -> list:
    with urllib.request.urlopen('https://example.com/domains.txt') as response:
        content = response.read().decode()
        return [line.strip() for line in content.splitlines() if line.strip()][:20]
    
async def scan_from_url():
    with urllib.request.urlopen('https://example.com/domains.txt') as response:
        for line in response:
            if line := line.strip():
                yield line.decode().strip()

async def scan_from_file():
    with open('domains.txt', 'r') as file:
        for line in file:
            if line := line.strip():
                yield line

async def main():
    # Initialize scanner with all possible options (showing defaults)
    scanner = HTTPZScanner(
        concurrent_limit=100,   # Number of concurrent requests
        timeout=5,              # Request timeout in seconds
        follow_redirects=False, # Follow redirects (max 10)
        check_axfr=False,       # Try AXFR transfer against nameservers
        resolver_file=None,     # Path to custom DNS resolvers file
        output_file=None,       # Path to JSONL output file
        show_progress=False,    # Show progress counter
        debug_mode=False,       # Show error states and debug info
        jsonl_output=False,     # Output in JSONL format
        shard=None,             # Tuple of (shard_index, total_shards) for distributed scanning
        
        # Control which fields to show (all False by default unless show_fields is None)
        show_fields={
            'status_code': True,      # Show status code
            'content_type': True,     # Show content type
            'content_length': True,   # Show content length
            'title': True,            # Show page title
            'body': True,             # Show body preview
            'ip': True,               # Show IP addresses
            'favicon': True,          # Show favicon hash
            'headers': True,          # Show response headers
            'follow_redirects': True, # Show redirect chain
            'cname': True,            # Show CNAME records
            'tls': True               # Show TLS certificate info
        },
        
        # Filter results
        match_codes={200,301,302},  # Only show these status codes
        exclude_codes={404,500,503} # Exclude these status codes
    )

    # Example 1: Process file
    print('\nProcessing file:')
    async for result in scanner.scan(scan_from_file()):
        print(f"{result['domain']}: {result['status']}")

    # Example 2: Stream URLs
    print('\nStreaming URLs:')
    async for result in scanner.scan(scan_from_url()):
        print(f"{result['domain']}: {result['status']}")

    # Example 3: Process list
    print('\nProcessing list:')
    domains = await scan_from_list()
    async for result in scanner.scan(domains):
        print(f"{result['domain']}: {result['status']}")

if __name__ == '__main__':
    asyncio.run(main())
```

The scanner accepts various input types:
- File paths (string)
- Lists/tuples of domains
- stdin (using '-')
- Async generators that yield domains

All inputs support sharding for distributed scanning using the `shard` parameter.

## Arguments

| Argument      | Long Form        | Description                                                 |
|---------------|------------------|-------------------------------------------------------------|
| `file`        |                  | File containing domains *(one per line)*, use `-` for stdin |
| `-d`          | `--debug`        | Show error states and debug information                     |
| `-c N`        | `--concurrent N` | Number of concurrent checks *(default: 100)*                |
| `-o FILE`     | `--output FILE`  | Output file path *(JSONL format)*                           |
| `-j`          | `--jsonl`        | Output JSON Lines format to console                         |
| `-all`        | `--all-flags`    | Enable all output flags                                     |
| `-sh`         | `--shard N/T`    | Process shard N of T total shards *(e.g., 1/3)*             |

### Output Field Flags

| Flag   | Long Form            | Description                      |
|--------| ---------------------|----------------------------------|
| `-sc`  | `--status-code`      | Show status code                 |
| `-ct`  | `--content-type`     | Show content type                |
| `-ti`  | `--title`            | Show page title                  |
| `-b`   | `--body`             | Show body preview                |
| `-i`   | `--ip`               | Show IP addresses                |
| `-f`   | `--favicon`          | Show favicon hash                |
| `-hr`  | `--headers`          | Show response headers            |
| `-cl`  | `--content-length`   | Show content length              |
| `-fr`  | `--follow-redirects` | Follow redirects *(max 10)*      |
| `-cn`  | `--cname`            | Show CNAME records               |
| `-tls` | `--tls-info`         | Show TLS certificate information |

### Other Options

| Option      | Long Form               | Description                                         |
|-------------|-------------------------|-----------------------------------------------------|
| `-to N`     | `--timeout N`           | Request timeout in seconds *(default: 5)*           |
| `-mc CODES` | `--match-codes CODES`   | Only show specific status codes *(comma-separated)* |
| `-ec CODES` | `--exclude-codes CODES` | Exclude specific status codes *(comma-separated)*   |
| `-p`        | `--progress`            | Show progress counter                               |
| `-ax`       | `--axfr`                | Try AXFR transfer against nameservers               |
| `-r FILE`   | `--resolvers FILE`      | File containing DNS resolvers *(one per line)*      |