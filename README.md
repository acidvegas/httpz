# HTTPZ Web Scanner

A high-performance concurrent web scanner written in Python. HTTPZ efficiently scans domains for HTTP/HTTPS services, extracting valuable information like status codes, titles, SSL certificates, and more.

## Requirements

- [Python](https://www.python.org/downloads/)
  - [aiohttp](https://pypi.org/project/aiohttp/)
  - [apv](https://pypi.org/project/apv/)
  - [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)
  - [cryptography](https://pypi.org/project/cryptography/)
  - [dnspython](https://pypi.org/project/dnspython/)
  - [mmh3](https://pypi.org/project/mmh3/)
  - [python-dotenv](https://pypi.org/project/python-dotenv/)
  - [tqdm](https://pypi.org/project/tqdm/)

## Installation
```bash
git clone https://github.com/acidvegas/httpz
cd httpz
chmod +x setup.sh
./setup.sh
```

## Usage
```bash
python httpz.py domains.txt [options]
```

### Arguments

| Argument  | Long Form        | Description                                                 |
|-----------|------------------|-------------------------------------------------------------|
| `file`    | -                | File containing domains *(one per line)*, use `-` for stdin |
| `-d`      | `--debug`        | Show error states and debug information                     |
| `-c N`    | `--concurrent N` | Number of concurrent checks *(default: 100)*                |
| `-o FILE` | `--output FILE`  | Output file path *(JSONL format)*                           |
| `-j`      | `--jsonl`        | Output JSON Lines format to console                         |
| `-all`    | `--all-flags`    | Enable all output flags                                     |

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

## Examples

Scan domains with all flags enabled and output to JSONL:
```bash
python httpz.py domains.txt -c 100 -o output.jsonl -j -all -to 10 -mc 200,301 -ec 404,500 -p
```

Scan domains from stdin:
```bash
cat domains.txt | python httpz.py - -c 100 -o output.jsonl -j -all -to 10 -mc 200,301 -ec 404,500 -p
```