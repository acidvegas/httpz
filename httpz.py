#!/usr/bin/env python
# HTTPZ Crawler - Developed by acidvegas in Python (https://git.acid.vegas/httpz)

'''
BCUZ FUCK HTTPX PYTHON STILL GO HARD
'''

import argparse
import asyncio
import json
import random
import re
import logging
import ssl
import urllib.request

try:
    import aiodns
except ImportError:
    print('Missing required module \'aiodns\'. (pip install aiodns)')
    exit(1)

try:
    import aiohttp
except ImportError:
    print('Missing required module \'aiohttp\'. (pip install aiohttp)')
    exit(1)

# ANSI escape codes for colors
RED = '\033[91m'
GREEN = '\033[92m'
DARK_GREY = '\033[90m'
RESET = '\033[0m'

# Globals
DNS_SERVERS = None
args = None  # Global args variable

def vlog(msg: str):
    '''
    Verbose logging only if enabled

    :param msg: Message to print to console
    '''
    if args.verbose:
        logging.info(msg)


def get_dns_servers() -> dict:
    '''Get a list of DNS servers to use for lookups.'''
    with urllib.request.urlopen('https://public-dns.info/nameservers.txt') as source:
        results = source.read().decode().split('\n')
    v4_servers = [server for server in results if ':' not in server]
    v6_servers = [server for server in results if ':'     in server]
    return {'4': v4_servers, '6': v6_servers}


async def dns_lookup(domain: str, record_type: str, timeout: int) -> list:
    '''
    Resolve DNS information from a domain

    :param domain: Domain name to resolve
    :param record_type: DNS record type to resolve
    :param timeout: Timeout for DNS request
    '''
    for i in range(args.retry):
        try:
            version = '4' if record_type == 'A' else '6' if record_type == 'AAAA' else random.choice(['4','6'])
            nameserver = random.choice(DNS_SERVERS[version])
            resolver = aiodns.DNSResolver(nameservers=[nameserver], timeout=timeout)
            records = await resolver.query(domain, record_type)
            return records.cname if record_type == 'CNAME' else [record.host for record in records]
        except Exception as e:
            vlog(f'{RED}[ERROR]{RESET} {domain} - Failed to resolve {record_type} record using {nameserver} {DARK_GREY}({str(e)}){RESET}')
    return []


async def get_body(source: str, preview: int) -> str:
    '''
    Get the body of a webpage

    :param source: HTML source of the webpage
    :param preview: Number of bytes to preview
    '''
    body_content = re.search(r'<body.*?>(.*?)</body>', source, re.DOTALL | re.IGNORECASE)
    processed_content = body_content.group(1) if body_content else source
    clean_content = re.sub(r'<[^>]+>', '', processed_content)
    return clean_content[:preview]


async def get_title(session: aiohttp.ClientSession, domain: str):
    '''
    Get the title of a webpage and its status code

    :param session: aiohttp session
    :param domain: URL to get the title of
    '''
    body = None
    status_code = None
    title = None

    try:
        async with session.get(domain, timeout=args.timeout, allow_redirects=False) as response:
            status_code = response.status
            if status_code in (200, 201):
                html_content = await response.text()
                match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
                title = match.group(1).strip() if match else None
                title = re.sub(r'[\r\n]+', ' ', title)[:300] if title else None # Fix this ugly shit
                body = await get_body(html_content, args.preview)
            elif status_code in (301, 302, 303, 307, 308) and args.retry > 0: # Need to implement a max redirect limit
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    return await get_title(session, redirect_url)
                else:
                    vlog(f'{RED}[ERROR]{RESET} {domain} - No redirect URL found for {status_code} status code')
            else:
                vlog(f'{RED}[ERROR]{RESET} {domain} - Invalid status code {DARK_GREY}{status_code}{RESET}')
    except asyncio.TimeoutError:
        vlog(f'{RED}[ERROR]{RESET} {domain} - HTTP request timed out')
    except Exception as e:
        vlog(f'{RED}[ERROR]{RESET} Failed to get title for {domain} {DARK_GREY}({e}){RESET}')
    return title, body, status_code


async def check_url(session: aiohttp.ClientSession, domain: str):
    '''
    Process a domain name

    :param session: aiohttp session
    :param domain: URL to get the title of
    '''
    dns_records = {}

    for record_type in ('A', 'AAAA'):
        records = await dns_lookup(domain, record_type, args.timeout)
        if records:
            dns_records[record_type] = records
    if not dns_records:
        cname_record = await dns_lookup(domain, 'CNAME', args.timeout)
        if cname_record:
            dns_records['CNAME'] = cname_record
            domain = cname_record
        else:
            vlog(f'{RED}[ERROR]{RESET} No DNS records found for {domain}')
            return domain, None, None, None, None, None

    title, body, status_code = await get_title(session, f'https://{domain}')
    if not title and not body:
        title, body, status_code = await get_title(session, f'http://{domain}')

    if title or body:
        logging.info(f'[{GREEN}SUCCESS{RESET}] {domain} - {title} - {body}')
        return domain, 'https', title, body, dns_records, status_code
    else:
        vlog(f'{RED}[ERROR]{RESET} {domain} - Failed to retrieve title')

    return domain, None, None, None, None, status_code


async def process_file():
    '''
    Process a list of domains from file
    '''
    counter = 0
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    headers = {'User-Agent': args.user_agent}
    connector = aiohttp.TCPConnector(ssl=ssl_context)

    session_params = {
        'connector': connector,
        'headers': headers,
        'timeout': aiohttp.ClientTimeout(total=args.timeout)
    }
    if args.proxy:
        session_params['proxy'] = args.proxy

    async with aiohttp.ClientSession(**session_params) as session:
        tasks = set()
        with open(args.file, 'r') as file:
            for line in file:
                domain = line.strip()
                if domain:
                    tasks.add(asyncio.create_task(check_url(session, domain)))

                    if len(tasks) >= args.concurrency:
                        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                        for task in done:
                            domain, protocol, title, body, dns_records, status_code = task.result()
                            if title or body: # log results for dns?
                                write_result_to_file(domain, protocol, title, body, dns_records, status_code)
                                counter += 1

                                if counter % args.memory_limit == 0:
                                    logging.info(f'Processed {counter} domains')

        if tasks:
            done, _ = await asyncio.wait(tasks)
            for task in done:
                domain, protocol, title, body, dns_records, status_code = task.result()
                if title:
                    write_result_to_file(domain, protocol, title, body, dns_records, status_code)


def write_result_to_file(domain, protocol, title, body, dns_records, status_code):
    '''
    Write a single domain result to file

    :param domain: Domain name
    :param protocol: Protocol used (http or https)
    :param title: Title of the domain
    :param dns_records: DNS records of the domain
    :param status_code: HTTP status code
    '''
    result = {
        'domain': domain,
        'protocol': protocol,
        'status_code': status_code,
        'title': title,
        'body': body,
        'dns_records': dns_records
    }
    with open(args.output, 'a') as f:
        json.dump(result, f)
        f.write('\n')


def main():
    global DNS_SERVERS, args

    parser = argparse.ArgumentParser(description='Check URLs from a file asynchronously, perform DNS lookups and store results in JSON.')
    parser.add_argument('file', help='File containing list of domains')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent requests')
    parser.add_argument('-m', '--memory_limit', type=int, default=1000, help='Number of results to store in memory before syncing to file')
    parser.add_argument('-o', '--output', default='results.json', help='Output file')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout for HTTP requests')
    parser.add_argument('-u', '--user_agent', default='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', help='User agent to use for HTTP requests')
    parser.add_argument('-x', '--proxy', help='Proxy to use for HTTP requests')
    parser.add_argument('-r', '--retry', type=int, default=3, help='Number of times to retry failed requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-p', '--preview', type=int, default=500, help='Preview size in bytes for body & title (default: 500)')
    args = parser.parse_args()

    log_level = logging.INFO
    logging.basicConfig(level=log_level, format=f'{DARK_GREY}%(asctime)s{RESET} %(message)s', datefmt='%H:%M:%S')

    logging.info('Loading DNS servers...')
    DNS_SERVERS = get_dns_servers()
    if not DNS_SERVERS:
        logging.fatal('Failed to get DNS servers.')
    logging.info(f'Found {len(DNS_SERVERS["4"])} IPv4 and {len(DNS_SERVERS["6"])} IPv6 DNS servers.')

    asyncio.run(process_file())

if __name__ == '__main__':
    main()