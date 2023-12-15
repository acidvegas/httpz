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
RED       = '\033[91m'
GREEN     = '\033[92m'
DARK_GREY = '\033[90m'
RESET     = '\033[0m'


# Globals
DNS_SERVERS = None


def get_dns_servers() -> list:
    '''Get a list of DNS servers to use for lookups.'''
    source = urllib.request.urlopen('https://public-dns.info/nameservers.txt')
    results = source.read().decode().split('\n')
    v4_servers = [server for server in results if ':' not in server]
    v6_servers = [server for server in results if ':' in server]
    return {'4': v4_servers, '6': v6_servers}


async def dns_lookup(domain: str, record_type: str) -> list:
    '''
    Resolve DNS information from a domain

    :param domain: Domain name to resolve
    :param record_type: DNS record type to resolve
    '''
    try:
        version = '4' if record_type == 'A' else '6' if record_type == 'AAAA' else random.choice(['4','6'])
        resolver = aiodns.DNSResolver(nameservers=[random.choice(DNS_SERVERS[version])])
        records = await resolver.query(domain, record_type)
        return [record.host for record in records]
    except Exception:
        pass


async def get_title(session: aiohttp.ClientSession, domain: str, max_redirects: int, timeout: int):
    '''
    Get the title of a webpage

    :param session: aiohttp session
    :param domain: URL to get the title of
    :param max_redirects: Maximum number of redirects to follow
    :param timeout: Timeout for HTTP requests
    '''
    try:
        async with session.get(domain, timeout=timeout, allow_redirects=False) as response:
            if response.status in (200, 201):
                html_content = await response.text()
                match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
                return match.group(1).strip() if match else None
            elif response.status in (301, 302, 303, 307, 308) and max_redirects > 0:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    return await get_title(session, redirect_url, max_redirects - 1, timeout)
            else:
                logging.error(f'{RED}[ERROR]{RESET} {domain} - Invalid HTTP status code {DARK_GREY}({response.status}){RESET}')
    except Exception as e:
        logging.error(f'{RED}[ERROR]{RESET} {domain} - {e}')
    return None


async def check_url(session: aiohttp.ClientSession, domain: str, timeout: int, retry: int):
    '''
    Process a domain name

    :param session: aiohttp session
    :param domain: URL to get the title of
    :param timeout: Timeout for HTTP requests
    :param retry: Number of retries for failed requests
    '''

    dns_records = {}
    for record_type in ('A', 'AAAA'):
        records = await dns_lookup(domain, record_type)
        if records:
            dns_records[record_type] = records
            break

    if not dns_records:
        cname_records = await dns_lookup(domain, 'CNAME')
        if cname_records:
            dns_records['CNAME'] = cname_records
            domain = cname_records[0]

    if not dns_records:
        logging.info(f'{DARK_GREY}[NO DNS RECORDS]{RESET} {domain}')
        return domain, None, None, None

    title = await get_title(session, f'https://{domain}', retry, timeout)
    if not title:
        title = await get_title(session, f'http://{domain}', retry, timeout)

    if title:
        logging.info(f'{GREEN}[SUCCESS]{RESET} {domain} - {title} - DNS: {dns_records}')
        return domain, 'https', title, dns_records
    else:
        logging.error(f'{RED}[ERROR]{RESET} {domain} - Failed to retrieve title')

    return domain, None, None, None


async def process_file(file_path: str, concurrency: int, memory_limit: int, output_file: str, timeout: int, user_agent: str, proxy: str, retry: int):
    '''
    Process a list of domains from file

    :param file_path: Path to the file to read from
    :param concurrency: Number of domains to look up concurrently
    :param memory_limit: Number of successful domain lookups to store in memory before syncing to file
    :param output_file: Output file for results
    :param timeout: Timeout for HTTP requests
    :param user_agent: User agent for HTTP requests
    :param proxy: Proxy for HTTP requests
    :param retry: Number of retries for failed requests
    '''
    results = {}
    counter = 0

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    headers = {'User-Agent': user_agent}
    connector = aiohttp.TCPConnector(ssl=ssl_context)

    session_params = {
        'connector': connector,
        'headers': headers,
        'timeout': aiohttp.ClientTimeout(total=timeout)
    }
    if proxy:
        session_params['proxy'] = proxy

    async with aiohttp.ClientSession(**session_params) as session:
        tasks = set()
        with open(file_path, 'r') as file:
            for line in file:
                domain = line.strip()
                if domain:
                    tasks.add(asyncio.create_task(check_url(session, domain, timeout, retry)))

                    if len(tasks) >= concurrency:
                        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                        for task in done:
                            domain, protocol, title, dns_records = task.result()
                            if title:
                                results[domain] = {'protocol': protocol, 'title': title, 'dns_records': dns_records}
                                counter += 1

                                if counter >= memory_limit:
                                    with open(output_file, 'w') as f:
                                        json.dump(results, f, indent=4)
                                    counter = 0
                                    results.clear()

        if tasks:
            await asyncio.wait(tasks)
            for task in tasks:
                domain, protocol, title, dns_records = task.result()
                if title:
                    results[domain] = {'protocol': protocol, 'title': title, 'dns_records': dns_records}

    with open(output_file, 'a') as f:
        json.dump(results, f, indent=4)


def main():
    global DNS_SERVERS

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
    args = parser.parse_args()

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format=f'{DARK_GREY}%(asctime)s{RESET} - %(message)s', datefmt='%H:%M:%S')

    logging.info('Loading DNS servers...')
    DNS_SERVERS = get_dns_servers()

    if not DNS_SERVERS:
        logging.fatal('Failed to get DNS servers.')
        exit(1)

    logging.info(f'Found {len(DNS_SERVERS["4"])} IPv4 and {len(DNS_SERVERS["6"])} IPv6 DNS servers.')

    asyncio.run(process_file(args.file, args.concurrency, args.memory_limit, args.output, args.timeout, args.user_agent, args.proxy, args.retry))



if __name__ == '__main__':
    main()