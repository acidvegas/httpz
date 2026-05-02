# httpz - Developed by acidvegas in Python (https://github.com/acidvegas)
# unit_test.py

#!/usr/bin/env python3
# HTTPZ Web Scanner - Unit Tests
# unit_test.py

import asyncio
import logging
import sys
import time

try:
    from httpz_scanner        import HTTPZScanner
    from httpz_scanner.colors import Colors
except ImportError:
    raise ImportError('missing httpz_scanner library (pip install httpz_scanner)')


class ColoredFormatter(logging.Formatter):
    '''Custom formatter for colored log output'''

    def format(self, record):
        if record.levelno == logging.INFO:
            color = Colors.GREEN
        elif record.levelno == logging.WARNING:
            color = Colors.YELLOW
        elif record.levelno == logging.ERROR:
            color = Colors.RED
        else:
            color = Colors.RESET

        record.msg = f'{color}{record.msg}{Colors.RESET}'
        return super().format(record)


logger  = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.setLevel(logging.INFO)
logger.addHandler(handler)


TEST_DOMAINS_URL = 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/email-top-100-domains.txt'


async def get_domains_from_url() -> list:
    '''Fetch a small known-good set of domains for testing.'''

    try:
        import aiohttp
    except ImportError:
        raise ImportError('missing aiohttp library (pip install aiohttp)')

    async with aiohttp.ClientSession() as session:
        async with session.get(TEST_DOMAINS_URL) as response:
            content = await response.text()
            return [line.strip() for line in content.splitlines() if line.strip()]


async def domain_generator(domains: list):
    '''Async generator yielding domains one at a time.'''

    for domain in domains:
        await asyncio.sleep(0)
        yield domain


def _make_scanner(concurrency: int) -> HTTPZScanner:
    '''Build a scanner with every feature toggle on.'''

    return HTTPZScanner(
        concurrent_limit     = concurrency,
        timeout              = 5,
        retries              = 1,
        follow_redirects     = True,
        fetch_headers        = True,
        fetch_content_type   = True,
        fetch_content_length = True,
        fetch_title          = True,
        fetch_body           = True,
        fetch_favicon        = True,
        fetch_tls            = True,
        fetch_ips            = True,
        fetch_cname          = True,
    )


async def run_benchmark(test_type: str, source, total: int, concurrency: int) -> tuple:
    '''Scan a source, log each result, return (elapsed_seconds, throughput).'''

    logging.info(f'{Colors.BOLD}Testing {test_type} input with {concurrency} concurrent connections...{Colors.RESET}')
    scanner = _make_scanner(concurrency)

    count      = 0
    got_first  = False
    start_time = None

    async for result in scanner.scan(source):
        if not result:
            continue
        if not got_first:
            got_first  = True
            start_time = time.time()
        count += 1

        if result['status'] < 0:
            status_str = f"{Colors.RED}[{result['status']} - {result.get('error_type','UNKNOWN')}: {result.get('error','')}]{Colors.RESET}"
        elif 200 <= result['status'] < 300:
            status_str = f"{Colors.GREEN}[{result['status']}]{Colors.RESET}"
        elif 300 <= result['status'] < 400:
            status_str = f"{Colors.YELLOW}[{result['status']}]{Colors.RESET}"
        else:
            status_str = f"{Colors.RED}[{result['status']}]{Colors.RESET}"

        proto    = f" {Colors.CYAN}({result.get('protocol','unknown')}){Colors.RESET}"
        title    = f" {Colors.DARK_GREEN}{result['title']}{Colors.RESET}" if result.get('title') else ''
        ips      = f" {Colors.YELLOW}{','.join(result['ips'])}{Colors.RESET}" if result.get('ips') else ''
        tls      = f" {Colors.GREEN}TLS:{result['tls']['subject']}{Colors.RESET}" if result.get('tls') else ''
        favicon  = f" {Colors.PURPLE}fav:{result['favicon_hash']}{Colors.RESET}" if result.get('favicon_hash') else ''
        redirect = f" {Colors.YELLOW}({len(result['redirect_chain'])} hops){Colors.RESET}" if result.get('redirect_chain') else ''
        cname    = f" {Colors.PURPLE}CNAME:{'->'.join(result['cname_chain'])}{Colors.RESET}" if result.get('cname_chain') else ''

        logging.info(
            f'{test_type}-{concurrency} #{count}: '
            f'{status_str}{proto} '
            f'{Colors.CYAN}{result["domain"]}{Colors.RESET}'
            f'{redirect}{cname}{title}{tls}{ips}{favicon}'
        )

    elapsed = (time.time() - start_time) if start_time else 0
    rps     = (count / elapsed) if elapsed > 0 else 0
    logging.info(f'{Colors.YELLOW}{test_type} {concurrency}c: {count}/{total} in {elapsed:.2f}s ({rps:.2f}/s){Colors.RESET}')
    return elapsed, rps


async def test_stop(domains: list) -> None:
    '''Confirm scanner.stop() drains in-flight tasks and exits cleanly.'''

    logging.info(f'{Colors.BOLD}Testing graceful stop()...{Colors.RESET}')
    scanner = _make_scanner(concurrency=20)

    t0    = time.time()
    count = 0

    async def kicker():
        await asyncio.sleep(1.0)
        logging.info(f'{Colors.YELLOW}stop() called at {time.time()-t0:.2f}s{Colors.RESET}')
        await scanner.stop()

    k = asyncio.create_task(kicker())
    async for _ in scanner.scan(domains):
        count += 1
    await k

    elapsed = time.time() - t0
    if count >= len(domains):
        raise AssertionError(f'stop() did not interrupt scan ({count}/{len(domains)})')
    logging.info(f'{Colors.GREEN}stop() OK: drained {count}/{len(domains)} in {elapsed:.2f}s{Colors.RESET}')


async def main() -> None:
    '''Run the full test suite.'''

    try:
        domains = await get_domains_from_url()
        logging.info(f'Loaded {Colors.YELLOW}{len(domains)}{Colors.RESET} test domains')

        results = []
        for concurrency in (25, 50, 100):
            gen_elapsed, gen_rps = await run_benchmark('Generator', domain_generator(domains), len(domains), concurrency)
            results.append(('Generator', concurrency, gen_elapsed, gen_rps))

            list_elapsed, list_rps = await run_benchmark('List', domains, len(domains), concurrency)
            results.append(('List', concurrency, list_elapsed, list_rps))

        await test_stop(domains)

        logging.info(f'\n{Colors.BOLD}Benchmark Results:{Colors.RESET}')
        logging.info('-' * 70)
        logging.info(f'{"Type":<12} {"Concurrency":<14} {"Time (s)":<12} {"Domains/sec":<12}')
        logging.info('-' * 70)
        results.sort(key=lambda x: x[3], reverse=True)
        for test_type, concurrency, elapsed, rps in results:
            logging.info(f'{test_type:<12} {concurrency:<14} {elapsed:<12.2f} {rps:<12.2f}')

        fastest = results[0]
        logging.info('-' * 70)
        logging.info(f'{Colors.GREEN}Fastest: {fastest[0]} @ {fastest[1]} concurrent — {fastest[3]:.2f}/s{Colors.RESET}')
        logging.info(f'\n{Colors.GREEN}All tests passed.{Colors.RESET}')

    except Exception as e:
        logging.error(f'Test failed: {Colors.RED}{e}{Colors.RESET}')
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.warning(f'{Colors.YELLOW}Tests interrupted by user{Colors.RESET}')
        sys.exit(1)
