#!/usr/bin/env python3
# HTTPZ Web Scanner - Unit Tests
# unit_test.py

import asyncio
import logging
import sys

try:
    from httpz_scanner import HTTPZScanner
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


# Configure logging with colors
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.setLevel(logging.INFO)
logger.addHandler(handler)


async def get_domains_from_url():
    '''
    Fetch domains from SecLists URL
    
    :return: List of domains
    '''
    
    try:
        import aiohttp
    except ImportError:
        raise ImportError('missing aiohttp library (pip install aiohttp)')

    url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/email-top-100-domains.txt'
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            content = await response.text()
            return [line.strip() for line in content.splitlines() if line.strip()]


async def domain_generator(domains):
    '''
    Async generator that yields domains
    
    :param domains: List of domains to yield
    '''
    
    for domain in domains:
        await asyncio.sleep(0) # Allow other coroutines to run
        yield domain


async def test_list_input(domains):
    '''
    Test scanning using a list input
    
    :param domains: List of domains to scan
    '''
    
    logging.info(f'{Colors.BOLD}Testing list input...{Colors.RESET}')
    scanner = HTTPZScanner(concurrent_limit=100, timeout=3, show_progress=True, debug_mode=True)
    
    count = 0
    async for result in scanner.scan(domains):
        if result:
            count += 1
            status_color = Colors.GREEN if 200 <= result['status'] < 300 else Colors.RED
            logging.info(f'List Result {count}: {Colors.CYAN}{result["domain"]}{Colors.RESET} - Status: {status_color}{result["status"]}{Colors.RESET}')


async def test_generator_input(domains):
    '''
    Test scanning using an async generator input
    
    :param domains: List of domains to generate from
    '''
    
    logging.info(f'{Colors.BOLD}Testing generator input...{Colors.RESET}')
    scanner = HTTPZScanner(concurrent_limit=100, timeout=3, show_progress=True, debug_mode=True)
    
    count = 0
    async for result in scanner.scan(domain_generator(domains)):
        if result:
            count += 1
            status_color = Colors.GREEN if 200 <= result['status'] < 300 else Colors.RED
            logging.info(f'Generator Result {count}: {Colors.CYAN}{result["domain"]}{Colors.RESET} - Status: {status_color}{result["status"]}{Colors.RESET}')


async def main() -> None:
    '''Main test function'''
    
    try:
        # Fetch domains
        domains = await get_domains_from_url()
        logging.info(f'Loaded {Colors.YELLOW}{len(domains)}{Colors.RESET} domains for testing')
        
        # Run tests
        await test_generator_input(domains)
        await test_list_input(domains)
        
        logging.info(f'{Colors.GREEN}All tests completed successfully!{Colors.RESET}')
        
    except Exception as e:
        logging.error(f'Test failed: {Colors.RED}{str(e)}{Colors.RESET}')
        sys.exit(1)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.warning(f'{Colors.YELLOW}Tests interrupted by user{Colors.RESET}')
        sys.exit(1) 