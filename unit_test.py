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


# Configure logging with colors
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.setLevel(logging.INFO)
logger.addHandler(handler)


async def get_domains_from_url() -> list:
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


async def domain_generator(domains: list):
    '''
    Async generator that yields domains
    
    :param domains: List of domains to yield
    '''
    
    for domain in domains:
        await asyncio.sleep(0) # Allow other coroutines to run
        yield domain


async def run_benchmark(test_type: str, domains: list, concurrency: int) -> tuple:
    '''Run a single benchmark test'''
    
    logging.info(f'{Colors.BOLD}Testing {test_type} input with {concurrency} concurrent connections...{Colors.RESET}')
    scanner = HTTPZScanner(concurrent_limit=concurrency, timeout=3, show_progress=True, debug_mode=True, follow_redirects=True)
    
    count = 0
    got_first = False
    start_time = None
    
    if test_type == 'List':
        async for result in scanner.scan(domains):
            if result:
                if not got_first:
                    got_first = True
                    start_time = time.time()
                count += 1
                
                # More detailed status reporting
                status_str = ''
                if result['status'] < 0:
                    error_type = result.get('error_type', 'UNKNOWN')
                    error_msg = result.get('error', 'Unknown Error')
                    status_str = f"{Colors.RED}[{result['status']} - {error_type}: {error_msg}]{Colors.RESET}"
                elif 200 <= result['status'] < 300:
                    status_str = f"{Colors.GREEN}[{result['status']}]{Colors.RESET}"
                elif 300 <= result['status'] < 400:
                    status_str = f"{Colors.YELLOW}[{result['status']}]{Colors.RESET}"
                else:
                    status_str = f"{Colors.RED}[{result['status']}]{Colors.RESET}"
                
                # Show protocol and response headers if available
                protocol_info = f" {Colors.CYAN}({result.get('protocol', 'unknown')}){Colors.RESET}" if result.get('protocol') else ''
                headers_info = ''
                if result.get('response_headers'):
                    important_headers = ['server', 'location', 'content-type']
                    headers = [f"{k}: {v}" for k, v in result['response_headers'].items() if k.lower() in important_headers]
                    if headers:
                        headers_info = f" {Colors.GRAY}[{', '.join(headers)}]{Colors.RESET}"
                
                # Show redirect chain if present
                redirect_info = ''
                if result.get('redirect_chain'):
                    redirect_info = f" -> {Colors.YELLOW}Redirects: {' -> '.join(result['redirect_chain'])}{Colors.RESET}"
                
                # Show error details if present
                error_info = ''
                if result.get('error'):
                    error_info = f" {Colors.RED}Error: {result['error']}{Colors.RESET}"
                
                # Show final URL if different from original
                url_info = ''
                if result.get('url') and result['url'] != f"http(s)://{result['domain']}":
                    url_info = f" {Colors.CYAN}Final URL: {result['url']}{Colors.RESET}"
                
                logging.info(
                    f"{test_type}-{concurrency} Result {count}: "
                    f"{status_str}{protocol_info} "
                    f"{Colors.CYAN}{result['domain']}{Colors.RESET}"
                    f"{redirect_info}"
                    f"{url_info}"
                    f"{headers_info}"
                    f"{error_info}"
                )
    else:
        # Skip generator test
        pass

    elapsed = time.time() - start_time if start_time else 0
    domains_per_sec = count/elapsed if elapsed > 0 else 0
    logging.info(f'{Colors.YELLOW}{test_type} test with {concurrency} concurrent connections completed in {elapsed:.2f} seconds ({domains_per_sec:.2f} domains/sec){Colors.RESET}')
    
    return elapsed, domains_per_sec


async def test_list_input(domains: list):
    '''Test scanning using a list input'''
    
    logging.info(f'{Colors.BOLD}Testing list input...{Colors.RESET}')
    scanner = HTTPZScanner(concurrent_limit=25, timeout=3, show_progress=True, debug_mode=True, follow_redirects=True)
    
    start_time = time.time()
    count = 0
    async for result in scanner.scan(domains):
        if result:
            count += 1
            status_color = Colors.GREEN if 200 <= result['status'] < 300 else Colors.RED
            title = f" - {Colors.CYAN}{result.get('title', 'No Title')}{Colors.RESET}" if result.get('title') else ''
            error = f" - {Colors.RED}{result.get('error', '')}{Colors.RESET}" if result.get('error') else ''
            logging.info(f'List-25 Result {count}: {status_color}[{result["status"]}]{Colors.RESET} {Colors.CYAN}{result["domain"]}{Colors.RESET}{title}{error}')


async def test_generator_input(domains: list):
    '''Test scanning using an async generator input'''
    
    logging.info(f'{Colors.BOLD}Testing generator input...{Colors.RESET}')
    scanner = HTTPZScanner(concurrent_limit=25, timeout=3, show_progress=True, debug_mode=True, follow_redirects=True)
    
    start_time = time.time()
    count = 0
    async for result in scanner.scan(domain_generator(domains)):
        if result:
            count += 1
            status_color = Colors.GREEN if 200 <= result['status'] < 300 else Colors.RED
            title = f" - {Colors.CYAN}{result.get('title', 'No Title')}{Colors.RESET}" if result.get('title') else ''
            error = f" - {Colors.RED}{result.get('error', '')}{Colors.RESET}" if result.get('error') else ''
            logging.info(f'Generator-25 Result {count}: {status_color}[{result["status"]}]{Colors.RESET} {Colors.CYAN}{result["domain"]}{Colors.RESET}{title}{error}')


async def main() -> None:
    '''Main test function'''
    
    try:
        # Fetch domains
        domains = await get_domains_from_url()
        logging.info(f'Loaded {Colors.YELLOW}{len(domains)}{Colors.RESET} domains for testing')
        
        # Store benchmark results
        results = []
        
        # Run tests with different concurrency levels
        for concurrency in [25, 50, 100]:
            # Generator tests
            gen_result = await run_benchmark('Generator', domains, concurrency)
            results.append(('Generator', concurrency, *gen_result))
            
            # List tests
            list_result = await run_benchmark('List', domains, concurrency)
            results.append(('List', concurrency, *list_result))
        
        # Print benchmark comparison
        logging.info(f'\n{Colors.BOLD}Benchmark Results:{Colors.RESET}')
        logging.info('-' * 80)
        logging.info(f'{"Test Type":<15} {"Concurrency":<15} {"Time (s)":<15} {"Domains/sec":<15}')
        logging.info('-' * 80)
        
        # Sort by domains per second (fastest first)
        results.sort(key=lambda x: x[3], reverse=True)
        
        for test_type, concurrency, elapsed, domains_per_sec in results:
            logging.info(f'{test_type:<15} {concurrency:<15} {elapsed:.<15.2f} {domains_per_sec:<15.2f}')
        
        # Highlight fastest result
        fastest = results[0]
        logging.info('-' * 80)
        logging.info(f'{Colors.GREEN}Fastest: {fastest[0]} test with {fastest[1]} concurrent connections')
        logging.info(f'Time: {fastest[2]:.2f} seconds')
        logging.info(f'Speed: {fastest[3]:.2f} domains/sec{Colors.RESET}')
        
        logging.info(f'\n{Colors.GREEN}All tests completed successfully!{Colors.RESET}')
        
    except Exception as e:
        logging.error(f'Test failed: {Colors.RED}{str(e)}{Colors.RESET}')
        sys.exit(1)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.warning(f'{Colors.YELLOW}Tests interrupted by user{Colors.RESET}')
        sys.exit(1) 