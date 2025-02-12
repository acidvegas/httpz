#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/scanner.py

import asyncio
import json
import random

try:
    import aiohttp
except ImportError:
    raise ImportError('missing aiohttp module (pip install aiohttp)')

try:
    import bs4
except ImportError:
    raise ImportError('missing bs4 module (pip install beautifulsoup4)')

from .dns        import resolve_all_dns, load_resolvers
from .formatters import format_console_output
from .colors     import Colors
from .parsers    import parse_domain_url, get_cert_info, get_favicon_hash, parse_title
from .utils      import debug, info, USER_AGENTS, input_generator


class HTTPZScanner:
    '''Core scanner class for HTTP domain checking'''
    
    def __init__(self, concurrent_limit = 100, timeout = 5, follow_redirects = False, check_axfr = False, resolver_file = None, output_file = None, show_progress = False, debug_mode = False, jsonl_output = False, show_fields = None, match_codes = None, exclude_codes = None, shard = None):
        '''
        Initialize the HTTPZScanner class
        
        :param concurrent_limit: Maximum number of concurrent requests
        :param timeout: Request timeout in seconds
        :param follow_redirects: Follow redirects
        :param check_axfr: Check for AXFR
        :param resolver_file: Path to resolver file
        :param output_file: Path to output file
        :param show_progress: Show progress bar
        :param debug_mode: Enable debug mode
        :param jsonl_output: Output in JSONL format
        :param show_fields: Fields to show
        :param match_codes: Status codes to match
        :param exclude_codes: Status codes to exclude
        :param shard: Tuple of (shard_index, total_shards) for distributed scanning
        '''

        self.concurrent_limit = concurrent_limit
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.check_axfr       = check_axfr
        self.resolver_file    = resolver_file
        self.output_file      = output_file
        self.show_progress    = show_progress
        self.debug_mode       = debug_mode
        self.jsonl_output     = jsonl_output
        self.shard            = shard

        self.show_fields = show_fields or {
            'status_code'      : True,
            'content_type'     : True,
            'content_length'   : True,
            'title'            : True,
            'body'             : True,
            'ip'               : True,
            'favicon'          : True,
            'headers'          : True,
            'follow_redirects' : True,
            'cname'            : True,
            'tls'              : True
        }

        self.match_codes       = match_codes
        self.exclude_codes     = exclude_codes
        self.resolvers         = None
        self.processed_domains = 0


    async def init(self):
        '''Initialize resolvers - must be called before scanning'''
        self.resolvers = await load_resolvers(self.resolver_file)


    async def check_domain(self, session: aiohttp.ClientSession, domain: str):
        '''Check a single domain and return results'''
        nameserver = random.choice(self.resolvers) if self.resolvers else None
        base_domain, port, protocols = parse_domain_url(domain)
        
        result = {
            'domain'  : base_domain,
            'status'  : 0,
            'url'     : protocols[0],
            'port'    : port,
        }

        # Try each protocol
        for url in protocols:
            try:
                # Set random user agent for each request
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                
                async with session.get(url, timeout=self.timeout, 
                                     allow_redirects=self.follow_redirects,
                                     max_redirects=10 if self.follow_redirects else 0,
                                     headers=headers) as response:
                    
                    result['status'] = response.status
                    
                    # Early exit if status code doesn't match criteria
                    if self.match_codes and result['status'] not in self.match_codes:
                        return result
                    if self.exclude_codes and result['status'] in self.exclude_codes:
                        return result

                    # Continue with full processing only if status code matches criteria
                    result['url'] = str(response.url)
                    
                    # Add headers if requested
                    headers = dict(response.headers)
                    if headers and (self.show_fields.get('headers') or self.show_fields.get('all_flags')):
                        result['headers'] = headers
                    else:
                        # Only add content type/length if headers aren't included
                        if content_type := response.headers.get('content-type', '').split(';')[0]:
                            result['content_type'] = content_type
                        if content_length := response.headers.get('content-length'):
                            result['content_length'] = content_length
                    
                    # Only add redirect chain if it exists
                    if self.follow_redirects and response.history:
                        result['redirect_chain'] = [str(h.url) for h in response.history] + [str(response.url)]

                    # Do DNS lookups only if we're going to use the result
                    ips, cname, nameservers, _ = await resolve_all_dns(
                        base_domain, self.timeout, nameserver, self.check_axfr
                    )
                    
                    # Only add DNS fields if they have values
                    if ips:
                        result['ips'] = ips
                    if cname:
                        result['cname'] = cname
                    if nameservers:
                        result['nameservers'] = nameservers

                    # Only add TLS info if available
                    if response.url.scheme == 'https':
                        try:
                            if ssl_object := response._protocol.transport.get_extra_info('ssl_object'):
                                if tls_info := await get_cert_info(ssl_object, str(response.url)):
                                    # Only add TLS fields that have values
                                    result['tls'] = {k: v for k, v in tls_info.items() if v}
                        except AttributeError:
                            debug(f'Failed to get SSL info for {url}')

                    content_type = response.headers.get('Content-Type', '')
                    html = await response.text() if any(x in content_type.lower() for x in ['text/html', 'application/xhtml']) else None
                    
                    # Only add title if it exists
                    if soup := bs4.BeautifulSoup(html, 'html.parser'):
                        if soup.title and soup.title.string:
                            result['title'] = ' '.join(soup.title.string.strip().split()).rstrip('.')[:300]
                    
                    # Only add body if it exists
                    if body_text := soup.get_text():
                        result['body'] = ' '.join(body_text.split()).rstrip('.')[:500]
                    
                    # Only add favicon hash if it exists
                    if favicon_hash := await get_favicon_hash(session, url, html):
                        result['favicon_hash'] = favicon_hash
                    
                    break
            except Exception as e:
                debug(f'Error checking {url}: {str(e)}')
                result['status'] = -1
                continue

        return result


    async def process_result(self, result):
        '''
        Process and output a single result
        
        :param result: result to process
        '''

        formatted = format_console_output(result, self.debug_mode, self.show_fields, self.match_codes, self.exclude_codes)
        
        if formatted:
            # Write to file if specified
            if self.output_file:
                if (not self.match_codes or result['status'] in self.match_codes) and \
                   (not self.exclude_codes or result['status'] not in self.exclude_codes):
                    async with aiohttp.ClientSession() as session:
                        with open(self.output_file, 'a') as f:
                            json.dump(result, f, ensure_ascii=False)
                            f.write('\n')
            
            # Console output
            if self.jsonl_output:
                print(json.dumps(result))
            else:
                self.processed_domains += 1
                if self.show_progress:
                    info(f"{Colors.GRAY}[{self.processed_domains:,}]{Colors.RESET} {formatted}")
                else:
                    info(formatted)


    async def scan(self, input_source):
        '''
        Scan domains from a file, stdin, or async generator
        
        :param input_source: Can be:
            - Path to file (str)
            - stdin ('-')
            - List/tuple of domains
            - Async generator yielding domains
        :yields: Result dictionary for each domain scanned
        '''
        
        if not self.resolvers:
            await self.init()

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = set()
            
            # Handle different input types
            if isinstance(input_source, str):
                # File or stdin input
                domain_iter = input_generator(input_source, self.shard)
                for domain in domain_iter:
                    if len(tasks) >= self.concurrent_limit:
                        done, tasks = await asyncio.wait(
                            tasks, return_when=asyncio.FIRST_COMPLETED
                        )
                        for task in done:
                            result = await task
                            await self.process_result(result)
                            yield result

                    task = asyncio.create_task(self.check_domain(session, domain))
                    tasks.add(task)
            elif isinstance(input_source, (list, tuple)):
                # List/tuple input
                for line_num, domain in enumerate(input_source):
                    if domain := str(domain).strip():
                        if self.shard is None or line_num % self.shard[1] == self.shard[0]:
                            if len(tasks) >= self.concurrent_limit:
                                done, tasks = await asyncio.wait(
                                    tasks, return_when=asyncio.FIRST_COMPLETED
                                )
                                for task in done:
                                    result = await task
                                    await self.process_result(result)
                                    yield result

                            task = asyncio.create_task(self.check_domain(session, domain))
                            tasks.add(task)
            else:
                # Async generator input
                line_num = 0
                async for domain in input_source:
                    if isinstance(domain, bytes):
                        domain = domain.decode()
                    domain = domain.strip()
                    
                    if domain:
                        if self.shard is None or line_num % self.shard[1] == self.shard[0]:
                            if len(tasks) >= self.concurrent_limit:
                                done, tasks = await asyncio.wait(
                                    tasks, return_when=asyncio.FIRST_COMPLETED
                                )
                                for task in done:
                                    result = await task
                                    await self.process_result(result)
                                    yield result

                            task = asyncio.create_task(self.check_domain(session, domain))
                            tasks.add(task)
                        line_num += 1

            # Process remaining tasks
            if tasks:
                done, _ = await asyncio.wait(tasks)
                for task in done:
                    result = await task
                    await self.process_result(result)
                    yield result 