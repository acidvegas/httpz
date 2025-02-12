#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/scanner.py

import asyncio
import random

try:
    import aiohttp
except ImportError:
    raise ImportError('missing aiohttp module (pip install aiohttp)')

try:
    import bs4
except ImportError:
    raise ImportError('missing bs4 module (pip install beautifulsoup4)')

from .dns     import resolve_all_dns, load_resolvers
from .parsers import parse_domain_url, get_cert_info, get_favicon_hash
from .utils   import debug, USER_AGENTS, input_generator


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
        self.progress_count    = 0


    async def check_domain(self, session: aiohttp.ClientSession, domain: str):
        '''
        Check a single domain and return results
        
        :param session: aiohttp.ClientSession
        :param domain: str
        '''

        # Get random nameserver
        nameserver = random.choice(self.resolvers) if self.resolvers else None

        # Parse domain
        base_domain, port, protocols = parse_domain_url(domain)

        # Initialize result dictionary
        result = {
            'domain' : base_domain,
            'status' : 0,
            'url'    : protocols[0],
            'port'   : port,
        }

        # Try each protocol
        for url in protocols:
            try:
                # Set random user agent for each request
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                
                async with session.get(url, timeout=self.timeout, allow_redirects=self.follow_redirects, max_redirects=10 if self.follow_redirects else 0, headers=headers) as response:
                    result['status'] = response.status
                    
                    # Bail immediately if it's a failed lookup - no point processing further
                    if result['status'] == -1:
                        return None

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
                continue  # Just continue to next protocol without setting status = -1

        # Return None if we never got a valid status
        return None if result['status'] == 0 else result


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
            self.resolvers = await load_resolvers(self.resolver_file)

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = set()
            domain_queue = asyncio.Queue()
            queue_empty = False
            
            async def process_domain(domain):
                try:
                    result = await self.check_domain(session, domain)
                    if result:
                        if self.show_progress:
                            self.progress_count += 1
                        return result
                except Exception as e:
                    debug(f'Error processing {domain}: {str(e)}')
                return None

            # Add domains to queue based on input type
            async def queue_domains():
                try:
                    if isinstance(input_source, str):
                        # File or stdin input
                        gen = input_generator(input_source, self.shard)
                        async for domain in gen:
                            await domain_queue.put(domain)
                    
                    elif isinstance(input_source, (list, tuple)):
                        # List/tuple input
                        for line_num, domain in enumerate(input_source):
                            if domain := str(domain).strip():
                                if self.shard is None or line_num % self.shard[1] == self.shard[0]:
                                    await domain_queue.put(domain)
                    
                    else:
                        # Async generator input
                        line_num = 0
                        async for domain in input_source:
                            if isinstance(domain, bytes):
                                domain = domain.decode()
                            if domain := domain.strip():
                                if self.shard is None or line_num % self.shard[1] == self.shard[0]:
                                    await domain_queue.put(domain)
                                line_num += 1
                except Exception as e:
                    debug(f'Error queuing domains: {str(e)}')
                finally:
                    # Signal queue completion
                    await domain_queue.put(None)

            # Start domain queuing task
            queue_task = asyncio.create_task(queue_domains())
            
            try:
                while not queue_empty or tasks:
                    # Fill up tasks to concurrent_limit
                    while len(tasks) < self.concurrent_limit and not queue_empty:
                        try:
                            domain = await domain_queue.get()
                            if domain is None:  # Queue is empty
                                queue_empty = True
                                break
                            task = asyncio.create_task(process_domain(domain))
                            tasks.add(task)
                        except asyncio.CancelledError:
                            break
                        except Exception as e:
                            debug(f'Error creating task: {str(e)}')
                    
                    if not tasks:
                        break
                    
                    # Wait for any task to complete with timeout
                    try:
                        done, pending = await asyncio.wait(
                            tasks,
                            timeout=self.timeout,
                            return_when=asyncio.FIRST_COMPLETED
                        )
                        
                        # Handle completed tasks
                        for task in done:
                            tasks.remove(task)
                            try:
                                if result := await task:
                                    yield result
                            except Exception as e:
                                debug(f'Error processing task result: {str(e)}')
                        
                        # Handle timed out tasks
                        if not done and pending:
                            for task in pending:
                                task.cancel()
                                try:
                                    await task
                                except asyncio.CancelledError:
                                    pass
                                tasks.remove(task)
                                
                    except Exception as e:
                        debug(f'Error in task processing loop: {str(e)}')
                    
            finally:
                # Clean up
                for task in tasks:
                    task.cancel()
                queue_task.cancel()
                try:
                    await queue_task
                except asyncio.CancelledError:
                    pass 