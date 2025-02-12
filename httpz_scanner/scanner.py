#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/scanner.py

import asyncio
import random
import urllib.parse
import json

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
    
    def __init__(self, concurrent_limit = 100, timeout = 5, follow_redirects = False, check_axfr = False, resolver_file = None, output_file = None, show_progress = False, debug_mode = False, jsonl_output = False, show_fields = None, match_codes = None, exclude_codes = None, shard = None, paths = None, custom_headers=None, post_data=None):
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
        :param paths: List of additional paths to check on each domain
        :param custom_headers: Dictionary of custom headers to send with each request
        :param post_data: Data to send with POST requests
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
        self.paths            = paths or []
        self.custom_headers   = custom_headers or {}
        self.post_data        = post_data

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
        '''Check a single domain and return results'''
        base_domain, port, protocols = parse_domain_url(domain)
        
        for protocol in protocols:
            url = f'{protocol}{base_domain}'
            if port:
                url += f':{port}'
                
            try:
                debug(f'Trying {url}...')
                result = await self._check_url(session, url)
                debug(f'Got result for {url}: {result}')
                if result and (result['status'] != 400 or result.get('redirect_chain')):  # Accept redirects
                    return result
            except Exception as e:
                debug(f'Error checking {url}: {str(e)}')
                continue
        
        return None

    async def _check_url(self, session: aiohttp.ClientSession, url: str):
        '''Check a single URL and return results'''
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            headers.update(self.custom_headers)
            
            debug(f'Making request to {url} with headers: {headers}')
            async with session.request('GET', url, 
                timeout=self.timeout,
                allow_redirects=True,
                max_redirects=10,
                ssl=False,
                headers=headers) as response:
                
                debug(f'Got response from {url}: status={response.status}, headers={dict(response.headers)}')
                
                # Get domain and parse URL
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.hostname
                
                # Basic result structure
                result = {
                    'domain': domain,
                    'status': response.status,
                    'url': str(response.url),
                    'response_headers': dict(response.headers),
                    'protocol': parsed_url.scheme
                }

                try:
                    # Get response body
                    body = await response.text()
                    result['body'] = body[:500]  # Limit body preview
                    
                    # Parse title using bs4
                    if 'text/html' in response.headers.get('content-type', '').lower():
                        soup = bs4.BeautifulSoup(body, 'html.parser')
                        if title_tag := soup.title:
                            result['title'] = title_tag.string.strip()

                    # Get content type and length
                    result['content_type'] = response.headers.get('content-type')
                    result['content_length'] = response.headers.get('content-length')

                    # Get redirect chain
                    if response.history:
                        result['redirect_chain'] = [str(h.url) for h in response.history] + [str(response.url)]

                    # Get DNS info
                    if self.show_fields.get('ip') or self.show_fields.get('cname'):
                        ips, cname, _, _ = await resolve_all_dns(domain)
                        if ips:
                            result['ips'] = ips
                        if cname:
                            result['cname'] = cname

                    # Get TLS info for HTTPS
                    if url.startswith('https://') and self.show_fields.get('tls'):
                        if cert_info := await get_cert_info(response.connection.transport.get_extra_info('ssl_object'), url):
                            result['tls'] = cert_info

                    # Get favicon hash if requested
                    if self.show_fields.get('favicon'):
                        if favicon_hash := await get_favicon_hash(session, f"{parsed_url.scheme}://{domain}", body):
                            result['favicon_hash'] = favicon_hash

                except Exception as e:
                    debug(f'Error processing response data for {url}: {str(e)}')
                    # Still return basic result even if additional processing fails
                    
                return result
                
        except aiohttp.ClientSSLError as e:
            debug(f'SSL Error for {url}: {str(e)}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'SSL Error: {str(e)}',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'SSL'
            }
        except aiohttp.ClientConnectorCertificateError as e:
            debug(f'Certificate Error for {url}: {str(e)}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'Certificate Error: {str(e)}',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'CERT'
            }
        except aiohttp.ClientConnectorError as e:
            debug(f'Connection Error for {url}: {str(e)}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'Connection Failed: {str(e)}',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'CONN'
            }
        except aiohttp.ClientError as e:
            debug(f'HTTP Error for {url}: {e.__class__.__name__}: {str(e)}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'HTTP Error: {e.__class__.__name__}: {str(e)}',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'HTTP'
            }
        except asyncio.TimeoutError:
            debug(f'Timeout for {url}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'Connection Timed Out after {self.timeout}s',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'TIMEOUT'
            }
        except Exception as e:
            debug(f'Unexpected error for {url}: {e.__class__.__name__}: {str(e)}')
            return {
                'domain': urllib.parse.urlparse(url).hostname,
                'status': -1,
                'error': f'Error: {e.__class__.__name__}: {str(e)}',
                'protocol': 'https' if url.startswith('https://') else 'http',
                'error_type': 'UNKNOWN'
            }


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

        # Just use ssl=False, that's all we need
        connector = aiohttp.TCPConnector(ssl=False, enable_cleanup_closed=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = {}  # Change to dict to track domain for each task
            domain_queue = asyncio.Queue()
            queue_empty = False
            
            async def process_domain(domain):
                try:
                    result = await self.check_domain(session, domain)
                    if self.show_progress:
                        self.progress_count += 1
                    if result:
                        return domain, result
                    else:
                        # Create a proper error result if check_domain returns None
                        return domain, {
                            'domain': domain,
                            'status': -1,
                            'error': 'No successful response from either HTTP or HTTPS',
                            'protocol': 'unknown',
                            'error_type': 'NO_RESPONSE'
                        }
                except Exception as e:
                    debug(f'Error processing {domain}: {e.__class__.__name__}: {str(e)}')
                    # Return structured error information
                    return domain, {
                        'domain': domain,
                        'status': -1,
                        'error': f'{e.__class__.__name__}: {str(e)}',
                        'protocol': 'unknown',
                        'error_type': 'PROCESS'
                    }

            # Queue processor
            async def queue_processor():
                async for domain in input_generator(input_source, self.shard):
                    await domain_queue.put(domain)
                    self.processed_domains += 1
                nonlocal queue_empty
                queue_empty = True

            # Start queue processor
            queue_task = asyncio.create_task(queue_processor())

            try:
                while not (queue_empty and domain_queue.empty() and not tasks):
                    # Fill up tasks until we hit concurrent limit
                    while len(tasks) < self.concurrent_limit and not domain_queue.empty():
                        domain = await domain_queue.get()
                        task = asyncio.create_task(process_domain(domain))
                        tasks[task] = domain
                    
                    if tasks:
                        # Wait for at least one task to complete
                        done, _ = await asyncio.wait(
                            tasks.keys(),
                            return_when=asyncio.FIRST_COMPLETED
                        )
                        
                        # Process completed tasks
                        for task in done:
                            domain = tasks.pop(task)
                            try:
                                _, result = await task
                                if result:
                                    yield result
                            except Exception as e:
                                debug(f'Task error for {domain}: {e.__class__.__name__}: {str(e)}')
                                yield {
                                    'domain': domain,
                                    'status': -1,
                                    'error': f'Task Error: {e.__class__.__name__}: {str(e)}',
                                    'protocol': 'unknown',
                                    'error_type': 'TASK'
                                }
                    else:
                        await asyncio.sleep(0.1)  # Prevent CPU spin when no tasks

            finally:
                # Clean up
                for task in tasks:
                    task.cancel()
                queue_task.cancel()
                try:
                    await queue_task
                except asyncio.CancelledError:
                    pass 