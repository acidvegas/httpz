#!/usr/bin/env python3
# Hyperfast Scalable HTTP Scanner - Developed by acidvegas (https://github.com/acidvegas)

import asyncio
import logging
import json
import socket
import ssl
import time

from collections import Counter

try:
    import aiohttp
except ImportError:
    raise ImportError('missing aiohttp library (pip install aiohttp)')

try:
    from bs4 import BeautifulSoup
except ImportError:
    raise ImportError('missing beautifulsoup4 library (pip install beautifulsoup4)')

try:
    from OpenSSL import SSL
except ImportError:
    raise ImportError('missing OpenSSL library (pip install pyOpenSSL)')

from utils         import get_status_color, ColoredFormatter, Colors
from cert_utils    import extract_cert_info
from dns_utils     import resolve_records
from favicon_utils import get_favicon_hash


class HTTPScanner:
    def __init__(self, concurrency: int = 100, timeout: float = 5, max_redirects: int = 10, user_agent: str = None, quiet: bool = False, json_output: bool = False):
        '''
        Initialize HTTP Scanner
        
        :param concurrency: Maximum number of concurrent connections
        :param timeout: Request timeout in seconds
        :param max_redirects: Maximum number of redirects to follow
        :param user_agent: Custom User-Agent string
        :param quiet: Suppress error messages
        :param json_output: Output in JSON format instead of colored text
        '''

        self.concurrency   = concurrency
        self.timeout       = timeout
        self.max_redirects = max_redirects
        self.user_agent    = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        self.quiet         = quiet
        self.json_output   = json_output
        self.processed     = Counter()
        
        # Setup logging - prevent propagation to root logger
        self.logger = logging.getLogger('HTTPScanner')
        self.logger.propagate = False
        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)


    async def scan(self, domains, output_file: str = None) -> None:
        '''
        Scan a list of domains
        
        :param domains: List/Iterator of domains to scan
        :param output_file: Optional file to write JSONL results to
        '''
        # Create SSL context that captures raw certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.get_ciphers() # This enables getting raw certs

        timeout_obj = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout)
        connector = aiohttp.TCPConnector(ssl=ssl_context, force_close=True, enable_cleanup_closed=True)
        headers = {'User-Agent': self.user_agent}

        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout_obj, trust_env=True) as session:
            tasks = set()
            for domain in domains:
                if not (domain := domain.strip()):
                    continue
                if len(tasks) >= self.concurrency:
                    done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                tasks.add(asyncio.create_task(self._process_url(session, domain, output_file)))
            
            if tasks:
                await asyncio.wait(tasks)


    async def _check_url(self, session, url: str) -> tuple:
        '''
        Attempt to fetch domain information with the given protocol.
        
        :param session: aiohttp client session
        :param url: URL to check
        '''

        try:
            async with session.get(url, allow_redirects=True, max_redirects=self.max_redirects, timeout=self.timeout) as r:
                final_url = str(r.url).rstrip('/')
                # Certificate extraction for HTTPS URLs in a compact form
                cert_info, cert_json = ('', '')
                if final_url.startswith('https://'):
                    try:
                        host = final_url.split('://')[1].split('/')[0]
                        conn = SSL.Connection(SSL.Context(SSL.TLS_METHOD), socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                        conn.set_tlsext_host_name(host.encode())
                        conn.connect((host, 443))
                        conn.do_handshake()
                        if (cert := conn.get_peer_certificate()):
                            if (ci := extract_cert_info(cert)):
                                cert_info = f' [{Colors.BRIGHT_GREEN}{" | ".join(f"{k}: {v}" for k,v in ci.items())}{Colors.RESET}]'
                                cert_json = ci
                        conn.close()
                    except Exception:
                        pass
                
                # Get original and final domains for comparison
                clean = lambda u: u.split('://')[-1].replace('www.','',1).split(':')[0].strip()
                orig_clean, final_clean = clean(url.rstrip('/')), clean(final_url)
                
                # Only show redirect info if domains actually differ
                redirect_info = ''
                if orig_clean != final_clean and r.history:
                    redirect_status = r.history[0].status
                    redirect_info = f' {Colors.RESET}[{Colors.ORANGE}{redirect_status} → {url}{Colors.RESET}]'
                
                # Extract title and body preview
                title, preview = '', ''
                content_type = r.headers.get('content-type', '').split(';')[0]
                
                # Extract server header and remove from general headers
                server = r.headers.get('server', '')
                # Get all headers except content-type, date, and server for display
                headers_str = '; '.join(f'{k}: {v}' for k,v in r.headers.items() if k.lower() not in ('content-type','date','server'))
                
                # Try to get content from any text-based response
                if content_type.startswith(('text/', 'application/json', 'application/xml', 'application/javascript')):
                    try:
                        text = await r.text(errors='ignore')
                        if content_type.startswith('text/html'):
                            soup = BeautifulSoup(text, 'html.parser')
                            title = ' '.join(soup.title.string.split()) if (soup.title and soup.title.string) else ''
                            preview = ' '.join(soup.get_text().split())[:300]
                        else:
                            # For non-HTML text content, just get the raw text
                            preview = ' '.join(text.split())[:300]
                    except Exception as e:
                        logging.debug(f'Error parsing content: {str(e)}')
                
                # Extract favicon and hash it
                favicon_hash = ''
                if content_type.startswith('text/html'):
                    try:
                        favicon_hash = await get_favicon_hash(session, soup, final_url, self.timeout)
                    except Exception:
                        pass
                
                return r.status, final_url.replace(':80', '').replace(':443', ''), title, redirect_info, redirect_status if redirect_info else None, preview, content_type, headers_str, cert_info, cert_json, favicon_hash, server

        except Exception as e:
            msg = str(e).strip()
            err = msg if msg else f'Connection failed: {e.__class__.__name__}'
            return 0, url, '', '', None, err, '', '', '', {}, '', ''


    def _format_result_json(self, status: int, url: str, final_url: str, title: str, redirect_info: str, preview: str, content_type: str, headers: str, ips: list, cname: str, nameservers: list, ns_ips: dict) -> dict:
        '''Format the result as a JSON object'''
        # Parse headers safely
        header_dict: dict = {}
        if headers:
            for header in headers.split('; '):
                if ': ' in header:
                    key, value = header.split(': ', 1)
                    header_dict[key] = value

        result: dict = {
            'timestamp'    : time.strftime('%Y-%m-%d %H:%M:%S'),
            'status'       : status,
            'url'          : url,
            'final_url'    : final_url,
            'title'        : title,
            'preview'      : preview,
            'content_type' : content_type,
            'headers'      : header_dict,
        }

        if redirect_info:
            parts = redirect_info.split('→ ')
            if len(parts) > 1:
                redir_url = parts[1].rstrip(']')
                try:
                    redir_status = int(redirect_info.split()[1])
                except Exception:
                    redir_status = None
                result['redirect'] = {
                    'status': redir_status,
                    'url': redir_url
                }

        # Build consolidated DNS info and omit empty fields
        dns_info: dict = {}
        if ips:
            dns_info['ips'] = ips
        if nameservers:
            ns_dict: dict = {}
            for ns in nameservers:
                ns_dict[ns] = ns_ips.get(ns, [])
            if ns_dict:
                dns_info['nameservers'] = ns_dict
        if dns_info:
            result['dns'] = dns_info

        return result

    async def _process_url(self, session, domain: str, output_file: str = None) -> dict:
        '''
        Process a domain by trying HTTPS first, then falling back to HTTP if needed.
        
        :param session: aiohttp client session
        :param domain: Domain name to process
        :param output_file: Optional file to write JSONL results to
        '''
        try:
            # Get base domain for DNS lookup
            base_domain = domain.split('://')[-1].split('/')[0].split(':')[0]
            
            # Resolve DNS records concurrently with HTTP check
            dns_task = asyncio.create_task(resolve_records(base_domain))
            
            urls = [domain] if domain.startswith(('http://', 'https://')) else [f'https://{domain}', f'http://{domain}']
            
            # Initialize result variables
            status          = 0
            url             = domain
            final_url       = ''
            title           = ''
            redirect_info   = ''
            redirect_status = None
            preview         = ''
            content_type    = ''
            headers         = ''
            cert_info       = ''
            cert_json       = {}
            favicon_hash    = ''
            server          = ''
            
            for url in urls:
                if (result := await self._check_url(session, url))[0]:
                    status, final_url, title, redirect_info, redirect_status, preview, content_type, headers, cert_info, cert_json, favicon_hash, server = result
                    
                    # Increment counter before output
                    self.processed['domains'] += 1
                    count = f"{self.processed['domains']:,}"  # Format with commas
                    
                    # Get DNS results
                    dns_records = await dns_task
                    ips, cname, nameservers, ns_ips = dns_records
                    
                    if self.json_output:
                        json_result = self._format_result_json(
                            status, url, final_url, title, redirect_info, preview,
                            content_type, headers, ips, cname, nameservers, ns_ips
                        )
                        print(json.dumps(json_result))
                    else:
                        status_info = f"{Colors.GRAY}{count}{Colors.RESET} [{get_status_color(status)}{status:3d}{Colors.RESET}]"
                        url_info    = f'[{Colors.DARK_BLUE}{Colors.UNDERLINE}{url}{Colors.RESET}]'
                        
                        if redirect_info:
                            redirect_info = f' {Colors.RESET}[{Colors.ORANGE}{redirect_status} → {final_url}{Colors.RESET}]'
                        
                        title_info        = f' [{Colors.DARK_GREEN}{title}{Colors.RESET}]' if title else ''
                        preview_info      = f' [{Colors.BLUE}{preview}{Colors.RESET}]' if preview else ''
                        content_type_info = f' [{Colors.PINK}{content_type}{Colors.RESET}]' if content_type else ''
                        headers_info      = f' [{Colors.CYAN}{headers}{Colors.RESET}]' if headers else ''
                        cert_info         = f' {cert_info}'                            if cert_info else ''
                        favicon_info      = f' [{Colors.PURPLE}{favicon_hash}{Colors.RESET}]' if favicon_hash else ''
                        server_info       = f' [{Colors.DARK_RED}{server}{Colors.RESET}]' if server else ''
                        
                        # Format domain info with CNAME and NS
                        url_info = f'[{Colors.DARK_BLUE}{Colors.UNDERLINE}{url}{Colors.RESET}]'
                        if cname:
                            # Show CNAME in redirect style
                            redirect_info = f' {Colors.RESET}[{Colors.ORANGE}CNAME → {cname}{Colors.RESET}]{redirect_info}'
                        if nameservers:
                            url_info += f' [{Colors.RED}{", ".join(nameservers)}{Colors.RESET}]'
                        
                        # Format remaining DNS info
                        dns_info = ''
                        if ips:
                            dns_info += f' [{Colors.YELLOW}A/AAAA: {", ".join(ips)}{Colors.RESET}]'
                        
                        log_msg = (f'{status_info} {url_info}{redirect_info}{title_info}'
                                  f'{preview_info}{content_type_info}{headers_info}'
                                  f'{server_info}{cert_info}{favicon_info}{dns_info}')
                        self.logger.info(log_msg)

                    # Save to file if output specified
                    if output_file:
                        json_result = self._format_result_json(
                            status, url, final_url, title, redirect_info, preview,
                            content_type, headers, ips, cname, nameservers, ns_ips
                        )
                        with open(output_file, 'a') as f:
                            f.write(json.dumps(json_result) + '\n')
                    
                    if status < 400:
                        break
                elif url == urls[-1] and not self.quiet and not self.json_output:
                    status, final_url, title, redirect_info, redirect_status, error_msg, content_type, headers, cert_info, cert_json, favicon_hash, server = result
                    self.logger.error(f'[{Colors.RED}ERR{Colors.RESET}] [{Colors.BLUE}{Colors.UNDERLINE}{domain}{Colors.RESET}] {Colors.GRAY}{error_msg}{Colors.RESET}')
            
            return {
                'status'          : status,
                'url'             : url,
                'final_url'       : final_url,
                'title'           : title,
                'redirect_info'   : redirect_info,
                'redirect_status' : redirect_status,
                'preview'         : preview,
                'content_type'    : content_type,
                'headers'         : headers,
                'cert_info'       : cert_info,
                'cert_json'       : cert_json,
                'favicon_hash'    : favicon_hash,
                'server'          : server
            }

        except Exception as e:
            error_msg = str(e) if str(e) else 'Connection failed'  # Ensure we have an error message
            if not self.quiet and not self.json_output:
                self.logger.error(f'[{Colors.RED}ERR{Colors.RESET}] [{Colors.BLUE}{Colors.UNDERLINE}{domain}{Colors.RESET}] {Colors.GRAY}{error_msg}{Colors.RESET}')

            return {
                'status'          : 0,
                'url'             : domain,
                'final_url'       : '',
                'title'           : '',
                'redirect_info'   : '',
                'redirect_status' : None,
                'preview'         : '',
                'content_type'    : '',
                'headers'         : '',
                'cert_info'       : f'Connection failed: {str(e)}',
                'cert_json'       : {},
                'favicon_hash'    : '',
                'server'          : ''
            }