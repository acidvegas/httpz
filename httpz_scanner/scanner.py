#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/scanner.py

import asyncio
import contextvars
import random
import urllib.parse

try:
    import aiohttp
except ImportError:
    raise ImportError('missing aiohttp module (pip install aiohttp)')


# Per-task bucket for capturing the ssl_object from the live aiohttp connection.
# Set on the request side, populated by the connector subclass on connection create.
_ssl_capture: contextvars.ContextVar = contextvars.ContextVar('_httpz_ssl_capture', default=None)


class _CertCapturingConnector(aiohttp.TCPConnector):
    '''
    TCPConnector subclass that captures the live ssl_object on every newly-created
    connection into the calling task's _ssl_capture bucket. Used to grab the peer
    cert without opening a second TLS handshake per https domain.
    '''

    async def _wrap_create_connection(self, *args, **kwargs):
        transport, proto = await super()._wrap_create_connection(*args, **kwargs)
        bucket = _ssl_capture.get()
        if bucket is not None:
            ssl_obj = transport.get_extra_info('ssl_object')
            if ssl_obj is not None:
                bucket['ssl_object'] = ssl_obj
        return transport, proto

from .parsers import (
    parse_domain_url,
    parse_cert,
    get_favicon_hash,
    parse_title,
    body_preview,
    body_clean,
    MAX_BODY_BYTES,
)
from .utils import debug, USER_AGENTS, input_generator, resolve_ips, resolve_cname_chain


# Hard cap on CNAME chain length (including the original hostname).
MAX_CNAME_CHAIN = 3


# Errors that are worth retrying / falling back on. Cert errors fall back but don't retry.
_TRANSIENT_ERROR_TYPES = ('TIMEOUT', 'CONN', 'HTTP')
_FALLBACK_ERROR_TYPES  = ('TIMEOUT', 'CONN', 'SSL', 'CERT', 'HTTP', 'UNKNOWN')


class HTTPZScanner:
    '''Core scanner class for HTTP domain checking'''

    def __init__(
        self,
        concurrent_limit  = 100,
        timeout           = 5,
        retries           = 1,
        retry_backoff     = 0.5,
        max_redirects     = 10,
        follow_redirects  = True,
        # feature toggles (all default OFF)
        fetch_headers         = False,
        fetch_content_type    = False,
        fetch_content_length  = False,
        fetch_title           = False,
        fetch_body            = False,
        fetch_favicon         = False,
        fetch_tls             = False,
        fetch_ips             = False,
        fetch_cname           = False,
        # filtering / misc
        match_codes    = None,
        exclude_codes  = None,
        custom_headers = None,
        post_data      = None,
        shard          = None,
        resolvers      = None,
        dns_timeout    = 2.0,
    ):
        '''
        :param concurrent_limit: max in-flight domain checks
        :param timeout: per-request timeout in seconds
        :param retries: retry attempts per protocol on transient errors (after the first try)
        :param retry_backoff: base seconds for linear backoff between retries
        :param max_redirects: redirect chain cap when follow_redirects is True
        :param follow_redirects: whether aiohttp follows redirects
        :param fetch_headers: include response_headers in result
        :param fetch_content_type: include content_type in result
        :param fetch_content_length: include content_length in result
        :param fetch_title: include title in result (requires body read)
        :param fetch_body: include body_preview and body_clean
        :param fetch_favicon: include favicon_hash (extra HTTP request)
        :param fetch_tls: include tls cert info (https only)
        :param fetch_ips: include resolved A/AAAA in result
        :param fetch_cname: detect CNAME chain (up to MAX_CNAME_CHAIN hostnames),
            scan against the final hop, and attach `cname_chain` to the result
        :param match_codes: only yield results with these status codes
        :param exclude_codes: skip results with these status codes
        :param custom_headers: dict of extra headers
        :param post_data: if set, send POST with this body
        :param shard: (index, total) for distributed scanning
        :param resolvers: optional list of DNS resolver IPs (used for fetch_ips)
        :param dns_timeout: per-query DNS timeout in seconds
        '''

        self.concurrent_limit = concurrent_limit
        self.timeout          = timeout
        self.retries          = retries
        self.retry_backoff    = retry_backoff
        self.max_redirects    = max_redirects
        self.follow_redirects = follow_redirects

        self.fetch_headers        = fetch_headers
        self.fetch_content_type   = fetch_content_type
        self.fetch_content_length = fetch_content_length
        self.fetch_title          = fetch_title
        self.fetch_body           = fetch_body
        self.fetch_favicon        = fetch_favicon
        self.fetch_tls            = fetch_tls
        self.fetch_ips            = fetch_ips
        self.fetch_cname          = fetch_cname

        self.match_codes    = match_codes
        self.exclude_codes  = exclude_codes
        self.custom_headers = custom_headers or {}
        self.post_data      = post_data
        self.shard          = shard
        self.resolvers      = resolvers
        self.dns_timeout    = dns_timeout

        self._needs_body = fetch_title or fetch_body or fetch_favicon
        self._stop_event = None  # set in scan(), used by stop()


    def _make_connector(self) -> aiohttp.TCPConnector:
        '''
        Build the TCP connector. Uses _CertCapturingConnector when fetch_tls is on
        so the peer cert can be parsed from the live ssl_object — no second handshake.
        '''

        kwargs = {
            'ssl'           : False,
            'limit'         : self.concurrent_limit * 2,
            'limit_per_host': 0,
            'ttl_dns_cache' : 300,
            'use_dns_cache' : True,
            'force_close'   : True,  # unique-host scan: keep-alive is wasted FDs
        }
        try:
            import aiodns  # noqa: F401
            from aiohttp.resolver import AsyncResolver
            kwargs['resolver'] = AsyncResolver()
        except ImportError:
            pass
        cls = _CertCapturingConnector if self.fetch_tls else aiohttp.TCPConnector
        return cls(**kwargs)


    async def stop(self):
        '''
        Signal the scan loop to drain. The producer is cancelled, no new domains
        are pulled from the queue, and in-flight requests are awaited (or cancelled
        when the session exits). Idempotent.
        '''

        if self._stop_event is not None:
            self._stop_event.set()


    @staticmethod
    def _err_result(domain: str, protocol: str, err_type: str, message: str) -> dict:
        return {
            'domain'     : domain,
            'protocol'   : protocol,
            'status'     : -1,
            'error'      : message,
            'error_type' : err_type,
        }


    @staticmethod
    def _classify_exception(exc: BaseException):
        '''Map an aiohttp/asyncio exception to (error_type, message).'''

        if isinstance(exc, asyncio.TimeoutError):
            return 'TIMEOUT', 'Connection timed out'
        if isinstance(exc, aiohttp.ClientConnectorCertificateError):
            return 'CERT', f'Certificate Error: {exc}'
        if isinstance(exc, aiohttp.ClientSSLError):
            return 'SSL', f'SSL Error: {exc}'
        if isinstance(exc, aiohttp.ClientConnectorError):
            return 'CONN', f'Connection Failed: {exc}'
        if isinstance(exc, aiohttp.ClientError):
            return 'HTTP', f'HTTP Error: {exc.__class__.__name__}: {exc}'
        return 'UNKNOWN', f'Error: {exc.__class__.__name__}: {exc}'


    async def _check_url(self, session: aiohttp.ClientSession, url: str, protocol: str, domain: str) -> dict:
        '''Single attempt against a URL. Returns a result dict (success or error shape).'''

        headers = {'User-Agent': random.choice(USER_AGENTS)}
        headers.update(self.custom_headers)

        method = 'POST' if self.post_data is not None else 'GET'
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        # Set up a per-task bucket that the cert-capturing connector will fill
        # in with the live ssl_object during connection creation.
        ssl_bucket = {} if self.fetch_tls and protocol == 'https' else None
        token      = _ssl_capture.set(ssl_bucket) if ssl_bucket is not None else None

        try:
            async with session.request(
                method,
                url,
                data              = self.post_data,
                timeout           = timeout,
                allow_redirects   = self.follow_redirects,
                max_redirects     = self.max_redirects,
                ssl               = False,
                headers           = headers,
            ) as response:
                debug(f'{url} -> {response.status}')

                result = {
                    'domain'   : domain,
                    'url'      : str(response.url),
                    'status'   : response.status,
                    'protocol' : protocol,
                }

                if self.fetch_headers:
                    result['response_headers'] = dict(response.headers)

                if self.fetch_content_type:
                    result['content_type'] = response.headers.get('Content-Type')

                if self.fetch_content_length:
                    cl = response.headers.get('Content-Length')
                    if cl is not None:
                        try:
                            result['content_length'] = int(cl)
                        except ValueError:
                            result['content_length'] = cl

                if response.history:
                    result['redirect_chain'] = [str(h.url) for h in response.history] + [str(response.url)]

                # TLS cert: parsed from ssl_object captured by the connector
                # subclass during connection creation — no extra handshake.
                if ssl_bucket is not None:
                    cert = parse_cert(ssl_bucket.get('ssl_object'))
                    if cert:
                        result['tls'] = cert

                # Body read (capped)
                raw_body = None
                if self._needs_body:
                    try:
                        raw_body = await response.content.read(MAX_BODY_BYTES)
                    except Exception as e:
                        debug(f'Body read error for {url}: {e}')
                        raw_body = None

                if raw_body is not None:
                    encoding = response.charset or 'utf-8'

                    if self.fetch_body:
                        result['body_preview'] = body_preview(raw_body, encoding=encoding)

                    if self.fetch_title or self.fetch_body or self.fetch_favicon:
                        try:
                            html_text = raw_body.decode(encoding, errors='replace')
                        except Exception:
                            html_text = raw_body.decode('utf-8', errors='replace')

                        if self.fetch_body:
                            result['body_clean'] = body_clean(html_text)

                        if self.fetch_title:
                            ct = response.headers.get('Content-Type')
                            title = parse_title(html_text, ct)
                            if title:
                                result['title'] = title

                        if self.fetch_favicon:
                            parsed = urllib.parse.urlparse(str(response.url))
                            base   = f'{parsed.scheme}://{parsed.netloc}'
                            fav    = await get_favicon_hash(session, base, html_text, timeout=self.timeout)
                            if fav:
                                result['favicon_hash'] = fav

                return result

        except Exception as e:
            err_type, msg = self._classify_exception(e)
            debug(f'{url} {err_type}: {msg}')
            return self._err_result(domain, protocol, err_type, msg)
        finally:
            if token is not None:
                _ssl_capture.reset(token)


    async def _check_url_with_retries(self, session, url, protocol, domain) -> dict:
        '''Try _check_url up to (1 + retries) times on transient failures.'''

        attempts = 1 + max(0, self.retries)
        last     = None
        for attempt in range(attempts):
            result = await self._check_url(session, url, protocol, domain)
            if result.get('status', -1) >= 0:
                return result
            last = result
            if result.get('error_type') not in _TRANSIENT_ERROR_TYPES:
                return result
            if attempt < attempts - 1:
                await asyncio.sleep(self.retry_backoff * (attempt + 1))
        return last


    async def check_domain(self, session: aiohttp.ClientSession, domain: str) -> dict:
        '''Try the preferred protocol; fall back to the other on failure.'''

        base_domain, port, protocols = parse_domain_url(domain)
        original_domain              = base_domain

        # CNAME chain (optional): resolve up to MAX_CNAME_CHAIN entries, then scan
        # against the final hop's hostname. Chain is reported even if length is 1.
        cname_chain = None
        scan_target = base_domain
        if self.fetch_cname:
            try:
                chain = await resolve_cname_chain(base_domain, self.resolvers, self.dns_timeout, MAX_CNAME_CHAIN)
                if len(chain) > 1:
                    cname_chain = chain
                    scan_target = chain[-1]
            except Exception as e:
                debug(f'CNAME resolve error for {base_domain}: {e}')

        ips_task = None
        if self.fetch_ips:
            ips_task = asyncio.create_task(resolve_ips(scan_target, self.resolvers, self.dns_timeout))

        last_error = None
        success    = None
        for protocol in protocols:
            url = f'{protocol}://{scan_target}'
            if port:
                url += f':{port}'
            result = await self._check_url_with_retries(session, url, protocol, original_domain)
            if result.get('status', -1) >= 0:
                success = result
                break
            last_error = result
            if result.get('error_type') not in _FALLBACK_ERROR_TYPES:
                break

        final = success if success is not None else last_error

        if cname_chain is not None:
            final['cname_chain'] = cname_chain

        if ips_task is not None:
            try:
                ips = await ips_task
                if ips:
                    final['ips'] = ips
            except Exception as e:
                debug(f'IP resolve error for {scan_target}: {e}')

        return final


    async def scan(self, input_source):
        '''
        Scan domains from a file path, '-' for stdin, an iterable, or an async iterable.
        Yields one result dict per domain.

        :param input_source: see utils.input_generator
        '''

        connector        = self._make_connector()
        self._stop_event = asyncio.Event()
        stop_event       = self._stop_event

        async with aiohttp.ClientSession(connector=connector) as session:
            domain_queue = asyncio.Queue(maxsize=self.concurrent_limit * 2)
            tasks        = {}
            queue_done   = False

            async def producer():
                nonlocal queue_done
                try:
                    async for domain in input_generator(input_source, self.shard):
                        if stop_event.is_set():
                            break
                        await domain_queue.put(domain)
                finally:
                    queue_done = True

            async def process(domain):
                try:
                    return await self.check_domain(session, domain)
                except Exception as e:
                    debug(f'process error for {domain}: {e.__class__.__name__}: {e}')
                    return self._err_result(domain, 'unknown', 'PROCESS', f'{e.__class__.__name__}: {e}')

            producer_task = asyncio.create_task(producer())

            try:
                while not (queue_done and domain_queue.empty() and not tasks):
                    # On stop: drop any queued domains, finish in-flight, then exit.
                    if stop_event.is_set():
                        while not domain_queue.empty():
                            try:
                                domain_queue.get_nowait()
                            except asyncio.QueueEmpty:
                                break
                        if not tasks:
                            break

                    if not stop_event.is_set():
                        while len(tasks) < self.concurrent_limit and not domain_queue.empty():
                            domain = domain_queue.get_nowait()
                            t = asyncio.create_task(process(domain))
                            tasks[t] = domain

                    if not tasks:
                        await asyncio.sleep(0.05)
                        continue

                    done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
                    for t in done:
                        domain = tasks.pop(t)
                        try:
                            result = t.result()
                        except Exception as e:
                            result = self._err_result(domain, 'unknown', 'TASK', f'{e.__class__.__name__}: {e}')
                        if result is None:
                            result = self._err_result(domain, 'unknown', 'NO_RESPONSE', 'No response from either protocol')

                        if self.match_codes is not None and result.get('status') not in self.match_codes:
                            continue
                        if self.exclude_codes is not None and result.get('status') in self.exclude_codes:
                            continue

                        yield result

            finally:
                for t in tasks:
                    t.cancel()
                producer_task.cancel()
                try:
                    await producer_task
                except (asyncio.CancelledError, Exception):
                    pass
