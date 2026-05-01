#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/parsers.py

import argparse
import re
import urllib.parse

try:
    import bs4
except ImportError:
    raise ImportError('missing bs4 module (pip install beautifulsoup4)')

try:
    from cryptography                   import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid          import NameOID, ExtensionOID
except ImportError:
    raise ImportError('missing cryptography module (pip install cryptography)')

try:
    import mmh3
except ImportError:
    raise ImportError('missing mmh3 module (pip install mmh3)')

from .utils import debug, error


_WS_RE = re.compile(r'\s+')

TITLE_MAX_CHARS       = 1024
BODY_PREVIEW_BYTES    = 1024
BODY_CLEAN_CHARS      = 1024
DEFAULT_FAVICON_BYTES = 256 * 1024


def parse_domain_url(domain: str) -> tuple:
    '''
    Parse a raw domain string into (base_domain, port, ordered_protocol_list).

    Protocol order:
      - explicit https:// → ['https', 'http']
      - explicit http://  → ['http', 'https']
      - no scheme         → ['https', 'http']

    :param domain: raw domain string
    '''

    raw  = domain.strip().rstrip('/')
    port = None

    if raw.startswith('https://'):
        protocols = ['https', 'http']
        rest      = raw[len('https://'):]
    elif raw.startswith('http://'):
        protocols = ['http', 'https']
        rest      = raw[len('http://'):]
    else:
        protocols = ['https', 'http']
        rest      = raw

    host_part = rest.split('/', 1)[0]
    if ':' in host_part:
        host, port_str = host_part.rsplit(':', 1)
        if port_str.isdigit():
            port = int(port_str)
            base_domain = host
        else:
            base_domain = host_part
    else:
        base_domain = host_part

    return base_domain, port, protocols


def _normalize_text(text: str) -> str:
    '''Collapse all runs of whitespace (including newlines) into single spaces and strip.'''

    if not text:
        return ''
    return _WS_RE.sub(' ', text).strip()


def parse_title(html: str, content_type: str = None) -> str:
    '''
    Extract the page title as a single line, max TITLE_MAX_CHARS.

    :param html: HTML content
    :param content_type: Content-Type header value (used to skip non-HTML)
    '''

    if content_type and not any(x in content_type.lower() for x in ('text/html', 'application/xhtml')):
        return None

    try:
        soup = bs4.BeautifulSoup(html, 'html.parser')
        if soup.title and soup.title.string:
            title = _normalize_text(soup.title.string)
            return title[:TITLE_MAX_CHARS] if title else None
    except Exception as e:
        debug(f'Error parsing title: {e}')

    return None


def body_preview(raw_bytes: bytes, encoding: str = 'utf-8') -> str:
    '''
    Decode the first BODY_PREVIEW_BYTES bytes of the raw body, normalize whitespace.

    :param raw_bytes: raw response body
    :param encoding: encoding to attempt for decoding
    '''

    if not raw_bytes:
        return None
    chunk = raw_bytes[:BODY_PREVIEW_BYTES]
    try:
        text = chunk.decode(encoding, errors='replace')
    except Exception:
        text = chunk.decode('utf-8', errors='replace')
    text = _normalize_text(text)
    return text or None


def body_clean(html: str) -> str:
    '''
    Strip HTML/script/style, normalize whitespace, return first BODY_CLEAN_CHARS chars.

    :param html: HTML content
    '''

    if not html:
        return None
    try:
        soup = bs4.BeautifulSoup(html, 'html.parser')
        for tag in soup(('script', 'style', 'noscript')):
            tag.decompose()
        text = soup.get_text(separator=' ')
    except Exception as e:
        debug(f'Error cleaning body: {e}')
        return None
    text = _normalize_text(text)
    if not text:
        return None
    return text[:BODY_CLEAN_CHARS]


def parse_cert(ssl_object) -> dict:
    '''
    Parse a TLS certificate from a live ssl_object captured on the connected socket.

    :param ssl_object: SSLObject from the live connection (via TraceConfig hook)
    '''

    try:
        if ssl_object is None:
            return None
        cert_der = ssl_object.getpeercert(binary_form=True)
        if not cert_der:
            return None

        cert = x509.load_der_x509_certificate(cert_der)

        try:
            san_ext   = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            alt_names = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            alt_names = []

        def _attr(subject_or_issuer, oid):
            attrs = subject_or_issuer.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None

        common_name = _attr(cert.subject, NameOID.COMMON_NAME)
        issuer      = _attr(cert.issuer,  NameOID.COMMON_NAME)

        # Email: prefer subject EMAIL_ADDRESS attribute, fall back to rfc822Name in SANs.
        email = _attr(cert.subject, NameOID.EMAIL_ADDRESS)
        if not email:
            try:
                rfc822 = san_ext.value.get_values_for_type(x509.RFC822Name)
                if rfc822:
                    email = rfc822[0]
            except Exception:
                pass

        not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
        not_after  = getattr(cert, 'not_valid_after_utc',  None) or cert.not_valid_after

        return {
            'fingerprint' : cert.fingerprint(hashes.SHA256()).hex(),
            'subject'     : common_name,
            'issuer'      : issuer,
            'email'       : email,
            'alt_names'   : alt_names,
            'not_before'  : not_before.isoformat(),
            'not_after'   : not_after.isoformat(),
        }
    except Exception as e:
        debug(f'Error parsing cert: {e}')
        return None


async def get_favicon_hash(session, base_url: str, html: str, max_bytes: int = DEFAULT_FAVICON_BYTES, timeout: float = 5.0) -> str:
    '''
    Fetch the favicon (capped to max_bytes) and return its mmh3 64-bit hash as a string.

    :param session: aiohttp ClientSession
    :param base_url: base URL of the page (scheme + host)
    :param html: HTML content (used to discover <link rel="icon">)
    :param max_bytes: maximum number of bytes to read from the favicon URL
    :param timeout: request timeout in seconds
    '''

    try:
        favicon_url = None
        try:
            soup = bs4.BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('link'):
                rels = link.get('rel') or []
                if any(r.lower() == 'icon' for r in rels):
                    favicon_url = link.get('href')
                    break
        except Exception:
            pass

        if not favicon_url:
            favicon_url = '/favicon.ico'

        favicon_url = urllib.parse.urljoin(base_url, favicon_url)

        try:
            import aiohttp
            client_timeout = aiohttp.ClientTimeout(total=timeout)
        except ImportError:
            client_timeout = timeout

        async with session.get(favicon_url, timeout=client_timeout, ssl=False) as response:
            if response.status != 200:
                return None
            content = b''
            async for chunk in response.content.iter_chunked(8192):
                content += chunk
                if len(content) >= max_bytes:
                    content = content[:max_bytes]
                    break
            if not content:
                return None
            hash_value = mmh3.hash64(content)[0]
            return str(hash_value) if hash_value != 0 else None

    except Exception as e:
        debug(f'Error getting favicon for {base_url}: {e}')
        return None


def parse_status_codes(codes_str: str) -> set:
    '''
    Parse comma-separated status codes and ranges into a set of ints.

    :param codes_str: e.g. "200,301-399,404,500-503"
    '''

    codes = set()
    try:
        for part in codes_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                codes.update(range(start, end + 1))
            else:
                codes.add(int(part))
        return codes
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid status code format. Use comma-separated numbers or ranges (e.g., 200,301-399,404,500-503)')


def parse_shard(shard_str: str) -> tuple:
    '''
    Parse a shard argument in the form "INDEX/TOTAL" (1-based index).

    :param shard_str: shard string "INDEX/TOTAL"
    '''

    try:
        shard_index, total_shards = map(int, shard_str.split('/'))
        if shard_index < 1 or total_shards < 1 or shard_index > total_shards:
            raise ValueError
        return shard_index - 1, total_shards
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('Shard must be in format INDEX/TOTAL where INDEX <= TOTAL')
