#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/parsers.py

try:
    import bs4
except ImportError:
    raise ImportError('missing bs4 module (pip install beautifulsoup4)')

try:
    from cryptography                   import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid          import NameOID
except ImportError:
    raise ImportError('missing cryptography module (pip install cryptography)')

try:
    import mmh3
except ImportError:
    raise ImportError('missing mmh3 module (pip install mmh3)')

from .utils import debug, error
import argparse


def parse_domain_url(domain: str) -> tuple:
    '''
    Parse domain string into base domain, port, and protocol list
    
    :param domain: Raw domain string to parse
    '''

    port = None
    base_domain = domain.rstrip('/')
    
    if base_domain.startswith(('http://', 'https://')):
        protocol = 'https://' if base_domain.startswith('https://') else 'http://'
        base_domain = base_domain.split('://', 1)[1]
        if ':' in base_domain.split('/')[0]:
            base_domain, port_str = base_domain.split(':', 1)
            try:
                port = int(port_str.split('/')[0])
            except ValueError:
                port = 443 if protocol == 'https://' else 80
        else:
            port = 443 if protocol == 'https://' else 80
        protocols = [f'{protocol}{base_domain}{":" + str(port) if port else ""}']
    else:
        if ':' in base_domain.split('/')[0]:
            base_domain, port_str = base_domain.split(':', 1)
            port = int(port_str.split('/')[0]) if port_str.split('/')[0].isdigit() else 443
        else:
            port = 443
        protocols = [
            f'https://{base_domain}{":" + str(port) if port else ""}',
            f'http://{base_domain}{":"  + str(port) if port else ""}'
        ]
    
    return base_domain, port, protocols


async def get_cert_info(ssl_object, url: str) -> dict:
    '''
    Get SSL certificate information for a domain
    
    :param ssl_object: SSL object to get certificate info from
    :param url: URL to get certificate info from
    '''

    try:            
        if not ssl_object or not (cert_der := ssl_object.getpeercert(binary_form=True)):
            return None

        cert = x509.load_der_x509_certificate(cert_der)

        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            alt_names     = [name.value for name in san_extension.value] if san_extension else []
        except x509.extensions.ExtensionNotFound:
            alt_names = []

        try:
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            common_name = None

        try:
            issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer = None

        return {
            'fingerprint'   : cert.fingerprint(hashes.SHA256()).hex(),
            'common_name'   : common_name,
            'issuer'        : issuer,
            'alt_names'     : alt_names,
            'not_before'    : cert.not_valid_before_utc.isoformat(),
            'not_after'     : cert.not_valid_after_utc.isoformat(),
            'version'       : cert.version.value,
            'serial_number' : format(cert.serial_number, 'x'),
        }
    except Exception as e:
        error(f'Error getting cert info for {url}: {str(e)}')
        return None


async def get_favicon_hash(session, base_url: str, html: str) -> str:
    '''
    Get favicon hash from a webpage
    
    :param session: aiohttp client session
    :param base_url: base URL of the website
    :param html: HTML content of the page
    '''

    try:
        soup = bs4.BeautifulSoup(html, 'html.parser')
        
        favicon_url = None
        for link in soup.find_all('link'):
            if link.get('rel') and any(x.lower() == 'icon' for x in link.get('rel')):
                favicon_url = link.get('href')
                break
        
        if not favicon_url:
            favicon_url = '/favicon.ico'
        
        if favicon_url.startswith('//'):
            favicon_url = 'https:' + favicon_url
        elif favicon_url.startswith('/'):
            favicon_url = base_url + favicon_url
        elif not favicon_url.startswith(('http://', 'https://')):
            favicon_url = base_url + '/' + favicon_url

        async with session.get(favicon_url, timeout=10) as response:
            if response.status == 200:
                content    = (await response.read())[:1024*1024]
                hash_value = mmh3.hash64(content)[0]
                if hash_value != 0:
                    return str(hash_value)

    except Exception as e:
        debug(f'Error getting favicon for {base_url}: {str(e)}')
    
    return None 


def parse_status_codes(codes_str: str) -> set:
    '''
    Parse comma-separated status codes and ranges into a set of integers
    
    :param codes_str: Comma-separated status codes (e.g., "200,301-399,404,500-503")
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
    Parse shard argument in format INDEX/TOTAL
    
    :param shard_str: Shard string in format "INDEX/TOTAL"
    '''

    try:
        shard_index, total_shards = map(int, shard_str.split('/'))
        if shard_index < 1 or total_shards < 1 or shard_index > total_shards:
            raise ValueError
        return shard_index - 1, total_shards  # Convert to 0-based index
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('Shard must be in format INDEX/TOTAL where INDEX <= TOTAL') 


def parse_title(html: str, content_type: str = None) -> str:
    '''
    Parse title from HTML content
    
    :param html: HTML content of the page
    :param content_type: Content-Type header value
    '''
    
    # Only parse title for HTML content
    if content_type and not any(x in content_type.lower() for x in ['text/html', 'application/xhtml']):
        return None
        
    try:
        soup = bs4.BeautifulSoup(html, 'html.parser', from_encoding='utf-8', features='lxml')
        if title := soup.title:
            return title.string.strip()
    except:
        pass
    
    return None 