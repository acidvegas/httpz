#!/usr/bin/env python3
# Hyperfast Scalable HTTP Scanner - Developed by acidvegas (https://github.com/acidvegas)

import logging

try:
    from bs4 import BeautifulSoup
except ImportError:
    raise ImportError('missing BeautifulSoup library (pip install beautifulsoup4)')

try:
    import mmh3
except ImportError:
    raise ImportError('missing mmh3 library (pip install mmh3)')


async def get_favicon_hash(session, soup, base_url, timeout):
    '''
    Extract and hash favicon from HTML
    
    :param session: aiohttp client session
    :param soup: BeautifulSoup object
    :param base_url: Base URL of the domain
    :param timeout: Request timeout in seconds
    '''
    
    try:
        # Find favicon URL from HTML
        favicon_url = None
        for link in soup.find_all('link', rel=True):
            if any(x in link.get('rel', []) for x in ['icon', 'shortcut icon', 'apple-touch-icon']):
                if href := link.get('href'):
                    favicon_url = href
                    break
        
        if favicon_url:
            # Handle relative URLs
            if not favicon_url.startswith(('http://', 'https://')):
                favicon_url = f"{'/'.join(base_url.rstrip('/').split('/')[:-1])}/{favicon_url.lstrip('/')}"
            
            # Fetch and hash the favicon
            async with session.get(favicon_url, timeout=timeout) as favicon_resp:
                if favicon_resp.status == 200:
                    favicon_bytes = (await favicon_resp.read())[:1024*1024]
                    return str(mmh3.hash(favicon_bytes))
    except Exception as e:
        logging.debug(f'Failed to get favicon hash for {base_url}: {str(e)}')
    
    return '' 