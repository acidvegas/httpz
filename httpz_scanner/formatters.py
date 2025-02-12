#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/formatters.py

from .colors import Colors
from .utils  import human_size


def format_console_output(result: dict, debug: bool = False, show_fields: dict = None, match_codes: set = None, exclude_codes: set = None) -> str:
    '''
    Format the output with colored sections
    
    :param result: Dictionary containing domain check results
    :param debug: Whether to show error states
    :param show_fields: Dictionary of fields to show
    :param match_codes: Set of status codes to match
    :param exclude_codes: Set of status codes to exclude
    '''
    if result['status'] < 0 and not debug:
        return ''
        
    if match_codes and result['status'] not in match_codes:
        return ''
    if exclude_codes and result['status'] in exclude_codes:
        return ''

    parts = []
    
    # Status code
    if show_fields.get('status_code'):
        if result['status'] < 0:
            status = f"{Colors.RED}[{result['status']}]{Colors.RESET}"
        elif 200 <= result['status'] < 300:
            status = f"{Colors.GREEN}[{result['status']}]{Colors.RESET}"
        elif 300 <= result['status'] < 400:
            status = f"{Colors.YELLOW}[{result['status']}]{Colors.RESET}"
        else:
            status = f"{Colors.RED}[{result['status']}]{Colors.RESET}"
        parts.append(status)
    
    # Domain (always shown)
    parts.append(f"[{result['url']}]")
    
    # Title
    if show_fields.get('title') and result.get('title'):
        parts.append(f"{Colors.DARK_GREEN}[{result['title']}]{Colors.RESET}")
    
    # Body preview
    if show_fields.get('body') and result.get('body'):
        body = result['body'][:100] + ('...' if len(result['body']) > 100 else '')
        parts.append(f"{Colors.BLUE}[{body}]{Colors.RESET}")
    
    # IPs
    if show_fields.get('ip') and result.get('ips'):
        ips_text = ', '.join(result['ips'])
        parts.append(f"{Colors.YELLOW}[{ips_text}]{Colors.RESET}")

    # Favicon hash
    if show_fields.get('favicon') and result.get('favicon_hash'):
        parts.append(f"{Colors.PURPLE}[{result['favicon_hash']}]{Colors.RESET}")

    # Headers
    if show_fields.get('headers') and result.get('headers'):
        headers_text = [f"{k}: {v}" for k, v in result['headers'].items()]
        parts.append(f"{Colors.CYAN}[{', '.join(headers_text)}]{Colors.RESET}")
    else:
        if show_fields.get('content_type') and result.get('content_type'):
            parts.append(f"{Colors.HEADER}[{result['content_type']}]{Colors.RESET}")
        
        if show_fields.get('content_length') and result.get('content_length'):
            try:
                size = human_size(int(result['content_length']))
                parts.append(f"{Colors.PINK}[{size}]{Colors.RESET}")
            except (ValueError, TypeError):
                parts.append(f"{Colors.PINK}[{result['content_length']}]{Colors.RESET}")
    
    # CNAME
    if show_fields.get('cname') and result.get('cname'):
        parts.append(f"{Colors.PURPLE}[CNAME: {result['cname']}]{Colors.RESET}")
    
    # Redirect Chain
    if show_fields.get('follow_redirects') and result.get('redirect_chain'):
        chain = ' -> '.join(result['redirect_chain'])
        parts.append(f"{Colors.YELLOW}[Redirects: {chain}]{Colors.RESET}")

    # TLS Certificate Info
    if result.get('tls'):
        cert = result['tls']
        tls_parts = []
        if cert.get('common_name'):
            tls_parts.append(f"Subject: {cert['common_name']}")
        if cert.get('issuer'):
            tls_parts.append(f"Issuer: {cert['issuer']}")
        if cert.get('fingerprint'):
            tls_parts.append(f"Fingerprint: {cert['fingerprint'][:16]}...")
        if cert.get('alt_names'):
            tls_parts.append(f"SANs: {', '.join(cert['alt_names'][:3])}")
        if cert.get('not_before') and cert.get('not_after'):
            tls_parts.append(f"Valid: {cert['not_before'].split('T')[0]} to {cert['not_after'].split('T')[0]}")
        if cert.get('version'):
            tls_parts.append(f"Version: {cert['version']}")
        if cert.get('serial_number'):
            tls_parts.append(f"Serial: {cert['serial_number'][:16]}...")
        
        if tls_parts:  # Only add TLS info if we have any parts
            parts.append(f"{Colors.GREEN}[{' | '.join(tls_parts)}]{Colors.RESET}")

    return ' '.join(parts) 