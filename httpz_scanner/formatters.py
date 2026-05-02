#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/formatters.py

from .colors import Colors
from .utils  import human_size


def format_console_output(result: dict, debug: bool = False, show_fields: dict = None, match_codes: set = None, exclude_codes: set = None) -> str:
    '''
    Format a result dict into a colored single-line console string.

    :param result: result dict from HTTPZScanner
    :param debug: include error rows when True
    :param show_fields: dict toggling which fields to render
    :param match_codes: only render rows whose status is in this set
    :param exclude_codes: skip rows whose status is in this set
    '''

    if result['status'] < 0 and not debug:
        return ''

    if match_codes and result['status'] not in match_codes:
        return ''
    if exclude_codes and result['status'] in exclude_codes:
        return ''

    show_fields = show_fields or {}
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

    # URL / domain
    parts.append(f"[{result.get('url') or result.get('domain')}]")

    # Error (when debug)
    if result['status'] < 0 and result.get('error'):
        parts.append(f"{Colors.RED}[{result.get('error_type','')}: {result['error']}]{Colors.RESET}")

    if show_fields.get('content_type') and result.get('content_type'):
        parts.append(f"{Colors.CYAN}[{result['content_type']}]{Colors.RESET}")

    if show_fields.get('content_length') and result.get('content_length') is not None:
        try:
            size = human_size(int(result['content_length']))
            parts.append(f"{Colors.PINK}[{size}]{Colors.RESET}")
        except (ValueError, TypeError):
            parts.append(f"{Colors.PINK}[{result['content_length']}]{Colors.RESET}")

    if show_fields.get('title') and result.get('title'):
        parts.append(f"{Colors.DARK_GREEN}[{result['title']}]{Colors.RESET}")

    if show_fields.get('body'):
        if result.get('body_clean'):
            preview = result['body_clean'][:100] + ('...' if len(result['body_clean']) > 100 else '')
            parts.append(f"{Colors.BLUE}[{preview}]{Colors.RESET}")
        elif result.get('body_preview'):
            preview = result['body_preview'][:100] + ('...' if len(result['body_preview']) > 100 else '')
            parts.append(f"{Colors.BLUE}[{preview}]{Colors.RESET}")

    if show_fields.get('cname') and result.get('cname_chain'):
        parts.append(f"{Colors.PURPLE}[CNAME: {' -> '.join(result['cname_chain'])}]{Colors.RESET}")

    if show_fields.get('ip') and result.get('ips'):
        parts.append(f"{Colors.YELLOW}[{', '.join(result['ips'])}]{Colors.RESET}")

    if show_fields.get('favicon') and result.get('favicon_hash'):
        parts.append(f"{Colors.PURPLE}[{result['favicon_hash']}]{Colors.RESET}")

    if show_fields.get('headers') and result.get('response_headers'):
        headers_text = ', '.join(f'{k}: {v}' for k, v in result['response_headers'].items())
        parts.append(f"{Colors.CYAN}[{headers_text}]{Colors.RESET}")

    if show_fields.get('follow_redirects') and result.get('redirect_chain'):
        chain = ' -> '.join(result['redirect_chain'])
        parts.append(f"{Colors.YELLOW}[Redirects: {chain}]{Colors.RESET}")

    if show_fields.get('tls') and result.get('tls'):
        cert = result['tls']
        tls_parts = []
        if cert.get('subject'):
            tls_parts.append(f"Subject: {cert['subject']}")
        if cert.get('issuer'):
            tls_parts.append(f"Issuer: {cert['issuer']}")
        if cert.get('email'):
            tls_parts.append(f"Email: {cert['email']}")
        if cert.get('fingerprint'):
            tls_parts.append(f"Fingerprint: {cert['fingerprint'][:16]}...")
        if cert.get('alt_names'):
            tls_parts.append(f"SANs: {', '.join(cert['alt_names'][:3])}")
        if cert.get('not_before') and cert.get('not_after'):
            tls_parts.append(f"Valid: {cert['not_before'].split('T')[0]} to {cert['not_after'].split('T')[0]}")
        if tls_parts:
            parts.append(f"{Colors.GREEN}[{' | '.join(tls_parts)}]{Colors.RESET}")

    return ' '.join(parts)
