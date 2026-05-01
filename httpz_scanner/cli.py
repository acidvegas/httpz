#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/cli.py

import argparse
import asyncio
import json
import logging
import os
import sys

from datetime import datetime

from . import utils
from .colors     import Colors
from .formatters import format_console_output
from .parsers    import parse_status_codes, parse_shard, DEFAULT_FAVICON_BYTES
from .scanner    import HTTPZScanner
from .utils      import info


def setup_logging(level='INFO', log_to_disk=False):
    '''
    Setup logging configuration.

    :param level: logging level (INFO or DEBUG)
    :param log_to_disk: also log to logs/httpz.log
    '''

    class ColoredFormatter(logging.Formatter):
        def formatTime(self, record):
            dt = datetime.fromtimestamp(record.created)
            return f'{Colors.GRAY}{dt.strftime("%m-%d %H:%M")}{Colors.RESET}'

        def format(self, record):
            return f'{self.formatTime(record)} {record.getMessage()}'

    handlers = []
    console = logging.StreamHandler()
    console.setFormatter(ColoredFormatter())
    handlers.append(console)

    if log_to_disk:
        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler('logs/httpz.log')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handlers.append(file_handler)

    logging.basicConfig(level=getattr(logging, level.upper()), handlers=handlers)


async def main():
    parser = argparse.ArgumentParser(description=f'{Colors.GREEN}Hyper-fast HTTP Scraping Tool{Colors.RESET}', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('file', nargs='?', default='-', help='File of domains (one per line), or - for stdin')
    parser.add_argument('-all', '--all-flags', action='store_true', help='Enable all output fields')
    parser.add_argument('-d',   '--debug', action='store_true', help='Show error states and debug information')
    parser.add_argument('-c',   '--concurrent', type=int, default=100, help='Concurrent in-flight checks')
    parser.add_argument('-j',   '--jsonl', action='store_true', help='Output JSONL to stdout')
    parser.add_argument('-o',   '--output', help='Output file path (JSONL)')

    # Output field flags
    parser.add_argument('-b',   '--body', action='store_true', help='Include body_preview/body_clean')
    parser.add_argument('-cl',  '--content-length', action='store_true', help='Include content_length')
    parser.add_argument('-ct',  '--content-type', action='store_true', help='Include content_type')
    parser.add_argument('-f',   '--favicon', action='store_true', help='Include favicon hash')
    parser.add_argument('-fr',  '--follow-redirects', action='store_true', help=f'Follow redirects (max {10})')
    parser.add_argument('-hr',  '--show-headers', action='store_true', help='Include response headers')
    parser.add_argument('-i',   '--ip', action='store_true', help='Include resolved A/AAAA IPs')
    parser.add_argument('-sc',  '--status-code', action='store_true', help='Show status code')
    parser.add_argument('-ti',  '--title', action='store_true', help='Include page title')
    parser.add_argument('-tls', '--tls-info', action='store_true', help='Include TLS certificate info')

    # Tunables
    parser.add_argument('-rt', '--retries', type=int, default=1, help='Retry attempts per protocol on transient errors')
    parser.add_argument('-rb', '--retry-backoff', type=float, default=0.5, help='Linear backoff base seconds between retries')
    parser.add_argument('-mb', '--max-body-size', type=int, default=1024*1024, help='Max body bytes to read')
    parser.add_argument('-fm', '--favicon-max-size', type=int, default=DEFAULT_FAVICON_BYTES, help='Max favicon bytes to read')

    # Filters / misc
    parser.add_argument('-ec', '--exclude-codes', type=parse_status_codes, help='Exclude these status codes (e.g., 404,500)')
    parser.add_argument('-mc', '--match-codes', type=parse_status_codes, help='Only show these status codes (e.g., 200,301,404)')
    parser.add_argument('-p',  '--progress', action='store_true', help='Show progress counter')
    parser.add_argument('-pd', '--post-data', help='Send POST request with this data')
    parser.add_argument('-r',  '--resolvers', help='File of DNS resolvers (one per line) for IP lookups')
    parser.add_argument('-to', '--timeout', type=int, default=5, help='Request timeout in seconds')
    parser.add_argument('-dt', '--dns-timeout', type=float, default=2.0, help='DNS query timeout in seconds')

    parser.add_argument('-sh', '--shard', type=parse_shard, help='Shard index/total (e.g., 1/3)')
    parser.add_argument('-hd', '--headers', help='Custom headers ("H1: v1,H2: v2")')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # SILENT_MODE controls library log helpers; mutate the module attribute, not a local global.
    utils.SILENT_MODE = args.jsonl

    if not utils.SILENT_MODE:
        if args.debug:
            setup_logging(level='DEBUG', log_to_disk=True)
        else:
            setup_logging(level='INFO')

        if args.file == '-':
            info('Reading domains from stdin')
        else:
            info(f'Processing file: {args.file}')

    show_fields = {
        'status_code'      : args.all_flags or args.status_code,
        'content_type'     : args.all_flags or args.content_type,
        'content_length'   : args.all_flags or args.content_length,
        'title'            : args.all_flags or args.title,
        'body'             : args.all_flags or args.body,
        'ip'               : args.all_flags or args.ip,
        'favicon'          : args.all_flags or args.favicon,
        'headers'          : args.all_flags or args.show_headers,
        'follow_redirects' : args.all_flags or args.follow_redirects,
        'tls'              : args.all_flags or args.tls_info,
    }
    if not any(show_fields.values()):
        show_fields = {k: True for k in show_fields}

    resolvers = None
    if args.resolvers:
        try:
            with open(args.resolvers) as f:
                resolvers = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f'Failed to load resolvers from {args.resolvers}: {e}')
            sys.exit(1)

    custom_headers = None
    if args.headers:
        custom_headers = dict(h.split(': ', 1) for h in args.headers.split(','))

    out_fh = open(args.output, 'a', buffering=1) if args.output else None
    try:
        scanner = HTTPZScanner(
            concurrent_limit     = args.concurrent,
            timeout              = args.timeout,
            retries              = args.retries,
            retry_backoff        = args.retry_backoff,
            follow_redirects     = args.all_flags or args.follow_redirects,
            max_body_size        = args.max_body_size,
            favicon_max_size     = args.favicon_max_size,
            fetch_headers        = show_fields['headers'],
            fetch_content_type   = show_fields['content_type'],
            fetch_content_length = show_fields['content_length'],
            fetch_title          = show_fields['title'],
            fetch_body           = show_fields['body'],
            fetch_favicon        = show_fields['favicon'],
            fetch_tls            = show_fields['tls'],
            fetch_ips            = show_fields['ip'],
            match_codes          = args.match_codes,
            exclude_codes        = args.exclude_codes,
            custom_headers       = custom_headers,
            post_data            = args.post_data,
            shard                = args.shard,
            resolvers            = resolvers,
            dns_timeout          = args.dns_timeout,
        )

        count = 0
        async for result in scanner.scan(args.file):
            if out_fh is not None:
                out_fh.write(json.dumps(result) + '\n')

            if args.jsonl:
                print(json.dumps(result), flush=True)
                continue

            formatted = format_console_output(result, args.debug, show_fields, args.match_codes, args.exclude_codes)
            if formatted:
                if args.progress:
                    count += 1
                    info(f'[{count}] {formatted}')
                    sys.stdout.flush()
                else:
                    print(formatted, flush=True)

    except KeyboardInterrupt:
        logging.warning('Process interrupted by user')
        sys.exit(1)
    except Exception as e:
        logging.error(f'Unexpected error: {e}')
        sys.exit(1)
    finally:
        if out_fh is not None:
            out_fh.close()


def run():
    '''Entry point for the CLI'''
    asyncio.run(main())


if __name__ == '__main__':
    run()
