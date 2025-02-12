#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/cli.py

import argparse
import asyncio
import logging
import os
import sys
import json

from .colors     import Colors
from .scanner    import HTTPZScanner
from .utils      import SILENT_MODE, info
from .parsers    import parse_status_codes, parse_shard
from .formatters import format_console_output

def setup_logging(level='INFO', log_to_disk=False):
    '''
    Setup logging configuration
    
    :param level: Logging level (INFO or DEBUG)
    :param log_to_disk: Whether to also log to file
    '''
    class ColoredFormatter(logging.Formatter):
        def formatTime(self, record, datefmt=None):
            # Format: MM-DD HH:MM
            from datetime import datetime
            dt = datetime.fromtimestamp(record.created)
            return f"{Colors.GRAY}{dt.strftime('%m-%d %H:%M')}{Colors.RESET}"
        
        def format(self, record):
            return f'{self.formatTime(record)} {record.getMessage()}'
    
    handlers = []
    
    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(ColoredFormatter())
    handlers.append(console)
    
    # File handler
    if log_to_disk:
        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler(f'logs/httpz.log')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handlers.append(file_handler)
    
    # Setup logger
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        handlers=handlers
    )

async def main():
    parser = argparse.ArgumentParser(
        description=f'{Colors.GREEN}Hyper-fast HTTP Scraping Tool{Colors.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Add arguments
    parser.add_argument('file', nargs='?', default='-', help='File containing domains to check (one per line), use - for stdin')
    parser.add_argument('-all', '--all-flags', action='store_true', help='Enable all output flags')
    parser.add_argument('-d', '--debug', action='store_true', help='Show error states and debug information')
    parser.add_argument('-c', '--concurrent', type=int, default=100, help='Number of concurrent checks')
    parser.add_argument('-j', '--jsonl', action='store_true', help='Output JSON Lines format to console')
    parser.add_argument('-o', '--output', help='Output file path (JSONL format)')
    
    # Output field flags
    parser.add_argument('-b', '--body', action='store_true', help='Show body preview')
    parser.add_argument('-cn', '--cname', action='store_true', help='Show CNAME records')
    parser.add_argument('-cl', '--content-length', action='store_true', help='Show content length')
    parser.add_argument('-ct', '--content-type', action='store_true', help='Show content type')
    parser.add_argument('-f', '--favicon', action='store_true', help='Show favicon hash')
    parser.add_argument('-fr', '--follow-redirects', action='store_true', help='Follow redirects (max 10)')
    parser.add_argument('-hr', '--headers', action='store_true', help='Show response headers')
    parser.add_argument('-i', '--ip', action='store_true', help='Show IP addresses')
    parser.add_argument('-sc', '--status-code', action='store_true', help='Show status code')
    parser.add_argument('-ti', '--title', action='store_true', help='Show page title')
    parser.add_argument('-tls', '--tls-info', action='store_true', help='Show TLS certificate information')
    
    # Other arguments
    parser.add_argument('-ax', '--axfr', action='store_true', help='Try AXFR transfer against nameservers')
    parser.add_argument('-ec', '--exclude-codes', type=parse_status_codes, help='Exclude these status codes (comma-separated, e.g., 404,500)')
    parser.add_argument('-mc', '--match-codes', type=parse_status_codes, help='Only show these status codes (comma-separated, e.g., 200,301,404)')
    parser.add_argument('-p', '--progress', action='store_true', help='Show progress counter')
    parser.add_argument('-r', '--resolvers', help='File containing DNS resolvers (one per line)')
    parser.add_argument('-to', '--timeout', type=int, default=5, help='Request timeout in seconds')
    
    # Add shard argument
    parser.add_argument('-sh','--shard', type=parse_shard, help='Shard index and total shards (e.g., 1/3)')
    
    # If no arguments provided, print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()

    # Setup logging based on arguments
    global SILENT_MODE
    SILENT_MODE = args.jsonl

    if not SILENT_MODE:
        if args.debug:
            setup_logging(level='DEBUG', log_to_disk=True)
        else:
            setup_logging(level='INFO')

        if args.file == '-':
            info('Reading domains from stdin')
        else:
            info(f'Processing file: {args.file}')

    # Setup show_fields
    show_fields = {
        'status_code'      : args.all_flags or args.status_code,
        'content_type'     : args.all_flags or args.content_type,
        'content_length'   : args.all_flags or args.content_length,
        'title'            : args.all_flags or args.title,
        'body'             : args.all_flags or args.body,
        'ip'               : args.all_flags or args.ip,
        'favicon'          : args.all_flags or args.favicon,
        'headers'          : args.all_flags or args.headers,
        'follow_redirects' : args.all_flags or args.follow_redirects,
        'cname'            : args.all_flags or args.cname,
        'tls'              : args.all_flags or args.tls_info
    }

    # If no fields specified show all
    if not any(show_fields.values()):
        show_fields = {k: True for k in show_fields}

    try:
        scanner = HTTPZScanner(
            concurrent_limit=args.concurrent,
            timeout=args.timeout,
            follow_redirects=args.all_flags or args.follow_redirects,
            check_axfr=args.axfr,
            resolver_file=args.resolvers,
            output_file=args.output,
            show_progress=args.progress,
            debug_mode=args.debug,
            jsonl_output=args.jsonl,
            show_fields=show_fields,
            match_codes=args.match_codes,
            exclude_codes=args.exclude_codes,
            shard=args.shard
        )

        # Run the scanner and handle ALL output here
        count = 0
        async for result in scanner.scan(args.file):
            # Write to output file if specified
            if args.output:
                with open(args.output, 'a') as f:
                    f.write(json.dumps(result) + '\n')
            
            # Console output
            if args.progress:
                count += 1
                info(f"[{count}] {format_console_output(result, args.debug, show_fields, args.match_codes, args.exclude_codes)}")
            else:
                if args.jsonl:
                    print(json.dumps(result))
                else:
                    print(format_console_output(result, args.debug, show_fields, args.match_codes, args.exclude_codes))

    except KeyboardInterrupt:
        logging.warning('Process interrupted by user')
        sys.exit(1)
    except Exception as e:
        logging.error(f'Unexpected error: {str(e)}')
        sys.exit(1)

def run():
    '''Entry point for the CLI'''
    asyncio.run(main())

if __name__ == '__main__':
    run() 