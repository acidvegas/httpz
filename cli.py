#!/usr/bin/env python3
# Hyperfast Scalable HTTP Scanner - Developed by acidvegas (https://github.com/acidvegas)

import argparse
import asyncio
import sys

from scanner import HTTPScanner
from utils   import read_domains


def main():
    '''Main function for the CLI'''

    # Create argument parser
    parser = argparse.ArgumentParser(description='Scalable HTTP Scanner', formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('domain', nargs='?', help='Single domain to check (e.g., example.com)')
    input_group.add_argument('-f', '--file', help='Read domains from a file, one per line')
    input_group.add_argument('-c', '--concurrency', type=int, default=100, help='Maximum number of concurrent connections (default: 100)')
    
    # HTTP options
    http_group = parser.add_argument_group('HTTP Options')
    http_group.add_argument('-t', '--timeout', type=float, default=5, help='Request timeout in seconds (default: 5)')
    http_group.add_argument('--max-redirects', type=int, default=10, help='Maximum number of redirects to follow (default: 10)')
    http_group.add_argument('--user-agent', help='Custom User-Agent string')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-q', '--quiet', action='store_true', help='Only output the results, no errors')
    output_group.add_argument('-o', '--output', help='Write results to a JSONL file')
    output_group.add_argument('-j', '--json', action='store_true', help='Output JSONL format to console instead of colored text')

    # Parse arguments
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = HTTPScanner(args.concurrency, args.timeout, args.max_redirects, args.user_agent, args.quiet, args.json)

    try:
        # Scan domains
        if args.domain:
            asyncio.run(scanner.scan([args.domain], args.output))

        # Scan domains from file
        elif args.file:
            try:
                with open(args.file) as f:
                    asyncio.run(scanner.scan(read_domains(f), args.output))
            except FileNotFoundError:
                raise FileNotFoundError(f'File not found: {args.file}')

        # Scan domains from stdin
        elif not sys.stdin.isatty():
            asyncio.run(scanner.scan(read_domains(sys.stdin), args.output))

        # Print help if no arguments are provided
        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        sys.exit(0)



if __name__ == '__main__':
    main() 