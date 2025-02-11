#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz/__main__.py

import asyncio
import sys
from .cli import main

def cli():
    """Entry point for the command line interface"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(1)

# This allows both 'python -m httpz' and the 'httpz' command to work
if __name__ == '__main__':
    cli() 