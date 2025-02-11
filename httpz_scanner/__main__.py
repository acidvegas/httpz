#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz_scanner/__main__.py

import asyncio
import sys
from .cli import main

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(1) 