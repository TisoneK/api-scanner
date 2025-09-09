"""
API Scanner - A Python package for capturing and analyzing API requests.

This package provides a mitmproxy-based tool for intercepting, analyzing, and logging
API requests and responses. It can be used both as a command-line tool and as a library.

Example usage:
    >>> from api_scanner import ApiSniffer, start
    >>> sniffer = ApiSniffer()
    >>> # Run the proxy server
    >>> import asyncio
    >>> asyncio.run(start(sniffer, host="127.0.0.1", port=8080))
    >>> # Access captured API calls
    >>> for call in sniffer.api_calls:
    ...     print(f"{call.request.method} {call.request.url}")
"""

from .core import ApiSniffer
from .cli import main, start
from .config import (
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL, MAX_CONTENT_LENGTH,
    EXCLUDED_EXTENSIONS, EXCLUDED_PATHS, FILTER_KEYWORDS
)
from .models import ApiCall, RequestData, ResponseData

__version__ = "0.2.0"
__all__ = [
    # Main classes
    'ApiSniffer',
    'ApiCall', 'RequestData', 'ResponseData',
    
    # Functions
    'main', 'start',
    
    # Configuration
    'OUTPUT_FILE', 'OUTPUT_DIR', 'MAX_CONTENT_LENGTH', 'LOG_LEVEL',
    'PROXY_HOST', 'PROXY_PORT', 'SSL_VERIFY',
    'EXCLUDED_EXTENSIONS', 'EXCLUDED_PATHS', 'FILTER_KEYWORDS'
]
