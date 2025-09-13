"""
API Scanner - A Python package for capturing and analyzing API requests.

This package provides a mitmproxy-based tool for intercepting, analyzing, and logging
API requests and responses. It can be used both as a command-line tool and as a library.

Example usage:
    >>> from api_scanner import ApiSniffer
    >>> import asyncio
    >>> 
    >>> # Create and start the scanner
    >>> scanner = ApiSniffer(host="127.0.0.1", port=8080)
    >>> asyncio.run(scanner.start())
    >>> 
    >>> # Access captured API calls
    >>> for call in scanner.api_calls:
    ...     print(f"{call.request.method} {call.request.url} -> {call.response.status_code if call.response else 'No response'}")
"""

__version__ = '0.1.0'

# Initialize configuration
from .config import (
    load_config, config,
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL, MAX_CONTENT_LENGTH,
    EXCLUDED_EXTENSIONS, EXCLUDED_PATHS, FILTER_KEYWORDS,
    API_PATHS, CONTENT_TYPES, ACCEPT_HEADERS, ALLOWED_HOSTS
)

# Import core functionality
try:
    from .core import ApiSniffer
    from .cli import main
    from .models import ApiCall, RequestData, ResponseData
    
    __all__ = [
        # Main class
        'ApiSniffer',
        
        # Data models
        'ApiCall', 'RequestData', 'ResponseData',
        
        # CLI
        'main',
        
        # Configuration
        'OUTPUT_FILE', 'OUTPUT_DIR', 'LOG_LEVEL',
        'PROXY_HOST', 'PROXY_PORT', 'SSL_VERIFY',
        'EXCLUDED_EXTENSIONS', 'EXCLUDED_PATHS', 'FILTER_KEYWORDS',
        'API_PATHS', 'CONTENT_TYPES', 'ACCEPT_HEADERS', 'ALLOWED_HOSTS'
    ]
    
except ImportError as e:
    import logging
    logging.error(f"Failed to import API Scanner: {e}")
    __all__ = []
