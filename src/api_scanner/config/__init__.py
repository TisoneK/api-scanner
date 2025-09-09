"""
Configuration module for API Scanner.
"""
from .config import (
    load_config, config,
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_DIR, OUTPUT_FILE, LOG_LEVEL
)
from .filters import (
    EXCLUDED_EXTENSIONS, EXCLUDED_PATHS, FILTER_KEYWORDS,
    load_filter_keywords
)

# For backward compatibility
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

__all__ = [
    # From config.py
    'load_config', 'config',
    'PROXY_HOST', 'PROXY_PORT', 'SSL_VERIFY',
    'OUTPUT_DIR', 'OUTPUT_FILE', 'LOG_LEVEL',
    'MAX_CONTENT_LENGTH',
    
    # From filters.py
    'EXCLUDED_EXTENSIONS', 'EXCLUDED_PATHS', 'FILTER_KEYWORDS',
    'load_filter_keywords'
]
