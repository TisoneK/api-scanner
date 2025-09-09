"""
Filter configurations for the API Scanner.
"""
import os
import logging
from typing import List, Set

def load_filter_keywords(filter_file: str) -> Set[str]:
    """Load filter keywords from a file."""
    default_keywords = {"api", "v1", "v2", "rest", "graphql", "soap"}
    
    if not os.path.exists(filter_file):
        logging.warning(f"Filter file not found at {filter_file}, using default keywords")
        return default_keywords
    
    try:
        with open(filter_file, 'r') as f:
            keywords = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            return keywords if keywords else default_keywords
    except Exception as e:
        logging.error(f"Error loading filter file {filter_file}: {e}")
        return default_keywords

# Default filter values
EXCLUDED_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3",
    ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z"
}

EXCLUDED_PATHS = {
    "/static/", "/assets/", "/public/", "/resources/",
    "/images/", "/img/", "/css/", "/js/", "/fonts/",
    "/vendor/", "/node_modules/", "/bower_components/"
}

# Load filter keywords from file
FILTER_KEYWORDS = load_filter_keywords(os.path.join(os.path.dirname(__file__), "filter.txt"))

# Export filter settings
__all__ = [
    'EXCLUDED_EXTENSIONS',
    'EXCLUDED_PATHS',
    'FILTER_KEYWORDS',
    'load_filter_keywords'
]
