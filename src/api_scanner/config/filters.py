"""
Filter configurations for the API Scanner.
"""
import os
import json
import logging
from typing import Dict, List, Set, Any

# Default filter values
DEFAULT_FILTERS = {
    "excluded_extensions": [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3",
        ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z"
    ],
    "excluded_paths": [
        "/static/", "/assets/", "/public/", "/resources/",
        "/images/", "/img/", "/css/", "/js/", "/fonts/",
        "/vendor/", "/node_modules/", "/bower_components/"
    ],
    "api_keywords": ["api", "v1", "v2", "rest", "graphql", "soap"],
    "content_types": ["application/json", "application/xml"],
    "accept_headers": ["application/json", "application/xml"]
}

def load_filter_config() -> Dict[str, Any]:
    """Load and combine configuration from both filter.txt and filter_rules.json."""
    config_dir = os.path.dirname(__file__)
    config = DEFAULT_FILTERS.copy()
    
    # 1. Load from filter.txt (required)
    txt_file = os.path.join(config_dir, "filter.txt")
    if not os.path.exists(txt_file):
        raise FileNotFoundError(f"Required file not found: {txt_file}")
    
    try:
        with open(txt_file, 'r') as f:
            patterns = [line.strip() for line in f 
                      if line.strip() and not line.startswith('#')]
            config["api_paths"] = patterns
    except Exception as e:
        raise RuntimeError(f"Error loading {txt_file}: {e}")
    
    # 2. Load from filter_rules.json (required)
    json_file = os.path.join(config_dir, "filter_rules.json")
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"Required file not found: {json_file}")
    
    try:
        with open(json_file, 'r') as f:
            json_config = json.load(f)
            # Merge with existing config, with JSON values taking precedence
            for key, value in json_config.items():
                if key in config and isinstance(value, list):
                    config[key] = list(set(config[key] + value))  # Merge lists
                else:
                    config[key] = value
    except Exception as e:
        raise RuntimeError(f"Error loading {json_file}: {e}")
    
    return config

# Load default configuration
try:
    FILTER_CONFIG = load_filter_config()
    
    # Export filter settings
    EXCLUDED_EXTENSIONS = set(FILTER_CONFIG.get("excluded_extensions", []))
    EXCLUDED_PATHS = set(FILTER_CONFIG.get("excluded_paths", []))
    FILTER_KEYWORDS = set(FILTER_CONFIG.get("api_keywords", []))
    API_PATHS = set(FILTER_CONFIG.get("api_paths", []))
    CONTENT_TYPES = set(FILTER_CONFIG.get("content_types", []))
    ACCEPT_HEADERS = set(FILTER_CONFIG.get("accept_headers", []))
    
except Exception as e:
    print(f"Error loading filter configuration: {e}")
    # Fall back to empty sets if there's an error
    EXCLUDED_EXTENSIONS = set()
    EXCLUDED_PATHS = set()
    FILTER_KEYWORDS = set()
    API_PATHS = set()
    CONTENT_TYPES = set()
    ACCEPT_HEADERS = set()
    FILTER_CONFIG = {}

__all__ = [
    'EXCLUDED_EXTENSIONS',
    'EXCLUDED_PATHS',
    'FILTER_KEYWORDS',
    'API_PATHS',
    'CONTENT_TYPES',
    'ACCEPT_HEADERS',
    'load_filter_config'
]
