"""
Configuration settings for the API Scanner.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 8080,
        "ssl_verify": True
    },
    "output": {
        "directory": "output",
        "filename": "captured_apis.json"
    },
    "logging": {
        "level": "INFO"
    },
    "filters": {
        # Optional allowlist of hosts (domains) to capture. Empty means allow all.
        "allowed_hosts": []
    }
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or use defaults."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
    
    config = DEFAULT_CONFIG.copy()
    
    try:
        with open(config_path, 'r') as f:
            file_config = json.load(f)
            # Merge with defaults
            for key, value in file_config.items():
                if isinstance(value, dict) and key in config:
                    config[key].update(value)
                else:
                    config[key] = value
    except FileNotFoundError:
        logging.warning(f"Config file not found at {config_path}, using defaults")
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing config file {config_path}: {e}")
    
    return config

# Load configuration
config = load_config()

# Export configuration
PROXY_HOST = config["proxy"]["host"]
PROXY_PORT = config["proxy"]["port"]
SSL_VERIFY = config["proxy"]["ssl_verify"]
OUTPUT_DIR = Path(config["output"]["directory"])
OUTPUT_FILE = OUTPUT_DIR / config["output"]["filename"]
LOG_LEVEL = config["logging"]["level"]
ALLOWED_HOSTS = set(config.get("filters", {}).get("allowed_hosts", []))

# Constants
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
