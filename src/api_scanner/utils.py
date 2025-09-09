"""
Utility functions for the API Scanner.
"""
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Configure logging
def setup_logging(level: str = "INFO") -> None:
    """
    Set up basic logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def save_to_file(data: Any, file_path: Union[str, Path]) -> bool:
    """
    Save data to a JSON file.
    
    Args:
        data: Data to save (must be JSON serializable)
        file_path: Path to the output file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        file_path = Path(file_path)
        # Ensure the directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # If file exists, load existing data and append
        if file_path.exists() and file_path.stat().st_size > 0:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    existing_data = json.load(f)
                    if isinstance(existing_data, list) and isinstance(data, list):
                        data = existing_data + data
                    elif isinstance(existing_data, dict) and isinstance(data, dict):
                        existing_data.update(data)
                        data = existing_data
                except json.JSONDecodeError:
                    # If the file is corrupted, overwrite it
                    pass
        
        # Write the data
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        return True
        
    except Exception as e:
        logging.error(f"Error saving to file {file_path}: {e}", exc_info=True)
        return False

def format_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        str: Formatted size string (e.g., "1.23 MB")
    """
    if size_bytes == 0:
        return "0B"
        
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    size = float(size_bytes)
    
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
        
    return f"{size:.2f} {units[i]}"
