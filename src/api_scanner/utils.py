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
    file_path = Path(file_path).absolute()
    
    try:
        # Ensure the directory exists
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logging.error(f"Failed to create directory {file_path.parent}: {e}")
            return False
        
        # Convert data to JSON to check serialization
        try:
            json_data = json.dumps(data, indent=2, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            logging.error(f"Failed to serialize data to JSON: {e}")
            return False
        
        # If file exists, load existing data and append
        if file_path.exists():
            try:
                if file_path.stat().st_size > 0:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        try:
                            existing_data = json.load(f)
                            if isinstance(existing_data, list) and isinstance(data, list):
                                data = existing_data + data
                            elif isinstance(existing_data, dict) and isinstance(data, dict):
                                existing_data.update(data)
                                data = existing_data
                            # Update the JSON data with merged content
                            json_data = json.dumps(data, indent=2, ensure_ascii=False)
                        except json.JSONDecodeError as e:
                            logging.warning(f"Existing file {file_path} is corrupted, it will be overwritten: {e}")
            except IOError as e:
                logging.error(f"Error reading existing file {file_path}: {e}")
                return False
        
        # Write the data atomically using a temporary file
        temp_path = file_path.with_suffix('.tmp')
        try:
            # Write to temporary file
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(json_data)
            
            # On Windows, we need to remove the destination file first if it exists
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError as e:
                    logging.error(f"Failed to remove existing file {file_path}: {e}")
                    return False
            
            # Rename temp file to target file
            temp_path.rename(file_path)
            logging.debug(f"Successfully wrote {len(json_data)} bytes to {file_path}")
            return True
            
        except (IOError, OSError) as e:
            logging.error(f"Failed to write to file {file_path}: {e}")
            # Clean up temp file if it exists
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            return False
            
    except Exception as e:
        logging.error(f"Unexpected error saving to {file_path}: {e}", exc_info=True)
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
