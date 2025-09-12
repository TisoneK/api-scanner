"""
Storage optimization utilities for API Scanner.

This module provides functionality to reduce storage usage by:
1. Deduplicating identical API responses
2. Filtering out non-essential endpoints
3. Compressing large responses
4. Optimizing response storage
"""
from typing import Dict, List, Any, Set, Optional, Tuple, Union, BinaryIO
import json
import re
import zlib
import gzip
import base64
import hashlib
import datetime
import time
import os
from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass, field

class CompressionMethod(Enum):
    NONE = auto()
    ZLIB = auto()
    GZIP = auto()
    BASE64 = auto()

    @classmethod
    def from_string(cls, value: str) -> 'CompressionMethod':
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.NONE

@dataclass
class RequestResponsePair:
    """Represents a captured request and its response."""
    request: Dict[str, Any]
    response: Dict[str, Any]
    timestamp: str
    index: int
    
    @property
    def signature(self) -> str:
        """Generate a unique signature for this request."""
        return generate_request_signature(self.request)
    
    @property
    def response_signature(self) -> str:
        """Generate a unique signature for this response."""
        return generate_response_signature(self.response)

@dataclass
class OptimizedStorage:
    """Manages optimized storage of API requests and responses.
    
    Attributes:
        compress_responses_larger_than: Size in bytes above which to compress responses
        compression_method: Method to use for compression
        minify_json: Whether to minify JSON responses
    """
    # Storage for unique responses
    unique_responses: Dict[str, Dict] = field(default_factory=dict)
    
    # Mapping from request signature to response signature
    request_to_response: Dict[str, str] = field(default_factory=dict)
    
    # Request metadata (index, timestamp, etc.)
    request_metadata: List[Dict] = field(default_factory=list)
    
    # Compression settings
    compress_responses_larger_than: int = 1024  # 1KB
    compression_method: CompressionMethod = CompressionMethod.ZLIB
    minify_json: bool = True
    
    # Path to configuration files
    config_dir: Path = field(default_factory=lambda: Path(__file__).parent / 'config')
    
    # Patterns for endpoints to ignore (loaded from config)
    ignore_patterns: List[str] = field(init=False)
    
    # Endpoints that should never be compressed (loaded from config)
    no_compress_patterns: List[str] = field(init=False)
    
    # Compiled regex patterns for faster matching
    _compiled_ignore: List[re.Pattern] = field(init=False)
    _compiled_no_compress: List[re.Pattern] = field(init=False)
    
    use_ignore_patterns: bool = True
    
    response_count: int = 0
    
    def __init__(
        self,
        compression_method: str = 'zlib',
        compress_threshold: int = 1024,
        minify_json: bool = True,
        use_ignore_patterns: bool = True,
        config_dir: Optional[Union[str, Path]] = None
    ):
        self.compression_method = compression_method
        self.compress_threshold = compress_threshold
        self.minify_json = minify_json
        self.use_ignore_patterns = use_ignore_patterns
        
        # Set up config directory
        if config_dir is None:
            self.config_dir = Path(__file__).parent / 'config'
        else:
            self.config_dir = Path(config_dir)
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize storage for tracking unique responses
        self.unique_responses = {}
        self.response_count = 0
        
        # Initialize patterns
        self.ignore_patterns = []
        self._compiled_ignore = []
        self.no_compress_patterns = []
        self._compiled_no_compress = []
        
        # Load patterns if config directory exists
        try:
            self._load_ignore_patterns()
            self._load_no_compress_patterns()
        except FileNotFoundError as e:
            print(f"Warning: {e}. Using empty pattern lists.")
        except Exception as e:
            print(f"Warning: Failed to load patterns: {e}")
    
    def _load_patterns(self, filename: str) -> List[str]:
        """Load patterns from a JSON config file."""
        config_path = self.config_dir / filename
        
        # Return empty list if config file doesn't exist
        if not config_path.exists():
            print(f"Warning: Config file not found: {config_path}")
            return []
            
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            # Handle both array and object with categories
            patterns = []
            if isinstance(config, dict):
                for category, items in config.items():
                    if isinstance(items, list):
                        patterns.extend(items)
                    else:
                        patterns.append(category)
            elif isinstance(config, list):
                patterns = config
            else:
                print(f"Warning: Invalid config format in {filename}. Expected object or array.")
                return []
                
            return patterns
            
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {filename}: {e}")
            return []
        except Exception as e:
            print(f"Warning: Failed to load {filename}: {e}")
            return []
    
    def _load_ignore_patterns(self) -> None:
        """Load ignore patterns from config."""
        self.ignore_patterns = self._load_patterns('ignore_patterns.json')
        self._compiled_ignore = [re.compile(p, re.IGNORECASE) for p in self.ignore_patterns]
    
    def _load_no_compress_patterns(self) -> None:
        """Load no-compress patterns from config."""
        self.no_compress_patterns = self._load_patterns('no_compress_patterns.json')
        self._compiled_no_compress = [re.compile(p, re.IGNORECASE) for p in self.no_compress_patterns]
    
    def should_ignore(self, url: str) -> bool:
        """Check if a URL should be ignored based on patterns."""
        if not self.use_ignore_patterns:
            return False
        return any(pattern.search(url) for pattern in self._compiled_ignore)
    
    def should_compress(self, url, data):
        """Check if data should be compressed based on patterns and size."""
        if not self.compression_method or self.compression_method == 'none':
            return False
            
        # Check if URL matches any no-compress patterns
        if self.use_ignore_patterns and any(pattern.search(url) for pattern in self._compiled_no_compress):
            return False
            
        # Check size threshold if compression is enabled
        return len(str(data)) >= self.compress_threshold
    
    def _compress_data(self, data: Union[str, bytes, dict, list], url: str) -> Tuple[Union[str, dict], Dict[str, str]]:
        """Compress response data if needed."""
        if not data:
            return data, {}
            
        # Convert to bytes if needed
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, separators=(',', ':') if self.minify_json else None)
            data_bytes = data_str.encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
            
        # Check if we should compress
        if not self.should_compress(url, len(data_bytes)):
            return data, {}
            
        # Apply compression
        compression_metadata = {}
        try:
            if self.compression_method == CompressionMethod.ZLIB:
                compressed = zlib.compress(data_bytes, level=6)
                compression_metadata = {
                    'compression': 'zlib',
                    'original_length': len(data_bytes),
                    'compressed_length': len(compressed)
                }
                return base64.b64encode(compressed).decode('ascii'), compression_metadata
                
            elif self.compression_method == CompressionMethod.GZIP:
                import io
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode='wb') as f:
                    f.write(data_bytes)
                compressed = buffer.getvalue()
                compression_metadata = {
                    'compression': 'gzip',
                    'original_length': len(data_bytes),
                    'compressed_length': len(compressed)
                }
                return base64.b64encode(compressed).decode('ascii'), compression_metadata
                
            elif self.compression_method == CompressionMethod.BASE64:
                compressed = base64.b64encode(data_bytes).decode('ascii')
                compression_metadata = {
                    'compression': 'base64',
                    'original_length': len(data_bytes),
                    'compressed_length': len(compressed)
                }
                return compressed, compression_metadata
                
        except Exception as e:
            print(f"Warning: Failed to compress response: {e}")
            
        return data, {}
    
    def _process_response(self, response: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Process and optimize a response dictionary."""
        if not response:
            return {}
            
        processed = response.copy()
        
        # Handle response body
        if 'body' in processed and processed['body'] is not None:
            body = processed['body']
            compressed_body, compression_info = self._compress_data(body, url)
            
            if compression_info:
                processed['body'] = compressed_body
                processed['_compression'] = compression_info
        
        return processed
    
    def _generate_response_key(self, response: Dict[str, Any]) -> str:
        """Generate a unique key for a response."""
        # For performance, we might want to exclude certain headers that change frequently
        # but don't affect the actual response data (e.g., date, cache-control)
        headers = {
            k: v for k, v in response.get('headers', {}).items()
            if k.lower() not in {'date', 'cache-control', 'expires', 'last-modified', 'etag'}
        }
        
        components = [
            str(response.get('status_code')),
            json.dumps(headers, sort_keys=True),
            json.dumps(response.get('body'), sort_keys=True) if 'body' in response else ''
        ]
        return hashlib.sha256('|'.join(str(c) for c in components).encode()).hexdigest()
    
    def add_request_response(
        self, 
        request: Dict[str, Any], 
        response: Dict[str, Any], 
        timestamp: str,
        request_id: Optional[str] = None
    ) -> bool:
        """
        Add a request/response pair to storage if it's not a duplicate.
        
        Args:
            request: The request dictionary
            response: The response dictionary
            timestamp: Timestamp of the request
            request_id: Optional request ID
            
        Returns:
            bool: True if the request/response was added, False if it was a duplicate
        """
        self.response_count += 1
        
        # Skip if URL matches ignore patterns
        url = request.get('url', '')
        if self.use_ignore_patterns and self.should_ignore(url):
            return False
            
        # Process the response
        processed = self._process_response(response, url)
        
        # Generate a unique key for this response
        response_key = self._generate_response_key(processed)
        
        # Check if we've seen this response before
        if response_key in self.unique_responses:
            # Update the reference count
            self.unique_responses[response_key]['count'] += 1
            self.unique_responses[response_key]['last_seen'] = timestamp
            self.unique_responses[response_key]['urls'].add(url)
            return False
            
        # Add to storage if it's a new response
        self.unique_responses[response_key] = {
            'response': processed,
            'count': 1,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'urls': {url}
        }
        
        return True
    
    def save_to_file(self, file_path: str) -> None:
        """Save the optimized storage to a file."""
        output = {
            'metadata': {
                'version': '1.0',
                'compression_method': self.compression_method,
                'total_requests': self.response_count,
                'unique_responses': len(self.unique_responses),
                'created_at': datetime.datetime.now().isoformat()
            },
            'responses': [
                {
                    'key': key,
                    'response': data['response'],
                    'count': data['count'],
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen'],
                    'urls': list(data['urls'])
                }
                for key, data in self.unique_responses.items()
            ]
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            if self.minify_json:
                json.dump(output, f, separators=(',', ':'))
            else:
                json.dump(output, f, indent=2)
    
    @classmethod
    def from_file(cls, file_path: str) -> 'OptimizedStorage':
        """Load optimized storage from a file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        storage = cls()
        storage.unique_responses = {}
        storage.response_count = data['metadata']['total_requests']
        
        for response in data['responses']:
            storage.unique_responses[response['key']] = {
                'response': response['response'],
                'count': response['count'],
                'first_seen': response['first_seen'],
                'last_seen': response['last_seen'],
                'urls': set(response['urls'])
            }
        storage.request_to_response = data.get('request_to_response', {})
        storage.request_metadata = data.get('request_metadata', [])
        
        return storage

def generate_request_signature(request: Dict[str, Any]) -> str:
    """Generate a unique signature for a request."""
    components = [
        request.get('method', '').upper(),
        request.get('url', ''),
        json.dumps(request.get('query', {}), sort_keys=True),
        json.dumps(request.get('headers', {}), sort_keys=True),
        json.dumps(request.get('body', {}), sort_keys=True) if 'body' in request else ''
    ]
    return hashlib.sha256('|'.join(str(c) for c in components).encode()).hexdigest()

def generate_response_signature(response: Dict[str, Any]) -> str:
    """Generate a unique signature for a response."""
    # For performance, we might want to exclude certain headers that change frequently
    # but don't affect the actual response data (e.g., date, cache-control)
    headers = {
        k: v for k, v in response.get('headers', {}).items()
        if k.lower() not in {'date', 'cache-control', 'expires', 'last-modified', 'etag'}
    }
    
    components = [
        str(response.get('status_code')),
        json.dumps(headers, sort_keys=True),
        json.dumps(response.get('body'), sort_keys=True) if 'body' in response else ''
    ]
    return hashlib.sha256('|'.join(str(c) for c in components).encode()).hexdigest()

def process_capture_file(
    input_file: str,
    output_file: str,
    optimizer: Optional[OptimizedStorage] = None,
    ignore_patterns: Optional[List[str]] = None,
    show_stats: bool = False,
    quiet: bool = False
) -> Dict[str, Any]:
    """
    Process a capture file to optimize storage.
    
    Args:
        input_file: Path to the input JSON file
        output_file: Path to save the optimized output
        optimizer: Configured OptimizedStorage instance (uses defaults if None)
        ignore_patterns: List of regex patterns to ignore (overrides optimizer's patterns if provided)
        show_stats: Whether to show detailed statistics
        quiet: Suppress all non-error output
        
    Returns:
        Dictionary with processing statistics
    """
    # Create default optimizer if none provided
    if optimizer is None:
        optimizer = OptimizedStorage()
    
    # Override ignore patterns if explicitly provided
    if ignore_patterns is not None:
        optimizer.ignore_patterns = ignore_patterns
        optimizer._compiled_ignore = [re.compile(p, re.IGNORECASE) for p in ignore_patterns]
        optimizer.use_ignore_patterns = True
    
    # Load input data
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            api_calls = json.load(f)
        
        if not isinstance(api_calls, list):
            api_calls = [api_calls]  # Handle case where input is a single object
            
        # Track statistics
        stats = {
            'total_requests': len(api_calls),
            'ignored_requests': 0,
            'compressed_responses': 0,
            'original_size': 0,
            'compressed_size': 0,
            'unique_responses': 0,
            'start_time': time.time(),
            'end_time': None
        }
    
        # Process each API call
        processed_count = 0
        for idx, call in enumerate(api_calls):
            try:
                if not isinstance(call, dict):
                    if not quiet:
                        print(f"Warning: Skipping non-dictionary item at index {idx}")
                    continue
                    
                request = call.get('request', {})
                response = call.get('response', {})
                timestamp = call.get('timestamp', datetime.datetime.now().isoformat())
                
                if optimizer.add_request_response(request, response, timestamp, str(idx)):
                    processed_count += 1
                
                # Update progress for large files
                if not quiet and (idx + 1) % 100 == 0:
                    print(f"Processed {idx + 1}/{len(api_calls)} requests...")
                    
            except Exception as e:
                if not quiet:
                    print(f"Error processing API call {idx}: {e}")
                continue
        
        # Finalize statistics
        stats['end_time'] = time.time()
        stats['unique_responses'] = len(optimizer.unique_responses)
        stats['processed_requests'] = processed_count
        stats['ignored_requests'] = stats['total_requests'] - processed_count
        
        # Calculate compression ratio based on file sizes
        input_size = os.path.getsize(input_file)
        optimizer.save_to_file(output_file)
        output_size = os.path.getsize(output_file)
        
        stats.update({
            'original_size': input_size,
            'compressed_size': output_size,
            'compression_ratio': input_size / output_size if output_size > 0 else 0,
            'output_file': output_file,
            'output_size': output_size,
            'processing_time': stats['end_time'] - stats['start_time']
        })
        
        # Print summary if not in quiet mode
        if not quiet:
            print("\nOptimization complete!")
            print(f"• Processed {stats['total_requests']} requests")
            print(f"• Unique responses: {stats['unique_responses']}")
            print(f"• Compression ratio: {stats['compression_ratio']:.2f}x")
            print(f"• Original size: {stats['original_size'] / 1024:.2f} KB")
            print(f"• Optimized size: {stats['compressed_size'] / 1024:.2f} KB")
            print(f"• Saved: {(1 - (stats['compressed_size'] / stats['original_size'])) * 100:.1f}%")
            print(f"• Time taken: {stats['processing_time']:.2f} seconds")
        
        return stats
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in input file: {e}")
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Input file not found: {input_file}")
    except Exception as e:
        raise RuntimeError(f"Failed to process capture file: {e}")
