"""
Storage optimization utilities for API Scanner.

This module provides functionality to reduce storage usage by:
1. Deduplicating identical API responses
2. Filtering out non-essential endpoints
3. Compressing large responses
4. Optimizing response storage
"""
from typing import Dict, List, Any, Set, Optional, Tuple, Union, BinaryIO
import hashlib
import json
import zlib
import base64
import gzip
from pathlib import Path
from dataclasses import dataclass, field
import re
from enum import Enum, auto

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
    _compiled_patterns: List[re.Pattern] = field(init=False)
    _no_compress_patterns: List[re.Pattern] = field(init=False)
    
    def __post_init__(self):
        """Initialize the optimizer by loading patterns from config files."""
        # Load ignore patterns from config
        self.ignore_patterns = self._load_patterns('ignore_patterns.json')
        self.no_compress_patterns = self._load_patterns('no_compress_patterns.json')
        
        # Compile all patterns for better performance
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.ignore_patterns]
        self._no_compress_patterns = [re.compile(p, re.IGNORECASE) for p in self.no_compress_patterns]
    
    def _load_patterns(self, filename: str) -> List[str]:
        """Load patterns from a JSON config file."""
        config_path = self.config_dir / filename
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
            
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            # Flatten the nested structure into a single list of patterns
            patterns = []
            for category in config.values():
                if isinstance(category, list):
                    patterns.extend(category)
                else:
                    patterns.append(category)
                    
            return patterns
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {filename}: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to load {filename}: {e}")
    
    def should_ignore(self, url: str) -> bool:
        """Check if a URL matches any of the ignore patterns."""
        if not url:
            return True
        return any(pattern.search(url) for pattern in self._compiled_patterns)
    
    def should_compress(self, url: str, content_length: int) -> bool:
        """Determine if a response should be compressed."""
        if content_length < self.compress_responses_larger_than:
            return False
            
        # Don't compress if URL matches no_compress patterns
        if any(pattern.search(url) for pattern in self._no_compress_patterns):
            return False
            
        return True
    
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
    
    def add_request_response(self, request: Dict[str, Any], response: Dict[str, Any], 
                           timestamp: str, index: int) -> bool:
        """
        Add a request/response pair to the optimized storage.
        
        Args:
            request: The request dictionary
            response: The response dictionary
            timestamp: Timestamp of the request
            index: Index of the request in the original capture
            
        Returns:
            bool: True if the request was added, False if it was ignored
        """
        # Skip ignored URLs
        url = request.get('url', '')
        if self.should_ignore(url):
            return False
            
        # Process and optimize the response
        processed_response = self._process_response(response, url)
        pair = RequestResponsePair(request, processed_response, timestamp, index)
        
        # Store response if we haven't seen it before
        if pair.response_signature not in self.unique_responses:
            self.unique_responses[pair.response_signature] = processed_response
        
        # Update request mapping
        self.request_to_response[pair.signature] = pair.response_signature
        
        # Store minimal request metadata
        self.request_metadata.append({
            'index': index,
            'timestamp': timestamp,
            'signature': pair.signature,
            'method': request.get('method'),
            'url': url,
            'status_code': response.get('status_code'),
            'content_length': len(str(response.get('body', ''))),
            'compressed': '_compression' in (processed_response or {})
        })
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the optimized storage to a dictionary for serialization."""
        return {
            'unique_responses': self.unique_responses,
            'request_to_response': self.request_to_response,
            'request_metadata': self.request_metadata,
            'stats': {
                'total_requests': len(self.request_metadata),
                'unique_responses': len(self.unique_responses),
                'compression_ratio': len(self.request_metadata) / len(self.unique_responses) if self.unique_responses else 0
            }
        }
    
    def save_to_file(self, file_path: str) -> None:
        """Save the optimized storage to a file."""
        output = self.to_dict()
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
    
    @classmethod
    def from_file(cls, file_path: str) -> 'OptimizedStorage':
        """Load optimized storage from a file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        storage = cls()
        storage.unique_responses = data.get('unique_responses', {})
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
    input_path: str, 
    output_path: str,
    compress_threshold: int = 1024,
    compression_method: str = 'zlib',
    minify_json: bool = True,
    custom_ignore_patterns: List[str] = None
) -> Dict[str, Any]:
    """
    Process a captured API file and save an optimized version.
    
    Args:
        input_path: Path to the input JSON file with captured APIs
        output_path: Path where to save the optimized output
        compress_threshold: Minimum response size in bytes to compress (0 = always compress)
        compression_method: Compression method to use (zlib, gzip, base64, none)
        minify_json: Whether to minify JSON responses
        custom_ignore_patterns: Additional regex patterns for endpoints to ignore
        
    Returns:
        Dict with statistics about the optimization
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        api_calls = json.load(f)
    
    # Initialize storage with custom settings
    storage = OptimizedStorage(
        compress_responses_larger_than=compress_threshold,
        compression_method=CompressionMethod.from_string(compression_method),
        minify_json=minify_json
    )
    
    # Add custom ignore patterns if provided
    if custom_ignore_patterns:
        storage.ignore_patterns.extend(custom_ignore_patterns)
        storage._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in storage.ignore_patterns]
    
    # Track statistics
    stats = {
        'total_requests': len(api_calls),
        'ignored_requests': 0,
        'compressed_responses': 0,
        'original_size': 0,
        'compressed_size': 0,
        'unique_responses': 0,
        'start_time': None,
        'end_time': None
    }
    
    import time
    stats['start_time'] = time.time()
    
    for idx, call in enumerate(api_calls):
        try:
            request = call.get('request', {})
            response = call.get('response', {})
            timestamp = call.get('timestamp', '')
            
            # Track original size
            if 'body' in response and response['body'] is not None:
                body = response['body']
                if isinstance(body, (dict, list)):
                    stats['original_size'] += len(json.dumps(body).encode('utf-8'))
                else:
                    stats['original_size'] += len(str(body).encode('utf-8'))
            
            # Process the request/response
            if storage.add_request_response(request, response, timestamp, idx):
                # Track compression
                processed_response = next((r for r in storage.unique_responses.values() 
                                        if r.get('_compression')), None)
                if processed_response and '_compression' in processed_response:
                    stats['compressed_responses'] += 1
                    stats['compressed_size'] += processed_response['_compression']['compressed_length']
            else:
                stats['ignored_requests'] += 1
                
        except Exception as e:
            print(f"Error processing API call {idx}: {e}")
    
    stats['end_time'] = time.time()
    stats['unique_responses'] = len(storage.unique_responses)
    stats['processing_time'] = stats['end_time'] - stats['start_time']
    
    if stats['original_size'] > 0:
        stats['compression_ratio'] = stats['original_size'] / (stats['compressed_size'] or 1)
    else:
        stats['compression_ratio'] = 0
    
    # Save the optimized storage
    storage.save_to_file(output_path)
    
    # Add output file info to stats
    stats['output_file'] = output_path
    stats['output_size'] = Path(output_path).stat().st_size if Path(output_path).exists() else 0
    
    return stats
