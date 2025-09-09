"""
Core functionality for the API Scanner.
"""
import asyncio
import json
import logging
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
from urllib.parse import urlparse, parse_qs

from mitmproxy import http, ctx

from .config.config import (
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL,
    PROXY_HOST, PROXY_PORT, SSL_VERIFY
)
from .config.filters import (
    EXCLUDED_EXTENSIONS, EXCLUDED_PATHS, FILTER_KEYWORDS
)

# For backward compatibility
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB
from .utils import setup_logging, save_to_file, format_size
from .models import ApiCall, RequestData, ResponseData

# Set up logging
setup_logging(LOG_LEVEL)
logger = logging.getLogger(__name__)

class ApiSniffer:
    """
    A mitmproxy addon to capture, analyze, and log API requests and responses.
    """
    def __init__(self, host: str = None, port: int = None, 
                 ssl_verify: bool = None, output: str = None,
                 filter_file: str = None):
        self.api_calls: List[ApiCall] = []
        self.request_count = 0
        self.filtered_count = 0
        self.should_exit = False
        self.shutdown_callbacks = []
        self.request_map: Dict[str, Dict] = {}  # Maps request_id to request data
        self.logger = logging.getLogger(__name__ + '.ApiSniffer')
        self.host = host or PROXY_HOST
        self.port = port or PROXY_PORT
        self.ssl_verify = ssl_verify if ssl_verify is not None else SSL_VERIFY
        self.output = output or str(OUTPUT_FILE)
        self._shutdown_event = asyncio.Event()
        
        # Load custom filter keywords if provided, otherwise use defaults
        if filter_file:
            from .config.filters import load_filter_keywords
            self.filter_keywords = load_filter_keywords(filter_file)
        else:
            from .config.filters import FILTER_KEYWORDS
            self.filter_keywords = FILTER_KEYWORDS
        
    def add_shutdown_callback(self, callback: Callable[[], None]) -> None:
        """Add a callback to be called on shutdown."""
        self.shutdown_callbacks.append(callback)
        
    def is_ui_asset(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is for a UI asset that should be excluded."""
        path = flow.request.path.lower()
        
        # Check file extensions
        if any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
            return True
            
        # Check path patterns
        if any(excluded in path for excluded in EXCLUDED_PATHS):
            return True
            
        return False
        
    def is_api_request(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is an API request that should be captured."""
        if self.is_ui_asset(flow):
            return False
            
        # Check if any of the filter keywords are in the URL
        url = flow.request.pretty_url.lower()
        return any(keyword.lower() in url for keyword in self.filter_keywords)
    
    def get_content_type(self, message) -> Optional[str]:
        """Extract and return the content type from a message."""
        if not hasattr(message, 'headers') or not message.headers:
            return None
        return message.headers.get('content-type', '').split(';')[0].strip().lower()
    
    def is_json_content(self, message) -> bool:
        """Check if the message has JSON content type."""
        content_type = self.get_content_type(message)
        return content_type in ['application/json', 'text/json']
    
    def is_xml_content(self, message) -> bool:
        """Check if the message has XML content type."""
        content_type = self.get_content_type(message)
        return content_type in ['application/xml', 'text/xml']
    
    def safe_get_text(self, message) -> Any:
        """
        Safely extract and parse the message body.
        
        Returns:
            Parsed content (dict/list) if content is JSON/XML, 
            raw text if content is text but not parseable,
            None if content is binary or empty.
        """
        if not hasattr(message, 'content'):
            return None
            
        content = message.content
        if not content:
            return None
            
        try:
            # Try to decode as text
            text = content.decode('utf-8', errors='replace')
            
            # Try to parse as JSON if content type matches
            if self.is_json_content(message):
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
                    
            # Try to parse as XML if content type matches
            if self.is_xml_content(message):
                try:
                    import xml.etree.ElementTree as ET
                    return ET.fromstring(text)
                except (ET.ParseError, UnicodeDecodeError):
                    pass
                    
            return text
            
        except Exception as e:
            logger.debug(f"Error parsing message content: {e}")
            return None
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Called when a client request is received."""
        if self.should_exit:
            flow.kill()
            return
            
        if not self.is_api_request(flow):
            return
            
        try:
            self.request_count += 1
            request_id = str(uuid.uuid4())
            
            # Store request data
            query_params = {}
            if hasattr(flow.request.query, 'items'):
                for key, value in flow.request.query.items():
                    # Convert single values to a list to match Dict[str, List[str]]
                    query_params[key] = [value] if not isinstance(value, list) else value
            
            self.request_map[request_id] = {
                'request': {
                    'method': flow.request.method,
                    'url': flow.request.pretty_url,
                    'headers': dict(flow.request.headers),
                    'query_params': query_params,
                    'body': self.safe_get_text(flow.request),
                    'timestamp': datetime.utcnow().isoformat(),
                },
                'start_time': time.time()
            }
            
            # Store the request ID for response matching
            flow.metadata['request_id'] = request_id
            
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a server response is received."""
        if self.should_exit or 'request_id' not in flow.metadata:
            return
            
        try:
            request_id = flow.metadata['request_id']
            if request_id not in self.request_map:
                return
                
            request_data = self.request_map.pop(request_id)
            
            # Calculate response time
            response_time = (time.time() - request_data['start_time']) * 1000  # in ms
            
            # Create response data
            response_data = {
                'status_code': flow.response.status_code,
                'reason': flow.response.reason,
                'headers': dict(flow.response.headers),
                'body': self.safe_get_text(flow.response),
                'response_time_ms': response_time,
                'timestamp': datetime.utcnow().isoformat(),
            }
            
            # Ensure query_params is properly formatted as Dict[str, List[str]]
            request_dict = request_data['request'].copy()
            if 'query_params' in request_dict:
                query_params = request_dict['query_params']
                if hasattr(query_params, 'items'):
                    # Convert to a regular dict and ensure all values are lists
                    query_params = {
                        k: [v] if not isinstance(v, list) else v
                        for k, v in query_params.items()
                    }
                    request_dict['query_params'] = query_params
            
            # Create API call entry
            api_call = ApiCall(
                id=request_id,
                request=RequestData(**request_dict),
                response=ResponseData(**response_data)
            )
            
            # Add to captured calls
            self.api_calls.append(api_call)
            
            # Log the API call
            logger.info(
                f"[{api_call.request.method}] {api_call.request.url} "
                f"-> {api_call.response.status_code} "
                f"({api_call.response.response_time_ms:.2f}ms)"
            )
            
            # Save to file periodically
            if len(self.api_calls) % 10 == 0:
                self._save_to_file()
                
        except Exception as e:
            logger.error(f"Error processing response: {e}", exc_info=True)
    
    def _save_to_file(self) -> None:
        """Save captured API calls to file."""
        try:
            # Convert API calls to dictionaries
            api_calls_dict = [call.dict() for call in self.api_calls]
            
            # Save to file
            save_to_file(api_calls_dict, OUTPUT_FILE)
            
        except Exception as e:
            logger.error(f"Error saving API calls to file: {e}", exc_info=True)
    
    async def start(self):
        """Start the proxy server."""
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy import options
        
        # Set up mitmproxy options
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=not self.ssl_verify,
        )
        
        # Create and configure the proxy server
        m = DumpMaster(opts)
        m.addons.add(self)
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            self.logger.info("\nReceived shutdown signal. Initiating graceful shutdown...")
            asyncio.create_task(self._graceful_shutdown(m))
            
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, signal_handler)
            except (ValueError, RuntimeError) as e:
                self.logger.warning(f"Could not set signal handler for {sig}: {e}")
        
        try:
            # Start the proxy server
            self.logger.info(f"Starting API Scanner on http://{self.host}:{self.port}")
            self.logger.info("Press Ctrl+C to stop")
            
            await m.run()
            await self._shutdown_event.wait()
            
        except asyncio.CancelledError:
            await self._graceful_shutdown(m)
        except Exception as e:
            self.logger.error(f"Error in proxy server: {e}", exc_info=True)
            await self._graceful_shutdown(m)
        finally:
            if m.running:
                m.shutdown()
    
    async def _graceful_shutdown(self, master):
        """Perform graceful shutdown of the proxy server."""
        if not hasattr(self, '_shutdown_initiated'):
            self._shutdown_initiated = True
            self.logger.info("\nShutting down gracefully. Please wait...")
            
            # Signal to stop processing new requests
            self.should_exit = True
            
            # Call all registered shutdown callbacks
            for callback in self.shutdown_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback()
                    else:
                        callback()
                except Exception as e:
                    self.logger.error(f"Error in shutdown callback: {e}", exc_info=True)
            
            # Save any remaining API calls
            if self.api_calls:
                self._save_to_file()
            
            # Signal that shutdown is complete
            self._shutdown_event.set()
    
    def done(self) -> None:
        """Called when the proxy shuts down."""
        try:
            # Save any remaining API calls
            if self.api_calls:
                self._save_to_file()
                
            # Log summary
            self.logger.info("\n" + "=" * 80)
            self.logger.info(f"API Scan Complete")
            self.logger.info("-" * 80)
            self.logger.info(f"Total Requests: {self.request_count}")
            self.logger.info(f"Filtered Requests: {self.filtered_count}")
            self.logger.info(f"Captured API Calls: {len(self.api_calls)}")
            
            # Calculate and log statistics
            if self.api_calls:
                # Calculate average response time
                total_time = sum(call.response.response_time_ms for call in self.api_calls if call.response)
                avg_time = total_time / len([c for c in self.api_calls if c.response]) if self.api_calls else 0
                self.logger.info(f"Average Response Time: {avg_time:.2f}ms")
                
                # Count status codes
                status_codes = {}
                for call in self.api_calls:
                    if call.response:
                        status = call.response.status_code
                        status_codes[status] = status_codes.get(status, 0) + 1
                
                self.logger.info("\nStatus Codes:")
                for code, count in sorted(status_codes.items()):
                    self.logger.info(f"  - {code}: {count}")
                
                # Count HTTP methods
                methods = {}
                for call in self.api_calls:
                    method = call.request.method
                    methods[method] = methods.get(method, 0) + 1
                
                self.logger.info("\nHTTP Methods:")
                for method, count in sorted(methods.items()):
                    self.logger.info(f"  - {method}: {count}")
                
                # Count domains
                domains = {}
                for call in self.api_calls:
                    domain = urlparse(call.request.url).netloc
                    domains[domain] = domains.get(domain, 0) + 1
                
                self.logger.info("\nTop Domains:")
                for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
                    self.logger.info(f"  - {domain}: {count}")
                
            self.logger.info("=" * 80)
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)
