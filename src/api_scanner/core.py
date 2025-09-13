class ApiSniffer:
    """
    ApiSniffer is the core engine of the API Scanner tool.

    It captures, analyzes, and logs API requests and responses
    from target domains to help identify available endpoints,
    headers, and common API patterns.

    Key Responsibilities:
        - Initialize and manage network sniffing sessions.
        - Capture HTTP/HTTPS requests made by the target site.
        - Match requests against common API patterns (e.g., /api/, /v1/, /json/).
        - Log request/response details such as URLs, headers, and status codes.
        - Store results in structured form for later processing or export.

    Attributes:
        config (ScannerConfig): User-provided configuration object that
            defines target domain, proxy, filters, and timeouts.
        logger (logging.Logger): Logger instance for tracking events and errors.
        results (list): Collected API request/response data.

    Usage:
        >>> sniffer = ApiSniffer(config)
        >>> sniffer.start()
        >>> endpoints = sniffer.results

    Notes:
        - Designed to be extensible for integration into larger applications.
        - Works in standalone CLI mode as well as programmatically.
    """

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import os
import re
import signal
import time
import uuid
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable, Pattern
from urllib.parse import urlparse, parse_qs

from mitmproxy import http, ctx

# Import configuration
from .config import (
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL, MAX_CONTENT_LENGTH,
    PROXY_HOST, PROXY_PORT, SSL_VERIFY, ALLOWED_HOSTS,
    EXCLUDED_EXTENSIONS, EXCLUDED_PATHS, FILTER_KEYWORDS,
    API_PATHS, CONTENT_TYPES, ACCEPT_HEADERS,
    load_filter_config, FILTER_CONFIG
)

from .utils import setup_logging, save_to_file, format_size
from .models import ApiCall, RequestData, ResponseData

# Set up module-level logging (used until instance logger is created)
setup_logging(LOG_LEVEL)
logger = logging.getLogger(__name__)


class ApiSniffer:
    """
    A mitmproxy addon to capture, analyze, and log API requests and responses.
    """
    def __init__(
        self,
        output_file: Optional[str] = None,
        ignore_ui: Optional[bool] = None,
        ignore_patterns: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
        blocked_hosts: Optional[List[str]] = None,
        filter_file: Optional[str] = None,
        domain: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize the API sniffer.
        """
        # Load configuration
        if config is None:
            from .config import config as default_config
            self.config = default_config
        else:
            self.config = config

        # Proxy defaults from config/provided constants
        proxy_cfg = self.config.get('proxy', {})
        self.host = proxy_cfg.get('host', PROXY_HOST)
        self.port = int(proxy_cfg.get('port', PROXY_PORT))
        self.ssl_verify = proxy_cfg.get('ssl_verify', SSL_VERIFY)

        # Configure logger first so further initialization can use it
        if logger is None:
            self.logger = logging.getLogger("api_scanner")
            log_level = self.config.get('logging', {}).get('level', 'INFO')
            self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

            # Prevent duplicate handlers if re-initialized
            if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
                handler = logging.StreamHandler()
                log_format = self.config.get('logging', {}).get('format',
                                                             "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
                formatter = logging.Formatter(log_format)
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
        else:
            self.logger = logger

        # Initialize other attributes
        self.ignore_ui = ignore_ui if ignore_ui is not None else self.config.get('filters', {}).get('ignore_ui', False)
        self.output_file = output_file or os.path.join(
            self.config.get('output', {}).get('directory', 'output'),
            self.config.get('output', {}).get('filename', 'captured_apis.json')
        )

        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.output_file)) or '.', exist_ok=True)

        self.ignore_patterns = ignore_patterns or []

        # Initialize allowed hosts
        self.allowed_hosts: Set[str] = set()
        if domain:
            # Strip protocol and path if present
            domain = domain.lower().replace('https://', '').replace('http://', '').split('/')[0]
            self.allowed_hosts.add(domain)
            if not domain.startswith('www.'):
                self.allowed_hosts.add(f'www.{domain}')

        # Add any explicitly allowed hosts from config or args
        if allowed_hosts:
            self.allowed_hosts.update(h.lower() for h in allowed_hosts)
        elif not domain:  # Only use config if no domain was provided
            self.allowed_hosts.update(str(h).lower() for h in self.config.get('filters', {}).get('allowed_hosts', []))

        # Initialize blocked hosts (store as raw strings; treated as substring match)
        self.blocked_hosts: Set[str] = set(h.lower() for h in (blocked_hosts or []))

        self._captured_apis: List[Dict[str, Any]] = []
        self._compiled_ignore: List[Pattern] = []
        self.should_exit = False
        self.filtered_count = 0
        self.shutdown_callbacks: List[Callable[[], None]] = []
        self.request_count = 0
        self.api_calls: List[ApiCall] = []
        self.request_map: Dict[str, Any] = {}

        # Async shutdown event used by start/_graceful_shutdown
        self._shutdown_event = asyncio.Event()
        self._shutdown_initiated = False

        # Initialize filter keywords from configuration
        self.filter_keywords = set(self.config.get('filters', {}).get('filter_keywords', FILTER_KEYWORDS))

        # Compile ignore patterns for better performance
        if self.ignore_patterns:
            try:
                self._compiled_ignore = [re.compile(p, re.IGNORECASE) for p in self.ignore_patterns]
            except Exception as e:
                self.logger.warning(f"Failed to compile ignore patterns: {e}")
                self.ignore_patterns = []
                self._compiled_ignore = []

        # Load filter file if specified
        if filter_file:
            self._load_filter_file(filter_file)

        # Debug output
        if self.logger.isEnabledFor(logging.DEBUG):
            if self.allowed_hosts:
                self.logger.debug(f"Allowed hosts: {', '.join(sorted(self.allowed_hosts))}")
            if self.blocked_hosts:
                self.logger.debug(f"Blocked hosts: {', '.join(sorted(self.blocked_hosts))}")

    def add_shutdown_callback(self, callback: Callable[[], None]) -> None:
        """Add a callback to be called on shutdown."""
        self.shutdown_callbacks.append(callback)

    def _load_ignore_patterns(self) -> None:
        """Load ignore patterns from JSON configuration."""
        try:
            config_path = Path(__file__).parent / 'config' / 'ignore_patterns.json'
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns_config = json.load(f)

            # Flatten all patterns from different categories into a single list
            self.ignore_patterns = []
            for category in patterns_config.values():
                if isinstance(category, list):
                    self.ignore_patterns.extend(category)

            # Pre-compile all regex patterns for better performance
            self._compiled_ignore = [re.compile(p, re.IGNORECASE) for p in self.ignore_patterns]

        except Exception as e:
            self.logger.warning(f"Failed to load ignore patterns: {e}")
            self.ignore_patterns = []
            self._compiled_ignore = []

    def is_ui_asset(self, flow: http.HTTPFlow) -> bool:
        """Check if the request/response is for a UI asset that should be excluded."""
        if not hasattr(flow, 'request') or not flow.request:
            return False

        path = flow.request.path.lower()
        url = flow.request.pretty_url.lower()

        # Get configuration values
        filters = self.config.get('filters', {})
        excluded_extensions = filters.get('excluded_extensions', [])
        excluded_paths = filters.get('excluded_paths', [])
        max_body_size = filters.get('max_body_size', 1048576)  # Default 1MB

        # Only check response content, not request headers
        if not hasattr(flow, 'response') or not flow.response or not flow.response.headers:
            return False

        content_type = self.get_content_type(flow.response) or ''

        # Only filter out actual HTML responses if ignore_ui is True
        if self.ignore_ui and 'text/html' in content_type:
            self.logger.debug(f"Filtered by HTML response content type: {url}")
            return True

        # Also check for HTML in response body if content-type is not properly set
        if self.ignore_ui and not content_type and getattr(flow.response, 'content', None):
            try:
                max_check_size = min(len(flow.response.content), max_body_size, 1024)
                body = flow.response.content[:max_check_size].decode('utf-8', errors='ignore')
                if body.lstrip().startswith('<!DOCTYPE html>') or '<html' in body.lower():
                    self.logger.debug(f"Filtered by HTML in response body: {url}")
                    return True
            except Exception as e:
                self.logger.debug(f"Error checking response body: {e}")

        # Check file extensions
        if any(path.endswith(ext.lower()) for ext in excluded_extensions):
            self.logger.debug(f"Filtered UI asset by extension: {url}")
            return True

        # Check path patterns
        if any(excluded.lower() in path for excluded in excluded_paths):
            self.logger.debug(f"Filtered UI asset by path: {url}")
            return True

        return False

    def is_api_request(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is an API request that should be captured."""
        if not hasattr(flow, 'request') or not flow.request:
            return False

        url = flow.request.pretty_url.lower()
        host = (flow.request.host or '').lower()
        path = flow.request.path.lower()
        method = (flow.request.method or '').upper()

        # Only process standard HTTP methods
        if method not in {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'}:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Filtered non-standard HTTP method: {method}")
            return False

        # Check if the host is in the blocked hosts list (takes precedence)
        if self.blocked_hosts and any(blocked_host in host for blocked_host in self.blocked_hosts):
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Blocked host: {host}")
            return False

        # If we have allowed hosts, verify the host matches
        if self.allowed_hosts:
            host_matches = any(
                host == allowed_host or host.endswith(f'.{allowed_host}') or host == f'www.{allowed_host}'
                for allowed_host in self.allowed_hosts
            )

            if not host_matches:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Host not in allowed list: {host}")
                return False

        # Skip UI assets if enabled
        if self.ignore_ui and self.is_ui_asset(flow):
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Filtered UI asset: {host}{path}")
            return False

        # Check content-type header for API-like content first
        content_type = (flow.request.headers.get('content-type', '') or '').lower()
        if content_type and 'text/html' in content_type:
            self.logger.debug(f"Filtered by HTML content type: {url}")
            return False

        # Check if the path matches any known API paths
        api_paths = self.config.get('filters', {}).get('api_paths', API_PATHS)
        if any(api_path in path for api_path in api_paths):
            self.logger.debug(f"Matched API path pattern: {url}")
            return True

        # Check if any of the filter keywords are in the URL
        if any(keyword.lower() in url for keyword in self.filter_keywords):
            self.logger.debug(f"Matched filter keyword in URL: {url}")
            return True

        # Check request content types
        content_types = self.config.get('filters', {}).get('content_types', CONTENT_TYPES)
        if any(ct in content_type for ct in content_types):
            self.logger.debug(f"Matched API content type {content_type}: {url}")
            return True

        # Check accept header for API-like content
        accept = (flow.request.headers.get('accept', '') or '').lower()
        accept_headers = self.config.get('filters', {}).get('accept_headers', ACCEPT_HEADERS)
        if any(ct in accept for ct in accept_headers):
            self.logger.debug(f"Matched API accept header {accept}: {url}")
            return True

        self.logger.debug(f"Filtered non-API request: {method} {url}")
        return False

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
        """
        if not hasattr(message, 'content'):
            return None

        content = getattr(message, 'content', None)
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
            self.logger.debug(f"Error parsing message content: {e}")
            return None

    def _should_skip(self, flow: http.HTTPFlow) -> bool:
        """Determine if the request should be skipped based on various criteria."""
        # Skip if we're in the process of shutting down
        if self.should_exit:
            return True

        # Get the host from the request
        host = (flow.request.pretty_host or '').lower()

        # Skip blocked hosts
        if self.blocked_hosts and any(blocked in host for blocked in self.blocked_hosts):
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Skipping blocked host")
            return True

        # Check allowed hosts if specified
        if self.allowed_hosts and not any(allowed in host or host.endswith(f'.{allowed}') for allowed in self.allowed_hosts):
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Skipping non-allowed host")
            return True

        # Check ignore patterns
        url = flow.request.pretty_url.lower()
        if self._compiled_ignore and any(pattern.search(url) for pattern in self._compiled_ignore):
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Skipping URL matching ignore pattern")
            return True

        return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP request."""
        if self._should_skip(flow):
            return

        # Store the request URL for later use in response handler
        try:
            flow.metadata['request_url'] = flow.request.pretty_url
        except Exception:
            flow.metadata['request_url'] = ''

        if self.should_exit:
            # If we're shutting down, kill the flow to avoid processing
            try:
                flow.kill()
            except Exception:
                pass
            return

        # Skip non-API requests early
        if not self.is_api_request(flow):
            self.filtered_count += 1
            return

        try:
            self.request_count += 1
            request_id = str(uuid.uuid4())

            # Store request data
            query_params: Dict[str, List[str]] = {}
            try:
                # mitmproxy query may behave like multidict; normalize to lists
                for key, values in getattr(flow.request, 'query', {}).items():
                    # values may already be a list-like
                    if isinstance(values, (list, tuple)):
                        query_params[key] = list(values)
                    else:
                        query_params[key] = [values]
            except Exception:
                query_params = {}

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
            self.logger.error(f"Error processing request: {e}", exc_info=True)

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a server response is received."""
        if self.should_exit or 'request_id' not in getattr(flow, 'metadata', {}):
            return

        try:
            request_id = flow.metadata.get('request_id')
            if not request_id or request_id not in self.request_map:
                return

            request_data = self.request_map.pop(request_id)

            # Calculate response time
            response_time = (time.time() - request_data['start_time']) * 1000  # in ms

            # Get response body and ensure it's a valid type
            body = self.safe_get_text(flow.response)

            # Convert None/boolean bodies to empty strings to avoid validation errors
            if body is None or isinstance(body, bool):
                body = str(body) if body is not None else ""

            # Create response data
            response_data = {
                'status_code': getattr(flow.response, 'status_code', 0),
                'reason': getattr(flow.response, 'reason', '') or "",
                'headers': dict(getattr(flow.response, 'headers', {})),
                'body': body,
                'response_time_ms': response_time,
                'timestamp': datetime.utcnow().isoformat(),
            }

            # Ensure query_params is properly formatted as Dict[str, List[str]]
            request_dict = request_data['request'].copy()
            if 'query_params' in request_dict:
                query_params = request_dict['query_params']
                if hasattr(query_params, 'items'):
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
            self.logger.info(
                f"[{api_call.request.method}] {api_call.request.url} "
                f"-> {api_call.response.status_code} "
                f"({api_call.response.response_time_ms:.2f}ms)"
            )

            # Save to file periodically
            if len(self.api_calls) % 10 == 0:
                self._save_to_file()

        except Exception as e:
            self.logger.error(f"Error processing response: {e}", exc_info=True)

    def _save_to_file(self) -> None:
        """Save captured API calls to file."""
        if not self.api_calls:
            self.logger.debug("No API calls to save")
            return

        try:
            output_path = Path(self.output_file).absolute()
            self.logger.debug(f"Saving {len(self.api_calls)} API calls to {output_path}")

            # Convert API calls to dictionaries
            api_calls_dict = [call.dict() for call in self.api_calls]

            # Save to file
            if save_to_file(api_calls_dict, output_path):
                self.logger.debug(f"Successfully saved API calls to {output_path}")
            else:
                self.logger.error(f"Failed to save API calls to {output_path}")

        except Exception as e:
            self.logger.error(f"Error saving API calls to file: {e}", exc_info=True)
            # Try to save to a fallback location if the original location fails
            try:
                fallback_path = Path("api_calls_fallback.json").absolute()
                self.logger.error(f"Attempting to save to fallback location: {fallback_path}")
                if save_to_file(api_calls_dict, fallback_path):
                    self.logger.error(f"Successfully saved API calls to fallback location: {fallback_path}")
            except Exception as fallback_error:
                self.logger.error(f"Failed to save to fallback location: {fallback_error}", exc_info=True)

    async def start(self):
        """Start the proxy server."""
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy import options

        # Set up mitmproxy options
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=not bool(self.ssl_verify),
        )

        # Create and configure the proxy server
        m = DumpMaster(opts)
        m.addons.add(self)

        # Set up signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            self.logger.info("Received shutdown signal. Initiating graceful shutdown...")
            try:
                asyncio.create_task(self._graceful_shutdown(m))
            except Exception:
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._graceful_shutdown(m))
                except Exception:
                    asyncio.run(self._graceful_shutdown(m))

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, signal_handler)
            except (ValueError, RuntimeError) as e:
                self.logger.warning(f"Could not set signal handler for {sig}: {e}")

        try:
            # Start the proxy server
            self.logger.info(f"Starting API Scanner on http://{self.host}:{self.port}")
            self.logger.info("Press Ctrl+C to stop")

            # DumpMaster.run is blocking; run it in a thread to keep compatibility with asyncio loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, m.run)

            # Wait for shutdown event
            await self._shutdown_event.wait()

        except asyncio.CancelledError:
            await self._graceful_shutdown(m)
        except Exception as e:
            self.logger.error(f"Error in proxy server: {e}", exc_info=True)
            await self._graceful_shutdown(m)
        finally:
            if getattr(m, 'running', False):
                m.shutdown()

    async def _graceful_shutdown(self, master):
        """Perform graceful shutdown of the proxy server."""
        if self._shutdown_initiated:
            return

        self._shutdown_initiated = True
        self.logger.info("Shutting down gracefully. Please wait...")

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
        try:
            self._shutdown_event.set()
        except Exception:
            # If event is not settable in this context, ignore
            pass

    def done(self) -> None:
        """Called when the proxy shuts down."""
        try:
            # Save any remaining API calls
            if self.api_calls:
                self._save_to_file()

            # Log summary
            self.logger.info("" + "=" * 80)
            self.logger.info("API Scan Complete")
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
                status_codes: Dict[int, int] = {}
                for call in self.api_calls:
                    if call.response:
                        status = call.response.status_code
                        status_codes[status] = status_codes.get(status, 0) + 1

                self.logger.info("Status Codes:")
                for code, count in sorted(status_codes.items()):
                    self.logger.info(f"  - {code}: {count}")

                # Count HTTP methods
                methods: Dict[str, int] = {}
                for call in self.api_calls:
                    method = call.request.method
                    methods[method] = methods.get(method, 0) + 1

                self.logger.info("HTTP Methods:")
                for method, count in sorted(methods.items()):
                    self.logger.info(f"  - {method}: {count}")

                # Count domains
                domains: Dict[str, int] = {}
                for call in self.api_calls:
                    domain = urlparse(call.request.url).netloc
                    domains[domain] = domains.get(domain, 0) + 1

                self.logger.info("Top Domains:")
                for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
                    self.logger.info(f"  - {domain}: {count}")

            self.logger.info("=" * 80)

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)
