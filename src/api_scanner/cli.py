"""
Command-line interface for the API Scanner.
"""
import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

from .version import __version__
from .core import ApiSniffer, ApiCall
from .storage_optimizer import OptimizedStorage
from pathlib import Path
import os
from .config.config import (
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL
)

# Set up logging
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args(args=None):
    """Parse command line arguments."""
    def parse_host_port(host_str):
        """Parse host:port format and return (host, port) tuple."""
        if ':' in host_str:
            host, port = host_str.rsplit(':', 1)
            try:
                return host, int(port)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {port}")
        return host_str, PROXY_PORT or 8080

    # Main parser
    parser = argparse.ArgumentParser(
        description='API Scanner - A tool for intercepting and analyzing API requests',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Start capturing API requests
  api-scanner start example.com
  
  # Specify custom host and port
  api-scanner start -H 0.0.0.0 -p 8888 example.com
  
  # Use a blocklist
  api-scanner start --block analytics.example.com example.com
  
  # Optimize captured data
  api-scanner optimize captured.json -o optimized.json
  
  # Show help for a specific command
  api-scanner start --help
  api-scanner optimize --help
'''
    )
    
    # Global arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Start command (default)
    start_parser = subparsers.add_parser(
        'start',
        help='Start the API scanner proxy',
        description='Start capturing API requests through the proxy',
        epilog='''
Examples:
  # Basic usage
  api-scanner start example.com
  
  # Multiple domains
  api-scanner start example.com api.example.com
  
  # With custom output
  api-scanner start -o output.json example.com
  
  # With SSL verification disabled
  api-scanner start -k example.com
  
  # With verbose logging
  api-scanner start -v example.com
'''
    )
    
    # Add a special argument for host:port format
    start_parser.add_argument('--bind', type=parse_host_port, metavar='HOST:PORT',
                           help=f'Bind address in format host:port (overrides --host and --port)')
    
    # Proxy options
    start_parser.add_argument('-H', '--host', type=str, default=PROXY_HOST or '127.0.0.1',
                            help=f'Proxy host to listen on (default: {PROXY_HOST or "127.0.0.1"})')
    start_parser.add_argument('-p', '--port', type=int, default=PROXY_PORT or 8080,
                            help=f'Proxy port to listen on (default: {PROXY_PORT or 8080})')
    start_parser.add_argument('-k', '--no-ssl-verify', action='store_true',
                            help='Disable SSL certificate verification (insecure)')
    
    # Output options
    start_parser.add_argument('-o', '--output', type=str, default=str(OUTPUT_FILE),
                            help=f'Output file path (default: {OUTPUT_FILE})')
    start_parser.add_argument('-l', '--log-level', type=str, default=LOG_LEVEL,
                            help=f'Logging level: DEBUG, INFO, WARNING, ERROR (default: {LOG_LEVEL})')
    
    # Filtering options
    filter_group = start_parser.add_argument_group('filtering options')
    filter_group.add_argument('--filter', type=str, dest='filter_file', default=None,
                            help='Path to a file containing filter patterns')
    
    # Blocking options
    blocking_group = start_parser.add_argument_group('blocking options')
    blocking_group.add_argument('-b', '--block', dest='blocked_hosts', nargs='+',
                              help='Block specific domains (space-separated). Can be used with allowed domains.')
    blocking_group.add_argument('--block-file', dest='block_file',
                              help='File containing a list of domains to block (one per line)')
    
    # Positional targets: list of domains to allow
    start_parser.add_argument('targets', nargs='*', 
                            help='Domains to allow (e.g., example.com api.example.com)')
    
    # Add a note about domain filtering
    start_parser.epilog = ('Note: You can use both allowed domains (positional args) and blocked domains (-b/--block or --block-file) together. ' 
                          'If no domains are specified, all domains will be allowed except blocked ones.')
    
    # Optimize command
    optimize_parser = subparsers.add_parser(
        'optimize',
        help='Optimize captured API storage',
        description='Optimize and clean captured API data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic optimization
  api-scanner optimize captured.json -o optimized.json
  
  # With gzip compression
  api-scanner optimize captured.json --compression-method gzip
  
  # Show optimization statistics
  api-scanner optimize captured.json --stats
  
  # Use custom ignore patterns
  api-scanner optimize captured.json --ignore-patterns ignore.txt
  
  # Disable default filters and minification
  api-scanner optimize captured.json --no-default-filters --no-minify
'''
    )
    optimize_parser.add_argument('input', help='Input JSON file with captured APIs')
    optimize_parser.add_argument('-o', '--output', help='Output file for optimized storage')
    
    # Compression options
    compression_group = optimize_parser.add_argument_group('compression options')
    compression_group.add_argument('--no-compression', action='store_true',
                                 help='Disable compression completely')
    compression_group.add_argument('--compress-threshold', type=int, default=1024,
                                 help='Minimum response size in bytes to compress (0 = always compress)')
    compression_group.add_argument('--compression-method', 
                                 choices=['zlib', 'gzip', 'base64'], 
                                 default='zlib',
                                 help='Compression method to use (default: zlib)')
    
    # Filtering options
    filter_group = optimize_parser.add_argument_group('filtering options')
    filter_group.add_argument('--no-filters', action='store_true',
                            help='Disable all filtering (ignore patterns)')
    filter_group.add_argument('--ignore-patterns', 
                            help='Comma-separated list of regex patterns to ignore, or path to a file containing patterns (one per line)')
    filter_group.add_argument('--no-default-filters', action='store_true',
                            help='Disable built-in ignore patterns')
    
    # Output options
    output_group = optimize_parser.add_argument_group('output options')
    output_group.add_argument('--no-minify', action='store_false', dest='minify_json',
                            help='Disable JSON minification')
    output_group.add_argument('--stats', action='store_true', 
                            help='Show detailed statistics after processing')
    output_group.add_argument('--quiet', action='store_true',
                            help='Suppress all output except errors')
    
    # Set start as the default command
    parser.set_defaults(func=start)
    
    # Parse arguments
    parsed_args = parser.parse_args(args)
    
    # Set up logging level based on verbosity
    if parsed_args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # For backward compatibility, if no command is provided, assume 'start'
    if parsed_args.command is None:
        if len(sys.argv) == 1 or not any(cmd in sys.argv[1] for cmd in ['start', 'optimize']):
            args = ['start'] + sys.argv[1:]
            return parser.parse_args(args)
    
    return parsed_args

def load_hosts_from_file(file_path: str) -> List[str]:
    """Load a list of hosts from a file, one per line."""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        logging.error(f"Error loading hosts from {file_path}: {e}")
        return []

async def start(sniffer: Optional[ApiSniffer] = None, host: str = None, port: int = None, 
               ssl_verify: bool = None, output: str = None,
               filter_file: str = None, allowed_hosts: Optional[list] = None,
               blocked_hosts: Optional[List[str]] = None, block_file: Optional[str] = None) -> None:
    """
    Start the API scanner.
    
    Args:
        sniffer: Optional ApiSniffer instance. If not provided, a new one will be created.
        host: Proxy host to listen on. Uses config value if None.
        port: Proxy port to listen on. Uses config value if None.
        ssl_verify: Whether to verify SSL certificates. Uses config value if None.
        output: Output file path. Uses config value if None.
    """
    from mitmproxy.tools.dump import DumpMaster
    
    # Process blocked hosts from file if provided
    final_blocked_hosts = set(blocked_hosts or [])
    if block_file:
        final_blocked_hosts.update(load_hosts_from_file(block_file))

    # Use provided sniffer or create a new one
    if sniffer is None:
        sniffer = ApiSniffer(
            filter_file=filter_file, 
            allowed_hosts=allowed_hosts,
            blocked_hosts=list(final_blocked_hosts) if final_blocked_hosts else None,
            host=host,
            port=port,
            ssl_verify=ssl_verify,
            output=output
        )
    else:
        # If an instance was provided, update its allowlist if specified
        if allowed_hosts:
            try:
                sniffer.allowed_hosts = set(allowed_hosts)
            except Exception as e:
                logger.warning(f"Failed to update allowed_hosts: {e}")
        
        # Update other parameters if provided
        if host is not None:
            sniffer.host = host
        if port is not None:
            sniffer.port = port
        if ssl_verify is not None:
            sniffer.ssl_verify = ssl_verify
        if output is not None:
            sniffer.output = output
    
    # Use provided values or fall back to config
    host = host or PROXY_HOST or '127.0.0.1'
    port = port or PROXY_PORT or 8080
    ssl_verify = ssl_verify if ssl_verify is not None else SSL_VERIFY
    output = output or str(OUTPUT_FILE)
    
    # Log the configuration being used
    logger = sniffer.logger
    logger.debug(f"Proxy configuration - Host: {host}, Port: {port}, SSL Verify: {ssl_verify}")
    if allowed_hosts:
        logger.debug(f"Allowed hosts: {allowed_hosts}")
    if hasattr(sniffer, 'blocked_hosts') and sniffer.blocked_hosts:
        logger.debug(f"Blocked hosts: {sniffer.blocked_hosts}")
    
    # Set up proxy options
    opts = options.Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=not ssl_verify,
    )
    
    # Initialize DumpMaster
    m = DumpMaster(
        opts,
        with_termlog=True,
        with_dumper=False
    )
    m.addons.add(sniffer)
    
    # Set up graceful shutdown flag and event
    shutdown_event = asyncio.Event()
    
    async def graceful_shutdown():
        """Perform graceful shutdown of the proxy server."""
        if not hasattr(graceful_shutdown, '_shutdown_initiated'):
            graceful_shutdown._shutdown_initiated = True
            logger.info("\nShutting down gracefully. Please wait...")
            
            # Signal all components to shut down
            sniffer.should_exit = True
            
            # Stop the proxy server
            if m.running:
                m.shutdown()
            
            # Wait for any pending tasks to complete
            await asyncio.sleep(0.5)
            
            # Signal that shutdown is complete
            shutdown_event.set()
    
    # Register shutdown callback
    sniffer.add_shutdown_callback(lambda: asyncio.create_task(graceful_shutdown()))
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("\nReceived shutdown signal. Initiating graceful shutdown...")
        asyncio.create_task(graceful_shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Log startup information
    logger.info(f"Starting proxy on {host}:{port}")
    logger.info(f"Output file: {output}")
    if allowed_hosts:
        logger.info(f"Host allowlist enabled: {allowed_hosts}")
    logger.info("Press Ctrl+C to stop")
    
    # Ensure sniffer writes to the computed output
    try:
        sniffer.output = output
        # Start the proxy server
        await m.run()
        
        # Wait for shutdown to complete if it was initiated
        if not shutdown_event.is_set():
            await graceful_shutdown()
        
        # Wait for shutdown to complete
        await shutdown_event.wait()
        
    except asyncio.CancelledError:
        await graceful_shutdown()
    except KeyboardInterrupt:
        await graceful_shutdown()
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        await graceful_shutdown()
    finally:
        # Final cleanup
        if m.running:
            m.shutdown()
        logger.info("Proxy server stopped successfully")

def load_patterns_from_file(file_path: str) -> List[str]:
    """Load patterns from a file, one per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        raise ValueError(f"Failed to load patterns from {file_path}: {e}")

def optimize_command(args):
    """Handle the optimize command."""
    from .storage_optimizer import process_capture_file, OptimizedStorage
    from pathlib import Path
    import os
    
    # Set default output filename if not provided
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_optimized.json")
    
    # Handle compression settings
    compression_method = None if args.no_compression else args.compression_method
    
    # Handle ignore patterns
    use_ignore_patterns = not (args.no_filters or args.no_default_filters)
    ignore_patterns = []
    
    if use_ignore_patterns and not args.no_default_filters:
        ignore_patterns = None  # Will use defaults
    
    if args.ignore_patterns and not args.no_filters:
        # Check if the argument is a file
        ignore_file = Path(args.ignore_patterns)
        if ignore_file.is_file():
            if not args.quiet:
                print(f"📄 Loading ignore patterns from: {ignore_file}")
            ignore_patterns = load_patterns_from_file(str(ignore_file))
            use_ignore_patterns = True
        else:
            # Treat as comma-separated patterns
            ignore_patterns = [p.strip() for p in args.ignore_patterns.split(',') if p.strip()]
            use_ignore_patterns = True
    
    # Process the file
    try:
        if not args.quiet:
            print(f"🔍 Processing {input_path}...")
            
            # Print compression info
            if compression_method:
                print(f"   • Compression: {compression_method} (threshold: {args.compress_threshold} bytes)")
            else:
                print("   • Compression: disabled")
                
            # Print filtering info
            if args.no_filters:
                print("   • Filters: disabled")
            else:
                if ignore_patterns is not None:
                    print(f"   • Using {len(ignore_patterns)} custom ignore patterns")
                elif not args.no_default_filters:
                    print("   • Using default ignore patterns")
                else:
                    print("   • No ignore patterns")
        
        # Create optimizer with current settings
        optimizer = OptimizedStorage(
            compression_method=compression_method,
            compress_threshold=args.compress_threshold,
            minify_json=args.minify_json,
            use_ignore_patterns=use_ignore_patterns
        )
        
        # Process the capture file
        stats = process_capture_file(
            input_file=str(input_path),
            output_file=str(output_path),
            optimizer=optimizer,
            ignore_patterns=ignore_patterns,
            show_stats=args.stats,
            quiet=args.quiet
        )
        
        if not args.quiet and stats:
            print(f"✅ Optimized storage saved to: {output_path}")
            print(f"   • Reduced {stats['total_requests']:,} requests to {stats['unique_responses']:,} unique responses")
            if stats.get('compression_ratio', 0) > 0:
                print(f"   • Compression ratio: {stats['compression_ratio']:.1f}x")
            print(f"   • Output size: {stats['output_size'] / 1024:.2f} KB")
                
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

async def async_main(args=None):
    """Async entry point for the CLI."""
    try:
        args = parse_args(args)
        
        if args.command == 'optimize':
            return await optimize_command(args)
        
        # Handle start command (default)
        if hasattr(args, 'bind') and args.bind:
            args.host, args.port = args.bind
        
        # Handle blocked hosts (takes precedence over allowed hosts)
        blocked_hosts = []
        if hasattr(args, 'blocked_hosts') and args.blocked_hosts:
            blocked_hosts.extend(args.blocked_hosts)
        if hasattr(args, 'block_file') and args.block_file:
            blocked_hosts.extend(load_hosts_from_file(args.block_file))
        
        # Handle allowed hosts (only if no blocked hosts specified)
        allowed_hosts = []
        if not blocked_hosts and hasattr(args, 'targets') and args.targets:
            # If a single file is provided, read hosts from it
            if len(args.targets) == 1 and Path(args.targets[0]).is_file():
                allowed_hosts = load_hosts_from_file(args.targets[0])
            else:
                allowed_hosts = args.targets
        
        # Verify output directory is writable
        if args.output:
            try:
                output_path = Path(args.output).absolute()
                output_dir = output_path.parent
                
                # Create the directory if it doesn't exist
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Test if directory is writable
                test_file = output_dir / '.api_scanner_test'
                try:
                    test_file.touch()
                    test_file.unlink()
                except OSError as e:
                    logger.error(f"Output directory {output_dir} is not writable: {e}")
                    return 1
                    
                logger.info(f"Output will be saved to: {output_path}")
                
            except Exception as e:
                logger.error(f"Error setting up output directory: {e}")
                return 1
        
        # Start the proxy
        try:
            await start(
                host=args.host,
                port=args.port,
                ssl_verify=not args.no_ssl_verify,
                output=args.output,
                filter_file=args.filter_file,
                allowed_hosts=allowed_hosts or None,
                blocked_hosts=blocked_hosts or None,
                block_file=args.block_file
            )
        except Exception as e:
            logging.error(f"Error: {e}")
            if hasattr(args, 'log_level') and args.log_level.upper() == 'DEBUG':
                import traceback
                traceback.print_exc()
            return 1
    except Exception as e:
        logging.error(f"Error: {e}")
        if hasattr(args, 'log_level') and args.log_level.upper() == 'DEBUG':
            import traceback
            traceback.print_exc()
        return 1
    return 0

def main(args=None):
    """Synchronous entry point for the CLI."""
    import asyncio
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nShutting down...")
        return 0

if __name__ == "__main__":
    sys.exit(main())
