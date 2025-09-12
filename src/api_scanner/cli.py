"""
Command-line interface for the API Scanner.
"""
import argparse
import asyncio
import signal
import sys
from typing import List, Optional

from mitmproxy import options

from .core import ApiSniffer
from .config.config import (
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL
)

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
    parser = argparse.ArgumentParser(description='API Scanner - A tool for intercepting and analyzing API requests')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1.0')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Start command (default)
    start_parser = subparsers.add_parser('start', help='Start the API scanner proxy')
    
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
    start_parser.add_argument('--filter', type=str, dest='filter_file', default=None,
                                  help='List of allowed hosts (can be specified multiple times)')
    start_parser.add_argument('--block-host', dest='blocked_hosts', action='append', default=None,
                            help='List of blocked hosts (can be specified multiple times)')
    
    # Positional targets: either a list of domains OR a single file path to a list
    start_parser.add_argument('targets', nargs='*', help='Domains to allowlist (e.g., example.com api.example.com) or a single file path containing one domain per line')
    
    # Optimize command
    optimize_parser = subparsers.add_parser('optimize', help='Optimize captured API data')
    optimize_parser.add_argument('input', help='Input JSON file with captured APIs')
    optimize_parser.add_argument('-o', '--output', help='Output file for optimized storage')
    optimize_parser.add_argument('--compress-threshold', type=int, default=1024,
                               help='Minimum response size in bytes to compress (0 = always compress)')
    optimize_parser.add_argument('--compression-method', 
                               choices=['zlib', 'gzip', 'base64', 'none'], 
                               default='zlib',
                               help='Compression method to use')
    optimize_parser.add_argument('--no-minify', action='store_false', dest='minify_json',
                               help='Disable JSON minification')
    optimize_parser.add_argument('--ignore-patterns', 
                               help='Comma-separated list of regex patterns to ignore, or path to a file containing patterns (one per line)')
    optimize_parser.add_argument('--no-default-filters', action='store_true',
                               help='Disable default ignore patterns')
    optimize_parser.add_argument('--stats', action='store_true', 
                               help='Show detailed statistics after processing')
    optimize_parser.add_argument('--quiet', action='store_true',
                               help='Suppress all output except errors')
    
    # Set start as the default command
    parser.set_defaults(func=start)
    
    # For backward compatibility, if no command is provided, assume 'start'
    if len(sys.argv) == 1 or not any(cmd in sys.argv[1] for cmd in ['start', 'optimize']):
        args = ['start'] + sys.argv[1:]
        return parser.parse_args(args)
    
    return parser.parse_args(args)

async def start(sniffer: Optional[ApiSniffer] = None, host: str = None, port: int = None, 
               ssl_verify: bool = None, output: str = None,
               filter_file: str = None, allowed_hosts: Optional[list] = None, blocked_hosts: Optional[list] = None) -> None:
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
    
    # Use provided sniffer or create a new one
    if sniffer is None:
        sniffer = ApiSniffer(filter_file=filter_file, allowed_hosts=allowed_hosts, blocked_hosts=blocked_hosts)
    else:
        # If an instance was provided, update its allowlist if specified
        if allowed_hosts:
            try:
                sniffer.allowed_hosts = set(allowed_hosts)
            except Exception:
                pass
        if blocked_hosts:
            try:
                sniffer.blocked_hosts = set(blocked_hosts)
            except Exception:
                pass
    
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
    if blocked_hosts:
        logger.debug(f"Blocked hosts: {blocked_hosts}")
    
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
    if blocked_hosts:
        logger.info(f"Host blocklist enabled: {blocked_hosts}")
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
    from .storage_optimizer import process_capture_file
    from pathlib import Path
    import os
    
    # Set default output filename if not provided
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_optimized.json")
    
    # Prepare ignore patterns
    ignore_patterns = []
    if not args.no_default_filters:
        ignore_patterns = None  # Will use defaults
    
    if args.ignore_patterns:
        # Check if the argument is a file
        ignore_file = Path(args.ignore_patterns)
        if ignore_file.is_file():
            if not args.quiet:
                print(f"📄 Loading ignore patterns from: {ignore_file}")
            ignore_patterns = load_patterns_from_file(str(ignore_file))
        else:
            # Treat as comma-separated patterns
            ignore_patterns = [p.strip() for p in args.ignore_patterns.split(',') if p.strip()]
    
    # Process the file
    try:
        if not args.quiet:
            print(f"🔍 Processing {input_path}...")
            if ignore_patterns is not None:
                print(f"   • Using {len(ignore_patterns)} custom ignore patterns")
            else:
                print("   • Using default ignore patterns")
            print(f"   • Compression: {args.compression_method} (threshold: {args.compress_threshold} bytes)")
            
        stats = process_capture_file(
            input_path=str(input_path),
            output_path=str(output_path),
            compress_threshold=args.compress_threshold,
            compression_method=args.compression_method,
            minify_json=args.minify_json,
            custom_ignore_patterns=ignore_patterns if ignore_patterns is not None else []
        )
        
        if not args.quiet or args.stats:
            if args.stats:
                # Import the print_stats function from optimize_storage
                from .optimize_storage import print_stats
                print_stats(stats)
            else:
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
    args = parse_args(args)
    
    # Set up logging
    import logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()) if hasattr(args, 'log_level') else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        if args.command == 'optimize':
            return optimize_command(args)
        else:  # start command or default
            # Handle --bind argument
            if hasattr(args, 'bind') and args.bind:
                args.host, args.port = args.bind
                
            # Start the proxy
            await start(
                host=args.host,
                port=args.port,
                ssl_verify=not getattr(args, 'no_ssl_verify', False),
                output=args.output,
                filter_file=getattr(args, 'filter_file', None),
                allowed_hosts=getattr(args, 'allowed_hosts', None),
                blocked_hosts=getattr(args, 'blocked_hosts', None)
            )
    except KeyboardInterrupt:
        print("\nShutting down...")
        return 0
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
