# Configure logging format before any other imports
import logging

# Configure our module logger with a simple format
cli_logger = logging.getLogger("api_scanner.cli")
cli_logger.handlers = []  # Clear any existing handlers

# Let mitmproxy handle its own logging

# Create and configure handler for our logs
handler = logging.StreamHandler()
formatter = logging.Formatter(
    "[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
handler.setFormatter(formatter)
cli_logger.addHandler(handler)
cli_logger.setLevel(logging.INFO)
cli_logger.propagate = False  # Only use our handler

"""
Command-line interface for the API Scanner.

It implements the commands used in deployment: starting the mitmproxy-based proxy (capturing
API traffic) and optimizing captured storage. The implementation aims to
preserve backward compatibility with existing installations and command-line
behaviour, while integrating with the project's configuration, logging, and
storage optimizer components.

Keep this header synchronized with repository documentation and release notes.
"""

import argparse
import asyncio
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .version import __version__
from .core import ApiSniffer, ApiCall
from .storage_optimizer import OptimizedStorage, process_capture_file
from .config import (
    PROXY_HOST,
    PROXY_PORT,
    SSL_VERIFY,
    OUTPUT_FILE,
    OUTPUT_DIR,
    LOG_LEVEL,
    MAX_CONTENT_LENGTH,
    ALLOWED_HOSTS,
    EXCLUDED_EXTENSIONS,
    EXCLUDED_PATHS,
    API_PATHS,
    CONTENT_TYPES,
    ACCEPT_HEADERS,
    load_filter_config,
    FILTER_CONFIG,
    load_config,
    config as default_config,
)

# Module logger (already set up above)
logger = cli_logger


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""

    def parse_host_port(host_str: str) -> Tuple[str, int]:
        """Parse host:port format and return (host, port).

        If port is missing, fall back to PROXY_PORT or 8080.
        """
        if ':' in host_str:
            host, port = host_str.rsplit(':', 1)
            try:
                return host, int(port)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {port}")
        return host_str, int(PROXY_PORT or 8080)

    parser = argparse.ArgumentParser(
        description='API Scanner - A tool for intercepting and analyzing API requests',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Start capturing API requests
  api-scanner start example.com

  # Start with custom host and port
  api-scanner start -H 0.0.0.0 -p 8888 example.com

  # Optimize captured data
  api-scanner optimize captured.json -o optimized.json
''',
    )

    # Global verbosity
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # START command
    start_parser = subparsers.add_parser(
        'start',
        help='Start the API scanner proxy',
        description='Start capturing API requests through the proxy',
    )

    # Positional domains (single definition only)
    start_parser.add_argument(
        'domains',
        nargs='*',
        help=(
            "Domain(s) to capture API requests for. If no domains are specified, "
            "all traffic will be captured. Use --all to explicitly capture all traffic."
        ),
    )

    start_parser.add_argument('--all', action='store_true', help='Capture all traffic regardless of domain')

    # Bind shorthand (host:port)
    start_parser.add_argument('--bind', type=parse_host_port, metavar='HOST:PORT',
                              help='Bind address in format host:port (overrides --host and --port)')

    # Proxy options
    start_parser.add_argument('-H', '--host', type=str, default=PROXY_HOST or '127.0.0.1',
                              help=f'Proxy host to listen on (default: {PROXY_HOST or "127.0.0.1"})')
    start_parser.add_argument('-p', '--port', type=int, default=int(PROXY_PORT or 8080),
                              help=f'Proxy port to listen on (default: {PROXY_PORT or 8080})')
    start_parser.add_argument('-k', '--no-ssl-verify', action='store_true',
                              help='Disable SSL certificate verification (insecure)')

    # Output & logging
    start_parser.add_argument('-o', '--output', type=str, default=str(OUTPUT_FILE),
                              help=f'Output file path (default: {OUTPUT_FILE})')
    start_parser.add_argument('-l', '--log-level', type=str, default=LOG_LEVEL,
                              help='Logging level: DEBUG, INFO, WARNING, ERROR')

    # Filters & blocking
    start_parser.add_argument('--filter', type=str, dest='filter_file', default=None,
                              help='Path to a file containing filter patterns')
    start_parser.add_argument('-b', '--block', dest='blocked_hosts', nargs='+',
                              help='Block specific domains (space-separated).')
    start_parser.add_argument('--block-file', dest='block_file', help='File containing a list of domains to block')
    start_parser.add_argument('--ignore-ui', action='store_true', help='Filter out UI assets (images, CSS, JS, etc.)')

    # OPTIMIZE command
    optimize_parser = subparsers.add_parser('optimize', help='Optimize captured API storage')
    optimize_parser.add_argument('input', help='Input JSON file with captured APIs')
    optimize_parser.add_argument('-o', '--output', help='Output file for optimized storage')

    compression_group = optimize_parser.add_argument_group('compression options')
    compression_group.add_argument('--no-compression', action='store_true', help='Disable compression')
    compression_group.add_argument('--compress-threshold', type=int, default=1024,
                                   help='Minimum response size in bytes to compress')
    compression_group.add_argument('--compression-method', choices=['zlib', 'gzip', 'base64'],
                                   default='zlib', help='Compression method to use')

    filter_group = optimize_parser.add_argument_group('filtering options')
    filter_group.add_argument('--no-filters', action='store_true', help='Disable filters')
    filter_group.add_argument('--ignore-patterns', help='Comma-separated regex patterns or path to file')
    filter_group.add_argument('--no-default-filters', action='store_true', help='Disable built-in ignore patterns')

    output_group = optimize_parser.add_argument_group('output options')
    output_group.add_argument('--no-minify', action='store_false', dest='minify_json', help='Disable JSON minification')
    output_group.add_argument('--stats', action='store_true', help='Show detailed statistics after processing')
    output_group.add_argument('--quiet', action='store_true', help='Suppress non-error output')

    # Default command is 'start' (keeps compatibility with prior behavior)
    parser.set_defaults(command='start')

    parsed = parser.parse_args(args)

    # Adjust logging if verbose
    if getattr(parsed, 'verbose', False):
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug('Verbose logging enabled')

    return parsed


def load_hosts_from_file(file_path: str) -> List[str]:
    """Load a list of hosts from a file, one per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        logger.error(f"Error loading hosts from {file_path}: {e}")
        return []


async def start(
    sniffer: Optional[ApiSniffer] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    ssl_verify: Optional[bool] = None,
    output: Optional[str] = None,
    filter_file: Optional[str] = None,
    allowed_hosts: Optional[List[str]] = None,
    blocked_hosts: Optional[List[str]] = None,
    block_file: Optional[str] = None,
    ignore_ui: Optional[bool] = None,
    domain: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    """Start the API scanner proxy in an asyncio-friendly way.

    This function will run the mitmproxy DumpMaster in a background thread
    (using a dedicated event loop per thread) and coordinate graceful shutdown
    via signal handlers. The shutdown path enforces a timeout and will
    forcefully exit the process if mitmproxy does not stop within a
    reasonable period.
    """
    # Use provided config or fallback
    if config is None:
        config = default_config

    final_allowed = set(allowed_hosts or [])
    final_blocked = set(blocked_hosts or [])

    if domain:
        final_allowed.add(domain)
        if not domain.startswith('www.'):
            final_allowed.add(f'www.{domain}')

    if block_file:
        final_blocked.update(load_hosts_from_file(block_file))

    # Apply CLI overrides to config
    if output:
        output_path = Path(output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        config.setdefault('output', {})['filename'] = output_path.name
        config['output']['directory'] = str(output_path.parent)

    if host:
        config.setdefault('proxy', {})['host'] = host
    if port:
        config.setdefault('proxy', {})['port'] = port
    if ssl_verify is not None:
        config.setdefault('proxy', {})['ssl_verify'] = ssl_verify
    if ignore_ui is not None:
        config.setdefault('filters', {})['ignore_ui'] = ignore_ui
    if allowed_hosts:
        config.setdefault('filters', {})['allowed_hosts'] = allowed_hosts

    # Initialize sniffer if not provided
    if sniffer is None:
        sniffer = ApiSniffer(
            output_file=output or os.path.join(
                config.get('output', {}).get('directory', 'output'),
                config.get('output', {}).get('filename', 'captured_apis.json'),
            ),
            ignore_ui=config.get('filters', {}).get('ignore_ui', True),
            allowed_hosts=list(final_allowed),
            blocked_hosts=list(final_blocked),
            filter_file=filter_file,
            domain=domain,
            config=config,
        )
    else:
        # Update provided sniffer instance
        try:
            if allowed_hosts:
                sniffer.allowed_hosts = set(allowed_hosts)
            if host is not None:
                sniffer.host = host
            if port is not None:
                sniffer.port = port
            if ssl_verify is not None:
                sniffer.ssl_verify = ssl_verify
            if output is not None:
                sniffer.output = output
            if ignore_ui is not None:
                sniffer.ignore_ui = ignore_ui
        except Exception as e:
            logger.warning(f"Failed to update provided sniffer instance: {e}")

    # Final runtime values
    host = host or config.get('proxy', {}).get('host', PROXY_HOST or '127.0.0.1')
    port = port or config.get('proxy', {}).get('port', PROXY_PORT or 8080)
    ssl_verify = ssl_verify if ssl_verify is not None else config.get('proxy', {}).get('ssl_verify', SSL_VERIFY)
    output = output or os.path.join(
        config.get('output', {}).get('directory', 'output'),
        config.get('output', {}).get('filename', 'captured_apis.json'),
    )

    cli_logger = sniffer.logger if hasattr(sniffer, 'logger') else logger
    cli_logger.debug(f"Proxy configuration - Host: {host}, Port: {port}, SSL Verify: {ssl_verify}")
    if final_allowed:
        cli_logger.debug(f"Allowed hosts: {final_allowed}")
    if final_blocked:
        cli_logger.debug(f"Blocked hosts: {final_blocked}")

    opts = options.Options(listen_host=host, listen_port=port, ssl_insecure=not ssl_verify)

    m = DumpMaster(opts, with_termlog=True, with_dumper=False)
    m.addons.add(sniffer)

    # Threading event to know when proxy thread has stopped
    proxy_stopped = threading.Event()
    # Flag to avoid re-entrance
    shutdown_requested = threading.Event()

    # timeout (seconds) to wait for a clean shutdown before forcing exit
    SHUTDOWN_TIMEOUT = float(os.environ.get('API_SCANNER_SHUTDOWN_TIMEOUT', '8.0'))

    def run_proxy():
        """Run DumpMaster.run() inside its own event loop on this thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Expose loop so main thread can schedule shutdown on it
        setattr(m, "_proxy_loop", loop)
        try:
            loop.run_until_complete(m.run())
        except (KeyboardInterrupt, SystemExit):
            # Expected on shutdown
            pass
        except Exception as e:
            cli_logger.error(f"Error in proxy thread: {e}", exc_info=True)
        finally:
            # Ensure shutdown is attempted if not already
            try:
                if hasattr(m, "shutdown"):
                    try:
                        # If loop still running, call shutdown there
                        if not loop.is_closed():
                            # call shutdown synchronously in this loop
                            loop.run_until_complete(m.shutdown())
                    except Exception:
                        # best-effort
                        try:
                            m.shutdown()
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                if not loop.is_closed():
                    loop.close()
            except Exception:
                pass
            proxy_stopped.set()

    def request_shutdown(reason: str = None):
        """Request shutdown from main thread / signal handlers."""
        if shutdown_requested.is_set():
            # second time: force exit
            cli_logger.warning("Force shutdown requested. Terminating immediately.")
            os._exit(1)

        shutdown_requested.set()
        if reason:
            cli_logger.info(f"Shutdown requested: {reason}")
        else:
            cli_logger.info("Shutdown requested.")

        # Tell sniffer to stop collecting/processing (best-effort)
        try:
            if hasattr(sniffer, "should_exit"):
                sniffer.should_exit = True
        except Exception as e:
            cli_logger.debug(f"Error setting sniffer.should_exit: {e}")

        # If proxy loop is available, schedule m.shutdown() there (safe)
        loop = getattr(m, "_proxy_loop", None)
        if loop and not getattr(loop, "is_closed", lambda: True)():
            try:
                loop.call_soon_threadsafe(m.shutdown)
            except Exception as e:
                cli_logger.debug(f"Error scheduling m.shutdown() on proxy loop: {e}")
        else:
            # No proxy loop known -> try direct shutdown (best-effort)
            try:
                if hasattr(m, "shutdown"):
                    m.shutdown()
            except Exception as e:
                cli_logger.debug(f"Direct m.shutdown() attempt failed: {e}")

    # Attach shutdown callback on sniffer if provided (best-effort)
    try:
        if hasattr(sniffer, "add_shutdown_callback"):
            sniffer.add_shutdown_callback(lambda: request_shutdown("addon requested shutdown"))
    except Exception:
        pass

    # Register signal handlers
    def _signal_handler(sig_num, frame):
        sig_name = signal.Signals(sig_num).name if hasattr(signal, "Signals") else str(sig_num)
        cli_logger.info(f"Received signal {sig_name}; initiating graceful shutdown...")
        request_shutdown(f"signal {sig_name}")

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Set up logging and info
    output_filename = os.path.basename(output)
    cli_logger.info(f"Output file: {output_filename}")
    if final_allowed:
        cli_logger.info(f"Host allowlist enabled: {', '.join(final_allowed)}")
    cli_logger.info("Press Ctrl+C to stop")

    # Ensure sniffer writes to computed output
    try:
        sniffer.output = output
    except Exception as e:
        cli_logger.debug(f"Could not set output path: {e}")

    # Start proxy thread
    proxy_thread = threading.Thread(target=run_proxy, daemon=True, name="api-scanner-proxy")
    proxy_thread.start()

    # Main wait loop: wait until the proxy thread stops or shutdown is requested
    try:
        # Wait in short intervals so signals are handled promptly
        while True:
            if proxy_stopped.wait(0.1):
                # proxy stopped naturally
                break
            if shutdown_requested.is_set():
                # we asked for shutdown; wait bounded time for thread to exit
                cli_logger.info(f"Waiting up to {SHUTDOWN_TIMEOUT:.1f}s for proxy to stop...")
                start_wait = time.monotonic()
                while True:
                    if proxy_stopped.wait(0.1):
                        break
                    if time.monotonic() - start_wait >= SHUTDOWN_TIMEOUT:
                        cli_logger.warning("Shutdown timeout reached; forcing exit.")
                        # best-effort: attempt to close loop / shutdown again
                        loop = getattr(m, "_proxy_loop", None)
                        if loop and not getattr(loop, "is_closed", lambda: True)():
                            try:
                                loop.call_soon_threadsafe(m.shutdown)
                            except Exception:
                                pass
                        # Force exit to avoid indefinite hang
                        os._exit(1)
                break
    except KeyboardInterrupt:
        # Ctrl+C pressed during wait - request shutdown and wait short time
        cli_logger.info("Shutdown requested by user (KeyboardInterrupt).")
        request_shutdown("KeyboardInterrupt")
        try:
            proxy_stopped.wait(min(3.0, SHUTDOWN_TIMEOUT))
        except Exception:
            pass
    except Exception as e:
        cli_logger.error(f"Unexpected error in main thread: {e}", exc_info=True)
        request_shutdown("unexpected error")
        try:
            proxy_stopped.wait(3.0)
        except Exception:
            pass
    finally:
        # Ensure thread cleanup
        if proxy_thread.is_alive():
            proxy_thread.join(timeout=1.0)
        cli_logger.info("Proxy server stopped")


def load_patterns_from_file(file_path: str) -> List[str]:
    """Load patterns from a file, one per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        raise ValueError(f"Failed to load patterns from {file_path}: {e}")


def optimize_command(args: argparse.Namespace) -> int:
    """Handle the optimize command synchronously.

    Returns 0 on success, non-zero on failure.
    """
    try:
        input_path = Path(args.input)
        output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_optimized.json")

        compression_method = None if args.no_compression else args.compression_method
        use_ignore_patterns = not (args.no_filters or args.no_default_filters)
        ignore_patterns = []

        if use_ignore_patterns and not args.no_default_filters:
            ignore_patterns = None  # signal to use defaults

        if args.ignore_patterns and not args.no_filters:
            ipath = Path(args.ignore_patterns)
            if ipath.is_file():
                if not args.quiet:
                    print(f"📄 Loading ignore patterns from: {ipath}")
                ignore_patterns = load_patterns_from_file(str(ipath))
                use_ignore_patterns = True
            else:
                ignore_patterns = [p.strip() for p in args.ignore_patterns.split(',') if p.strip()]
                use_ignore_patterns = True

        if not args.quiet:
            print(f"🔍 Processing {input_path}...")
            if compression_method:
                print(f"   • Compression: {compression_method} (threshold: {args.compress_threshold} bytes)")
            else:
                print("   • Compression: disabled")

            if args.no_filters:
                print("   • Filters: disabled")
            else:
                if ignore_patterns is not None:
                    print(f"   • Using {len(ignore_patterns)} custom ignore patterns")
                elif not args.no_default_filters:
                    print("   • Using default ignore patterns")
                else:
                    print("   • No ignore patterns")

        optimizer = OptimizedStorage(
            compression_method=compression_method,
            compress_threshold=args.compress_threshold,
            minify_json=getattr(args, 'minify_json', True),
            use_ignore_patterns=use_ignore_patterns,
        )

        stats = process_capture_file(
            input_file=str(input_path),
            output_file=str(output_path),
            optimizer=optimizer,
            ignore_patterns=ignore_patterns,
            show_stats=args.stats,
            quiet=args.quiet,
        )

        if not args.quiet and stats:
            print(f"✅ Optimized storage saved to: {output_path}")
            print(f"   • Reduced {stats['total_requests']:,} requests to {stats['unique_responses']:,} unique responses")
            if stats.get('compression_ratio', 0) > 0:
                print(f"   • Compression ratio: {stats['compression_ratio']:.1f}x")
            print(f"   • Output size: {stats['output_size'] / 1024:.2f} KB")

    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if not getattr(args, 'quiet', False):
            import traceback

            traceback.print_exc()
        return 1

    return 0


async def async_main(argv: Optional[List[str]] = None) -> int:
    """Async entry point for the CLI."""
    try:
        args = parse_args(argv)

        # If optimize command, run synchronously and return its exit code
        if args.command == 'optimize':
            return optimize_command(args)

        # Handle bind -> host/port override
        if hasattr(args, 'bind') and args.bind:
            args.host, args.port = args.bind

        # Load/prepare config
        config = default_config

        # Output file handling
        output_file = None
        if hasattr(args, 'output') and args.output:
            output_path = Path(args.output).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_file = str(output_path)
            config.setdefault('output', {})['filename'] = output_path.name
            config['output']['directory'] = str(output_path.parent)

        # Apply CLI proxy/filter overrides
        if hasattr(args, 'host') and args.host:
            config.setdefault('proxy', {})['host'] = args.host
        if hasattr(args, 'port') and args.port:
            config.setdefault('proxy', {})['port'] = args.port
        if getattr(args, 'no_ssl_verify', False):
            config.setdefault('proxy', {})['ssl_verify'] = False
        if getattr(args, 'ignore_ui', False):
            config.setdefault('filters', {})['ignore_ui'] = True

        # Blocked hosts
        blocked_hosts: List[str] = []
        if getattr(args, 'blocked_hosts', None):
            blocked_hosts.extend(args.blocked_hosts)
        if getattr(args, 'block_file', None):
            blocked_hosts.extend(load_hosts_from_file(args.block_file))

        # Allowed hosts (domains)
        allowed_hosts: List[str] = []
        if getattr(args, 'domains', None):
            if len(args.domains) == 1 and Path(args.domains[0]).is_file():
                allowed_hosts = load_hosts_from_file(args.domains[0])
            else:
                allowed_hosts = args.domains

        # Warn if capturing all traffic unintentionally
        if not blocked_hosts and not allowed_hosts and not getattr(args, 'all', False):
            logger.warning(
                "No domains specified. Capturing all traffic. Use '--all' or specify domains to limit capture."
            )

        # Logging level
        log_level = getattr(args, 'log_level', 'INFO').upper()
        logging.getLogger().setLevel(log_level)
        logger.setLevel(log_level)

        logger.debug(f"Configuration: {config}")
        if allowed_hosts:
            logger.info(f"Allowing traffic for domains: {', '.join(allowed_hosts)}")
        if blocked_hosts:
            logger.info(f"Blocking traffic for domains: {', '.join(blocked_hosts)}")

        # Initialize sniffer
        sniffer = ApiSniffer(
            output_file=output_file,
            ignore_ui=config.get('filters', {}).get('ignore_ui', False),
            allowed_hosts=allowed_hosts,
            blocked_hosts=blocked_hosts,
            filter_file=getattr(args, 'filter_file', None),
            logger=logger,
            config=config,
        )

        # Start proxy (this is an awaitable)
        await start(
            host=args.host,
            port=args.port,
            ssl_verify=not getattr(args, 'no_ssl_verify', False),
            output=output_file,
            filter_file=getattr(args, 'filter_file', None),
            allowed_hosts=allowed_hosts,
            blocked_hosts=blocked_hosts,
            block_file=getattr(args, 'block_file', None),
            ignore_ui=config.get('filters', {}).get('ignore_ui', False),
            sniffer=sniffer,
            config=config,
        )

    except Exception as e:
        logger.error(f"Error: {e}")
        if getattr(e, 'args', None) and os.getenv('DEBUG') == '1':
            import traceback

            traceback.print_exc()
        return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Synchronous entry point for the CLI."""
    try:
        return asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        print("Shutting down...")
        return 0


if __name__ == '__main__':
    sys.exit(main())
