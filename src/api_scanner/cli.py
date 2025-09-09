"""
Command-line interface for the API Scanner.
"""
import argparse
import asyncio
import signal
import sys
from typing import Optional

from mitmproxy import options

from .core import ApiSniffer
from .config.config import (
    PROXY_HOST, PROXY_PORT, SSL_VERIFY,
    OUTPUT_FILE, OUTPUT_DIR, LOG_LEVEL
)

def parse_args(args=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='API Scanner - A tool for intercepting and analyzing API requests')
    parser.add_argument('--host', type=str, default=PROXY_HOST or '127.0.0.1',
                      help=f'Proxy host to listen on (default: {PROXY_HOST or "127.0.0.1"})')
    parser.add_argument('--port', type=int, default=PROXY_PORT or 8080,
                      help=f'Proxy port to listen on (default: {PROXY_PORT or 8080})')
    parser.add_argument('--no-ssl-verify', action='store_true',
                      help='Disable SSL certificate verification')
    parser.add_argument('--output', type=str, default=str(OUTPUT_FILE),
                      help=f'Output file path (default: {OUTPUT_FILE})')
    parser.add_argument('--log-level', type=str, default=LOG_LEVEL,
                      help=f'Logging level (default: {LOG_LEVEL})')
    
    return parser.parse_args(args)

async def start(sniffer: Optional[ApiSniffer] = None, host: str = None, port: int = None, 
               ssl_verify: bool = None, output: str = None) -> None:
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
        sniffer = ApiSniffer()
    
    # Use provided values or fall back to config
    host = host or PROXY_HOST or '127.0.0.1'
    port = port or PROXY_PORT or 8080
    ssl_verify = ssl_verify if ssl_verify is not None else SSL_VERIFY
    output = output or str(OUTPUT_FILE)
    
    # Log the configuration being used
    logger = sniffer.logger
    logger.debug(f"Proxy configuration - Host: {host}, Port: {port}, SSL Verify: {ssl_verify}")
    
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
    logger.info("Press Ctrl+C to stop")
    
    try:
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

def main(args=None):
    """Entry point for the CLI."""
    args = parse_args(args)
    
    # Update config with command line arguments
    global PROXY_HOST, PROXY_PORT, SSL_VERIFY, OUTPUT_FILE, LOG_LEVEL
    PROXY_HOST = args.host
    PROXY_PORT = args.port
    SSL_VERIFY = not args.no_ssl_verify
    OUTPUT_FILE = args.output
    LOG_LEVEL = args.log_level
    
    try:
        asyncio.run(start())
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
