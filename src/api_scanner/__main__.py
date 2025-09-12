"""API Scanner main entry point."""
import sys

def main():
    """Run the CLI with version check."""
    # Handle version flag before any imports to avoid unnecessary imports
    if '--version' in sys.argv or '-v' in sys.argv and len(sys.argv) == 2:
        from . import __version__
        print(f"api-scanner {__version__}")
        return 0
        
    from .cli import main as cli_main
    return cli_main()

if __name__ == "__main__":
    sys.exit(main() or 0)
