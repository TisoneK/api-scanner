"""API Scanner main entry point."""

def main():
    """Run the CLI."""
    from .cli import main as cli_main
    cli_main()

if __name__ == "__main__":
    main()
