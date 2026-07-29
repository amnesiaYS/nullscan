"""Allow ``python -m nullscan`` to invoke the CLI."""

from nullscan.cli import app

if __name__ == "__main__":
    app()