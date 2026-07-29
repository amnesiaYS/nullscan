"""ASCII banner for the nullsec/dedsec aesthetic."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

BANNER_ART = r"""
 _   _ _ _   ____                 
| \ | | | | / ___|  ___  _ __   ___ _ __
|  \| | | | \___ \ / _ \| '_ \ / _ \ '__|
| |\  | | | | ___) | (_) | | | |  __/ |   
|_| \_|_|_| |____/ \___/|_| |_|\___|_|   
"""

TAGLINE = "// privacy is not a crime — recon in the silence"
VERSION_LINE = "v{version} · nullsec collective · MIT"


def render_banner(console: Console, version: str) -> None:
    """Print the banner to a Rich console.

    Renders the ASCII art in matrix green, then the tagline and version.
    """
    title = Text(BANNER_ART, style="primary")
    console.print(title)
    console.print(f"[accent]{TAGLINE}[/accent]")
    console.print(f"[muted]{VERSION_LINE.format(version=version)}[/muted]")
    console.print()