"""ASCII banner for nullscan."""

from __future__ import annotations

import platform
import socket
from datetime import datetime

from rich.console import Console

BANNER_ART = r"""
 _   _ _ _   ____                 
| \ | | | | / ___|  ___  _ __   ___ _ __
|  \| | | | \___ \ / _ \| '_ \ / _ \ '__|
| |\  | | | | ___) | (_) | | | |  __/ |   
|_| \_|_|_| |____/ \___/|_| |_|\___|_|   
"""

TAGLINE = "// privacy is not a crime — recon in the silence"


def render_banner(
    console: Console,
    version: str,
    *,
    show_system_info: bool = True,
    keys_summary: list[tuple[str, str]] | None = None,
    theme_name: str | None = None,
) -> None:
    """Print the banner plus optional system info and API key status."""
    console.print(BANNER_ART, style="primary")
    console.print(f"[accent]{TAGLINE}[/accent]")
    console.print(f"[muted]nullscan {version} · nullsec collective · MIT[/muted]")

    if show_system_info:
        host = socket.gethostname()
        os_name = platform.system().lower()
        py_ver = platform.python_version()
        console.print(f"[muted]host: {host} · {os_name} · python {py_ver}[/muted]")

    if keys_summary:
        keys_line = " · ".join(f"{name}={status}" for name, status in keys_summary)
        console.print(f"[muted]keys: {keys_line}[/muted]")

    if theme_name:
        console.print(f"[muted]theme: {theme_name}[/muted]")

    console.print(f"[muted]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/muted]")
    console.print()