"""Output helpers: rich tables, panels, JSON dumps."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .theme import status


def print_status(console: Console, kind: str, message: str) -> None:
    """Print a themed status line."""
    console.print(status(kind, message))


def print_table(
    console: Console,
    title: str,
    headers: list[str],
    rows: Iterable[list[Any]],
    *,
    styles: list[str] | None = None,
) -> None:
    """Print a themed rich table.

    Each row is a list of cell values. ``styles`` optionally overrides the
    style for specific columns (by index).
    """
    table = Table(title=f"[title]{title}[/title]", show_header=True, header_style="title")
    for header in headers:
        table.add_column(header, style="primary", overflow="fold")
    for row in rows:
        rendered: list[Any] = []
        for i, cell in enumerate(row):
            style = styles[i] if styles and i < len(styles) else None
            if style is not None:
                rendered.append(f"[{style}]{cell}[/{style}]")
            else:
                rendered.append(str(cell) if cell is not None else "")
        table.add_row(*rendered)
    console.print(table)


def print_kv_panel(
    console: Console,
    title: str,
    items: dict[str, Any],
    *,
    style_map: dict[str, str] | None = None,
) -> None:
    """Print a key/value panel (one row per item, with styled keys)."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="accent", no_wrap=True)
    table.add_column(style="primary")
    style_map = style_map or {}
    for key, value in items.items():
        rendered_value = (
            str(value) if not isinstance(value, (list, dict)) else json.dumps(value, ensure_ascii=False)
        )
        table.add_row(f"{key}:", rendered_value)
    console.print(Panel(table, title=f"[title]{title}[/title]", border_style="accent"))


def print_list_panel(
    console: Console,
    title: str,
    items: list[str],
    *,
    empty_message: str = "(none)",
    style: str = "primary",
) -> None:
    """Print a panel containing a list of strings (one per line)."""
    body = "\n".join(items) if items else f"[muted]{empty_message}[/muted]"
    console.print(Panel(body, title=f"[title]{title}[/title]", border_style="accent"))


def dump_json(console: Console, data: Any) -> None:
    """Print data as JSON to stdout (bypassing rich styling)."""
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")