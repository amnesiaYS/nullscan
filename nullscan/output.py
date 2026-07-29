"""Output helpers: rich tables/panels, JSON, markdown reports, file output."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .theme import make_console, status


def stderr_console(theme: str = "matrix", no_color: bool = False) -> Console:
    """Console for status/progress messages. Always writes to stderr."""
    return make_console(theme=theme, no_color=no_color, file=sys.stderr)


def stdout_console(theme: str = "matrix", no_color: bool = False) -> Console:
    """Console for data output. Writes to stdout (or a file when redirected)."""
    return make_console(theme=theme, no_color=no_color, file=sys.stdout)


def print_status(console: Console, kind: str, message: str) -> None:
    """Print a themed status line."""
    console.print(status(kind, message))


def print_table(
    console: Console,
    title: str,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    styles: Sequence[str | None] | None = None,
) -> None:
    """Print a themed rich table."""
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
    items: Mapping[str, Any],
) -> None:
    """Print a key/value panel."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="accent", no_wrap=True)
    table.add_column(style="primary")
    for key, value in items.items():
        rendered = (
            str(value) if not isinstance(value, (list, dict))
            else json.dumps(value, ensure_ascii=False)
        )
        table.add_row(f"{key}:", rendered)
    console.print(Panel(table, title=f"[title]{title}[/title]", border_style="accent"))


def print_list_panel(
    console: Console,
    title: str,
    items: Sequence[str],
    *,
    empty_message: str = "(none)",
) -> None:
    """Print a panel containing a list of strings (one per line)."""
    body = "\n".join(items) if items else f"[muted]{empty_message}[/muted]"
    console.print(Panel(body, title=f"[title]{title}[/title]", border_style="accent"))


def dump_json(file, data: Any) -> None:
    """Write data as JSON to a file-like object (bypasses rich styling)."""
    json.dump(data, file, indent=2, ensure_ascii=False, default=str)
    file.write("\n")


def write_output(
    output_path: Path | None,
    data: Any,
    *,
    format: str = "table",
    target: str = "",
    module: str = "",
) -> None:
    """Write scan results to stdout (or to a file if ``output_path`` is set).

    ``format`` is one of: ``table``, ``json``, ``markdown``.
    """
    if output_path is not None:
        target_file = output_path.open("w", encoding="utf-8")
    else:
        target_file = sys.stdout

    try:
        if format == "json":
            payload = {
                "tool": "nullscan",
                "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "module": module,
                "target": target,
                "result": data,
            }
            dump_json(target_file, payload)
        elif format == "markdown":
            md = render_markdown(module=module, target=target, data=data)
            target_file.write(md)
            if not md.endswith("\n"):
                target_file.write("\n")
        else:  # table — but if writing to a file, render as plain text
            console = make_console(file=target_file, force_terminal=False)
            console.print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    finally:
        if target_file is not sys.stdout:
            target_file.close()


# ---------------------------------------------------------------------------
# Markdown rendering (generic)
# ---------------------------------------------------------------------------


def _render_value(value: Any) -> str:
    """Render a single value as markdown inline."""
    if value is None:
        return "_empty_"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "_empty_"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def render_markdown(*, module: str, target: str, data: Mapping[str, Any]) -> str:
    """Render a generic markdown report from a recon result dict.

    The rendering is best-effort: top-level dict keys become sections, nested
    dicts become definition lists, lists become bullet lists, scalars become
    bold key/value pairs.
    """
    lines: list[str] = [
        f"# nullscan — {module} report",
        "",
        f"- **target**: `{target}`",
        f"- **module**: `{module}`",
        f"- **generated**: {datetime.now(timezone.utc).isoformat()}",
        f"- **tool**: nullscan {__version__}",
        "",
    ]

    skip_keys = {"input", "target", "handle", "valid", "version", "domain", "local_part", "addr", "raw", "error"}

    for key, value in data.items():
        if key in skip_keys:
            continue
        if value is None or value == "" or value == [] or value == {}:
            continue

        title = key.replace("_", " ").title()
        if isinstance(value, dict):
            lines.append(f"## {title}")
            lines.append("")
            for k, v in value.items():
                lines.append(f"- **{k.replace('_', ' ')}**: {_render_value(v)}")
            lines.append("")
        elif isinstance(value, list):
            lines.append(f"## {title} ({len(value)})")
            lines.append("")
            for item in value[:200]:  # cap to avoid huge reports
                if isinstance(item, dict):
                    rendered = ", ".join(f"{k}: {_render_value(v)}" for k, v in item.items())
                    lines.append(f"- {rendered}")
                else:
                    lines.append(f"- {_render_value(item)}")
            if len(value) > 200:
                lines.append(f"- _… {len(value) - 200} more_")
            lines.append("")
        elif isinstance(value, bool):
            lines.append(f"- **{title}**: {'yes' if value else 'no'}")
        else:
            lines.append(f"- **{title}**: {_render_value(value)}")

    lines.append("")
    lines.append("---")
    lines.append("_Report generated by nullscan. Verify findings independently._")
    lines.append("")
    return "\n".join(lines)