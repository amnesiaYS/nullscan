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


# ---------------------------------------------------------------------------
# CSV rendering (flat key/value rows)
# ---------------------------------------------------------------------------


import csv as _csv
from io import StringIO as _StringIO


def render_csv(data: Any) -> str:
    """Render a recon result as CSV: one row per key/value pair.

    Nested dicts become ``key.subkey=value`` rows. Lists become
    ``key.0=value``, ``key.1=value``, etc.
    """
    buf = _StringIO()
    writer = _csv.writer(buf)
    writer.writerow(["key", "value"])

    def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                rows.extend(_flatten(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                rows.extend(_flatten(v, f"{prefix}.{i}" if prefix else str(i)))
        elif obj is None:
            rows.append((prefix, ""))
        elif isinstance(obj, bool):
            rows.append((prefix, "true" if obj else "false"))
        else:
            rows.append((prefix, str(obj)))
        return rows

    for key, value in _flatten(data):
        writer.writerow([key, value])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML rendering (self-contained, dark/light mode, print-friendly)
# ---------------------------------------------------------------------------


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nullscan report — {module}</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg: #fafafa; --fg: #1a1a1a; --muted: #6e6e6e;
    --accent: #00aa41; --accent-fg: #ffffff;
    --panel: #f0f0f0; --border: #dddddd; --code-bg: #f5f5f5;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0e0e0e; --fg: #e6e6e6; --muted: #888;
      --accent: #00ff41; --accent-fg: #0e0e0e;
      --panel: #1a1a1a; --border: #2a2a2a; --code-bg: #1f1f1f;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg); color: var(--fg);
    max-width: 900px; margin: 2em auto; padding: 0 1.5em; line-height: 1.55;
  }}
  h1 {{ color: var(--accent); margin-bottom: 0.2em; font-size: 1.8em; }}
  h2 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.3em; margin-top: 2em; }}
  h3 {{ margin-top: 1.5em; color: var(--fg); }}
  .meta {{ color: var(--muted); font-size: 0.92em; margin-bottom: 2em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ text-align: left; padding: 0.5em 0.75em; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--accent); color: var(--accent-fg); font-weight: 600; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:nth-child(even) td {{ background: var(--panel); }}
  details {{ margin: 0.5em 0; }}
  summary {{ cursor: pointer; font-weight: 600; padding: 0.3em 0; color: var(--accent); }}
  pre {{
    background: var(--code-bg); padding: 1em; border-radius: 4px;
    overflow-x: auto; font-size: 0.85em; border: 1px solid var(--border);
  }}
  code {{ font-family: "SF Mono", Menlo, Consolas, monospace; }}
  .ok {{ color: #00aa41; }}
  .bad {{ color: #cc0000; }}
  .warn {{ color: #cc8800; }}
  footer {{ margin-top: 3em; padding-top: 1em; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.85em; }}
  @media print {{ body {{ background: white; color: black; }} th {{ background: #00aa41; }} details[open] summary ~ * {{ display: block; }} }}
</style>
</head>
<body>
<h1>nullscan report</h1>
<p class="meta">
  <strong>{module}</strong> · target: <code>{target}</code><br>
  generated {generated} · nullscan {version}
</p>

{toc}

{body}

<footer>
  Generated by <a href="https://github.com/amnesiaYS/nullscan" style="color: var(--accent);">nullscan</a>.
  Verify findings independently before acting on them.
</footer>
</body>
</html>
"""


def _escape(text: str) -> str:
    """HTML-escape and preserve newlines."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_object_html(obj: Any, indent: int = 0) -> str:
    """Render a Python value as HTML. Scalars -> inline. Dicts/lists -> tables."""
    if obj is None:
        return "<em>empty</em>"
    if isinstance(obj, bool):
        return f'<span class="{"ok" if obj else "bad"}">{"yes" if obj else "no"}</span>'
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        return _escape(obj)
    if isinstance(obj, dict):
        rows = "\n".join(
            f"<tr><th>{_escape(k)}</th><td>{_render_object_html(v, indent + 1)}</td></tr>"
            for k, v in obj.items()
            if v not in (None, "", [], {})
        )
        return f"<table>{rows}</table>"
    if isinstance(obj, list):
        if not obj:
            return "<em>empty</em>"
        if all(isinstance(x, (str, int, float, bool)) for x in obj):
            items = "".join(f"<li>{_escape(str(x))}</li>" for x in obj[:200])
            more = f"<li><em>… {len(obj) - 200} more</em></li>" if len(obj) > 200 else ""
            return f"<ul>{items}{more}</ul>"
        # Mixed list — render each as JSON-ish.
        rows = []
        for i, item in enumerate(obj[:100]):
            rows.append(f"<tr><td>{i}</td><td>{_render_object_html(item, indent + 1)}</td></tr>")
        more = f"<em>… {len(obj) - 100} more entries omitted</em>" if len(obj) > 100 else ""
        return f"<table>{''.join(rows)}</table>{more}"
    return _escape(str(obj))


def render_html(*, module: str, target: str, data: Any) -> str:
    """Render a recon result as a self-contained HTML report."""
    generated = datetime.now(timezone.utc).isoformat()

    # Build TOC from top-level dict keys.
    toc_items = ""
    body_sections = ""
    if isinstance(data, dict):
        top_keys = [k for k, v in data.items() if v not in (None, "", [], {})]
        toc_items = "<details open><summary>Contents</summary><ul>" + "".join(
            f'<li><a href="#sec-{i}">{_escape(k)}</a></li>' for i, k in enumerate(top_keys)
        ) + "</ul></details>"
        body_sections = "".join(
            f'<h2 id="sec-{i}">{_escape(k)}</h2>{_render_object_html(v)}'
            for i, (k, v) in enumerate(data.items())
            if v not in (None, "", [], {})
        )
    else:
        body_sections = _render_object_html(data)

    # Raw JSON details block at the bottom.
    raw_json = ""
    try:
        import json as _json

        body_sections += (
            f'<details><summary>Raw JSON</summary>'
            f'<pre><code>{_escape(_json.dumps(data, indent=2, default=str, ensure_ascii=False))}</code></pre>'
            f'</details>'
        )
    except Exception:
        pass

    return _HTML_TEMPLATE.format(
        module=_escape(module),
        target=_escape(target),
        generated=_escape(generated),
        version=_escape(__version__),
        toc=toc_items,
        body=body_sections,
    )