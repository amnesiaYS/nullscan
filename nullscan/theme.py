"""Color theme and status helpers for the nullsec/dedsec aesthetic."""

from rich.console import Console
from rich.theme import Theme

# Matrix-inspired palette: blacks and greens, with cyan/yellow/red accents.
THEME_DICT: dict[str, str] = {
    "primary": "bold #00FF41",       # matrix green — primary accent
    "accent": "#00CC33",             # darker green — secondary
    "info": "#00FFFF",               # cyan — informational
    "warn": "#FFD700",               # gold — warnings
    "error": "#FF0040",              # red — errors
    "muted": "#6E6E6E",              # gray — muted text
    "ok": "#00FF41",                 # success green
    "bad": "#FF0040",                # error red
    "title": "bold #00FF41",         # titles
    "subtitle": "#00CC33",           # subtitles
    "status.ok": "bold #00FF41",
    "status.bad": "bold #FF0040",
    "status.warn": "bold #FFD700",
    "status.info": "bold #00FFFF",
    "status.work": "bold #00CCFF",
}

THEME = Theme(THEME_DICT)

# Status glyphs. Use plain ASCII to avoid surprises in non-UTF terminals.
GLYPHS = {
    "ok": "[+]",
    "bad": "[-]",
    "warn": "[!]",
    "info": "[*]",
    "work": "[~]",
    "q": "[?]",
}


def make_console(file=None, force_terminal: bool | None = None) -> Console:
    """Build a Rich Console with our theme applied."""
    return Console(
        theme=THEME,
        file=file,
        force_terminal=force_terminal,
        highlight=False,
    )


def status(kind: str, message: str) -> str:
    """Render a status line. ``kind`` is one of: ok, bad, warn, info, work."""
    glyph = GLYPHS.get(kind, "[*]")
    style = f"status.{kind if kind in ('ok', 'bad', 'warn', 'info') else 'info'}"
    if kind == "work":
        style = "status.work"
    return f"[{style}]{glyph}[/{style}] [primary]{message}[/primary]"