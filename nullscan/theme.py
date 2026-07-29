"""Color theme system for nullscan.

Multiple themes are available; ``matrix`` is the default. Themes can be
selected at runtime via the ``theme`` key in ``~/.config/nullscan/config.toml``
or with the ``--theme`` flag.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# Three built-in themes. Add new ones here.
THEMES: dict[str, Theme] = {
    "matrix": Theme(
        {
            "primary": "bold #00FF41",
            "accent": "#00CC33",
            "info": "#00FFFF",
            "warn": "#FFD700",
            "error": "#FF0040",
            "muted": "#6E6E6E",
            "ok": "#00FF41",
            "bad": "#FF0040",
            "title": "bold #00FF41",
            "subtitle": "#00CC33",
            "status.ok": "bold #00FF41",
            "status.bad": "bold #FF0040",
            "status.warn": "bold #FFD700",
            "status.info": "bold #00FFFF",
            "status.work": "bold #00CCFF",
        }
    ),
    "minimal": Theme(
        {
            "primary": "bold white",
            "accent": "white",
            "info": "cyan",
            "warn": "yellow",
            "error": "red",
            "muted": "bright_black",
            "ok": "green",
            "bad": "red",
            "title": "bold white",
            "subtitle": "white",
            "status.ok": "bold green",
            "status.bad": "bold red",
            "status.warn": "bold yellow",
            "status.info": "bold cyan",
            "status.work": "bold blue",
        }
    ),
    "neon": Theme(
        {
            "primary": "bold #FF00FF",
            "accent": "#00FFFF",
            "info": "#00FFFF",
            "warn": "#FFFF00",
            "error": "#FF0080",
            "muted": "#808080",
            "ok": "#00FF80",
            "bad": "#FF0080",
            "title": "bold #FF00FF",
            "subtitle": "#00FFFF",
            "status.ok": "bold #00FF80",
            "status.bad": "bold #FF0080",
            "status.warn": "bold #FFFF00",
            "status.info": "bold #00FFFF",
            "status.work": "bold #FF00FF",
        }
    ),
}

DEFAULT_THEME = "matrix"


def list_themes() -> list[str]:
    """Return the names of all available themes."""
    return sorted(THEMES.keys())


def get_theme(name: str) -> Theme:
    """Return a Theme by name, falling back to the default."""
    return THEMES.get(name, THEMES[DEFAULT_THEME])


def make_console(
    theme: str = DEFAULT_THEME,
    no_color: bool = False,
    *,
    file=None,
    force_terminal: bool | None = None,
) -> Console:
    """Build a Rich Console with the requested theme.

    ``force_terminal`` controls whether Rich emits ANSI escapes. When ``None``,
    Rich auto-detects; pass ``False`` to force plain output (for pipes / CI).
    """
    return Console(
        theme=get_theme(theme),
        file=file,
        no_color=no_color,
        force_terminal=force_terminal,
        highlight=False,
    )


# Glyphs used by ``status()``. ASCII only for portability.
GLYPHS = {
    "ok": "[+]",
    "bad": "[-]",
    "warn": "[!]",
    "info": "[*]",
    "work": "[~]",
    "q": "[?]",
}


def status(kind: str, message: str) -> str:
    """Render a status line. ``kind`` is one of: ok, bad, warn, info, work."""
    glyph = GLYPHS.get(kind, "[*]")
    style = f"status.{kind if kind in ('ok', 'bad', 'warn', 'info') else 'info'}"
    if kind == "work":
        style = "status.work"
    return f"[{style}]{glyph}[/{style}] [primary]{message}[/primary]"