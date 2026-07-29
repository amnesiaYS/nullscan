"""Configuration loader: API keys, theme, default settings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nullscan"
CONFIG_PATH = CONFIG_DIR / "config.toml"

_API_KEYS = ("hibp", "shodan", "virustotal")
_ENV_KEY_MAP = {
    "hibp": "HIBP_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
}


@dataclass
class Config:
    """Runtime configuration."""

    api: dict[str, str] = field(default_factory=dict)
    theme: str = "matrix"
    defaults: dict[str, str] = field(default_factory=dict)
    config_path: Path = CONFIG_PATH
    sources: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.api.get(name)

    def require(self, name: str) -> str:
        """Return an API key or raise a helpful error."""
        value = self.api.get(name)
        if not value:
            raise RuntimeError(
                f"missing API key for '{name}'. Set the {_ENV_KEY_MAP.get(name, '???')} "
                f"environment variable, or add it to {self.config_path} under [api] '{name}'."
            )
        return value

    def summary(self) -> list[tuple[str, str, str]]:
        """Return (key, source, masked_value) rows for display."""
        rows = []
        for name in _API_KEYS:
            if name in self.api:
                value = self.api[name]
                masked = value[:4] + "…" + value[-2:] if len(value) > 8 else "***"
                rows.append((name, self.sources.get(name, "?"), masked))
        return rows

    def keys_short_summary(self) -> list[tuple[str, str]]:
        """Short key status (name, "set"/"none") for the banner."""
        return [(name, "set" if name in self.api else "none") for name in _API_KEYS]


def _load_toml(path: Path) -> dict:
    """Load a small subset of TOML: [section] headers and ``key = "value"`` pairs."""
    if not path.exists():
        return {}

    try:
        import tomllib  # type: ignore[import-not-found]

        with path.open("rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        pass

    text = path.read_text(encoding="utf-8")
    result: dict = {}
    section = result
    import re

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        section_match = re.match(r"^\[([\w.]+)\]$", line)
        if section_match:
            section_name = section_match.group(1)
            section = result
            for part in section_name.split("."):
                section = section.setdefault(part, {})
                if not isinstance(section, dict):
                    section = {}
            continue
        kv_match = re.match(r'^([\w.]+)\s*=\s*"(.*)"\s*$', line)
        if kv_match:
            key, value = kv_match.group(1), kv_match.group(2)
            section[key] = value
    return result


def load_config() -> Config:
    """Build a Config from env vars + TOML file (env wins)."""
    config = Config()

    toml_data = _load_toml(CONFIG_PATH)
    api_section = toml_data.get("api", {}) if isinstance(toml_data, dict) else {}
    if isinstance(api_section, dict):
        for name in _API_KEYS:
            value = api_section.get(name)
            if isinstance(value, str) and value:
                config.api[name] = value
                config.sources[name] = f"file:{CONFIG_PATH}"

    for name, env in _ENV_KEY_MAP.items():
        value = os.environ.get(env, "").strip()
        if value:
            config.api[name] = value
            config.sources[name] = f"env:{env}"

    # Theme + defaults from [settings] if present.
    settings = toml_data.get("settings", {}) if isinstance(toml_data, dict) else {}
    if isinstance(settings, dict):
        theme = settings.get("theme")
        if isinstance(theme, str) and theme:
            config.theme = theme
        for k, v in settings.items():
            if k != "theme" and isinstance(v, str):
                config.defaults[k] = v

    # Allow NULLSCAN_THEME env var to override.
    env_theme = os.environ.get("NULLSCAN_THEME", "").strip()
    if env_theme:
        config.theme = env_theme

    return config


def write_default_config() -> Path:
    """Create a template config file at the canonical path. Returns the path."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        return CONFIG_PATH
    CONFIG_PATH.write_text(
        "# nullscan configuration\n"
        "# API keys — leave empty to skip features that need them.\n"
        "\n"
        "[api]\n"
        'hibp = ""\n'
        'shodan = ""\n'
        'virustotal = ""\n'
        "\n"
        "[settings]\n"
        '# theme = "matrix"   # one of: matrix, minimal, neon\n'
        '# format = "table"  # default output format\n'
        '# concurrency = "10" # default parallel requests\n',
        encoding="utf-8",
    )
    return CONFIG_PATH


def main_config_command(console, show_path: bool) -> int:
    """Entry point used by the ``nullscan config`` CLI subcommand."""
    from .output import print_status
    from .theme import list_themes

    config = load_config()

    if show_path:
        console.print(f"[accent]{CONFIG_PATH}[/accent]")
        return 0

    print_status(console, "info", f"config file: {CONFIG_PATH} ({'present' if CONFIG_PATH.exists() else 'missing'})")

    rows = config.summary()
    if rows:
        for name, source, masked in rows:
            console.print(f"  [accent]{name}[/accent]  [primary]{masked}[/primary]  [muted]({source})[/muted]")
    else:
        print_status(console, "warn", "no API keys configured")

    console.print()
    console.print(f"[accent]theme:[/accent] [primary]{config.theme}[/primary] [muted](available: {', '.join(list_themes())})[/muted]")
    if config.defaults:
        console.print(f"[accent]defaults:[/accent] [primary]{config.defaults}[/primary]")

    write_default_config()
    return 0