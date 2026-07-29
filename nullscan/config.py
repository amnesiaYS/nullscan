"""Configuration loader: API keys from env or TOML config file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nullscan"
CONFIG_PATH = CONFIG_DIR / "config.toml"

# Recognised API keys. Anything not in this map is ignored.
_KEYS = ("hibp", "shodan", "virustotal")
_ENV_MAP = {
    "hibp": "HIBP_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
}


@dataclass
class Config:
    """Runtime configuration: API keys and paths."""

    api: dict[str, str] = field(default_factory=dict)
    config_path: Path = CONFIG_PATH
    sources: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.api.get(name)

    def require(self, name: str) -> str:
        """Return an API key or raise a helpful error."""
        value = self.api.get(name)
        if not value:
            raise RuntimeError(
                f"Missing API key for '{name}'. Set the "
                f"{_ENV_MAP.get(name, '???')} environment variable, or add it "
                f"to {self.config_path} under [api] '{name}'."
            )
        return value

    def summary(self) -> list[tuple[str, str, str]]:
        """Return a list of (key, source, masked_value) for display."""
        rows = []
        for name in _KEYS:
            if name in self.api:
                value = self.api[name]
                masked = value[:4] + "…" + value[-2:] if len(value) > 8 else "***"
                rows.append((name, self.sources.get(name, "?"), masked))
        return rows


def _load_toml(path: Path) -> dict:
    """Load a TOML file without forcing a third-party dependency.

    Falls back to a hand-rolled parser supporting the small subset we use:
    ``[section]`` headers and ``key = "value"`` pairs.
    """
    if not path.exists():
        return {}

    # Prefer tomllib (Python 3.11+).
    try:
        import tomllib  # type: ignore[import-not-found]

        with path.open("rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        pass

    # Fallback: regex-based mini-parser.
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
    """Build a Config from env vars + the TOML file (env wins)."""
    config = Config()

    # 1. TOML file (lowest priority).
    toml_data = _load_toml(CONFIG_PATH)
    api_section = toml_data.get("api", {}) if isinstance(toml_data, dict) else {}
    if isinstance(api_section, dict):
        for name in _KEYS:
            value = api_section.get(name)
            if isinstance(value, str) and value:
                config.api[name] = value
                config.sources[name] = f"file:{CONFIG_PATH}"

    # 2. Environment (highest priority).
    for name, env in _ENV_MAP.items():
        value = os.environ.get(env, "").strip()
        if value:
            config.api[name] = value
            config.sources[name] = f"env:{env}"

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
        'virustotal = ""\n',
        encoding="utf-8",
    )
    return CONFIG_PATH


def main_config_command(console, show_path: bool) -> int:
    """Entry point used by the ``nullscan config`` CLI subcommand."""
    from .output import print_status

    config = load_config()

    if show_path:
        console.print(f"[accent]{CONFIG_PATH}[/accent]")
        return 0

    print_status(console, "info", f"config file: {CONFIG_PATH} ({'present' if CONFIG_PATH.exists() else 'missing'})")

    rows = config.summary()
    if not rows:
        print_status(console, "warn", "no API keys configured")
    else:
        for name, source, masked in rows:
            console.print(f"  [accent]{name}[/accent]  [primary]{masked}[/primary]  [muted]({source})[/muted]")

    write_default_config()
    return 0