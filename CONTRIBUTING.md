# Contributing to nullscan

Thanks for your interest in making nullscan better. 🎯

## Code of conduct

Be respectful. No doxxing, no targeting of individuals. nullscan is a tool for **defensive research, journalism, and protecting privacy** — not for harassment.

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feat/better-banner` (or `fix/`, `docs/`, `style/` etc.)
3. Make your changes
4. Run tests: `python -m pytest`
5. Lint: `ruff check nullscan/ tests/`
6. Push and open a PR

## Areas where we'd love help

### 🎨 Graphics / UI (`nullscan/banner.py`, `nullscan/theme.py`, `nullscan/output.py`)

The aesthetic is what makes nullscan feel like nullsec. If you want to contribute here:

- **New banner variants**: ASCII art alternatives, figlet fonts, animated spinners, per-module banners
- **Color palettes**: `THEME_DICT` in `theme.py` controls all colors. Suggest alternatives (e.g. cyberpunk, retro-terminal, blood-red, midnight-blue) — keep them readable in both light and dark terminals
- **Tables & panels**: richer `rich` table styles, custom borders, status badges
- **Spinners / progress bars**: long scans could use `rich.progress` for feedback
- **Themed prompt**: we could add an interactive `nullscan shell` mode with a custom prompt (`nullscan> ` with autocomplete)

When proposing visual changes, include a screenshot or terminal recording in your PR.

### 🛰 New modules (`nullscan/recon/`)

Each module is a self-contained file with two functions: `async def scan(target) -> dict` and `def render(results, console)`. If you want to add a new recon capability, follow the existing structure and add tests.

Ideas: phone/IMEI lookup, MAC vendor lookup, BGP prefix lookup, AS-path visualization, port-scan (use cautiously, **only** against assets you own or have explicit written permission to test).

### 🔌 Integrations

We currently support HIBP, Shodan, VirusTotal. Add more via the `config.py` loader pattern (env var + TOML key).

### 🐛 Bug reports

Open an issue with: Python version, OS, the exact command, and the full traceback. If a network request is failing, include `--json` output if possible.

## Coding style

- Python 3.10+
- `ruff` for lint (config in `pyproject.toml`)
- Type hints on public functions
- Async I/O for any network call
- Tests for new pure functions (`tests/test_smoke.py` is the place to start)

## License

By contributing, you agree your work is released under the same MIT license as the project.