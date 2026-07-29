# Contributing

PRs and issues are open.

## Where help is welcome

### Graphics / UI

Files: `nullscan/banner.py`, `nullscan/theme.py`, `nullscan/output.py`.

- alternate ASCII banners or figlet fonts
- color palette variants (current is matrix-green / cyan / red)
- themed prompt or interactive `nullscan shell` mode
- progress spinners for long scans

For UI changes, attach a screenshot or terminal recording to the PR.

### New modules

Each module in `nullscan/recon/` exposes two functions:
`async def scan(target) -> dict` and `def render(results, console)`.
Follow that shape and the others will pick it up.

Ideas: phone/IMEI, MAC vendor, BGP prefix lookup, AS-path
visualization.

### Bug reports

Open an issue with: Python version, OS, the exact command, the
full traceback. Include `--json` output when a network request
fails.

## Style

- Python 3.10+
- `ruff` for lint (config in `pyproject.toml`)
- Type hints on public functions
- Async I/O for network calls
- Add tests in `tests/test_smoke.py`

## License

MIT. By contributing you agree to the same license.