"""Command-line interface for nullscan.

This module wires together the recon modules, theme system, config loader,
and output helpers. It enforces Unix-style hygiene:

- Status and progress go to stderr
- Data output goes to stdout (or a file via ``--output``)
- Exit codes: 0 success, 1 error, 2 invalid usage, 3 invalid target, 130 interrupted
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer

from . import __version__
from .banner import render_banner
from .config import load_config, main_config_command
from .output import print_status, stderr_console, stdout_console, write_output
from .recon import domain, email, ip, leak, username
from .theme import list_themes


@dataclass
class Opts:
    """Per-invocation options."""

    no_banner: bool = False
    no_color: bool = False
    format: str = "table"
    output: Path | None = None
    concurrency: int = 10
    quiet: bool = False
    verbose: bool = False
    theme: str = "matrix"


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INVALID_TARGET = 3
EXIT_INTERRUPTED = 130

_VALID_FORMATS = ("table", "json", "markdown")

# Shared global options — declared once so subcommands can reuse them and
# users can pass them either before or after the subcommand name.
_GLOBAL_OPTS = {
    "no_banner": typer.Option(False, "--no-banner", help="Skip the ASCII banner."),
    "no_color": typer.Option(False, "--no-color", help="Disable ANSI colors."),
    "format": typer.Option("table", "--format", "-f", help="Output format: table, json, or markdown."),
    "output": typer.Option(None, "--output", "-o", help="Write output to FILE instead of stdout."),
    "concurrency": typer.Option(10, "--concurrency", "-c", help="Max concurrent network requests.", min=1, max=100),
    "quiet": typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
    "verbose": typer.Option(False, "--verbose", "-v", help="Show detailed progress."),
    "theme": typer.Option("matrix", "--theme", help=f"Color theme. One of: {', '.join(list_themes())}."),
}


def _collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme) -> Opts:
    return Opts(
        no_banner=no_banner,
        no_color=no_color,
        format=format,
        output=output,
        concurrency=concurrency,
        quiet=quiet,
        verbose=verbose,
        theme=theme,
    )


def _validate(format: str, theme: str, err_console) -> int | None:
    if format not in _VALID_FORMATS:
        print_status(err_console, "bad", f"invalid --format '{format}' (must be: {', '.join(_VALID_FORMATS)})")
        return EXIT_USAGE
    if theme not in list_themes():
        print_status(err_console, "bad", f"unknown theme '{theme}' (available: {', '.join(list_themes())})")
        return EXIT_USAGE
    return None


app = typer.Typer(
    name="nullscan",
    help="OSINT reconnaissance toolkit with a nullsec/dedsec flavor.",
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

config_app = typer.Typer(help="Manage API keys, theme, and defaults.", no_args_is_help=False)
app.add_typer(config_app, name="config")


def _version_callback(value: bool) -> None:
    if value:
        stderr_console().print(f"nullscan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Show version."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """nullscan — passive and active OSINT for the nullsec movement."""
    err_console = stderr_console(theme=theme, no_color=no_color)
    rc = _validate(format, theme, err_console)
    if rc is not None:
        raise typer.Exit(code=rc)

    ctx.obj = _collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme)


def _get_opts(ctx: typer.Context) -> Opts:
    if isinstance(ctx.obj, Opts):
        return ctx.obj
    return Opts()


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


@app.command(name="domain")
def domain_cmd(
    ctx: typer.Context,
    targets: list[str] = typer.Argument(..., help="Domain(s) to investigate."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """DNS, WHOIS, subdomains (crt.sh), security headers."""
    asyncio.run(_multi_scan(_collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme), "domain", targets, domain.scan, domain.render))


@app.command(name="email")
def email_cmd(
    ctx: typer.Context,
    addrs: list[str] = typer.Argument(..., help="Email address(es) to investigate."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """Format check, MX records, gravatar, breach lookup (HIBP)."""
    asyncio.run(_multi_scan(_collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme), "email", addrs, email.scan, email.render))


@app.command(name="user")
def user_cmd(
    ctx: typer.Context,
    handles: list[str] = typer.Argument(..., help="Username(s) to enumerate across platforms."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """Check ~20 platforms for one or more usernames."""
    asyncio.run(_multi_scan(_collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme), "user", handles, username.scan, username.render))


@app.command(name="ip")
def ip_cmd(
    ctx: typer.Context,
    addrs: list[str] = typer.Argument(..., help="IPv4 or IPv6 address(es)."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """Reverse DNS, ASN, geo, optional Shodan."""
    asyncio.run(_multi_scan(_collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme), "ip", addrs, ip.scan, ip.render))


@app.command(name="leak")
def leak_cmd(
    ctx: typer.Context,
    passwords: list[str] = typer.Argument(..., help="Password(s) to check (HIBP k-anonymity)."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
    no_color: bool = _GLOBAL_OPTS["no_color"],
    format: str = _GLOBAL_OPTS["format"],
    output: Path | None = _GLOBAL_OPTS["output"],
    concurrency: int = _GLOBAL_OPTS["concurrency"],
    quiet: bool = _GLOBAL_OPTS["quiet"],
    verbose: bool = _GLOBAL_OPTS["verbose"],
    theme: str = _GLOBAL_OPTS["theme"],
) -> None:
    """Check if one or more passwords appear in known breach corpora."""
    asyncio.run(_multi_scan(_collect(no_banner, no_color, format, output, concurrency, quiet, verbose, theme), "leak", passwords, leak.scan_password, leak.render_password))


@config_app.callback(invoke_without_command=True)
def config_main(
    ctx: typer.Context,
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
) -> None:
    """Manage API keys, theme, and defaults."""
    opts = _get_opts(ctx)
    if ctx.invoked_subcommand is None:
        console = stderr_console(theme=opts.theme, no_color=opts.no_color)
        if not (opts.no_banner or no_banner):
            render_banner(console, __version__, theme_name=opts.theme)
        raise typer.Exit(main_config_command(console, show_path=False))


@config_app.command("show")
def config_show(
    ctx: typer.Context,
    path: bool = typer.Option(False, "--path", help="Print only the config file path."),
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
) -> None:
    """Show loaded API keys (masked) and config file path."""
    opts = _get_opts(ctx)
    console = stderr_console(theme=opts.theme, no_color=opts.no_color)
    if not (opts.no_banner or no_banner):
        render_banner(console, __version__, theme_name=opts.theme)
    raise typer.Exit(main_config_command(console, show_path=path))


@config_app.command("path")
def config_path_cmd(
    ctx: typer.Context,
    no_banner: bool = _GLOBAL_OPTS["no_banner"],
) -> None:
    """Print the config file path."""
    opts = _get_opts(ctx)
    console = stderr_console(theme=opts.theme, no_color=opts.no_color)
    if not (opts.no_banner or no_banner):
        render_banner(console, __version__, theme_name=opts.theme)
    raise typer.Exit(main_config_command(console, show_path=True))


@config_app.command("themes")
def config_themes_cmd(ctx: typer.Context) -> None:
    """List available color themes."""
    opts = _get_opts(ctx)
    console = stderr_console(theme=opts.theme, no_color=opts.no_color)
    for name in list_themes():
        marker = "*" if name == opts.theme else " "
        console.print(f"  [accent]{marker} {name}[/accent]")
    console.print(f"  [muted]current: {opts.theme}[/muted]")


# ---------------------------------------------------------------------------
# Core scan orchestration
# ---------------------------------------------------------------------------


async def _multi_scan(
    opts: Opts,
    module_name: str,
    targets: list[str],
    scan_fn,
    render_fn,
) -> None:
    """Run ``scan_fn`` over a list of targets and render results."""
    err_console = stderr_console(theme=opts.theme, no_color=opts.no_color)

    rc = _validate(opts.format, opts.theme, err_console)
    if rc is not None:
        raise typer.Exit(code=rc)

    if not opts.no_banner:
        config = load_config()
        render_banner(
            err_console,
            __version__,
            keys_summary=config.keys_short_summary(),
            theme_name=opts.theme,
        )

    if not opts.quiet and opts.format == "table":
        print_status(err_console, "info", f"module: {module_name}")
        print_status(err_console, "work", f"targets: {len(targets)}")

    started = time.monotonic()
    sem = asyncio.Semaphore(opts.concurrency)
    results: list[tuple[str, Any, Exception | None]] = []

    async def run_one(target: str) -> tuple[str, Any, Exception | None]:
        async with sem:
            try:
                return target, await scan_fn(target), None
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001
                return target, None, exc

    coros = [run_one(t) for t in targets]
    try:
        outcomes = await asyncio.gather(*coros)
    except KeyboardInterrupt:
        print_status(err_console, "warn", "interrupted by user")
        raise typer.Exit(code=EXIT_INTERRUPTED) from None

    elapsed = time.monotonic() - started
    failed = sum(1 for _, _, exc in outcomes if exc is not None)

    # Render each target for table format.
    for target, result, exc in outcomes:
        if exc is not None:
            print_status(err_console, "bad", f"{module_name} {target}: {exc}")
            results.append((target, {"error": str(exc)}, exc))
            continue

        if opts.format == "table":
            try:
                render_fn(result, err_console)
            except Exception as exc:  # noqa: BLE001
                print_status(err_console, "bad", f"render failed for {target}: {exc}")
                results.append((target, {"error": str(exc)}, exc))
                continue
        results.append((target, result, None))

    # Non-table formats: write to stdout (or --output file).
    if opts.format in ("json", "markdown"):
        if len(targets) == 1 and results and results[0][2] is None:
            payload = results[0][1]
        else:
            payload = {
                "module": module_name,
                "results": [
                    {"target": t, "result": r, "error": (str(e) if e else None)}
                    for t, r, e in results
                ],
            }
        write_output(
            opts.output,
            payload,
            format=opts.format,
            target=", ".join(targets) if len(targets) > 1 else targets[0],
            module=module_name,
        )

    if not opts.quiet:
        msg = f"scan complete in {elapsed:.2f}s"
        if failed:
            msg += f" ({failed} failed)"
        print_status(err_console, "ok" if failed == 0 else "warn", msg)

    if failed == len(outcomes) and len(outcomes) > 0:
        raise typer.Exit(code=EXIT_ERROR)


def main_entry() -> None:
    """Console-script entry point."""
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)


if __name__ == "__main__":
    main_entry()