"""Command-line interface for nullscan."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass
from typing import Any

import typer

from . import __version__
from .banner import render_banner
from .config import main_config_command
from .output import dump_json, print_status
from .recon import domain, email, ip, leak, username
from .theme import make_console

# Shared global options. Reused on every subcommand so users can place them
# either before or after the subcommand name (Click's parser is otherwise
# positional about which command owns an option).
_GLOBAL_OPTS = [
    typer.Option(False, "--no-banner", help="Skip the ASCII banner."),
    typer.Option(False, "--json", help="Emit results as JSON to stdout."),
    typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
]


@dataclass
class Opts:
    """Per-invocation options."""

    no_banner: bool = False
    json_output: bool = False
    quiet: bool = False


app = typer.Typer(
    name="nullscan",
    help="OSINT reconnaissance toolkit with a nullsec/dedsec flavor.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

config_app = typer.Typer(help="Manage API keys and view configuration.", no_args_is_help=False)
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_main(
    ctx: typer.Context,
    no_banner: bool = _GLOBAL_OPTS[0],
) -> None:
    """Manage API keys and view configuration."""
    if not isinstance(ctx.obj, Opts):
        ctx.obj = _collect_opts(no_banner, False, False)
    # If no subcommand was given, default to 'show'.
    if ctx.invoked_subcommand is None:
        opts = _get_opts(ctx)
        console = make_console()
        if not opts.no_banner:
            render_banner(console, __version__)
        raise typer.Exit(main_config_command(console, show_path=False))


def _version_callback(value: bool) -> None:
    if value:
        make_console().print(f"nullscan {__version__}")
        raise typer.Exit()


def _collect_opts(no_banner: bool, json_output: bool, quiet: bool) -> Opts:
    return Opts(no_banner=no_banner, json_output=json_output, quiet=quiet)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Show version."),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """nullscan — passive & active OSINT for the nullsec movement."""
    ctx.obj = _collect_opts(no_banner, json_output, quiet)


def _get_opts(ctx: typer.Context) -> Opts:
    if isinstance(ctx.obj, Opts):
        return ctx.obj
    return Opts()


@app.command(name="domain")
def domain_cmd(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Domain to investigate (e.g. example.com)"),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """DNS, WHOIS, subdomains (crt.sh), security headers."""
    _run_module(_collect_opts(no_banner, json_output, quiet), "domain", target, domain.scan, domain.render)


@app.command(name="email")
def email_cmd(
    ctx: typer.Context,
    addr: str = typer.Argument(..., help="Email address to investigate"),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """Format check, MX records, gravatar, breach lookup (HIBP)."""
    _run_module(_collect_opts(no_banner, json_output, quiet), "email", addr, email.scan, email.render)


@app.command(name="user")
def user_cmd(
    ctx: typer.Context,
    handle: str = typer.Argument(..., help="Username to enumerate across platforms"),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """Check ~20 platforms for a username."""
    _run_module(_collect_opts(no_banner, json_output, quiet), "user", handle, username.scan, username.render)


@app.command(name="ip")
def ip_cmd(
    ctx: typer.Context,
    addr: str = typer.Argument(..., help="IPv4 or IPv6 address"),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """Reverse DNS, ASN, geo, optional Shodan."""
    _run_module(_collect_opts(no_banner, json_output, quiet), "ip", addr, ip.scan, ip.render)


@app.command(name="leak")
def leak_cmd(
    ctx: typer.Context,
    password: str = typer.Argument(..., help="Password to check (HIBP k-anonymity)"),
    no_banner: bool = _GLOBAL_OPTS[0],
    json_output: bool = _GLOBAL_OPTS[1],
    quiet: bool = _GLOBAL_OPTS[2],
) -> None:
    """Check if a password appears in known breach corpora (no key required)."""
    _run_module(_collect_opts(no_banner, json_output, quiet), "leak", password, leak.scan_password, leak.render_password)


@config_app.command("show")
def config_show(
    ctx: typer.Context,
    path: bool = typer.Option(False, "--path", help="Print only the config file path."),
    no_banner: bool = _GLOBAL_OPTS[0],
) -> None:
    """Show loaded API keys (masked) and the config file path."""
    opts = _get_opts(ctx)
    console = make_console()
    if not (opts.no_banner or no_banner):
        render_banner(console, __version__)
    raise typer.Exit(main_config_command(console, show_path=path))


@config_app.command("path")
def config_path_cmd(
    ctx: typer.Context,
    no_banner: bool = _GLOBAL_OPTS[0],
) -> None:
    """Print the config file path."""
    opts = _get_opts(ctx)
    console = make_console()
    if not (opts.no_banner or no_banner):
        render_banner(console, __version__)
    raise typer.Exit(main_config_command(console, show_path=True))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_module(
    opts: Opts,
    name: str,
    target: str,
    scan_fn,
    render_fn,
) -> None:
    console = make_console()

    if not opts.no_banner:
        render_banner(console, __version__)

    started = time.monotonic()
    if not opts.quiet and not opts.json_output:
        print_status(console, "info", f"module: {name}")
        print_status(console, "work", f"target: {target}")

    try:
        result: Any = asyncio.run(scan_fn(target))
    except KeyboardInterrupt:
        print_status(console, "warn", "interrupted by user")
        raise typer.Exit(code=130) from None
    except Exception as exc:
        print_status(console, "bad", f"{name} failed: {exc}")
        raise typer.Exit(code=1) from None

    elapsed = time.monotonic() - started

    if opts.json_output:
        payload = {
            "module": name,
            "target": target,
            "elapsed_seconds": round(elapsed, 3),
            "result": result,
        }
        dump_json(console, payload)
        return

    render_fn(result, console)

    if not opts.quiet:
        print_status(console, "ok", f"scan complete in {elapsed:.2f}s")


def main_entry() -> None:
    """Console-script entry point."""
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main_entry()