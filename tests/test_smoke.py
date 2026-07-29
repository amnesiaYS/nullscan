"""Smoke tests for nullscan. These run offline and exercise pure helpers."""

from __future__ import annotations

import pytest

from nullscan import banner
from nullscan.recon import email, leak
from nullscan.recon import username as username_mod
from nullscan.utils import whois_lookup


def test_email_validation_valid():
    assert email.EMAIL_REGEX.match("user@example.com") is not None
    assert email.EMAIL_REGEX.match("first.last+tag@sub.example.org") is not None


def test_email_validation_invalid():
    assert email.EMAIL_REGEX.match("not-an-email") is None
    assert email.EMAIL_REGEX.match("@nodomain.com") is None
    assert email.EMAIL_REGEX.match("user@") is None
    assert email.EMAIL_REGEX.match("user@.com") is None


def test_gravatar_hash_is_md5():
    g = email._gravatar_for("user@example.com")
    assert len(g["hash"]) == 32
    assert g["url"].endswith("?d=404")


def test_typo_suggestion():
    assert email._common_typo("gmial.com") == "gmail.com"
    assert email._common_typo("yahooo.com") == "yahoo.com"
    assert email._common_typo("example.com") is None


def test_disposable_detection():
    assert email.DISPOSABLE_DOMAINS  # non-empty
    assert "mailinator.com" in email.DISPOSABLE_DOMAINS


@pytest.mark.asyncio
async def test_leak_password_returns_dict_shape():
    """Smoke test for the leak module's return shape (no network).

    We don't assert a real HIBP response — just that the function is
    callable and returns the expected keys.
    """
    result = await leak.scan_password("definitely-not-a-real-password-xyz")
    assert "count" in result
    assert "prefix" in result
    assert "hash_suffix" in result
    assert len(result["prefix"]) == 5
    assert len(result["hash_suffix"]) == 35


def test_platforms_have_unique_names():
    names = [p.name for p in username_mod.PLATFORMS]
    assert len(names) == len(set(names))
    assert len(names) >= 15  # sanity: we promised ~20 platforms


def test_whois_lookup_does_not_raise():
    """whois_lookup with an unreachable target should not raise."""
    try:
        result = whois_lookup("this-domain-does-not-exist-asdfqwer-1234.invalid")
    except Exception as exc:  # pragma: no cover - defensive
        pytest.fail(f"whois_lookup raised: {exc}")
    assert "server" in result
    assert "raw" in result


def test_banner_art_is_present():
    # The banner art is multi-line ASCII. We just check it has the
    # expected shape (5 rows of figlet-style text).
    art = banner.BANNER_ART
    lines = [ln for ln in art.splitlines() if ln.strip()]
    assert len(lines) >= 4
    # Should contain underscore and pipe characters typical of figlet.
    assert "_" in art and "|" in art


def test_banner_renders():
    """Banner.render_banner should not raise on a Rich console."""
    from rich.console import Console

    from nullscan import __version__
    from nullscan.theme import make_console

    console = make_console(file=None)  # default theme
    # render_banner writes via console.print which goes to stdout in tests
    banner.render_banner(console, __version__)
    # Use a record buffer to capture text.
    capture = Console(record=True, force_terminal=False, width=120)
    banner.render_banner(capture, __version__)
    output = capture.export_text().lower()
    assert "nullsec" in output, "expected 'nullsec' in banner version line"
    assert "privacy" in output, "expected tagline in banner"


def test_cli_help_runs():
    """The Typer app should respond to --help without error."""
    from typer.testing import CliRunner

    from nullscan.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "nullscan" in result.output.lower()


def test_cli_version_runs():
    from typer.testing import CliRunner

    from nullscan.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "nullscan" in result.output.lower()


def test_config_loads_with_no_env():
    """Config loader must return a valid Config even with no keys."""
    from nullscan.config import load_config

    config = load_config()
    assert config is not None
    assert isinstance(config.api, dict)


def test_status_helper_renders():
    from nullscan.theme import status

    line = status("ok", "test message")
    assert "[+]" in line
    assert "test message" in line