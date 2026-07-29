"""Leak check: HIBP Password Range API (k-anonymity, no key required)."""

from __future__ import annotations

import hashlib
from typing import Any

from rich.console import Console

from ..output import print_status
from ..utils import make_async_client


async def scan_password(password: str) -> dict[str, Any]:
    """Check a password against HIBP via k-anonymity. Returns count of breaches.

    Only the first 5 chars of the SHA-1 hash are sent. The password itself
    never leaves the machine.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    async with make_async_client(timeout=15) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except Exception as exc:
            return {"error": str(exc), "count": 0, "hash_suffix": suffix}

    count = 0
    for line in resp.text.splitlines():
        line_suffix, _, line_count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            count = int(line_count.strip() or "0")
            break

    return {"prefix": prefix, "hash_suffix": suffix, "count": count, "error": None}


def render_password(results: dict[str, Any], console: Console) -> None:
    """Pretty-print a password leak check."""
    if results.get("error"):
        print_status(console, "bad", f"HIBP lookup failed: {results['error']}")
        return

    count = results.get("count", 0)
    if count > 0:
        console.print(
            f"[status.bad][!][/status.bad] [primary]pwned: seen {count:,} times in known breach corpora[/primary]"
        )
        console.print("  [warn]change this password immediately and never reuse it[/warn]")
    else:
        print_status(console, "ok", "not found in known breach corpora (HIBP)")
    console.print(f"[muted]  hash prefix: {results.get('prefix')} (k-anonymity — full hash never sent)[/muted]")