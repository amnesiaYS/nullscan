"""Domain reconnaissance: DNS, WHOIS, crt.sh subdomains, security headers."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from ..output import print_kv_panel, print_list_panel, print_status, print_table
from ..utils import dns_query, fetch_security_headers, make_async_client, whois_lookup

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


async def scan(target: str) -> dict[str, Any]:
    """Run the full domain recon pipeline. Returns a structured dict."""
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        target = urlparse(target).netloc

    results: dict[str, Any] = {"target": target, "dns": {}, "whois": {}, "subdomains": [], "headers": {}}

    # 1. DNS records (sync, fast).
    for rdtype in DNS_RECORD_TYPES:
        answers = dns_query(target, rdtype)
        if answers:
            results["dns"][rdtype] = answers

    # 2. WHOIS.
    results["whois"] = whois_lookup(target)

    # 3. crt.sh subdomain enumeration.
    results["subdomains"] = await _crt_sh_subdomains(target)

    # 4. Security headers (HTTPS only, only if a hostname resolves).
    if "A" in results["dns"] or "AAAA" in results["dns"]:
        results["headers"] = await fetch_security_headers(f"https://{target}/")

    return results


async def _crt_sh_subdomains(domain: str) -> list[str]:
    """Query crt.sh Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with make_async_client(timeout=30) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            entries = resp.json()
        except Exception:
            return []
    found: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for raw in name_value.split("\n"):
            name = raw.strip().lstrip("*.")
            if not name:
                continue
            if name == domain or name.endswith(f".{domain}"):
                found.add(name.lower())
    return sorted(found)


def render(results: dict[str, Any], console: Console) -> None:
    """Pretty-print scan results to a Rich console."""
    target = results.get("target", "?")
    print_status(console, "info", f"target: {target}")

    dns = results.get("dns") or {}
    if dns:
        rows = []
        for rdtype, values in dns.items():
            display = ", ".join(values) if not rdtype == "TXT" else " | ".join(values)
            rows.append([rdtype, display])
        print_table(console, "DNS RECORDS", ["Type", "Value"], rows)
    else:
        print_status(console, "warn", "no DNS records found")

    whois = results.get("whois") or {}
    if whois.get("error"):
        print_status(console, "bad", f"WHOIS failed: {whois['error']}")
    elif whois:
        printable = {k: v for k, v in whois.items() if k not in {"raw", "error"}}
        if printable:
            print_kv_panel(console, "WHOIS", printable)
        else:
            print_status(console, "warn", "WHOIS returned no parseable fields")

    subs = results.get("subdomains") or []
    if subs:
        # Cap displayed list at 50 to keep output tidy.
        display = subs[:50]
        print_list_panel(console, f"SUBDOMAINS via crt.sh ({len(subs)} total)", display)
        if len(subs) > 50:
            print_status(console, "info", f"… {len(subs) - 50} more subdomains omitted")
    else:
        print_status(console, "info", "no subdomains found via crt.sh")

    headers = results.get("headers") or {}
    if headers.get("error"):
        print_status(console, "warn", f"headers: {headers['error']}")
    elif headers.get("present") is not None:
        rows = []
        for label, value in headers.get("present", {}).items():
            rows.append([label, value[:120]])
        for label in headers.get("missing", []):
            rows.append([label, "— missing —"])
        if rows:
            print_table(console, "SECURITY HEADERS", ["Header", "Value"], rows)
        else:
            print_status(console, "info", "no security headers observed (HTTP non-200?)")