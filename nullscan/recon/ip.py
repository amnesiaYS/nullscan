"""IP reconnaissance: reverse DNS, ASN, geo, optional Shodan."""

from __future__ import annotations

import ipaddress
from typing import Any

from rich.console import Console

from ..config import load_config
from ..output import print_kv_panel, print_status
from ..utils import asn_lookup, dns_query, make_async_client


async def scan(addr: str) -> dict[str, Any]:
    """Run the IP recon pipeline on a single IPv4/IPv6 address."""
    addr = addr.strip()
    results: dict[str, Any] = {"input": addr, "valid": False, "reverse_dns": [], "asn": {}, "geo": {}, "shodan": None}

    try:
        ip_obj = ipaddress.ip_address(addr)
        results["valid"] = True
        results["version"] = ip_obj.version
    except ValueError:
        results["error"] = "not a valid IP address"
        return results

    # Reverse DNS: PTR lookup uses the in-addr.arpa / ip6.arpa name.
    try:
        if ip_obj.version == 4:
            reversed_name = ".".join(reversed(addr.split("."))) + ".in-addr.arpa"
        else:
            # IPv6 nibble expansion.
            expanded = ip_obj.exploded.replace(":", "")
            reversed_name = ".".join(reversed(expanded)) + ".ip6.arpa"
        results["reverse_dns"] = dns_query(reversed_name, "PTR")
    except Exception:
        results["reverse_dns"] = []

    # ASN via Team Cymru DNS.
    if ip_obj.version == 4:
        results["asn"] = asn_lookup(addr)

    # GeoIP via ip-api.com (no key, rate-limited).
    results["geo"] = await _geo_lookup(addr)

    # Optional Shodan host intel.
    cfg = load_config()
    if cfg.get("shodan"):
        results["shodan"] = await _shodan_lookup(addr, cfg.require("shodan"))
    else:
        results["shodan"] = {"skipped": "set SHODAN_API_KEY"}

    return results


async def _geo_lookup(addr: str) -> dict[str, Any]:
    """GeoIP lookup via ip-api.com (free tier)."""
    url = f"http://ip-api.com/json/{addr}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    async with make_async_client(timeout=10) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                return data
            return {"error": data.get("message", "unknown error")}
        except Exception as exc:
            return {"error": str(exc)}


async def _shodan_lookup(addr: str, api_key: str) -> dict[str, Any]:
    """Shodan host lookup (requires API key)."""
    url = f"https://api.shodan.io/shodan/host/{addr}?key={api_key}"
    async with make_async_client(timeout=15) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 404:
                return {"found": False}
            resp.raise_for_status()
            data = resp.json()
            return {
                "found": True,
                "org": data.get("org"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "city": data.get("city"),
                "country": data.get("country_name"),
            }
        except Exception as exc:
            return {"error": str(exc)}


def render(results: dict[str, Any], console: Console) -> None:
    """Pretty-print IP recon results."""
    if not results.get("valid"):
        print_status(console, "bad", results.get("error", "invalid IP"))
        return

    addr = results["input"]
    print_status(console, "info", f"target: {addr} (IPv{results.get('version', '?')})")

    ptrs = results.get("reverse_dns") or []
    if ptrs:
        console.print(f"[accent]reverse DNS:[/accent] [primary]{', '.join(ptrs)}[/primary]")
    else:
        print_status(console, "info", "no reverse DNS record")

    asn = results.get("asn") or {}
    if asn.get("asn"):
        print_kv_panel(console, "ASN", {k: v for k, v in asn.items() if v})
    else:
        print_status(console, "info", "no ASN info (IPv6 or lookup failed)")

    geo = results.get("geo") or {}
    if geo.get("error"):
        print_status(console, "warn", f"geo lookup failed: {geo['error']}")
    elif geo:
        printable = {
            "country": geo.get("country"),
            "region": geo.get("regionName"),
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "org": geo.get("org"),
            "as": geo.get("as"),
            "lat,lon": f"{geo.get('lat')}, {geo.get('lon')}",
        }
        printable = {k: v for k, v in printable.items() if v}
        if printable:
            print_kv_panel(console, "GEO / ISP", printable)

    shodan = results.get("shodan") or {}
    if "skipped" in shodan:
        print_status(console, "info", f"shodan skipped: {shodan['skipped']}")
    elif "error" in shodan:
        print_status(console, "warn", f"shodan error: {shodan['error']}")
    elif shodan.get("found"):
        printable = {
            "org": shodan.get("org"),
            "os": shodan.get("os"),
            "ports": shodan.get("ports"),
            "hostnames": shodan.get("hostnames"),
        }
        printable = {k: v for k, v in printable.items() if v}
        if printable:
            print_kv_panel(console, "SHODAN", printable)