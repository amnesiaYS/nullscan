"""CIDR expansion: turn a CIDR range into a list of IPs (capped)."""

from __future__ import annotations

import ipaddress
from typing import Any

from rich.console import Console

from ..output import print_list_panel, print_status

MAX_IPS_DISPLAY = 200
MAX_IPS_TOTAL = 1_000_000  # safety cap to avoid memory blowup on /8 ranges


def parse_cidr(target: str) -> dict[str, Any]:
    """Parse a single CIDR string and return its expansion metadata."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        return {"input": target, "error": str(exc)}

    total = network.num_addresses
    truncated = total > MAX_IPS_TOTAL
    if truncated:
        hosts_iter = network.hosts()
        sample = []
        for i, ip in enumerate(hosts_iter):
            if i >= MAX_IPS_TOTAL:
                break
            sample.append(str(ip))
    else:
        sample = [str(ip) for ip in network.hosts()]

    return {
        "input": target,
        "valid": True,
        "version": network.version,
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address) if network.version == 4 else None,
        "netmask": str(network.netmask),
        "prefix_length": network.prefixlen,
        "is_private": network.is_private,
        "is_multicast": network.is_multicast,
        "total_addresses": total,
        "usable_hosts": len(sample),
        "truncated": truncated,
        "hosts": sample,
        "error": None,
    }


def scan(targets: list[str]) -> dict[str, Any]:
    """Expand one or more CIDR ranges."""
    results = [parse_cidr(t) for t in targets]
    valid = sum(1 for r in results if r.get("valid"))
    return {"count": len(results), "valid": valid, "results": results}


def render(data: dict[str, Any], console: Console) -> None:
    if not data.get("results"):
        print_status(console, "info", "no CIDR ranges provided")
        return

    print_status(
        console,
        "ok" if data.get("valid", 0) == data.get("count", 0) else "warn",
        f"{data['valid']}/{data['count']} CIDR ranges parsed",
    )

    for r in data["results"]:
        if r.get("error"):
            print_status(console, "bad", f"{r['input']}: {r['error']}")
            continue

        console.print(
            f"[accent]{r['input']}[/accent]  [primary]{r['total_addresses']:,} addresses[/primary] "
            f"[muted](IPv{r['version']}, /{r['prefix_length']}, netmask {r['netmask']})[/muted]"
        )
        if r.get("is_private"):
            print_status(console, "info", "private range (RFC1918 / ULA)")
        if r.get("is_multicast"):
            print_status(console, "info", "multicast range")
        if r.get("truncated"):
            print_status(
                console,
                "warn",
                f"truncated to first {MAX_IPS_TOTAL:,} of {r['total_addresses']:,} addresses",
            )

        display = r["hosts"][:MAX_IPS_DISPLAY]
        if display:
            print_list_panel(
                console,
                f"HOSTS ({r['usable_hosts']:,} total)",
                display,
                empty_message="(none)",
            )
        if len(r["hosts"]) > MAX_IPS_DISPLAY:
            print_status(
                console,
                "info",
                f"… {len(r['hosts']) - MAX_IPS_DISPLAY:,} more hosts omitted from display",
            )