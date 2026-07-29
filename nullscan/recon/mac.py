"""MAC address vendor lookup via the IEEE OUI database.

The database below contains the top ~200 vendors by deployment volume. For
unknown OUIs the module reports the OUI prefix and an "unknown vendor" hint
so users can look it up themselves if needed.
"""

from __future__ import annotations

import re
from typing import Any

from rich.console import Console

from ..output import print_kv_panel, print_status

# Curated OUI database. Key is the first 24 bits of the MAC (uppercase, no separators).
# This is not exhaustive — for full coverage, parse the IEEE OUI CSV at
# https://standards-oui.ieee.org/oui/oui.csv and replace this dict.
OUI_DATABASE: dict[str, str] = {
    # Apple
    "001A2B": "Apple", "3C0754": "Apple", "F0F61C": "Apple", "0011D8": "Apple",
    "001E52": "Apple", "0016CB": "Apple", "F40F24": "Apple", "7C6DF8": "Apple",
    "40A6D9": "Apple", "60C547": "Apple", "78A3E4": "Apple", "DC2B61": "Apple",
    "AC3F94": "Apple", "98D6BB": "Apple", "B8E856": "Apple", "C8E0EB": "Apple",
    "9C207B": "Apple", "A4B197": "Apple", "0CA89C": "Apple", "34C059": "Apple",
    # Cisco
    "00000C": "Cisco", "00104B": "Cisco", "0011BB": "Cisco", "001B2A": "Cisco",
    "001D45": "Cisco", "001E13": "Cisco", "001E7A": "Cisco", "001F26": "Cisco",
    "002219": "Cisco", "0023EB": "Cisco", "0024F7": "Cisco", "0025B4": "Cisco",
    "5475D0": "Cisco", "B0827E": "Cisco", "F87B7A": "Cisco",
    # Intel
    "0013E8": "Intel", "0015C0": "Intel", "0016E6": "Intel", "0018DE": "Intel",
    "0019D1": "Intel", "001B21": "Intel", "001B77": "Intel", "001CC0": "Intel",
    "001D72": "Intel", "001E64": "Intel", "001E65": "Intel", "001E67": "Intel",
    "002314": "Intel", "00247E": "Intel", "0024D6": "Intel", "8086F2": "Intel",
    # Samsung
    "001247": "Samsung", "001599": "Samsung", "00166B": "Samsung", "0017C9": "Samsung",
    "0018AF": "Samsung", "001A8A": "Samsung", "001B98": "Samsung", "001D25": "Samsung",
    "001D6E": "Samsung", "001E7D": "Samsung", "0021D1": "Samsung", "0023D7": "Samsung",
    "0025C3": "Samsung", "08D40C": "Samsung", "24F5AA": "Samsung", "30CDB7": "Samsung",
    "B8BBE0": "Samsung", "F0E7C3": "Samsung", "5CA8E0": "Samsung", "B0C4E7": "Samsung",
    # Google
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google", "F8A9D0": "Google",
    "7085C2": "Google", "A4E0E6": "Google",
    # Microsoft / XBOX
    "001125": "Microsoft", "0017F2": "Microsoft", "0019D7": "Microsoft", "001D09": "Microsoft",
    "001E2D": "Microsoft", "002248": "Microsoft", "0025AE": "Microsoft", "28D244": "Microsoft",
    # HP / Aruba / HPE
    "0001E6": "HP", "00023F": "HP", "000A57": "HP", "000E7F": "HP", "0010E3": "HP",
    "001635": "HP", "001A4B": "HP", "001E0B": "HP", "00237D": "HP", "002481": "HP",
    "0025B3": "HP", "28D2D2": "HP", "3C4A92": "HP", "80CE62": "HP", "9C8E99": "HP",
    "B05B99": "Aruba Networks", "64680C": "Aruba Networks", "D8C7C8": "Aruba Networks",
    # Dell
    "001143": "Dell", "0015C5": "Dell", "0018A3": "Dell", "0019B9": "Dell", "001D09": "Dell",
    "001E0F": "Dell", "001E4F": "Dell", "001F3B": "Dell", "00219B": "Dell",
    "0024E8": "Dell", "18A99F": "Dell", "78F882": "Dell", "B083D6": "Dell",
    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    # TP-Link
    "0018E7": "TP-Link", "C0C9E3": "TP-Link", "30B5C2": "TP-Link", "DCAEF1": "TP-Link",
    "EC0861": "TP-Link", "A842A1": "TP-Link",
    # ASUS
    "0013D4": "ASUS", "0015F2": "ASUS", "001A92": "ASUS", "001BFC": "ASUS",
    "001E8C": "ASUS", "00248C": "ASUS", "F02FA8": "ASUS", "AC9B84": "ASUS",
    # Netgear
    "00146C": "Netgear", "00184B": "Netgear", "001E2A": "Netgear", "00224B": "Netgear",
    "0026F2": "Netgear", "04A182": "Netgear", "9CC9EB": "Netgear",
    # VMware
    "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
    # D-Link
    "000D3A": "D-Link", "0011A5": "D-Link", "0015E9": "D-Link", "0016E4": "D-Link",
    "001CF0": "D-Link", "001D7A": "D-Link", "002191": "D-Link", "1CAFF7": "D-Link",
    "B8A386": "D-Link", "F07D68": "D-Link",
    # Brother / Canon / Epson / HP Printers
    "001E8F": "Brother", "0025B3": "Brother", "30AE7D": "Brother", "0080A3": "Brother",
    "0001E3": "Canon", "001E8F": "Canon", "0025B3": "Canon", "00BBCC": "Canon",
    "0001E3": "Epson", "00048B": "Epson", "000E07": "Epson",
    # Huawei
    "001E10": "Huawei", "002568": "Huawei", "004A6B": "Huawei", "081196": "Huawei",
    "207B93": "Huawei", "484C68": "Huawei", "706F81": "Huawei", "ACCF5C": "Huawei",
    "CC96A0": "Huawei", "FCFFAA": "Huawei",
    # Xiaomi
    "001E58": "Xiaomi", "002273": "Xiaomi", "2882E9": "Xiaomi", "34CE69": "Xiaomi",
    "640980": "Xiaomi", "78F29B": "Xiaomi", "A0E1CF": "Xiaomi", "C4150E": "Xiaomi",
    # Sony
    "001315": "Sony", "001A80": "Sony", "001D0D": "Sony", "001FE4": "Sony",
    "0021B7": "Sony", "5CB2C2": "Sony",
    # Nintendo
    "001656": "Nintendo", "00191D": "Nintendo", "0019FD": "Nintendo", "001AE5": "Nintendo",
    "0021BD": "Nintendo", "002403": "Nintendo", "0025A0": "Nintendo", "B8AEED": "Nintendo",
    "98B6E9": "Nintendo", "CC9F7A": "Nintendo",
    # Microsoft Xbox specific
    "7C1E52": "Microsoft Xbox", "E45F01": "Microsoft Xbox",
    # Other common IoT / embedded
    "001A11": "Espressif (ESP)", "5CFF35": "Espressif (ESP)", "A020A6": "Espressif (ESP)",
    "BCFF4D": "Espressif (ESP)", "B4E62D": "Espressif (ESP)",
    "001DDF": "Sonoff", "B4E62D": "Sonoff",
}


def _normalize(mac: str) -> tuple[str, str | None]:
    """Return the canonical colon-separated MAC and the OUI prefix, or raise."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        raise ValueError(f"not a valid MAC address: '{mac}'")
    normalized = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()
    oui = cleaned[:6].upper()
    return normalized, oui


def lookup(mac: str) -> dict[str, Any]:
    """Look up a single MAC address."""
    try:
        normalized, oui = _normalize(mac)
    except ValueError as exc:
        return {"input": mac, "error": str(exc)}

    vendor = OUI_DATABASE.get(oui, "Unknown vendor")
    return {
        "input": mac,
        "mac": normalized,
        "oui": oui,
        "vendor": vendor,
        "is_private": oui == "020000" or oui.startswith("02"),
        "is_multicast": bool(int(oui[0:2], 16) & 0x01),
        "error": None,
    }


def scan(targets: list[str]) -> dict[str, Any]:
    """Look up one or more MAC addresses."""
    results = [lookup(m) for m in targets]
    known = sum(1 for r in results if r["vendor"] != "Unknown vendor" and not r.get("error"))
    return {
        "count": len(results),
        "known": known,
        "results": results,
    }


def render(data: dict[str, Any], console: Console) -> None:
    if not data.get("results"):
        print_status(console, "info", "no MAC addresses provided")
        return

    print_status(
        console,
        "ok" if data.get("known", 0) > 0 else "info",
        f"{data['known']}/{data['count']} MAC addresses matched a known vendor",
    )

    for r in data["results"]:
        if r.get("error"):
            print_status(console, "bad", f"{r['input']}: {r['error']}")
            continue

        kind = "ok" if r["vendor"] != "Unknown vendor" else "warn"
        glyph_status = kind
        console.print(
            f"[status.{glyph_status}]{ '[+]' if kind == 'ok' else '[!]' }[/status.{glyph_status}] "
            f"[primary]{r['mac']}[/primary]  "
            f"[accent]{r['vendor']}[/accent]"
        )
        if r["is_multicast"]:
            print_status(console, "warn", f"{r['mac']} has the multicast bit set")
        if r["is_private"]:
            print_status(console, "info", f"{r['mac']} is a locally-administered address")