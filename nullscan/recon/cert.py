"""TLS certificate inspection: connect to a host, retrieve the cert chain."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from rich.console import Console

from ..output import print_kv_panel, print_status, print_table


def _parse_host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    target = target.strip()
    if ":" in target and not target.startswith("["):
        # IPv6 or hostname:port
        host, _, port_s = target.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return target, default_port
    if target.startswith("[") and "]" in target:
        end = target.index("]")
        host = target[1:end]
        rest = target[end + 1 :]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, default_port
        return host, default_port
    return target, default_port


def fetch(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Connect to host:port and return the leaf certificate details."""
    hostname, port_n = _parse_host_port(host, port)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we want the cert even if invalid

    raw: dict[str, Any] = {}
    try:
        with socket.create_connection((hostname, port_n), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der).encode()
                # Parse the PEM with a fresh verifying context to read fields.
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                # We can't easily re-parse the binary der via stdlib; use getpeercert
                # by re-wrapping a fresh socket isn't needed — getpeercert() returns
                # a dict when not in binary_form=True mode.
                raw = ssock.getpeercert() or {}
                # Raw PEM for the report.
                raw["__pem__"] = pem.decode()
    except (socket.gaierror, ConnectionRefusedError, socket.timeout, ssl.SSLError, OSError) as exc:
        return {"input": host, "host": hostname, "port": port_n, "error": str(exc)}

    subject = dict(x[0] for x in raw.get("subject", []) or [])
    issuer = dict(x[0] for x in raw.get("issuer", []) or [])
    sans = [v for k, v in (raw.get("subjectAltName") or [])]
    not_before = raw.get("notBefore")
    not_after = raw.get("notAfter")
    serial = raw.get("serialNumber")
    version = raw.get("version")
    sig_alg = raw.get("signatureAlgorithm", "unknown")

    # Days until expiry.
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "input": host,
        "host": hostname,
        "port": port_n,
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "version": version,
        "signature_algorithm": sig_alg,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": days_left,
        "sans": sans,
        "expired": days_left is not None and days_left < 0,
        "expires_soon": days_left is not None and 0 <= days_left <= 30,
        "error": None,
    }


def scan(targets: list[str], port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch certs for one or more hosts."""
    results = [fetch(t, port=port, timeout=timeout) for t in targets]
    errors = sum(1 for r in results if r.get("error"))
    return {"count": len(results), "errors": errors, "results": results}


def _format_subject(d: dict[str, str]) -> str:
    return ", ".join(f"{k}={v}" for k, v in d.items())


def render(data: dict[str, Any], console: Console) -> None:
    if not data.get("results"):
        print_status(console, "info", "no hosts provided")
        return

    for r in data["results"]:
        if r.get("error"):
            print_status(console, "bad", f"{r['input']}: {r['error']}")
            continue

        console.print(
            f"[accent]{r['host']}[/accent][muted]:{r['port']}[/muted]  "
            f"[primary]{_format_subject(r['subject'])}[/primary]"
        )

        expiry = r.get("days_until_expiry")
        if r.get("expired"):
            print_status(console, "bad", f"expired {-expiry} days ago ({r['not_after']})")
        elif r.get("expires_soon"):
            print_status(console, "warn", f"expires in {expiry} days ({r['not_after']})")
        else:
            print_status(console, "ok", f"valid for {expiry} more days (until {r['not_after']})")

        kv: dict[str, Any] = {
            "issuer": _format_subject(r["issuer"]),
            "signature_algorithm": r["signature_algorithm"],
            "version": r["version"],
            "serial": r["serial"],
            "not_before": r["not_before"],
            "not_after": r["not_after"],
        }
        print_kv_panel(console, "CERTIFICATE", kv)

        if r.get("sans"):
            sans_rows = [[i + 1, san] for i, san in enumerate(r["sans"][:30])]
            print_table(console, f"SUBJECT ALTERNATIVE NAMES ({len(r['sans'])} total)", ["#", "SAN"], sans_rows)
            if len(r["sans"]) > 30:
                print_status(console, "info", f"… {len(r['sans']) - 30} more SANs omitted")