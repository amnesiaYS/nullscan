"""Shared utilities: WHOIS lookup, ASN via DNS, async HTTP, shodan helper."""

from __future__ import annotations

import asyncio
import re
import socket
from collections.abc import Iterable
from typing import Any

import dns.resolver
import httpx

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
DEFAULT_USER_AGENT = "nullscan/0.1 (+https://github.com/nullsec/nullscan)"


def make_async_client(timeout: float = 15.0, follow_redirects: bool = True) -> httpx.AsyncClient:
    """Build an httpx async client with sensible defaults."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=follow_redirects,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"},
    )


async def gather_limited(coros: Iterable, limit: int = 10) -> list[Any]:
    """Run coroutines with bounded concurrency. Returns results in input order."""
    sem = asyncio.Semaphore(limit)

    async def wrapped(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*(wrapped(c) for c in coros), return_exceptions=True)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def dns_query(domain: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
    """Run a DNS query and return a list of string answers (empty on failure)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = lifetime
        resolver.timeout = lifetime
        answers = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        return [str(r.to_text().rstrip(".")) for r in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# WHOIS (raw socket protocol, no third-party lib)
# ---------------------------------------------------------------------------


_WHOIS_FIELDS: dict[str, list[str]] = {
    "registrar": [r"(?im)^registrar:\s*(.+)"],
    "creation_date": [
        r"(?im)^(?:creation date|created):\s*(.+)",
    ],
    "expiration_date": [
        r"(?im)^(?:expir(?:y|ation) date|registry expiry date|expires):\s*(.+)",
    ],
    "updated_date": [r"(?im)^(?:updated date|last[- ]updated):\s*(.+)"],
    "status": [r"(?im)^(?:domain status|status):\s*(.+)"],
    "nameservers": [r"(?im)^(?:name server|nserver):\s*(.+)"],
    "emails": [r"(?im)(?:registrant|admin|tech) email:\s*(.+)"],
    "country": [r"(?im)^country:\s*(.+)"],
    "org": [r"(?im)^(?:org[- ]?name|organization|registrant organization):\s*(.+)"],
}


def _whois_socket_query(domain: str, server: str, port: int = 43, timeout: int = 10) -> str:
    """Send a single-line WHOIS query over TCP."""
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(f"{domain}\r\n".encode())
        chunks: list[bytes] = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse_referral(response: str) -> str | None:
    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            value = line.split(":", 1)[1].strip()
            if value and "://" not in value:
                return value
    return None


def whois_lookup(domain: str) -> dict[str, Any]:
    """Look up WHOIS info. First queries IANA, then the referred server."""
    try:
        iana_resp = _whois_socket_query(domain, "whois.iana.org")
    except Exception as exc:
        return {"error": f"IANA query failed: {exc}", "raw": "", "server": "whois.iana.org"}

    referral = _parse_referral(iana_resp)
    if referral:
        try:
            response = _whois_socket_query(domain, referral)
        except Exception as exc:
            return {
                "error": f"referral query failed: {exc}",
                "raw": iana_resp,
                "server": referral,
            }
        server = referral
    else:
        response = iana_resp
        server = "whois.iana.org"

    parsed: dict[str, Any] = {"server": server, "raw": response, "error": None}
    for field, patterns in _WHOIS_FIELDS.items():
        matches: list[str] = []
        for pattern in patterns:
            found = re.findall(pattern, response)
            matches.extend(found)
        if matches:
            cleaned = sorted({m.strip() for m in matches if m.strip()})
            parsed[field] = cleaned if field in {"nameservers", "status", "emails"} else cleaned[0]
    return parsed


# ---------------------------------------------------------------------------
# ASN via Team Cymru DNS
# ---------------------------------------------------------------------------


def asn_lookup(ip: str) -> dict[str, Any]:
    """Look up ASN info for an IP via Team Cymru's DNS-based service."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    result: dict[str, Any] = {"ip": ip}

    try:
        answers = dns.resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT", lifetime=5)
        if answers:
            txt = str(answers[0].to_text().strip('"'))
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                result.update(
                    {
                        "asn": parts[0],
                        "block": parts[1],
                        "country": parts[2],
                        "registry": parts[3],
                        "allocation_date": parts[4],
                        "as_name": " | ".join(parts[5:]) if len(parts) > 5 else "",
                    }
                )
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(f"{reversed_ip}.peer.asn.cymru.com", "TXT", lifetime=5)
        if answers:
            txt = str(answers[0].to_text().strip('"'))
            parts = [p.strip() for p in txt.split("|")]
            if parts:
                result["peers"] = " | ".join(parts)
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "clickjacking"),
    ("X-Content-Type-Options", "MIME sniffing"),
    ("Referrer-Policy", "referrer leak"),
    ("Permissions-Policy", "feature policy"),
    ("X-XSS-Protection", "legacy XSS filter"),
    ("Cross-Origin-Opener-Policy", "COOP"),
    ("Cross-Origin-Resource-Policy", "CORP"),
]


async def fetch_security_headers(url: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    """HEAD/GET a URL and report the presence of common security headers."""
    own_client = client is None
    client = client or make_async_client(timeout=10)
    try:
        response = await client.get(url, follow_redirects=True)
        found = {header: response.headers.get(header, "") for header, _ in SECURITY_HEADERS}
        present = {label: value for (header, label), value in zip(SECURITY_HEADERS, found.values()) if value}
        missing = [label for header, label in SECURITY_HEADERS if not response.headers.get(header)]
        return {
            "url": str(response.url),
            "status": response.status_code,
            "present": present,
            "missing": missing,
        }
    except Exception as exc:
        return {"url": url, "error": str(exc), "present": {}, "missing": []}
    finally:
        if own_client:
            await client.aclose()