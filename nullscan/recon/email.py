"""Email reconnaissance: validation, MX, gravatar, HIBP breach lookup."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from rich.console import Console

from ..config import Config, load_config
from ..output import print_kv_panel, print_status
from ..utils import dns_query, make_async_client

# Pragmatic RFC 5322-ish regex. Catches the common cases, allows most legal
# addresses, accepts unicode local parts.
EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)

# Small disposable email blocklist (curated). Avoids dependency on a third
# party list. Add to as needed.
DISPOSABLE_DOMAINS: set[str] = {
    "10minutemail.com", "10minutemail.net", "20minutemail.com",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "mailinator.com", "mailinator.net", "mailinator2.com",
    "tempmail.com", "temp-mail.org", "temp-mail.io",
    "throwawaymail.com", "yopmail.com", "yopmail.fr",
    "maildrop.cc", "dispostable.com", "fakeinbox.com",
    "getairmail.com", "getnada.com", "inboxbear.com",
    "mailcatch.com", "mailnesia.com", "mintemail.com",
    "mohmal.com", "spambox.us", "spamfree24.org",
    "spamgourmet.com", "trashmail.com", "trashmail.net",
    "mailtemp.info", "tempmailaddress.com", "sharklasers.com",
    "emailondeck.com", "mail7.io", "tempr.email",
    "tempmail.dev", "tempmail.us.com", "tempmailo.com",
    "burnermail.io", "harakirimail.com", "objectmail.com",
    "proxymail.eu", "rcpt.at", "tempemail.net",
    "byom.de", "discard.email", "discardmail.com",
    "discardmail.de", "dodsi.com", "e4ward.com",
    "emailfake.com", "emailmiser.com", "emltmp.com",
    "fakemail.fr", "fakemailgenerator.com", "filzmail.com",
    "fleckens.hu", "hidemail.de",
    "letthemeatspam.com", "mailforspam.com", "mailinater.com",
    "mailnull.com", "mvrht.com", "mvrht.net",
    "no-spam.ws", "nogmailspam.info", "one-time.email",
    "poofy.org", "pookmail.com", "privacy.net",
    "put2.net", "reallymymail.com",
    "recode.me", "recursor.net", "reliable-mail.com",
    "rmqkr.net", "rppkn.com", "rtrtr.com",
    "s0ny.net", "safetymail.info", "sandelf.de",
    "saynotospams.com", "schafmail.de", "schrott-email.de",
    "secretemail.de", "sendspamhere.com", "sharedmailbox.org",
    "shieldedmail.com", "shieldemail.com", "shitmail.me",
    "shitware.nl", "shmeriously.com", "shortmail.net",
    "sify.com", "sinnlos-mail.de", "skeefmail.com",
    "slapsfromlastnight.com", "slaskpost.se", "smashmail.de",
    "smellfear.com", "snakemail.com", "sneakemail.de",
    "snkmail.com", "sofimail.com", "sofort-mail.de",
    "solvemail.info", "sogetthis.com", "soodonims.com",
    "spam.la", "spam.su", "spamavert.com",
    "spambob.com", "spambob.net", "spambob.org",
    "spambooger.com", "spambox.info", "spambox.irishspringrealty.com",
}


async def scan(addr: str) -> dict[str, Any]:
    """Run email recon on a single address."""
    addr = addr.strip()
    local, _, domain = addr.partition("@")
    results: dict[str, Any] = {
        "input": addr,
        "valid_format": bool(local and domain and EMAIL_REGEX.match(addr)),
        "local_part": local,
        "domain": domain,
        "mx": [],
        "disposable": False,
        "gravatar": None,
        "breaches": None,
        "suggestion": None,
    }

    if not results["valid_format"]:
        return results

    results["disposable"] = domain.lower() in DISPOSABLE_DOMAINS

    if not results["disposable"]:
        results["mx"] = dns_query(domain, "MX")

    results["gravatar"] = _gravatar_for(addr)
    results["suggestion"] = _common_typo(domain)

    # Optional HIBP breach lookup (requires API key).
    cfg = load_config()
    if cfg.get("hibp"):
        results["breaches"] = await _hibp_breach_lookup(addr, cfg)
    else:
        results["breaches"] = {"skipped": "set HIBP_API_KEY or run `nullscan config`"}

    return results


def _gravatar_for(addr: str) -> dict[str, str]:
    """Compute the gravatar hash + URLs for an email."""
    digest = hashlib.md5(addr.strip().lower().encode("utf-8")).hexdigest()
    return {
        "hash": digest,
        "url": f"https://www.gravatar.com/avatar/{digest}?d=404",
        "profile": f"https://www.gravatar.com/{digest}.json",
    }


def _common_typo(domain: str) -> str | None:
    """Suggest a correction for common typos (e.g. gmial.com → gmail.com)."""
    suggestions = {
        "gmial.com": "gmail.com",
        "gnail.com": "gmail.com",
        "gmal.com": "gmail.com",
        "gmail.co": "gmail.com",
        "gmail.con": "gmail.com",
        "yahooo.com": "yahoo.com",
        "yahoo.co": "yahoo.com",
        "yahoo.con": "yahoo.com",
        "hotnail.com": "hotmail.com",
        "hotmai.com": "hotmail.com",
        "hotmil.com": "hotmail.com",
        "hotmail.co": "hotmail.com",
        "outlok.com": "outlook.com",
        "outloo.com": "outlook.com",
    }
    return suggestions.get(domain.lower())


async def _hibp_breach_lookup(addr: str, cfg: Config) -> dict[str, Any]:
    """Look up the address in HIBP breach corpus (requires API key)."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{addr}"
    headers = {"hibp-api-key": cfg.require("hibp"), "user-agent": "nullscan/0.1"}
    async with make_async_client(timeout=15) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {"found": False, "breaches": []}
            resp.raise_for_status()
            data = resp.json()
            return {
                "found": True,
                "count": len(data),
                "breaches": [
                    {"name": b.get("Name"), "date": b.get("BreachDate"), "exposed": b.get("DataClasses")}
                    for b in data
                ],
            }
        except Exception as exc:
            return {"error": str(exc)}


def render(results: dict[str, Any], console: Console) -> None:
    """Pretty-print email recon results."""
    if not results.get("valid_format"):
        print_status(console, "bad", f"'{results['input']}' is not a valid email address")
        return

    addr = results["input"]
    print_status(console, "info", f"target: {addr}")

    kv: dict[str, Any] = {
        "format": "valid",
        "disposable": "yes" if results.get("disposable") else "no",
        "mx_records": results.get("mx") or "(none)",
    }
    if results.get("suggestion"):
        kv["did you mean"] = results["suggestion"]
    print_kv_panel(console, "EMAIL CHECK", kv)

    g = results.get("gravatar") or {}
    if g:
        console.print(
            f"[accent]gravatar:[/accent] [primary]{g.get('hash', '?')[:12]}…[/primary] "
            f"[muted]({g.get('url')})[/muted]"
        )

    breaches = results.get("breaches")
    if breaches is None:
        pass
    elif "skipped" in breaches:
        print_status(console, "info", f"breach lookup skipped: {breaches['skipped']}")
    elif "error" in breaches:
        print_status(console, "bad", f"breach lookup failed: {breaches['error']}")
    elif breaches.get("found"):
        console.print(f"[status.bad][!][/status.bad] [primary]found in {breaches['count']} breach(es)[/primary]")
        for b in breaches.get("breaches", [])[:10]:
            console.print(f"  - [accent]{b.get('name')}[/accent] [muted]({b.get('date')})[/muted]")
    else:
        print_status(console, "ok", "no breaches found for this address")