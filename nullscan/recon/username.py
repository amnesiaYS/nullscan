"""Username enumeration across ~20 platforms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from rich.console import Console

from ..output import print_status, print_table
from ..utils import gather_limited, make_async_client


@dataclass(frozen=True)
class Platform:
    """A site we can probe for the presence of a username."""

    name: str
    url_template: str
    method: str = "status"     # "status" or "content"
    found: int = 200           # HTTP status indicating "user exists"
    not_found: int = 404       # HTTP status indicating "user does not exist"
    content_marker: str = ""   # for "content" method: substring that MUST be present


# Curated platform list. Detection is best-effort: sites change their
# behaviour, so a probe can give false positives/negatives.
PLATFORMS: list[Platform] = [
    Platform("GitHub",       "https://github.com/{user}",        "status", 200, 404),
    Platform("GitLab",       "https://gitlab.com/{user}",        "status", 200, 404),
    Platform("Twitter/X",    "https://twitter.com/{user}",       "status", 200, 404),
    Platform("Reddit",       "https://www.reddit.com/user/{user}", "status", 200, 404),
    Platform("Instagram",    "https://www.instagram.com/{user}/", "status", 200, 404),
    Platform("YouTube",      "https://www.youtube.com/@{user}",  "status", 200, 404),
    Platform("TikTok",       "https://www.tiktok.com/@{user}",   "status", 200, 404),
    Platform("Mastodon",     "https://mastodon.social/@{user}",  "status", 200, 404),
    Platform("HackerNews",   "https://news.ycombinator.com/user?id={user}", "status", 200, 404),
    Platform("Medium",       "https://medium.com/@{user}",       "status", 200, 404),
    Platform("StackOverflow", "https://stackoverflow.com/users/{user}", "status", 200, 404),
    Platform("Twitch",       "https://www.twitch.tv/{user}",     "status", 200, 404),
    Platform("Pinterest",    "https://www.pinterest.com/{user}/", "status", 200, 404),
    Platform("Telegram",     "https://t.me/{user}",              "status", 200, 404),
    Platform("VK",           "https://vk.com/{user}",            "status", 200, 404),
    Platform("Steam",        "https://steamcommunity.com/id/{user}", "status", 200, 404),
    Platform("Spotify",      "https://open.spotify.com/user/{user}", "status", 200, 404),
    Platform("SoundCloud",   "https://soundcloud.com/{user}",    "status", 200, 404),
    Platform("DeviantArt",   "https://www.deviantart.com/{user}", "status", 200, 404),
    Platform("Flickr",       "https://www.flickr.com/people/{user}/", "status", 200, 404),
    Platform("DockerHub",    "https://hub.docker.com/u/{user}",  "status", 200, 404),
    Platform("npm",          "https://www.npmjs.com/~{user}",   "status", 200, 404),
    Platform("PyPI",         "https://pypi.org/user/{user}",     "status", 200, 404),
]


async def _probe(platform: Platform, user: str, client: httpx.AsyncClient) -> dict[str, Any]:
    url = platform.url_template.format(user=user)
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"name": platform.name, "url": url, "status": "error", "detail": str(exc)}

    if platform.method == "status":
        if resp.status_code == platform.found:
            status = "found"
        elif resp.status_code == platform.not_found:
            status = "missing"
        else:
            status = f"http_{resp.status_code}"
    elif platform.method == "content":
        if resp.status_code == platform.not_found:
            status = "missing"
        elif platform.content_marker and platform.content_marker in resp.text:
            status = "found"
        else:
            status = "missing"
    else:
        status = f"unknown_method_{platform.method}"

    return {"name": platform.name, "url": url, "status": status, "http": resp.status_code}


async def scan(handle: str, concurrency: int = 10) -> dict[str, Any]:
    """Probe all platforms for ``handle``. Returns a structured dict."""
    handle = handle.strip().lstrip("@")
    coros = [_probe(p, handle, make_async_client(timeout=10)) for p in PLATFORMS]
    raw = await gather_limited(coros, limit=concurrency)

    results: list[dict[str, Any]] = []
    for platform, outcome in zip(PLATFORMS, raw):
        if isinstance(outcome, Exception):
            results.append(
                {"name": platform.name, "url": platform.url_template.format(user=handle), "status": "error", "detail": str(outcome)}
            )
        else:
            results.append(outcome)

    return {"handle": handle, "results": results}


def render(results: dict[str, Any], console: Console) -> None:
    """Pretty-print the username scan."""
    handle = results.get("handle", "?")
    rows = results.get("results") or []
    found = sum(1 for r in rows if r.get("status") == "found")

    print_status(console, "info", f"handle: {handle}")
    print_status(console, "ok" if found else "info", f"found on {found}/{len(rows)} platforms")

    table_rows = []
    styles = []
    for r in rows:
        status = r.get("status", "?")
        if status == "found":
            cell_style = "ok"
        elif status == "missing":
            cell_style = "muted"
        elif status == "error":
            cell_style = "bad"
        else:
            cell_style = "warn"
        table_rows.append([r.get("name", "?"), status, r.get("url", "")])
        styles.extend([None, cell_style, None])
    if table_rows:
        print_table(console, "USERNAME PRESENCE", ["Platform", "Status", "URL"], table_rows, styles=styles)