"""Hash module: MD5 / SHA1 / SHA256 / SHA512 / SHA3 of files or strings."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from rich.console import Console

from ..output import print_kv_panel, print_status

ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512")


def _hash_bytes(data: bytes, algorithm: str) -> str:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm '{algorithm}' (use one of: {', '.join(ALGORITHMS)})")
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(path: Path, algorithms: list[str]) -> dict[str, Any]:
    """Hash a file with the given algorithms. Reads in chunks for large files."""
    p = Path(path)
    if not p.exists():
        return {"input": str(p), "kind": "file", "error": "file not found"}
    if not p.is_file():
        return {"input": str(p), "kind": "file", "error": "not a regular file"}

    hashes: dict[str, str] = {alg: hashlib.new(alg) for alg in algorithms}
    size = 0
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            size += len(chunk)
            for h in hashes.values():
                h.update(chunk)

    return {
        "input": str(p),
        "kind": "file",
        "size_bytes": size,
        "algorithms": {alg: h.hexdigest() for alg, h in hashes.items()},
        "error": None,
    }


def hash_text(text: str, algorithms: list[str]) -> dict[str, Any]:
    """Hash a string with the given algorithms."""
    data = text.encode("utf-8")
    return {
        "input": text,
        "kind": "text",
        "size_bytes": len(data),
        "algorithms": {alg: _hash_bytes(data, alg) for alg in algorithms},
        "error": None,
    }


def scan_file(path: Path, algorithm: str = "all") -> dict[str, Any]:
    """Public entry point used by the CLI for file inputs."""
    if algorithm == "all":
        algorithms = list(ALGORITHMS)
    elif algorithm in ALGORITHMS:
        algorithms = [algorithm]
    else:
        return {"input": str(path), "kind": "file", "error": f"unknown algorithm '{algorithm}'"}
    return hash_file(path, algorithms)


def scan_text(text: str, algorithm: str = "all") -> dict[str, Any]:
    """Public entry point used by the CLI for --text inputs."""
    if algorithm == "all":
        algorithms = list(ALGORITHMS)
    elif algorithm in ALGORITHMS:
        algorithms = [algorithm]
    else:
        return {"input": text, "kind": "text", "error": f"unknown algorithm '{algorithm}'"}
    return hash_text(text, algorithms)


def render(results: dict[str, Any], console: Console) -> None:
    """Pretty-print a hash result."""
    if results.get("error"):
        print_status(console, "bad", f"{results['input']}: {results['error']}")
        return

    console.print(
        f"[accent]{results['kind']}[/accent] [primary]{results['input']}[/primary] "
        f"[muted]({results['size_bytes']} bytes)[/muted]"
    )
    rows = {alg.upper(): value for alg, value in results["algorithms"].items()}
    print_kv_panel(console, "HASHES", rows)