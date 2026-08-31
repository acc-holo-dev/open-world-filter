"""Hardened external source fetching: retries, size cap, cache, sha256 pins."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, engine
from .config import Source

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
DOWNLOAD_TIMEOUT = 45.0
DOWNLOAD_RETRIES = 3
DOWNLOAD_CHUNK = 1 << 16
USER_AGENT = f"routeforge/{__version__}"


def fetch_bytes(url: str, *, timeout: float = DOWNLOAD_TIMEOUT, retries: int = DOWNLOAD_RETRIES,
                max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Download a URL with retries and a hard size cap. Supports file:// URLs."""
    if url.startswith("file://"):
        parsed = urllib.parse.urlparse(url)
        raw = urllib.parse.unquote(parsed.path)
        if os.name == "nt":  # file:///C:/x -> Path must not see a leading slash
            raw = re.sub(r"^/(?=[A-Za-z]:)", "", raw)
        data = Path(raw).read_bytes()
        if len(data) > max_bytes:
            raise RuntimeError(f"file exceeds {max_bytes} bytes")
        return data

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                chunks = []
                total = 0
                while True:
                    chunk = response.read(DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"response exceeds {max_bytes} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
        except Exception as exc:  # noqa: BLE001 - retried below
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8) + random.random())
    raise RuntimeError(f"download failed after {retries} attempts: {last_error}")


def cache_paths(cache_dir: Path, url: str) -> tuple[Path, Path]:
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{key}.body", cache_dir / f"{key}.meta.json"


def cache_load(cache_dir: Path, url: str, ttl: int) -> dict | None:
    body_path, meta_path = cache_paths(cache_dir, url)
    if not (body_path.exists() and meta_path.exists()):
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if ttl >= 0:
        try:
            fetched_at = datetime.fromisoformat(meta["fetched_at"])
        except (KeyError, TypeError, ValueError):
            return None
        if datetime.now(timezone.utc) - fetched_at > timedelta(seconds=ttl):
            return None
    try:
        return {"body": body_path.read_bytes(), "meta": meta}
    except OSError:
        return None


def probe_url(url: str, timeout: float = 10.0) -> tuple[bool, str]:
    """Light reachability probe: (ok, message). Reads at most one chunk."""
    if url.startswith("file://"):
        parsed = urllib.parse.urlparse(url)
        raw = urllib.parse.unquote(parsed.path)
        if os.name == "nt":
            raw = re.sub(r"^/(?=[A-Za-z]:)", "", raw)
        path = Path(raw)
        return (path.is_file(), "file exists" if path.is_file() else "file missing")
    started = time.perf_counter()
    last: Exception | None = None
    for method in ("HEAD", "GET"):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method=method)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response.read(1)
            return True, f"{round((time.perf_counter() - started) * 1000)} ms"
        except Exception as exc:  # noqa: BLE001 - try the next method, then report
            last = exc
    return False, str(last)


def cache_store(cache_dir: Path, url: str, body: bytes, digest: str) -> None:
    body_path, meta_path = cache_paths(cache_dir, url)
    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp = body_path.with_name(body_path.name + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, body_path)
    meta = {"url": url, "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sha256": digest, "bytes": len(body)}
    tmp = meta_path.with_name(meta_path.name + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, meta_path)


def fetch_source_record(source: Source, cache_dir: Path | None, ttl: int, offline: bool) -> dict:
    """Download (or load from cache), verify and parse one external source."""
    url = source.url
    label = f"forge.toml:sources.{source.name}"
    record = {
        "name": source.name,
        "action": source.action,
        "target": source.target,
        "url": url,
        "kind": source.kind or "auto",
        "cached": False,
        "status": "ok",
        "error": None,
        "sha256": None,
        "bytes": 0,
        "duration_ms": 0,
        "lines": 0,
        "accepted": 0,
        "rejected": 0,
        "skipped": 0,
        "offline_missing": False,
    }
    started = time.perf_counter()
    body: bytes | None = None

    if cache_dir is not None:
        hit = cache_load(cache_dir, url, ttl)
        if hit is not None:
            body = hit["body"]
            record["cached"] = True
            record["sha256"] = hit["meta"].get("sha256")

    if body is None:
        if offline:
            record["status"] = "failed"
            record["error"] = "offline mode: no cached copy available"
            record["offline_missing"] = True
            return record
        try:
            body = fetch_bytes(url)
        except Exception as exc:  # noqa: BLE001 - reported as a failed source
            record["status"] = "failed"
            record["error"] = str(exc)
            return record
        digest = hashlib.sha256(body).hexdigest()
        record["sha256"] = digest
        if cache_dir is not None:
            try:
                cache_store(cache_dir, url, body, digest)
            except OSError:
                pass  # cache is best-effort
    elif record["sha256"] is None:
        record["sha256"] = hashlib.sha256(body).hexdigest()

    if source.sha256 and record["sha256"] != source.sha256:
        record["status"] = "failed"
        record["error"] = f"sha256 mismatch: expected {source.sha256}, got {record['sha256']}"
        return record

    record["bytes"] = len(body)
    lines = body.decode("utf-8", errors="replace").splitlines()
    if source.kind == "domains":
        record["_domains"], errors, stats = engine.parse_entries(lines, "domain", label)
        record["_ips"] = []
    elif source.kind == "ips":
        record["_ips"], errors, stats = engine.parse_entries(lines, "ip", label)
        record["_domains"] = []
    else:
        record["_domains"], record["_ips"], errors, stats = engine.parse_mixed_lines(lines, label)
    record.update({"lines": stats["lines"], "accepted": stats["accepted"],
                   "rejected": stats["rejected"], "skipped": stats["skipped"]})
    record["duration_ms"] = round((time.perf_counter() - started) * 1000)
    record["_errors"] = errors
    return record
