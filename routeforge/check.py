"""routeforge check — a health/doctor command for your forge."""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

from . import __version__
from .config import load_config
from .sources import probe_url


def _emit(kind: str, message: str) -> None:
    print(f"{kind:4} {message}")


def check_command(args) -> int:
    """The check subcommand. Returns 1 when problems are found, else 0."""
    root = Path(getattr(args, "root", None)) if getattr(args, "root", None) else Path.cwd()
    offline = bool(getattr(args, "offline", False))
    failures = 0

    print(f"routeforge {__version__} — health check")
    print(f"root: {root}")

    config, fatal = load_config(root)
    if config is None:
        for message in fatal:
            _emit("FAIL", f"config: {message}")
            failures += 1
        return 1 if failures else 0

    _emit("OK", f"config: forge.toml loaded ({len(config.targets)} targets)")
    _emit("OK", f"repo: {config.owner}/{config.repo}")

    for target in config.targets:
        rules_path = root / "rules" / f"{target.name}.txt"
        if rules_path.exists():
            _emit("OK", f"target {target.name}: rules/{target.name}.txt present")
        else:
            _emit("WARN", f"target {target.name}: rules/{target.name}.txt missing (will be empty)")

    enabled = [s for s in config.sources if s.enabled]
    for source in enabled:
        ref = f" (catalog: {source.catalog})" if source.catalog else ""
        if offline:
            _emit("INFO", f"source {source.name}{ref}: reachability skipped (--offline)")
            continue
        ok, message = probe_url(source.url)
        if ok:
            _emit("OK", f"source {source.name}{ref}: reachable ({message})")
        else:
            _emit("FAIL", f"source {source.name}{ref}: unreachable: {message}")
            failures += 1
        if source.sha256:
            _emit("INFO", f"source {source.name}: sha256 pinned")
        else:
            _emit("WARN", f"source {source.name}: not pinned")

    if not enabled:
        _emit("INFO", "sources: none enabled (neutral forge — add [[sources]] to forge.toml)")

    sing_box = shutil.which("sing-box")
    if sing_box:
        _emit("OK", f"sing-box: {sing_box}")
    else:
        _emit("WARN", "sing-box: not on PATH (only needed to compile .srs locally; CI installs it)")

    manifest = root / "release-assets" / "build-manifest.json"
    if manifest.exists():
        try:
            age_days = (time.time() - manifest.stat().st_mtime) / 86400
            _emit("OK", f"manifest: present (built {age_days:.1f} days ago)")
            if age_days > 7:
                _emit("WARN", "manifest: older than 7 days — run routeforge build")
        except OSError:
            _emit("WARN", "manifest: unreadable")
    else:
        _emit("INFO", "manifest: no build yet (run routeforge build)")

    if failures:
        print(f"{failures} problem(s) found", file=sys.stderr)
    else:
        print("healthy")
    return 1 if failures else 0
