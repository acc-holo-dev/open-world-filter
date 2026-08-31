"""Build orchestration: merge, exclude, and write rule-sets, profiles, reports."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, engine
from .config import Config, load_config
from .profiles import render_profiles
from .sources import fetch_source_record

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_LIMIT = 100
KINDS = ("domains", "ips")


class Layout:
    """Filesystem layout of one build root."""

    def __init__(self, root: str | Path | None = None, output_dir: str | Path | None = None,
                 cache_dir: str | Path | None = None):
        self.root = Path(root).resolve() if root else DEFAULT_ROOT
        self.rules_dir = self.root / "rules"
        self.templates_dir = self.root / "templates"
        self.output_dir = Path(output_dir) if output_dir else self.root / "release-assets"
        self.cache_dir = Path(cache_dir) if cache_dir else self.root / ".source-cache"


def git_info(root: Path) -> dict | None:
    def run(*cmd: str) -> str | None:
        try:
            proc = subprocess.run(["git", "-C", str(root), *cmd], capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.strip() or None

    commit = run("rev-parse", "HEAD")
    if not commit:
        return None
    return {"commit": commit, "ref": run("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(run("status", "--porcelain"))}


def collect_warnings(config: Config, all_entries: dict, records: list[dict]) -> list[str]:
    warnings: list[str] = []
    empty = []
    for target in config.targets:
        for kind in KINDS:
            if not all_entries[target.name][kind]:
                empty.append(f"{target.name}-{kind}")
    if empty:
        warnings.append("empty rule-sets: " + ", ".join(empty))
    for target in config.targets:
        entries = all_entries[target.name]["domains"]
        broad = sorted({e for e in entries if e.startswith("keyword:") and len(e) < len("keyword:") + 3})
        if broad:
            warnings.append(f"{target.name}: very broad keyword rules: " + ", ".join(broad))
    for record in records:
        if record["status"] == "ok" and record["rejected"]:
            warnings.append(f"sources.{record['name']}: {record['rejected']} invalid lines skipped")
    return warnings


def build_changes(config: Config, all_entries: dict, previous_dir: Path) -> dict:
    """Diff the freshly built entries against previously built rule-sets."""
    targets_out: dict[str, dict] = {}
    any_previous = False
    for target in config.targets:
        for kind in KINDS:
            stem = f"{target.name}-{kind}"
            prev_path = previous_dir / f"{stem}.json"
            has_previous = prev_path.exists()
            prev_set: set[str] = set()
            before = None
            if has_previous:
                try:
                    prev_set = engine.entries_from_rule_set(json.loads(prev_path.read_text(encoding="utf-8")))
                    before = len(prev_set)
                    any_previous = True
                except (json.JSONDecodeError, OSError):
                    has_previous = False
            current = set(all_entries[target.name][kind])
            added = sorted(current - prev_set)
            removed = sorted(prev_set - current)
            targets_out[stem] = {
                "before": before,
                "after": len(current),
                "added": len(added),
                "removed": len(removed),
                "added_examples": added[:EXAMPLE_LIMIT],
                "removed_examples": removed[:EXAMPLE_LIMIT],
                "truncated": len(added) > EXAMPLE_LIMIT or len(removed) > EXAMPLE_LIMIT,
            }
    totals = {"added": sum(t["added"] for t in targets_out.values()),
              "removed": sum(t["removed"] for t in targets_out.values())}
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "first_build": not any_previous, "targets": targets_out, "totals": totals}


def clean_generated_outputs(output_dir: Path) -> None:
    """The output directory is fully managed: generated files are removed."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.json", "*.srs"):
        for path in output_dir.glob(pattern):
            path.unlink(missing_ok=True)
    (output_dir / "checksums.txt").unlink(missing_ok=True)


def write_outputs(layout: Layout, config: Config, all_entries: dict, manifest: dict,
                  changes: dict | None, no_profiles: bool) -> None:
    clean_generated_outputs(layout.output_dir)
    for target in config.targets:
        for kind in KINDS:
            engine_kind = "domain" if kind == "domains" else "ip"
            output = layout.output_dir / f"{target.name}-{kind}.json"
            output.write_text(
                json.dumps(engine.to_rule_set(engine_kind, all_entries[target.name][kind]),
                           ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not no_profiles:
        render_profiles(config, layout.templates_dir, layout.output_dir)
    if changes is not None:
        (layout.output_dir / "changes-report.json").write_text(
            json.dumps(changes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (layout.output_dir / "build-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    checksum_lines = []
    for path in sorted(layout.output_dir.glob("*.json"), key=lambda p: p.name):
        checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (layout.output_dir / "checksums.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")


def print_summary(config: Config, meta_by_target: dict, records: list[dict], warnings: list[str],
                  changes: dict | None, layout: Layout, args, duration_ms: int) -> None:
    print(f"== routeforge {__version__} ==")
    print(f"root: {layout.root}")
    for target in config.targets:
        meta = meta_by_target[target.name]
        print(f"  {target.name} ({target.action}): domains={meta['domains']['entries']} ips={meta['ips']['entries']}")
    enabled = len(records)
    failed = sum(1 for r in records if r["status"] != "ok")
    cached = sum(1 for r in records if r["cached"])
    print(f"sources: {enabled} enabled, {enabled - failed} ok ({cached} cached), {failed} failed")
    if getattr(args, "verbose", False):
        for record in records:
            state = "ok" if record["status"] == "ok" else f"FAILED ({record['error']})"
            print(f"  [{record['action']}] sources.{record['name']} -> {record['target']}: {state} "
                  f"({record['lines']} lines, {record['accepted']} accepted, {record['rejected']} rejected, "
                  f"{record['duration_ms']}ms)")
    for warning in warnings:
        print(f"warning: {warning}")
    if changes is not None:
        if changes["first_build"]:
            print("changes: first build, no previous rule-sets to compare")
        else:
            totals = changes["totals"]
            print(f"changes: +{totals['added']} added, -{totals['removed']} removed vs previous")
    print(f"outputs -> {layout.output_dir}")
    print(f"build completed in {duration_ms} ms")


def build_command(args) -> int:
    """The `build` subcommand. Returns the process exit code."""
    layout = Layout(root=getattr(args, "root", None), output_dir=getattr(args, "output_dir", None),
                    cache_dir=getattr(args, "cache_dir", None))
    started = time.perf_counter()
    config, fatal = load_config(layout.root)
    if getattr(args, "offline", False) and getattr(args, "no_cache", False):
        fatal = list(fatal) + ["--offline requires the source cache; remove --no-cache"]

    records: list[dict] = []
    errors: list[str] = []
    if config is not None and not fatal:
        enabled = [s for s in config.sources if s.enabled]
        cache_dir = None if args.no_cache else layout.cache_dir
        if enabled:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
                futures = [pool.submit(fetch_source_record, source, cache_dir, args.cache_ttl, args.offline)
                           for source in enabled]
                records = [future.result() for future in futures]
        for record in records:
            if record["offline_missing"]:
                fatal.append(f"forge.toml:sources.{record['name']}: {record['error']}")
            elif record["status"] != "ok":
                errors.append(f"forge.toml:sources.{record['name']}: {record['error']}")
            errors.extend(record.get("_errors", []))

    if fatal:
        for message in fatal:
            print(f"fatal: {message}", file=sys.stderr)
        return 2

    all_entries: dict[str, dict[str, list[str]]] = {}
    meta_by_target: dict[str, dict] = {}
    for target in config.targets:
        rules_path = layout.rules_dir / f"{target.name}.txt"
        inc_d, inc_i, exc_d, exc_i, file_errors, _stats = engine.parse_rules_file(
            engine.read_text_lines(rules_path), f"rules/{target.name}.txt")
        errors.extend(file_errors)
        ext_inc_d: list[str] = []
        ext_inc_i: list[str] = []
        ext_exc_d: list[str] = []
        ext_exc_i: list[str] = []
        for record in records:
            if record["target"] != target.name or record["status"] != "ok":
                continue
            if record["action"] == "include":
                ext_inc_d.extend(record["_domains"])
                ext_inc_i.extend(record["_ips"])
            else:
                ext_exc_d.extend(record["_domains"])
                ext_exc_i.extend(record["_ips"])

        merged_d = set(inc_d + ext_inc_d)
        merged_i = set(inc_i + ext_inc_i)
        excluder = engine.domain_excluder(exc_d + ext_exc_d)
        kept_d = sorted(entry for entry in merged_d if not excluder(entry))
        kept_i = engine.subtract_ip_ranges(list(merged_i), exc_i + ext_exc_i)
        all_entries[target.name] = {"domains": kept_d, "ips": kept_i}
        meta_by_target[target.name] = {
            "action": target.action,
            "domains": {"entries": len(kept_d), "counts": engine.entry_counts("domain", kept_d),
                        "includes": {"local": len(inc_d), "external": len(ext_inc_d)},
                        "excludes": {"local": len(exc_d), "external": len(ext_exc_d),
                                     "removed": len(merged_d) - len(kept_d)}},
            "ips": {"entries": len(kept_i), "counts": engine.entry_counts("ip", kept_i),
                    "includes": {"local": len(inc_i), "external": len(ext_inc_i)},
                    "excludes": {"local": len(exc_i), "external": len(ext_exc_i),
                                 "removed": len(merged_i) - len(kept_i)}},
        }

    warnings = collect_warnings(config, all_entries, records)

    if errors and args.strict:
        for message in errors:
            print(f"error: {message}", file=sys.stderr)
        return 1

    changes = build_changes(config, all_entries, Path(args.previous_dir)) if args.previous_dir else None
    duration_ms = round((time.perf_counter() - started) * 1000)
    manifest = {
        "forge": {"name": "routeforge", "version": __version__},
        "python": platform.python_version(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": duration_ms,
        "git": git_info(layout.root),
        "options": {"strict": args.strict, "offline": args.offline, "no_cache": args.no_cache,
                    "cache_ttl": args.cache_ttl, "jobs": args.jobs},
        "repo": {"owner": config.owner, "name": config.repo},
        "sources": [{k: v for k, v in record.items() if not k.startswith("_")} for record in records],
        "disabled_sources": [s.name for s in config.sources if not s.enabled],
        "targets": meta_by_target,
        "warnings": warnings,
        "errors": errors,
    }

    if args.dry_run:
        print_summary(config, meta_by_target, records, warnings, changes, layout, args, duration_ms)
        print("dry-run: no files written")
        return 0

    write_outputs(layout, config, all_entries, manifest, changes, args.no_profiles)
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    print_summary(config, meta_by_target, records, warnings, changes, layout, args, duration_ms)
    return 0
