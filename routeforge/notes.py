"""Render GitHub release notes / job step summary from build outputs."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fmt_int(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "?"


def asset_rows(manifest: dict) -> list[tuple[str, int | None]]:
    rows: list[tuple[str, int | None]] = []
    for tname, info in sorted((manifest.get("targets") or {}).items()):
        if not isinstance(info, dict):
            continue
        for kind in ("domains", "ips"):
            kind_info = info.get(kind) or {}
            rows.append((f"{tname}-{kind}", kind_info.get("entries")))
    return rows


def render(manifest: dict, changes: dict | None = None, sing_box_version: str | None = None,
           note: str | None = None) -> str:
    lines: list[str] = []
    forge = manifest.get("forge") or {}
    generated_at = str(manifest.get("generated_at") or "")
    date_part = generated_at[:10] if generated_at else "unknown date"
    lines.append(f"# Routing Build — {date_part}")
    lines.append("")

    bits: list[str] = []
    if forge.get("version"):
        bits.append(f"**routeforge {forge['version']}**")
    if sing_box_version:
        bits.append(f"sing-box **{sing_box_version}**")
    git = manifest.get("git") or {}
    if git.get("commit"):
        commit = f"`{str(git['commit'])[:12]}`"
        if git.get("dirty"):
            commit += " (dirty)"
        bits.append(f"commit {commit}")
    if manifest.get("python"):
        bits.append(f"Python {manifest['python']}")
    if bits:
        lines.append(" · ".join(bits))
        lines.append("")

    rows = asset_rows(manifest)
    if rows:
        changes_targets = (changes or {}).get("targets") or {}
        lines.append("## Rule-sets")
        lines.append("")
        lines.append("| Rule-set | Entries | Added | Removed |")
        lines.append("|---|---:|---:|---:|")
        for stem, entries in rows:
            change = changes_targets.get(stem) or {}
            added = change.get("added")
            removed = change.get("removed")
            added_cell = ("+" + fmt_int(added)) if added is not None else "—"
            removed_cell = ("−" + fmt_int(removed)) if removed is not None else "—"
            lines.append(f"| {stem} | {fmt_int(entries)} | {added_cell} | {removed_cell} |")
        lines.append("")

    sources = manifest.get("sources") or []
    if sources:
        lines.append("## Sources")
        lines.append("")
        lines.append("| Source | Action | Target | Accepted | Status |")
        lines.append("|---|---|---|---:|---|")
        for source in sources:
            if source.get("status") == "ok":
                status = "ok" + (" (cached)" if source.get("cached") else "")
            else:
                status = "failed: " + str(source.get("error") or "unknown")[:80]
            lines.append(f"| {source.get('name', '?')} | {source.get('action', '?')} | "
                         f"{source.get('target', '?')} | {fmt_int(source.get('accepted'))} | {status} |")
        lines.append("")

    warnings = manifest.get("warnings") or []
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    if changes and changes.get("first_build"):
        lines.append("First build — no previous rule-sets to compare.")
        lines.append("")
    elif changes:
        totals = changes.get("totals") or {}
        lines.append(f"Diff vs previous build: **+{fmt_int(totals.get('added'))} added**, "
                     f"**−{fmt_int(totals.get('removed'))} removed**.")
        lines.append("")

    if note:
        lines.append("## Note")
        lines.append("")
        lines.append(note)
        lines.append("")

    lines.append("Assets include `checksums.txt` (SHA-256), `build-manifest.json` (full build report) "
                 "and `changes-report.json` (entry-level diff).")
    return "\n".join(lines) + "\n"


def command(args) -> int:
    """The `notes` subcommand. Returns the process exit code."""
    try:
        manifest = load_json(Path(args.manifest))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return 1
    changes = None
    if getattr(args, "changes", None):
        try:
            changes = load_json(Path(args.changes))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read changes report: {exc}", file=sys.stderr)
            return 1
    markdown = render(manifest, changes, getattr(args, "sing_box_version", None),
                       getattr(args, "note", None))
    if getattr(args, "output", None):
        Path(args.output).write_text(markdown, encoding="utf-8")
    else:
        sys.stdout.write(markdown)
    return 0
