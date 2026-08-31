"""Validate generated rule-sets, checksums, and the build manifest."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

from .config import load_config

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_BUCKETS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
IP_BUCKETS = ("ip_cidr",)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def expected_files(config) -> list[str]:
    return [f"{target.name}-{kind}.json" for target in config.targets for kind in ("domains", "ips")]


def validate_rule_set(path: Path) -> tuple[list[str], list[str], list[str], int]:
    """Validate one rule-set file. Returns (errors, warnings, notices, entry_count)."""
    errors: list[str] = []
    warnings: list[str] = []
    notices: list[str] = []
    name = path.name
    kind = "ip" if name.endswith("-ips.json") else "domain"
    allowed = set(IP_BUCKETS if kind == "ip" else DOMAIN_BUCKETS)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"{name}: missing generated rule-set"], [], [], 0
    except json.JSONDecodeError as exc:
        return [f"{name}: invalid JSON: {exc}"], [], [], 0
    if not isinstance(data, dict):
        return [f"{name}: root must be an object"], [], [], 0
    if data.get("version") != 1:
        errors.append(f"{name}: missing version=1")

    rules = data.get("rules")
    if not isinstance(rules, list):
        errors.append(f"{name}: rules must be a list")
        return errors, warnings, notices, 0

    seen: dict[str, set[str]] = {}
    entries = 0
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            errors.append(f"{name}: rule {index} must be an object")
            continue
        unknown = set(rule) - allowed
        if unknown:
            errors.append(f"{name}: rule {index} has unknown fields: {sorted(unknown)}")
        for bucket, values in rule.items():
            if bucket not in allowed:
                continue
            if not isinstance(values, list) or not values:
                errors.append(f"{name}: rule {index} field {bucket} must be a non-empty list")
                continue
            bucket_seen = seen.setdefault(bucket, set())
            for value in values:
                entries += 1
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{name}: rule {index} field {bucket} has an empty value")
                    continue
                if value in bucket_seen:
                    errors.append(f"{name}: duplicate {bucket} entry: {value}")
                else:
                    bucket_seen.add(value)
                if bucket == "domain_suffix" and not DOMAIN_RE.match(value):
                    errors.append(f"{name}: invalid domain_suffix entry: {value}")
                if bucket == "domain_keyword" and len(value) < 2:
                    notices.append(f"{name}: very broad keyword: {value}")
                if bucket == "domain_regex":
                    try:
                        re.compile(value)
                    except re.error as exc:
                        warnings.append(
                            f"{name}: domain_regex not compilable by Python re (Go RE2 may differ): {value}: {exc}")
                if bucket == "ip_cidr":
                    try:
                        ipaddress.ip_network(value)
                    except ValueError:
                        errors.append(f"{name}: invalid ip_cidr entry: {value}")

    if not rules:
        notices.append(f"{name}: rule-set is empty")

    if kind == "ip" and rules:
        all_cidrs = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for value in rule.get("ip_cidr", []) or []:
                try:
                    all_cidrs.append(ipaddress.ip_network(value))
                except ValueError:
                    pass
        v4 = sorted((n for n in all_cidrs if n.version == 4), key=lambda n: int(n.network_address))
        v6 = sorted((n for n in all_cidrs if n.version == 6), key=lambda n: int(n.network_address))
        collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
        if len(collapsed) < len(all_cidrs):
            warnings.append(f"{name}: ip_cidr list is not fully collapsed ({len(all_cidrs)} -> {len(collapsed)})")

    return errors, warnings, notices, entries


def verify_checksums(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    path = directory / "checksums.txt"
    if not path.exists():
        return errors, warnings
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        errors.append(f"checksums.txt: unreadable: {exc}")
        return errors, warnings
    listed = set()
    for line in lines:
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, filename = parts[0], parts[1].strip()
        listed.add(filename)
        target = directory / filename
        if not target.is_file():
            errors.append(f"checksums.txt: listed file missing: {filename}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f"checksums.txt: mismatch for {filename}")
    for json_file in sorted(directory.glob("*.json")):
        if json_file.name not in listed:
            warnings.append(f"checksums.txt does not cover {json_file.name}")
    return errors, warnings


def verify_manifest(directory: Path, require: bool, file_counts: dict[str, int]) -> tuple[list[str], dict]:
    errors: list[str] = []
    path = directory / "build-manifest.json"
    if not path.exists():
        if require:
            errors.append("build-manifest.json: missing")
        return errors, {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"build-manifest.json: invalid JSON: {exc}"], {}
    if not isinstance(data, dict):
        return ["build-manifest.json: root must be an object"], {}
    forge = data.get("forge") or {}
    if not forge.get("version"):
        errors.append("build-manifest.json: missing forge version")
    targets = data.get("targets")
    if not isinstance(targets, dict):
        errors.append("build-manifest.json: targets must be an object")
        return errors, data
    for tname, info in sorted(targets.items()):
        if not isinstance(info, dict):
            errors.append(f"build-manifest.json: targets.{tname} must be an object")
            continue
        for kind in ("domains", "ips"):
            stem = f"{tname}-{kind}"
            if stem in file_counts:
                kind_info = info.get(kind) or {}
                if kind_info.get("entries") != file_counts[stem]:
                    errors.append(f"build-manifest.json: entry count mismatch for {stem}: "
                                  f"manifest={kind_info.get('entries')} file={file_counts[stem]}")
    return errors, data


def command(args) -> int:
    """The `validate` subcommand. Returns the process exit code."""
    root = Path(getattr(args, "root", None)) if getattr(args, "root", None) else DEFAULT_ROOT
    directory = Path(args.dir) if getattr(args, "dir", None) else root / "release-assets"
    config, fatal = load_config(root)

    errors: list[str] = list(fatal)
    warnings: list[str] = []
    notices: list[str] = []
    file_counts: dict[str, int] = {}
    expected = expected_files(config) if config is not None else []
    for name in expected:
        rule_errors, rule_warnings, rule_notices, entries = validate_rule_set(directory / name)
        errors.extend(rule_errors)
        warnings.extend(rule_warnings)
        notices.extend(rule_notices)
        if not rule_errors:
            file_counts[name] = entries

    checksum_errors, checksum_warnings = verify_checksums(directory)
    errors.extend(checksum_errors)
    warnings.extend(checksum_warnings)
    manifest_errors, _manifest = verify_manifest(directory, bool(args.require_manifest), file_counts)
    errors.extend(manifest_errors)

    for name in sorted(file_counts):
        print(f"{name}: {file_counts[name]} entries")
    for notice in notices:
        print(f"notice: {notice}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)

    if errors:
        return 1
    if args.strict and warnings:
        return 1
    return 0
