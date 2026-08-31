"""Parsing, normalization, exclusion semantics, and rule-set rendering.

Entry auto-typing: in local rules files and auto-detected external lists, every
line is first tried as a domain and then as an IP/CIDR, so one file can freely
mix both. Local rules files use `!line` for exclusions; external lists treat
`!` lines as uBlock-style comments (skipped) and `@@` lines as AdGuard
exceptions (also skipped).
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

INLINE_COMMENT_MARKERS = (" #", "\t#", " //")
HOSTS_BOILERPLATE = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "localhost4", "localhost6", "broadcasthost", "ip6-allnodes",
    "ip6-allrouters", "ip6-localnet", "ip6-mcastprefix", "ip6-allhosts",
}
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOSTS_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)$")

RULE_BUCKETS = {
    "domain": "domain",
    "suffix": "domain_suffix",
    "keyword": "domain_keyword",
    "regexp": "domain_regex",
}
BUCKET_TO_PREFIX = {
    "domain": "domain:",
    "domain_suffix": "suffix:",
    "domain_keyword": "keyword:",
    "domain_regex": "regexp:",
    "ip_cidr": "",
}


def read_text_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def strip_line(line: str) -> str:
    value = line.strip()
    if not value or value.startswith("#"):
        return ""
    for marker in INLINE_COMMENT_MARKERS:
        if marker in value:
            value = value.split(marker, 1)[0].strip()
    return value


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower()
    value = value.removeprefix("http://").removeprefix("https://")
    value = value.split("/", 1)[0]
    value = value.removeprefix(".")
    if not value:
        return None

    hosts = HOSTS_RE.match(value)
    if hosts:  # hosts-file line: "0.0.0.0 example.com" -> take the domain
        candidate = hosts.group(2)
        if candidate in ("localhost", "localhost.localdomain"):
            return None
        return normalize_domain(candidate)

    for prefix in ("domain:", "suffix:", "keyword:", "regexp:", "regex:"):
        if value.startswith(prefix):
            rule_value = value.split(":", 1)[1].strip()
            if not rule_value:
                return None
            if prefix == "regex:":
                return f"regexp:{rule_value}"
            if prefix in ("domain:", "suffix:") and not (DOMAIN_RE.match(rule_value) or rule_value == "localhost"):
                return None
            return f"{prefix}{rule_value}"

    if value.startswith("||"):  # AdGuard-style filter: "||example.com^"
        stripped = value[2:].split("^", 1)[0].rstrip(".")
        if not stripped or "*" in stripped or "/" in stripped:
            return None
        if DOMAIN_RE.match(stripped):
            return f"suffix:{stripped}"
        return None

    if IPV4_RE.match(value):  # a bare IPv4 literal is never a domain
        return None

    value = value.removesuffix("^")
    if DOMAIN_RE.match(value) or value == "localhost":
        return f"suffix:{value}"
    return None


def normalize_ip(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    tokens = value.split()
    if len(tokens) >= 2:  # hosts-file line: "1.2.3.4 example.com" -> take the address
        try:
            ipaddress.ip_address(tokens[0])
            value = tokens[0]
        except ValueError:
            pass
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        ip_obj = ipaddress.ip_address(value)
        suffix = 32 if ip_obj.version == 4 else 128
        return f"{ip_obj}/{suffix}"
    except ValueError:
        return None


def _hosts_parts(raw: str) -> tuple | None:
    """Split a hosts-file line "<address> <name>"; None when not hosts-shaped."""
    tokens = raw.split(None, 1)
    if len(tokens) != 2:
        return None
    try:
        address = ipaddress.ip_address(tokens[0])
    except ValueError:
        return None
    return address, tokens[1].split(None, 1)[0]


def _typed(raw: str) -> tuple[str, str | None]:
    """Classify one stripped line. Returns (kind, normalized_entry).

    kind is "domain", "ip", "skip" (hosts-file boilerplate) or "" (invalid).
    """
    hosts = _hosts_parts(raw)
    if hosts is not None:
        _address, candidate = hosts
        if candidate in HOSTS_BOILERPLATE:
            return "skip", None  # "127.0.0.1 localhost", "::1 localhost", ...
        try:
            ipaddress.ip_address(candidate)  # "0.0.0.0 0.0.0.0" self-reference
            return "skip", None
        except ValueError:
            pass
        item = normalize_domain(candidate)
        if item is not None:
            return "domain", item
        return "", None
    item = normalize_domain(raw)
    if item is not None:
        return "domain", item
    item = normalize_ip(raw)
    if item is not None:
        return "ip", item
    return "", None


def parse_entries(lines: list[str], kind: str, source_name: str) -> tuple[list[str], list[str], dict]:
    """Parse lines strictly typed as *kind* ("domain" or "ip").

    Returns (entries, errors, stats).
    """
    entries: list[str] = []
    errors: list[str] = []
    stats = {"lines": len(lines), "accepted": 0, "rejected": 0, "skipped": 0}
    for number, line in enumerate(lines, start=1):
        raw = strip_line(line)
        if not raw or raw.startswith("@@"):
            stats["skipped"] += 1
            continue
        if raw.startswith("!"):  # uBlock-style comment in external lists
            stats["skipped"] += 1
            continue
        found_kind, item = _typed(raw)
        if found_kind == "skip":
            stats["skipped"] += 1
            continue
        if item is None or found_kind != kind:
            stats["rejected"] += 1
            errors.append(f"{source_name}:{number}: invalid {kind} entry: {raw[:120]}")
        else:
            stats["accepted"] += 1
            entries.append(item)
    return entries, errors, stats


def parse_mixed_lines(lines: list[str], source_name: str) -> tuple[list[str], list[str], list[str], dict]:
    """Parse lines with auto type detection. Returns (domains, ips, errors, stats)."""
    domains: list[str] = []
    ips: list[str] = []
    errors: list[str] = []
    stats = {"lines": len(lines), "accepted": 0, "rejected": 0, "skipped": 0}
    for number, line in enumerate(lines, start=1):
        raw = strip_line(line)
        if not raw or raw.startswith("@@"):
            stats["skipped"] += 1
            continue
        if raw.startswith("!"):  # uBlock-style comment in external lists
            stats["skipped"] += 1
            continue
        found_kind, item = _typed(raw)
        if found_kind == "skip":
            stats["skipped"] += 1
            continue
        if item is None:
            stats["rejected"] += 1
            errors.append(f"{source_name}:{number}: invalid entry: {raw[:120]}")
        else:
            stats["accepted"] += 1
            (domains if found_kind == "domain" else ips).append(item)
    return domains, ips, errors, stats


def parse_rules_file(lines: list[str], source_name: str):
    """Parse a local rules/<target>.txt file.

    `!`-prefixed lines are exclusions applied after merging external lists.
    Returns (include_domains, include_ips, exclude_domains, exclude_ips, errors, stats).
    """
    include_domains: list[str] = []
    include_ips: list[str] = []
    exclude_domains: list[str] = []
    exclude_ips: list[str] = []
    errors: list[str] = []
    stats = {"lines": len(lines), "accepted": 0, "rejected": 0, "skipped": 0}
    for number, line in enumerate(lines, start=1):
        raw = strip_line(line)
        if not raw or raw.startswith("@@"):
            stats["skipped"] += 1
            continue
        exclude = raw.startswith("!")
        if exclude:
            raw = raw[1:].strip()
            if not raw:
                stats["skipped"] += 1
                continue
        found_kind, item = _typed(raw)
        if found_kind == "skip":
            stats["skipped"] += 1
            continue
        if item is None:
            stats["rejected"] += 1
            errors.append(f"{source_name}:{number}: invalid entry: {raw[:120]}")
            continue
        stats["accepted"] += 1
        if exclude:
            (exclude_domains if found_kind == "domain" else exclude_ips).append(item)
        else:
            (include_domains if found_kind == "domain" else include_ips).append(item)
    return include_domains, include_ips, exclude_domains, exclude_ips, errors, stats


def domain_excluder(exclude_entries: list[str]):
    """Build a predicate implementing semantic domain exclusion.

    - "domain:X" removes "domain:X" and "suffix:X" (both match exactly host X).
    - "suffix:X" removes domain/suffix rules for X and any subdomain of X.
    - "keyword:X" removes exactly "keyword:X"; "regexp:X" removes exactly "regexp:X".
    """
    exact = set()
    suffixes = set()
    keywords = set()
    regexps = set()
    for entry in exclude_entries:
        prefix, value = entry.split(":", 1)
        if prefix == "domain":
            exact.add(value)
        elif prefix == "suffix":
            suffixes.add(value)
        elif prefix == "keyword":
            keywords.add(entry)
        elif prefix == "regexp":
            regexps.add(entry)

    def is_excluded(entry: str) -> bool:
        if entry in keywords or entry in regexps:
            return True
        prefix, value = entry.split(":", 1)
        if prefix in ("domain", "suffix"):
            if value in exact:
                return True
            return any(value == base or value.endswith("." + base) for base in suffixes)
        return False

    return is_excluded


def subtract_ip_ranges(include_entries: list[str], exclude_entries: list[str]) -> list[str]:
    """Subtract excluded CIDRs from included CIDRs, then collapse the result.

    Fully contained networks are removed; partially overlapping networks are
    split with ipaddress.address_exclude, so exclusion is exact.
    """
    includes = [ipaddress.ip_network(e) for e in include_entries]
    excludes = [ipaddress.ip_network(e) for e in exclude_entries]
    remaining: list[ipaddress._BaseNetwork] = []

    for net in includes:
        pieces = [net]
        for excluded in excludes:
            if excluded.version != net.version:
                continue
            next_pieces = []
            for piece in pieces:
                if piece.subnet_of(excluded):
                    continue  # fully covered by an exclude
                if excluded.subnet_of(piece):
                    next_pieces.extend(piece.address_exclude(excluded))
                else:
                    next_pieces.append(piece)
            pieces = next_pieces
        remaining.extend(pieces)

    v4 = sorted((n for n in remaining if n.version == 4), key=lambda n: int(n.network_address))
    v6 = sorted((n for n in remaining if n.version == 6), key=lambda n: int(n.network_address))
    collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return [str(n) for n in collapsed]


def entry_counts(kind: str, entries: list[str]) -> dict:
    if kind == "ip":
        nets = [ipaddress.ip_network(e) for e in entries]
        return {"ipv4": sum(1 for n in nets if n.version == 4), "ipv6": sum(1 for n in nets if n.version == 6)}
    counts = {"domain": 0, "domain_suffix": 0, "domain_keyword": 0, "domain_regex": 0}
    for entry in entries:
        counts[RULE_BUCKETS[entry.split(":", 1)[0]]] += 1
    return counts


def to_rule_set(kind: str, entries: list[str]) -> dict:
    """Render normalized entries as a sing-box source rule-set (version 1).

    One rule holds all condition fields: sing-box OR-combines destination
    address conditions within a rule, so this shape is both correct and the
    most compact representation.
    """
    if kind == "ip":
        ip_cidr = list(dict.fromkeys(entries))
        return {"version": 1, "rules": [{"ip_cidr": ip_cidr}] if ip_cidr else []}

    rule: dict[str, list[str]] = {}
    for entry in entries:
        prefix, value = entry.split(":", 1)
        rule.setdefault(RULE_BUCKETS[prefix], []).append(value)
    for key in rule:
        rule[key] = sorted(set(rule[key]))
    return {"version": 1, "rules": [rule] if rule else []}


def entries_from_rule_set(data: dict) -> set[str]:
    """Reconstruct normalized entry strings from a rule-set JSON document."""
    out: set[str] = set()
    for rule in data.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        for bucket, prefix in BUCKET_TO_PREFIX.items():
            for value in rule.get(bucket) or []:
                out.add(prefix + str(value))
    return out
