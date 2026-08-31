"""Scaffold a new routeforge workspace with `routeforge init`."""

from __future__ import annotations

import json
from pathlib import Path

FORGE_TOML = """# routeforge — the single build configuration.
# Docs: README.md and documentation/.

[repo]
owner = "your-name"      # GitHub user or organization
name  = "routeforge"     # repository name

# ── Targets ─────────────────────────────────────────────────────────────
# One target = one rules/<name>.txt file. action: route | reject.
# Declaration order = rule order for route targets: declare direct before proxy.
# minimal      — include this target in the generated minimal Throne profile.
# outbound_id  — Throne outbound hint (reject → 0, route → -1 by default).

[targets.direct]
action = "route"
outbound_id = -2

[targets.proxy]
action = "route"
minimal = true
outbound_id = -1

[targets.reject]
action = "reject"
outbound_id = 0

# ── External sources ────────────────────────────────────────────────────
# action "include" merges a list into its target, "exclude" removes it after.
# Use source = "<name>" to pull from the built-in catalog, or url = "..."
# for a literal raw-text list. sha256 pins a source.
#
# [[sources]]
# name    = "stevenblack-hosts"
# enabled = false
# action  = "include"
# source  = "stevenblack-hosts"   # resolved via the catalog
# target  = "reject"
"""

RULES = {
    "proxy.txt": """# proxy: traffic routed through the VPN.
# "!"-prefixed lines are exclusions, applied after merging external lists.
# Domains and IPs mix freely — types are detected automatically.
# Formats: example.com, domain:example.org, suffix:example.net, keyword:discord,
# regexp:^.+example.com$, 0.0.0.0 ads.example.com, ||ads.example.com^, 1.2.3.4/24
""",
    "direct.txt": """# direct: traffic that must never touch the VPN.
# "!..." lines are exclusions; domains and IPs mix freely.

localhost

127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
::1/128
fc00::/7
fe80::/10
""",
    "reject.txt": """# reject: domains and networks blocked locally.
# Put ad/tracker/telemetry domains here, e.g.:
#   0.0.0.0 ads.example.com
#   ||tracker.example.com^
""",
}

_DNS_RULE = {
    "actionType": "hijack-dns",
    "invert": False,
    "ip_is_private": False,
    "ip_version": "",
    "name": "DNS hijack",
    "network": "",
    "noDrop": False,
    "outboundID": -2,
    "override_address": "",
    "override_port": 0,
    "protocol": "dns",
    "rejectMethod": "",
    "simple_action": -10880,
    "sniffOverrideDest": False,
    "source_ip_is_private": False,
    "strategy": "",
    "type": 0,
}

_TARGET_RULE = {
    "actionType": "{{target_action_type}}",
    "invert": False,
    "ip_is_private": False,
    "ip_version": "",
    "name": "{{target_name}} rule-sets",
    "network": "",
    "noDrop": False,
    "outboundID": "{{target_outbound_id}}",
    "override_address": "",
    "override_port": 0,
    "protocol": "",
    "rejectMethod": "{{target_reject_method}}",
    "rule_set": ["{{target_rule_sets}}"],
    "simple_action": 0,
    "sniffOverrideDest": False,
    "source_ip_is_private": False,
    "strategy": "",
    "type": 0,
}

_THRONE_FULL = {
    "default_outbound": -1,
    "id": 1002,
    "name": "GitHub Routing Full",
    "rules": [_DNS_RULE, {"$per_target": _TARGET_RULE}],
}

_THRONE_MINIMAL = {
    "default_outbound": -1,
    "id": 1001,
    "name": "GitHub Routing Minimal",
    "rules": [_DNS_RULE, {"$filter": "minimal", "$per_target": _TARGET_RULE}],
}

_SB_ROUTE = {
    "route": {
        "rules": [{"$per_target": {"rule_set": ["{{target_rule_sets_tags}}"], "$action_fields": {}}}],
        "final": "direct",
    }
}

_SB_RULE_SETS = {
    "route": {
        "rule_set": [
            {"$per_asset": {"type": "remote", "tag": "{{asset_tag}}", "format": "binary",
                            "url": "{{asset_url}}", "update_interval": "24h", "download_detour": "direct"}},
            {"$per_extra": {"type": "remote", "tag": "{{extra_tag}}", "format": "binary",
                            "url": "{{extra_url}}", "update_interval": "24h", "download_detour": "direct"}},
        ]
    }
}

def _dump(obj) -> str:
    return json.dumps(obj, indent=2) + chr(10)


TEMPLATES = {
    "throne-full.json": _dump(_THRONE_FULL),
    "throne-minimal.json": _dump(_THRONE_MINIMAL),
    "sing-box-route.json": _dump(_SB_ROUTE),
    "sing-box-rule-sets.json": _dump(_SB_RULE_SETS),
}

GITIGNORE = """release-assets/*
!release-assets/.gitkeep
*.log
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
.source-cache/
previous-release/
release-notes.md
"""

CATALOG_STUB = """# Your workspace source catalog — merged with the built-in catalog.
# Add raw-text lists you trust here and reference them from forge.toml with
# source = "<name>". Workspace entries override built-in ones with the same key.
#
# [sources.my-list]
# name = "My list"
# url  = "https://raw.githubusercontent.com/owner/repo/main/list.txt"
# kind = "domains"   # optional: "domains" | "ips"; omit to auto-detect
"""


def init_command(args) -> int:
    """The `init` subcommand: scaffold a workspace. Returns the exit code."""
    target = Path(getattr(args, "directory", None) or ".")
    force = bool(getattr(args, "force", False))
    target.mkdir(parents=True, exist_ok=True)

    writes: dict[Path, str] = {
        target / "forge.toml": FORGE_TOML,
        target / "catalog.toml": CATALOG_STUB,
        target / ".gitignore": GITIGNORE,
    }
    for name, content in RULES.items():
        writes[target / "rules" / name] = content
    for name, content in TEMPLATES.items():
        writes[target / "templates" / name] = content

    created: list[str] = []
    skipped: list[str] = []
    for path, content in writes.items():
        if path.exists() and not force:
            skipped.append(str(path))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(str(path))

    for name in sorted(created):
        print(f"created {name}")
    for name in sorted(skipped):
        print(f"skipped {name} (exists; use --force to overwrite)")
    print()
    print("Next steps:")
    print("  1. edit forge.toml: set [repo] owner/name, add sources")
    print("  2. edit rules/<target>.txt")
    print("  3. python -m routeforge build")
    print("  4. python -m routeforge check")
    return 0
