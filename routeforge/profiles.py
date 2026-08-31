"""Render Throne/sing-box profiles from templates/ placeholders.

Template DSL (no external template engines, JSON only):
- "{{owner}}", "{{repo}}"                    global substitution everywhere
- {"$per_target": {...}}                      expands to one object per target;
                                              reject-action targets come first
- "$filter": "minimal"                        sibling of $per_target: only targets
                                              with minimal = true in forge.toml
- "$action_fields": {}                        sibling inside a $per_target prototype:
                                              merged as {"action": "reject"} for reject
                                              targets, {"outbound": "<target>"} for route
- {"$per_asset": {...}}                       one object per target asset (domains+ips)
- {"$per_extra": {...}}                       one object per attached extra rule-set
- "{{target_name}}", "{{target_action}}", "{{target_action_type}}",
  "{{target_reject_method}}", "{{target_outbound_id}}"
- "{{target_rule_sets}}" (as the only list item)   -> list of the target's rule-set URLs
- "{{target_rule_sets_tags}}" (as the only list item) -> list of the target's rule-set tags
- "{{asset_tag}}", "{{asset_url}}", "{{extra_tag}}", "{{extra_url}}"

Integer conversion: after substitution, values of outboundID/override_port/
simple_action/id/default_outbound that look like integers are converted to int.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

from .config import Config, Target, load_config

TEMPLATE_OUTPUT_NAMES = {
    "throne-minimal.json": "route-profile-throne-minimal.json",
    "throne-full.json": "route-profile-throne-full.json",
    "sing-box-route.json": "sing-box-route-snippet.json",
    "sing-box-rule-sets.json": "sing-box-rule-sets-snippet.json",
}
INT_KEYS = ("outboundID", "override_port", "simple_action", "id", "default_outbound")
MARKER_KEYS = ("$per_target", "$per_asset", "$per_extra")
KINDS = ("domains", "ips")


def stem_for(target: Target, kind: str) -> str:
    return f"{target.name}-{kind}"


def asset_url(config: Config, stem: str) -> str:
    return f"https://github.com/{config.owner}/{config.repo}/releases/latest/download/{stem}.srs"


def ordered_targets(config: Config) -> list[Target]:
    """Reject targets first (they must precede route rules), then config order."""
    routed = [t for t in config.targets if t.action != "reject"]
    rejected = [t for t in config.targets if t.action == "reject"]
    return rejected + routed


def target_urls(config: Config, target: Target) -> list[str]:
    urls = [asset_url(config, stem_for(target, kind)) for kind in KINDS]
    urls.extend(extra.url for extra in target.extra_rule_sets)
    return urls


def target_tags(config: Config, target: Target) -> list[str]:
    tags = [stem_for(target, kind) for kind in KINDS]
    tags.extend(extra.tag for extra in target.extra_rule_sets)
    return tags


def outbound_id(target: Target) -> int:
    if target.outbound_id is not None:
        return target.outbound_id
    return 0 if target.action == "reject" else -1


def _subs_globals(text: str, config: Config) -> str:
    text = text.replace("{{owner}}", config.owner)
    return text.replace("{{repo}}", config.repo)


def _subs_target(text: str, target: Target, config: Config) -> str:
    text = _subs_globals(text, config)
    replacements = {
        "{{target_name}}": target.name,
        "{{target_action}}": target.action,
        "{{target_action_type}}": "reject" if target.action == "reject" else "route",
        "{{target_reject_method}}": "default" if target.action == "reject" else "",
        "{{target_outbound_id}}": str(outbound_id(target)),
    }
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    return text


def _convert_ints(rule: dict) -> dict:
    for key in INT_KEYS:
        if key in rule and isinstance(rule[key], str) and re.fullmatch(r"-?\d+", rule[key]):
            rule[key] = int(rule[key])
    return rule


def _expand_target(prototype: dict, target: Target, config: Config) -> dict:
    rule = copy.deepcopy(prototype)
    has_action_fields = rule.pop("$action_fields", None) is not None
    for key, value in list(rule.items()):
        if isinstance(value, str):
            rule[key] = _subs_target(value, target, config)
        elif isinstance(value, list):
            if value == ["{{target_rule_sets}}"]:
                rule[key] = target_urls(config, target)
            elif value == ["{{target_rule_sets_tags}}"]:
                rule[key] = target_tags(config, target)
            else:
                rule[key] = [_subs_target(v, target, config) if isinstance(v, str) else v for v in value]
    if has_action_fields:
        if target.action == "reject":
            rule.update({"action": "reject"})
        else:
            rule.update({"outbound": target.name})
    return _convert_ints(rule)


def _expand_asset(prototype: dict, target: Target, kind: str, config: Config) -> dict:
    rule = copy.deepcopy(prototype)
    for key, value in rule.items():
        if isinstance(value, str):
            value = _subs_globals(value, config)
            value = value.replace("{{asset_tag}}", stem_for(target, kind))
            rule[key] = value.replace("{{asset_url}}", asset_url(config, stem_for(target, kind)))
    return _convert_ints(rule)


def _expand_extra(prototype: dict, target: Target, extra, config: Config) -> dict:
    rule = copy.deepcopy(prototype)
    for key, value in rule.items():
        if isinstance(value, str):
            value = _subs_globals(value, config)
            value = value.replace("{{extra_tag}}", extra.tag)
            rule[key] = value.replace("{{extra_url}}", extra.url)
    return _convert_ints(rule)


def _walk(value, config: Config):
    if isinstance(value, dict):
        if "$per_target" in value:
            prototype = value["$per_target"]
            filt = value.get("$filter")
            out = []
            for target in ordered_targets(config):
                if filt == "minimal" and not target.minimal:
                    continue
                out.append(_expand_target(prototype, target, config))
            return out
        if "$per_asset" in value:
            return [_expand_asset(value["$per_asset"], target, kind, config)
                    for target in ordered_targets(config) for kind in KINDS]
        if "$per_extra" in value:
            out = []
            for target in ordered_targets(config):
                for extra in target.extra_rule_sets:
                    out.append(_expand_extra(value["$per_extra"], target, extra, config))
            return out
        return {key: _walk(item, config) for key, item in value.items()}
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict) and any(marker in item for marker in MARKER_KEYS):
                out.extend(_walk(item, config))  # splice the expanded sequence
            else:
                out.append(_walk(item, config))
        return out
    if isinstance(value, str):
        return _subs_globals(value, config)
    return value


def render_profiles(config: Config, templates_dir: Path, output_dir: Path) -> list[str]:
    """Render every templates/*.json into the output directory. Returns names written."""
    if not templates_dir.is_dir():
        print(f"warning: templates directory not found: {templates_dir}", file=sys.stderr)
        return []
    written: list[str] = []
    for path in sorted(templates_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"warning: skipping template {path.name}: {exc}", file=sys.stderr)
            continue
        rendered = _walk(data, config)
        output_name = TEMPLATE_OUTPUT_NAMES.get(path.name, path.name)
        (output_dir / output_name).write_text(
            json.dumps(rendered, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append(output_name)
    return written


def profiles_command(args) -> int:
    """The `profiles` subcommand: render profiles only."""
    root = Path(getattr(args, "root", None)) if getattr(args, "root", None) else Path.cwd()
    config, fatal = load_config(root)
    if fatal:
        for message in fatal:
            print(f"fatal: {message}", file=sys.stderr)
        return 2
    output_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else root / "release-assets"
    output_dir.mkdir(parents=True, exist_ok=True)
    written = render_profiles(config, root / "templates", output_dir)
    for name in written:
        print(f"wrote {output_dir / name}")
    return 0
