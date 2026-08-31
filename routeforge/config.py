"""forge.toml loading, validation, and the target/source model."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .catalog import load_catalog

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TARGET_ACTIONS = ("route", "reject")
SOURCE_ACTIONS = ("include", "exclude")
SOURCE_KINDS = ("domains", "ips")


@dataclass
class ExtraRuleSet:
    """A ready-made remote rule-set attached to a target (e.g. Re-filter)."""

    tag: str
    url: str


@dataclass
class Target:
    """One routing target: rules/<name>.txt plus its routing semantics."""

    name: str
    action: str
    minimal: bool = False
    outbound_id: int | None = None
    extra_rule_sets: list[ExtraRuleSet] = field(default_factory=list)
    order: int = 0


@dataclass
class Source:
    """One external raw-text list merged into (or subtracted from) a target."""

    name: str
    enabled: bool
    action: str
    target: str
    url: str
    sha256: str | None = None
    kind: str | None = None
    catalog: str | None = None
    index: int = 0


@dataclass
class Config:
    """Everything forge.toml describes."""

    root: Path
    owner: str
    repo: str
    targets: list[Target]
    sources: list[Source]

    def target(self, name: str) -> Target | None:
        return next((t for t in self.targets if t.name == name), None)


def load_config(root: Path) -> tuple[Config | None, list[str]]:
    """Load forge.toml. Returns (config, fatal_errors); config is None on fatal errors."""
    root = Path(root)
    path = root / "forge.toml"
    if not path.exists():
        return None, ["forge.toml: missing (no build configuration found)"]
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return None, [f"forge.toml: invalid TOML: {exc}"]

    fatal: list[str] = []
    repo = data.get("repo") or {}
    if not isinstance(repo, dict):
        fatal.append("forge.toml: [repo] must be a table")
        repo = {}
    owner = str(repo.get("owner") or "")
    name = str(repo.get("name") or "")
    if not owner:
        fatal.append("forge.toml: repo.owner is required (GitHub user or organization)")
    if not name:
        fatal.append("forge.toml: repo.name is required (repository name)")

    raw_targets = data.get("targets") or {}
    if not isinstance(raw_targets, dict) or not raw_targets:
        fatal.append("forge.toml: at least one [targets.<name>] table is required")
        raw_targets = {}
    targets: list[Target] = []
    for order, (tname, meta) in enumerate(raw_targets.items()):
        label = f"forge.toml: targets.{tname}"
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", tname):
            fatal.append(f"{label}: target name must be lowercase letters, digits and dashes")
            continue
        if not isinstance(meta, dict):
            fatal.append(f"{label}: must be a table")
            continue
        action = meta.get("action", "")
        if action not in TARGET_ACTIONS:
            fatal.append(f"{label}: action must be one of {TARGET_ACTIONS}: {action!r}")
            action = "route"
        minimal = bool(meta.get("minimal", False))
        outbound_id = meta.get("outbound_id")
        if outbound_id is not None and not isinstance(outbound_id, int):
            fatal.append(f"{label}: outbound_id must be an integer")
            outbound_id = None
        extras: list[ExtraRuleSet] = []
        for extra in meta.get("extra_rule_sets") or []:
            if not isinstance(extra, dict) or not extra.get("tag") or not extra.get("url"):
                fatal.append(f"{label}: extra_rule_sets entries need both tag and url")
                continue
            extras.append(ExtraRuleSet(str(extra["tag"]), str(extra["url"])))
        targets.append(Target(tname, action, minimal, outbound_id, extras, order))

    catalog, catalog_errors = load_catalog(root)
    fatal.extend(catalog_errors)

    raw_sources = data.get("sources") or []
    if not isinstance(raw_sources, list):
        fatal.append("forge.toml: sources must be an array of tables")
        raw_sources = []
    sources: list[Source] = []
    for index, raw in enumerate(raw_sources, start=1):
        if not isinstance(raw, dict):
            fatal.append(f"forge.toml: sources[{index}] must be a table")
            continue
        sname = str(raw.get("name") or f"source-{index}")
        label = f"forge.toml: sources.{sname}"

        # Resolve source = "<catalog-key>" (or fall back to a literal url).
        url = str(raw.get("url") or "")
        catalog_ref = str(raw.get("source") or "")
        if catalog_ref and url:
            fatal.append(f"{label}: use either source= or url=, not both")
        kind = raw.get("kind")
        if catalog_ref:
            entry = catalog.get(catalog_ref)
            if entry is None:
                fatal.append(f"{label}: unknown source in catalog: {catalog_ref!r}")
            else:
                if not url:
                    url = entry.url
                if kind is None:
                    kind = entry.kind
        source = Source(
            name=sname,
            enabled=bool(raw.get("enabled", False)),
            action=str(raw.get("action") or ""),
            target=str(raw.get("target") or ""),
            url=url,
            sha256=raw.get("sha256"),
            kind=kind,
            catalog=catalog_ref or None,
            index=index,
        )
        if source.enabled:
            if source.action not in SOURCE_ACTIONS:
                fatal.append(f"{label}: action must be one of {SOURCE_ACTIONS}")
            if not source.target or all(t.name != source.target for t in targets):
                fatal.append(f"{label}: unknown target: {source.target!r}")
            if not source.url:
                fatal.append(f"{label}: missing url")
            if source.sha256 is not None and (
                    not isinstance(source.sha256, str) or not SHA256_RE.fullmatch(source.sha256)):
                fatal.append(f"{label}: sha256 must be 64 lowercase hex characters")
            if source.kind is not None and source.kind not in SOURCE_KINDS:
                fatal.append(f"{label}: kind must be one of {SOURCE_KINDS} (or omitted for auto-detection)")
        sources.append(source)

    if fatal:
        return None, fatal
    return Config(root=root, owner=owner, repo=name, targets=targets, sources=sources), []
