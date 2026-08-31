"""The routeforge source catalog: known-good public raw-text lists."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

PACKAGE_CATALOG = Path(__file__).with_name("catalog.toml")


@dataclass
class CatalogEntry:
    """One entry of the built-in (or workspace) source catalog."""

    name: str
    url: str
    kind: str | None = None
    format: str = ""
    license: str = ""
    note: str = ""


def load_catalog(root: Path) -> tuple[dict[str, CatalogEntry], list[str]]:
    """Load the package catalog merged with an optional workspace catalog.toml.

    Later files override earlier entries. Returns (entries, fatal_errors).
    """
    entries: dict[str, CatalogEntry] = {}
    errors: list[str] = []
    paths = [PACKAGE_CATALOG, Path(root) / "catalog.toml"]
    for path in paths:
        if not path.exists():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            errors.append(f"{path.name}: invalid TOML: {exc}")
            continue
        sources = data.get("sources") or {}
        if not isinstance(sources, dict):
            errors.append(f"{path.name}: sources must be a table")
            continue
        for key, meta in sources.items():
            if not isinstance(meta, dict) or not meta.get("url"):
                errors.append(f"{path.name}: sources.{key}: needs a url")
                continue
            kind = meta.get("kind")
            if kind is not None and kind not in ("domains", "ips"):
                errors.append(f"{path.name}: sources.{key}: kind must be domains or ips")
                kind = None
            entries[key] = CatalogEntry(
                name=str(meta.get("name") or key),
                url=str(meta["url"]),
                kind=kind,
                format=str(meta.get("format") or ""),
                license=str(meta.get("license") or ""),
                note=str(meta.get("note") or ""),
            )
    return entries, errors
