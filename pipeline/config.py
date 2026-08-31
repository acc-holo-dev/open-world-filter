# Конфигурация источников (sources.toml) — stdlib tomllib, ноль зависимостей.

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_KINDS = {"domains", "ips", "exclusions"}


@dataclass
class Source:
    name: str
    kind: str = "domains"
    tier: str = "auto"          # auto | community | heuristic
    enabled: bool = True
    url: str | None = None      # удалённый источник
    file: str | None = None     # локальный файл (относительно корня проекта)
    evidence: str = ""          # человекочитаемое «почему источник достоверен»

    @property
    def is_remote(self) -> bool:
        return self.url is not None

    @property
    def is_local(self) -> bool:
        return self.file is not None


def load_sources(path: Path | str) -> list[Source]:
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    sources: list[Source] = []
    fields = set(Source.__dataclass_fields__)
    for item in raw.get("source", []):
        kind = item.get("kind", "domains")
        if kind not in SUPPORTED_KINDS:
            raise ValueError(f"source '{item.get('name')}': unsupported kind '{kind}'")
        if not item.get("url") and not item.get("file"):
            raise ValueError(f"source '{item.get('name')}': need 'url' or 'file'")
        sources.append(Source(**{k: v for k, v in item.items() if k in fields}))
    return sources
