# Модель записи с происхождением (provenance) и JSONL-персистентность.

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Evidence:
    source: str
    fetched_at: str
    url: str | None = None
    reason: str | None = None


@dataclass
class Entry:
    value: str                       # домен | IP | CIDR | правило исключения
    kind: str = "domain"             # domain | ip | cidr | exclusion
    tier: str = "auto"               # auto | community | heuristic
    flags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        evs = [Evidence(**e) for e in d.get("evidence", [])]
        return cls(
            value=d["value"],
            kind=d.get("kind", "domain"),
            tier=d.get("tier", "auto"),
            flags=list(d.get("flags", [])),
            evidence=evs,
        )


def save_entries(entries: list[Entry], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            print(json.dumps(e.to_dict(), ensure_ascii=False), file=fh)


def load_entries(path: Path) -> list[Entry]:
    entries: list[Entry] = []
    if not path.exists():
        return entries
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(Entry.from_dict(json.loads(line)))
    return entries
