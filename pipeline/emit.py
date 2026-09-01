# Шаг выпуска: политика + итоговые списки + forge.toml для мастерской.
#
# Политика по умолчанию (прозрачность, а не молчаливые удаления):
#  - dead (NXDOMAIN) исключается из итогового списка (--keep-dead оставляет);
#  - empty / error / parked ОСТАЮТСЯ: пустой или непроверенный — не значит мёртвый,
#    запаркованный домен всё равно заблокирован;
#  - полное происхождение сохраняется в entries.jsonl и emit-report.json.

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path


def apply_policy(entries: list, cache: dict | None, keep_dead: bool = False) -> tuple:
    """Фильтрует доменные записи по кэшу проб. Возвращает (оставленные записи, статистика)."""
    cache = cache or {}
    kept = []
    stats = {"domains_total": 0, "kept": 0, "dropped_dead": 0, "kept_parked": 0,
             "kept_empty": 0, "kept_error": 0, "unknown": 0}
    for e in entries:
        if e.kind != "domain":
            continue
        stats["domains_total"] += 1
        record = cache.get(e.value)
        if record is None:
            stats["unknown"] += 1
            kept.append(e)
            continue
        status = record.get("status")
        if status == "dead" and not keep_dead:
            stats["dropped_dead"] += 1
            continue
        if record.get("parked"):
            stats["kept_parked"] += 1
        elif status == "empty":
            stats["kept_empty"] += 1
        elif status == "error":
            stats["kept_error"] += 1
        kept.append(e)
    stats["kept"] = len(kept)
    return kept, stats




def build_provenance(entries: list, cache: dict | None = None) -> dict:
    """value -> {kind, tier, flags, evidence[], probe?} для страницы «почему в базе»."""
    cache = cache or {}
    keyed: dict = {}
    for e in entries:
        if e.kind not in ("domain", "ip", "cidr"):
            continue
        keyed[e.value] = {
            "kind": e.kind,
            "tier": e.tier,
            "flags": e.flags,
            "evidence": [
                {"source": ev.source, "fetched_at": ev.fetched_at, "reason": ev.reason, "url": ev.url}
                for ev in e.evidence
            ],
        }
    for value, rec in cache.items():
        recd = keyed.get(value)
        if recd is None:
            continue
        recd["probe"] = {
            "status": rec.get("status"),
            "parked": bool(rec.get("parked")),
            "https": rec.get("https"),
            "checked_at": rec.get("checked_at"),
        }
    return keyed


def write_provenance_gz(data: dict, path: Path) -> int:
    """Двоичный provenance.json.gz: страница «почему в базе» скачивает и распаковывает."""
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    gz = gzip.compress(raw, compresslevel=6)
    path.write_bytes(gz)
    return len(gz)


def render_forge_toml(domains_path: Path, ips_path: Path, owner: str, repo: str) -> str:
    """forge.toml для мастерской: цель proxy + два локальных источника (file://)."""
    lines = [
        "# СГЕНЕРИРОВАНО 'python -m pipeline emit' — не редактируй вручную.",
        "# Источники — file:// ссылки на свежие списки конвейера;",
        "# точечные правила и исключения живут в rules/proxy.txt.",
        "",
        "[repo]",
        f"owner = \"{owner}\"",
        f"name = \"{repo}\"",
        "",
        "[targets.proxy]",
        "action = \"route\"",
        "minimal = true",
        "",
        "[[sources]]",
        "name = \"owf-domains\"",
        "enabled = true",
        "action = \"include\"",
        "target = \"proxy\"",
        "kind = \"domains\"",
        f"url = \"{domains_path.as_uri()}\"",
        "",
        "[[sources]]",
        "name = \"owf-ips\"",
        "enabled = true",
        "action = \"include\"",
        "target = \"proxy\"",
        "kind = \"ips\"",
        f"url = \"{ips_path.as_uri()}\"",
    ]
    return "\n".join(lines) + "\n"


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **report}
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
