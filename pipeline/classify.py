# Шаг классификации: исключения состава и эвристические флаги.
# Правило проекта: эвристики НИКОГДА не удаляют записи молча.
# Они лишь ставят флаг heuristic:<имя> — решение принимает человек
# (через allowlist / review в PR). По умолчанию список эвристик пуст —
# расширяется осознанно, а не по образцу агрессивного keyword-фильтра Re-filter.

from __future__ import annotations

import re

from .provenance import Entry

# (имя, regex по значению записи). Пусто по умолчанию.
HEURISTIC_PATTERNS: list[tuple[str, str]] = [
    # ("example-fraud-keyword", r"\b(?:casino|bet)\b"),  # пример: помечает, но НЕ удаляет
]


def flag_heuristics(entry: Entry) -> None:
    for name, pattern in HEURISTIC_PATTERNS:
        if re.search(pattern, entry.value):
            flag = f"heuristic:{name}"
            if flag not in entry.flags:
                entry.flags.append(flag)


def parse_exclusion_rule(raw: str) -> tuple[str, str] | None:
    # suffix:x -> ('suffix','x'); domain:x / x -> ('domain','x'); прочее -> None.
    if raw.startswith("suffix:"):
        return "suffix", raw[len("suffix:"):]
    if raw.startswith("domain:"):
        return "domain", raw[len("domain:"):]
    if raw.startswith(("keyword:", "regexp:")):
        return None  # M0: не поддерживаются, задокументировано
    return "domain", raw


def _matches_exclusion(value: str, kind: str, rule: str) -> bool:
    if kind == "suffix":
        return value == rule or value.endswith("." + rule)
    if kind == "domain":
        return value == rule
    return False


def apply_exclusions(entries: list[Entry], exclusions: list[Entry]) -> tuple[list[Entry], list[Entry]]:
    # IP/CIDR-исключения — в M1.
    rules = [r for e in exclusions if (r := parse_exclusion_rule(e.value)) is not None]
    kept: list[Entry] = []
    removed: list[Entry] = []
    for e in entries:
        if e.kind != "domain" or not any(_matches_exclusion(e.value, k, v) for k, v in rules):
            kept.append(e)
        else:
            removed.append(e)
    return kept, removed
