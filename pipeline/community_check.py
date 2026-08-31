# CI-ревью правок сообщества (M3): валидация community/*.txt.
# Вызывается в workflow на PR; ошибки валят сборку, предупреждения — в отчёт.

from __future__ import annotations

from pathlib import Path

from .classify import parse_exclusion_rule
from .collect import detect_kind, sanitize_line


def validate_additions(path: Path) -> tuple:
    errors: list[str] = []
    seen: dict[str, int] = {}
    stats = {"lines": 0, "accepted": 0, "junk": 0, "duplicates": 0}
    if not path.exists():
        return errors, stats
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stats["lines"] += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            errors.append(f"{path.name}:{lineno}: AdGuard-исключения живут в exclusions.txt: {raw!r}")
            stats["junk"] += 1
            continue
        clean = sanitize_line(raw)
        if clean is None:  # sanitize не разобрал строку (мусор, @@ и т.п.)
            errors.append(f"{path.name}:{lineno}: не удаётся распознать запись: {raw!r}")
            stats["junk"] += 1
            continue
        kind = detect_kind(clean)
        if kind is None:
            errors.append(f"{path.name}:{lineno}: не удаётся распознать запись: {raw!r}")
            stats["junk"] += 1
            continue
        if clean in seen:
            errors.append(f"{path.name}:{lineno}: дубликат строки {seen[clean]}: {clean}")
            stats["duplicates"] += 1
            continue
        seen[clean] = lineno
        stats["accepted"] += 1
    return errors, stats


def validate_exclusions(path: Path) -> tuple:
    errors: list[str] = []
    seen: dict[str, int] = {}
    stats = {"lines": 0, "accepted": 0, "unsupported": 0, "duplicates": 0}
    if not path.exists():
        return errors, stats
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stats["lines"] += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rule = line[1:].strip().lower() if line.startswith("!") else line.lower()
        if not rule:
            continue
        parsed = parse_exclusion_rule(rule)
        if parsed is None:
            errors.append(f"{path.name}:{lineno}: правило не поддерживается (keyword:/regexp:): {raw!r}")
            stats["unsupported"] += 1
            continue
        if rule in seen:
            errors.append(f"{path.name}:{lineno}: дубликат исключения (строка {seen[rule]}): {rule}")
            stats["duplicates"] += 1
            continue
        seen[rule] = lineno
        stats["accepted"] += 1
    return errors, stats


def check_community(root: Path) -> dict:
    """Возвращает отчёт {ok, errors[], stats}. Ошибки — повод отклонить PR."""
    add_errors, add_stats = validate_additions(root / "community" / "additions.txt")
    excl_errors, excl_stats = validate_exclusions(root / "community" / "exclusions.txt")
    return {
        "ok": not add_errors and not excl_errors,
        "errors": add_errors + excl_errors,
        "stats": {"additions": add_stats, "exclusions": excl_stats},
    }
