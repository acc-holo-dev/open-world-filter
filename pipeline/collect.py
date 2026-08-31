# Шаг сбора: скачивание источников и построение записей с provenance.
# Правила чистки строки соответствуют семантике routeforge: домены/IP/CIDR,
# комментарии '#', uBlock-стиль '!' пропускается, AdGuard-исключения '@@' не импортируются.
# Один упавший источник не валит всё — ошибка уходит в отчёт.

from __future__ import annotations

import ipaddress
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from .config import Source
from .provenance import Entry, Evidence, utcnow_iso

MAX_BYTES = 256 * 1024 * 1024  # предохранитель: не больше 256 МиБ на источник (domains.lst antifilter ~90 МиБ)
UA = "open-world-filter/0.1 (+https://github.com/acc-holo-dev/open-world-filter)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def detect_kind(line: str) -> str | None:
    """Определяет тип записи: ip | cidr | domain (None — мусор).

    IP/CIDR проверяются раньше домена: «1.2.3.4» валиден и как домен
    (числовые лейблы), но как IP он встречается в списках несравнимо чаще.
    """
    try:
        ipaddress.ip_address(line)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(line, strict=False)
        return "cidr"
    except ValueError:
        pass
    if DOMAIN_RE.match(line):
        return "domain"
    return None


def sanitize_line(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    if "@@" in line:  # AdGuard-исключения не импортируем
        return None
    # хвостовой комментарий срезаем ДО проверки AdGuard-маркера:
    # «||Example.COM^ # trail» -> «||Example.COM^» -> «example.com»
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    if line.startswith("||") and line.endswith("^"):
        line = line[2:-1]
    line = line.lower()
    return line or None


def fetch_text(url: str, timeout: int = 30) -> str:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise RuntimeError(f"source too large (> {MAX_BYTES} bytes): {url}")
            return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"unreachable {url}: {exc.reason}") from exc


def _parse_exclusion_line(raw: str, src: Source, now: str) -> Entry | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    v = line[1:].strip().lower() if line.startswith("!") else line.lower()
    if not v:
        return None
    return Entry(
        value=v,
        kind="exclusion",
        tier=src.tier,
        evidence=[Evidence(source=src.name, fetched_at=now, url=src.url, reason=src.evidence or None)],
    )


def collect_source(src: Source, root: Path, offline: bool = False) -> tuple[list[Entry], str | None]:
    if src.is_remote:
        if offline:
            return [], f"skipped (--offline): {src.name}"
        try:
            lines = fetch_text(src.url).splitlines()
        except Exception as exc:  # noqa: BLE001 — намеренно: всё уходит в отчёт
            return [], f"{src.name}: {exc}"
    else:
        path = root / src.file
        if not path.exists():
            return [], f"{src.name}: missing local file {path}"
        lines = path.read_text(encoding="utf-8").splitlines()

    now = utcnow_iso()
    if src.kind == "exclusions":
        entries = [e for e in (_parse_exclusion_line(line, src, now) for line in lines) if e is not None]
        return entries, None

    evidence = Evidence(source=src.name, fetched_at=now, url=src.url, reason=src.evidence or None)
    seen: set[str] = set()
    entries: list[Entry] = []
    junk = 0
    for raw in lines:
        clean = sanitize_line(raw)
        if clean is None:
            continue
        kind = detect_kind(clean)
        if kind is None:
            junk += 1
            continue
        if clean in seen:
            continue
        seen.add(clean)
        entries.append(Entry(value=clean, kind=kind, tier=src.tier, evidence=[evidence]))
    return entries, None
