# Шаг проб доступности: async DNS (A + NS) и опциональный HTTPS-проб.
#
# Ключевые решения (отличия от step2 Re-filter):
#  - инкрементальность: результат кэшируется в out/probe-cache.json; при следующем
#    запуске проверяются только новые/устаревшие домены — пересборка занимает минуты, а не часы;
#  - прозрачность: неизвестный результат (timeout/SERVFAIL) НЕ считается «мёртвым» —
#    статус error остаётся за записью, а решение принимает политика emit;
#  - «запаркованные» домены детектятся по NS (список паттернов расширяемый);
#  - резолверы — round-robin по нескольким публичным серверам (в т.ч. RU),
#    повтор ошибки выполняется другим резолвером.
#
# Статусы: alive (есть A-записи) | empty (имя есть, A нет) | dead (NXDOMAIN) | error (неизвестно).

from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path

try:  # опциональные зависимости: без них доступны чистые функции и работа с кэшем
    import dns.asyncresolver
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - зависит от окружения
    HAS_DNSPYTHON = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

PUBLIC_RESOLVERS = [
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "77.88.8.8", "77.88.8.1",        # Yandex (RU)
]

# NS, типичные для «запаркованных» доменов (по мотивам step2 Re-filter, расширяемо).
PARKED_NS_PATTERNS = [
    "parking", "parked", "sedoparking", "bodis", "hugedomains", "afternic",
    "dan.com", "parklogic", "above.com", "cashparking", "parkcreatives",
    "redirect", "domaincontrol", "ns1.ago", "undeveloped", "frigidfar",
]

DAY = 86400.0
# TTL кэша по статусу (сек): живые перепроверяются раз в неделю,
# мёртвые — раз в месяц, ошибки — на следующий запуск.
TTL_MAP = {"alive": 7 * DAY, "empty": 7 * DAY, "dead": 30 * DAY, "error": 1 * DAY}


def classify_dns(rcode: str, a_count: int) -> str:
    """Классифицирует исход DNS-запроса: alive | empty | dead | error."""
    if rcode == "NXDOMAIN":
        return "dead"
    if rcode in ("NOERROR", "NOANSWER"):
        return "alive" if a_count > 0 else "empty"
    return "error"


def is_parked(ns_names: list[str]) -> bool:
    """True, если среди NS есть типичные для парковки доменов."""
    lowered = [str(n).lower().rstrip(".") for n in ns_names]
    return any(p in name for name in lowered for p in PARKED_NS_PATTERNS)


def is_expired(record: dict, now: float, ttl_map: dict | None = None) -> bool:
    """Истёк ли TTL записи кэша (по её статусу).

    Запись без отметки времени (повреждённая/старая) считается просроченной —
    её перепроверяем, ничего не угадывая за неё.
    """
    if "checked_at" not in record:
        return True
    ttl = (ttl_map or TTL_MAP).get(str(record.get("status", "error")), TTL_MAP["error"])
    return now - float(record["checked_at"]) > ttl


def load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def collect_ips_from_cache(cache: dict) -> list[str]:
    """A-записи живых доменов из кэша (без повторов, в порядке кэша)."""
    seen: set[str] = set()
    ips: list[str] = []
    for record in cache.values():
        if record.get("status") != "alive":
            continue
        for ip in record.get("ips", []):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


async def _resolve_a(domain: str, resolver_ip: str, lifetime: float = 4.0) -> dict:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = lifetime
    try:
        answer = await resolver.resolve(domain, "A")
        ips = sorted({r.to_text() for r in answer})
        return {"rcode": "NOERROR", "ips": ips}
    except dns.resolver.NXDOMAIN:
        return {"rcode": "NXDOMAIN", "ips": []}
    except dns.resolver.NoAnswer:
        return {"rcode": "NOANSWER", "ips": []}
    except Exception:  # noqa: BLE001 — timeout/SERVFAIL/сеть: это статус error, не падение
        return {"rcode": "ERROR", "ips": []}


async def _resolve_ns(domain: str, resolver_ip: str, lifetime: float = 4.0) -> list[str]:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = lifetime
    try:
        answer = await resolver.resolve(domain, "NS")
        return sorted({str(r).rstrip(".") for r in answer})
    except Exception:  # noqa: BLE001 — без вердикта по NS это не ошибка пробы
        return []


async def _https_probe(domain: str, timeout: float = 8.0) -> str:
    url = "https://" + domain
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "open-world-filter-probe/0.1"},
        ) as session:
            async with session.head(url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    return "redirect"
                return "ok" if resp.status < 500 else "fail"
    except Exception:  # noqa: BLE001
        return "fail"


async def _probe_one(domain: str, resolvers: list[str], https: bool, ns_check: bool,
                     sem: asyncio.Semaphore) -> dict:
    async with sem:
        first = random.choice(resolvers)
        result = await _resolve_a(domain, first)
        if result["rcode"] == "ERROR" and len(resolvers) > 1:
            second = random.choice([r for r in resolvers if r != first] or resolvers)
            result = await _resolve_a(domain, second)
        status = classify_dns(result["rcode"], len(result["ips"]))
        ns: list[str] = []
        parked = False
        if ns_check and status == "alive":
            ns = await _resolve_ns(domain, random.choice(resolvers))
            parked = is_parked(ns)
        https_status = None
        if https and status == "alive":
            https_status = await _https_probe(domain)
        return {
            "status": status,
            "ips": result["ips"],
            "ns": ns,
            "parked": parked,
            "https": https_status,
            "checked_at": time.time(),
        }


async def probe_domains(domains: list[str], cache: dict, *, workers: int = 256,
                        https: bool = False, ns_check: bool = True,
                        resolvers: list[str] | None = None, limit: int | None = None,
                        verbose: bool = False) -> dict:
    """Пробует домены, отсутствующие в кэше или с истёкшим TTL. Мутирует cache.

    Возвращает статистику прогона. Уже покрытые кэшем домены не трогаются.
    """
    if not HAS_DNSPYTHON:
        raise RuntimeError("dnspython не установлен: pip install dnspython")
    if https and not HAS_AIOHTTP:
        raise RuntimeError("aiohttp не установлен: pip install aiohttp (--https требует его)")

    now = time.time()
    todo = [d for d in domains if d not in cache or is_expired(cache[d], now)]
    cached = len(domains) - len(todo)
    if limit is not None and limit >= 0:
        todo = todo[:limit]

    sem = asyncio.Semaphore(max(1, workers))
    servers = list(resolvers or PUBLIC_RESOLVERS)
    stats = {"domains": len(domains), "cached": cached, "probed": 0,
             "alive": 0, "empty": 0, "dead": 0, "error": 0, "parked": 0}

    async def run_one(domain: str) -> None:
        record = await _probe_one(domain, servers, https, ns_check, sem)
        cache[domain] = record
        stats["probed"] += 1
        stats[record["status"]] += 1
        if record.get("parked"):
            stats["parked"] += 1
        if verbose and stats["probed"] % 10000 == 0:
            print(f"  probe progress: {stats['probed']}/{len(todo)} "
                  f"(alive={stats['alive']} dead={stats['dead']} error={stats['error']})", flush=True)

    await asyncio.gather(*(run_one(d) for d in todo))
    return stats
