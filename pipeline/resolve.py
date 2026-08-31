# Шаг резолвинга: единый IP-инвентарь из кэша проб + IP-источников.
# A-записи уже получены на этапе probe (повторного DNS-запроса нет);
# сюда приходят также «сырые» IP/CIDR из источников (antifilter-ips, community, Discord).
# Опционально — ASN-аннотация через GeoLite2-ASN.mmdb (см. --download-geolite).

from __future__ import annotations

import urllib.request
from pathlib import Path

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:  # pragma: no cover - опциональная зависимость
    HAS_GEOIP2 = False

GEOLITE_ASN_URL = "https://github.com/FyraLabs/geolite2/releases/latest/download/GeoLite2-ASN.mmdb"
GEOLITE_MAX_BYTES = 128 * 1024 * 1024


def collect_ips_from_entries(entries: list) -> list[str]:
    """IP/CIDR из собранных записей (kind ip | cidr), без повторов, в порядке появления."""
    seen: set[str] = set()
    ips: list[str] = []
    for e in entries:
        if e.kind in ("ip", "cidr") and e.value not in seen:
            seen.add(e.value)
            ips.append(e.value)
    return ips


def download_geolite(path: Path, url: str = GEOLITE_ASN_URL) -> None:
    """Скачивает GeoLite2-ASN.mmdb (для ASN-аннотации). Один раз, с лимитом размера."""
    path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "open-world-filter/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - фиксированный https
        data = resp.read(GEOLITE_MAX_BYTES + 1)
    if len(data) > GEOLITE_MAX_BYTES:
        raise RuntimeError(f"GeoLite2-ASN.mmdb слишком большой: {len(data)} байт")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def annotate_asn(ips: list[str], mmdb_path: Path) -> dict:
    """{ip: [asn, aso]} для уникальных IP. Требует geoip2 и наличия mmdb."""
    if not HAS_GEOIP2:
        raise RuntimeError("geoip2 не установлен: pip install 'open-world-filter[asn]'")
    reader = geoip2.database.Reader(str(mmdb_path))
    result: dict = {}
    try:
        for ip in dict.fromkeys(ips):
            try:
                resp = reader.asn(ip)
                result[ip] = [resp.autonomous_system_number, resp.autonomous_system_organization]
            except Exception:  # noqa: BLE001 — частная/неизвестная сеть: без аннотации
                continue
    finally:
        reader.close()
    return result
