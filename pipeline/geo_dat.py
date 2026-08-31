# Подготовка входов для конвертеров форматов (M2.5):
#  - xray-geoip (Go, vendored):      наши CIDR -> geoip.dat (категория owf)
#  - generate-geoip-geosite (Go):    наши списки -> geoip.db / geosite.db
# Сама компиляция бинарников и прогон — в CI (нужен Go toolchain):
#   см. .github/workflows/open-world-filter.yml (job convert) и tools/README.md.

from __future__ import annotations

import json
import shutil
from pathlib import Path

XRAY_GEOIP_CONFIG_NAME = "owf-geoip.json"


def render_xray_geoip_config(ips_path: Path, name: str = "owf", uri: str | None = None) -> dict:
    """Конфиг xray-geoip: text-вход наших CIDR + private, выход geoip.dat."""
    return {
        "input": [
            {"type": "text", "action": "add",
             "args": {"name": name, "uri": uri or ips_path.as_posix()}},
            {"type": "private", "action": "add"},
        ],
        "output": [
            {"type": "v2rayGeoIPDat", "action": "output",
             "args": {"outputName": "geoip.dat", "outputDir": "out/geo-dat",
                      "wantedList": [name, "private"]}},
        ],
    }


def prepare_generator_input(ips_path: Path, domains_path: Path, out_dir: Path,
                            name: str = "owf", only_ipv4: bool = False) -> list:
    """Файлы для generate-geoip-geosite: include-{ip,domain}-<name>.lst."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ip_target = out_dir / f"include-ip-{name}.lst"
    domain_target = out_dir / f"include-domain-{name}.lst"
    written: list = []
    if ips_path.exists():
        if only_ipv4:
            lines = [l for l in ips_path.read_text(encoding="utf-8").splitlines()
                     if l.strip() and ":" not in l]
            ip_target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            shutil.copyfile(ips_path, ip_target)
        written.append(str(ip_target))
    if domains_path.exists():
        shutil.copyfile(domains_path, domain_target)
        written.append(str(domain_target))
    return written


def prepare_all(root: Path, output: Path, name: str = "owf") -> dict:
    """Готовит всё, что нужно конвертерам: входы генератора + конфиг xray-geoip."""
    ips = output / "owf-ips.lst"
    domains = output / "owf-domains.lst"
    gen_dir = output / "convert-input"
    gen_files = prepare_generator_input(ips, domains, gen_dir, name=name)
    cfg = render_xray_geoip_config(ips, name=name)
    cfg_path = gen_dir / XRAY_GEOIP_CONFIG_NAME
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "xray_config": str(cfg_path),
        "generator_input": gen_files,
        "note": "Бинарники собираются в CI (setup-go); локально нужен Go toolchain. См. tools/README.md.",
    }
