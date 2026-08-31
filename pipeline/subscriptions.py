# Подписки/конфиги для клиентов + манифест ссылок + генерация сайта.
#
# Throne и sing-box/Hiddify генерирует routeforge из шаблонов open-world-filter/templates/*.json
# (см. зовём в CI 'routeforge build' без --no-profiles).
# Здесь — то, что DSL routeforge не покрывает:
#   - clash-meta.yaml   (объектная карта rule-providers, текст-провайдеры на наши .lst)
#   - v2rayn-routing.json (сниппет routing с ext:geoip/geosite.dat:owf)
#   - subscriptions.json (манифест всех ссылок — его использует сайт)
#   - site/index.html   (статичный RU/EN, генерируется из манифеста)
#
# Подписки содержат ТОЛЬКО правила; прокси-ноды пользователь вставляет свои.

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CATEGORY = "owf"  # категория внутри geoip.dat / geosite.dat (Xray)

CLIENTS = ("throne-full", "throne-minimal", "sing-box-config", "sing-box-route-snippet",
           "sing-box-rule-sets-snippet", "clash-meta", "v2rayn-routing",
           "proxy-domains-srs", "proxy-ips-srs", "geoip-dat", "geosite-dat",
           "geoip-db", "geosite-db", "owf-domains-lst", "owf-ips-lst", "provenance-gz")


def release_base(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}/releases/latest/download/"


def render_clash(owner: str, repo: str) -> dict:
    """Clash Meta: rule-providers на наши текстовые списки (.lst). JSON = валидный YAML."""
    base = release_base(owner, repo)
    return {
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "info",
        "proxies": [],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["__YOUR_NODES__"]}
        ],
        "rule-providers": {
            "owf-domains": {"type": "http", "behavior": "domain", "format": "text",
                            "url": base + "owf-domains.lst", "interval": 21600},
            "owf-ips": {"type": "http", "behavior": "ipcidr", "format": "text",
                        "url": base + "owf-ips.lst", "interval": 21600},
        },
        "rules": [
            "RULE-SET,owf-domains,PROXY",
            "RULE-SET,owf-ips,PROXY",
            "MATCH,DIRECT",
        ],
    }


def render_v2rayn(owner: str, repo: str, category: str = DEFAULT_CATEGORY) -> dict:
    """v2rayN routing snippet: ext-ссылки на geoip.dat/geosite.dat (категория owf)."""
    return {
        "routing": {
            "rules": [
                {"type": "field", "ip": [f"ext:geoip.dat:{category}"], "outboundTag": "proxy"},
                {"type": "field", "domain": [f"ext:geosite.dat:{category}"], "outboundTag": "proxy"},
                {"type": "field", "outboundTag": "direct"},
            ]
        }
    }


def render_manifest(owner: str, repo: str, category: str = DEFAULT_CATEGORY) -> dict:
    """Все ссылки на артефакты релиза — единая точка правды для сайта."""
    base = release_base(owner, repo)
    return {
        "owner": owner,
        "repo": repo,
        "category": category,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "clients": {
            "throne-full": base + "route-profile-throne-full.json",
            "throne-minimal": base + "route-profile-throne-minimal.json",
            "sing-box-config": base + "sing-box-config.json",
            "sing-box-route-snippet": base + "sing-box-route-snippet.json",
            "sing-box-rule-sets-snippet": base + "sing-box-rule-sets-snippet.json",
            "clash-meta": base + "clash-meta.yaml",
            "v2rayn-routing": base + "v2rayn-routing.json",
            "proxy-domains-srs": base + "proxy-domains.srs",
            "proxy-ips-srs": base + "proxy-ips.srs",
            "geoip-dat": base + "geoip.dat",
            "geosite-dat": base + "geosite.dat",
            "geoip-db": base + "geoip.db",
            "geosite-db": base + "geosite.db",
            "owf-domains-lst": base + "owf-domains.lst",
            "owf-ips-lst": base + "owf-ips.lst",
            "provenance-gz": base + "provenance.json.gz",
        },
    }


def render_site(manifest: dict) -> str:
    """Минимальный статичный сайт RU/EN со ссылками из манифеста."""
    c = manifest["clients"]
    repo_url = f"https://github.com/{manifest['owner']}/{manifest['repo']}"
    def a(name, key):
        return f'      <li><a href="{c[key]}">{name}</a> <code>{c[key]}</code></li>'
    lines = [
        "<!doctype html>",
        '<html lang="ru"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Open World Filter — реестр блокировок РКН / RKN blocklist</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;line-height:1.55}"
        "a{color:#1a6fb0}code{background:#f2f2f2;padding:.1em .35em;border-radius:4px;font-size:.92em}"
        "h2{border-bottom:1px solid #ddd;padding-bottom:.2rem}</style>",
        "</head><body>",
        '<h1>🌍 Open World Filter</h1>',
        "<p>Свежие списки блокировок РКН и ресурсов, недоступных из РФ, с полной историей происхождения. ",
        f'<a href="{repo_url}">Репозиторий</a>.</p>',
        "<hr>",
        "<h2>Как подключить / How to install</h2>",
        "<h3>🇷🇺 Инструкции</h3>",
        "<ol>",
        "<li>Скачай свой VPN-клиент (Hiddify, Clash Meta, v2rayN или Throne) и добавь свои серверы.</li>",
        "<li>Импортируй конфиг или rule-sets по ссылкам ниже (подписка содержит только правила).</li>",
        "<li>Готово: заблокированные домены и подсети пойдут через прокси, остальное — напрямую.</li>",
        "</ol>",
        "<h3>🇬🇧 Instructions</h3>",
        "<ol>",
        "<li>Install your VPN client (Hiddify, Clash Meta, v2rayN or Throne) and add your servers.</li>",
        "<li>Import a config or rule-sets from the links below (rules only, no proxy nodes).</li>",
        "<li>Done: blocked domains/IPs go through your proxy; everything else stays direct.</li>",
        "</ol>",
        "<h2>Подписки / Subscriptions</h2>",
        "<ul>",
        a("Throne — полный профиль", "throne-full"),
        a("Throne — минимальный профиль", "throne-minimal"),
        a("sing-box / Hiddify — конфиг", "sing-box-config"),
        a("sing-box — rule-sets (двоичные)", "proxy-domains-srs"),
        a("Clash Meta — конфиг", "clash-meta"),
        a("v2rayN — routing-сниппет", "v2rayn-routing"),
        a("Xray geoip.dat / geosite.dat", "geoip-dat"),
        "</ul>",
        "<p><em>Обновляется автоматически каждый релиз. / Updated automatically on every release.</em></p>",
        "</body></html>",
    ]
    return "\n".join(lines) + "\n"


def render_all(owner: str, repo: str, category: str = DEFAULT_CATEGORY) -> dict:
    """Все артефакты подписок: имя файла -> (формат, содержимое, путь)."""
    clash = render_clash(owner, repo)
    v2rayn = render_v2rayn(owner, repo, category)
    manifest = render_manifest(owner, repo, category)
    return {
        "clash-meta.yaml": ("json", clash),
        "v2rayn-routing.json": ("json", v2rayn),
        "subscriptions.json": ("json", manifest),
        "index.html": ("text", render_site(manifest)),
    }


def write_all(artifacts: dict, out_dir: Path, site_dir: Path) -> list:
    """Пишет артефакты: clash/v2rayn/manifest -> out_dir/subscriptions, index.html -> site_dir."""
    subs_dir = out_dir / "subscriptions"
    subs_dir.mkdir(parents=True, exist_ok=True)
    site_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (kind, payload) in artifacts.items():
        target = site_dir / name if name == "index.html" else subs_dir / name
        if kind == "json":
            text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        else:
            text = payload
        target.write_text(text, encoding="utf-8")
        written.append(str(target))
    return written
