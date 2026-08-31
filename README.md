# Open World Filter

Свежие и **прозрачные** списки блокировок РКН и ресурсов, недоступных из РФ,
плюс готовые правила/подписки для клиентов: **Throne**, sing-box/Hiddify, Clash Meta, v2rayN, Xray.

Самостоятельный проект на основе опыта и исходников Re-filter-lists
(https://github.com/1andrevich/Re-filter-lists), но с другим подходом:

- Двухуровневая модель доверия: жёсткие доказательства (реестр, antifilter, OONI) -> tier auto;
  правки сообщества -> tier community; эвристики только флагают, а не удаляют молча.
- Прозрачность: у каждой записи provenance — откуда, когда, почему; статусы проб — отдельно;
  страница «почему в базе» (site/check.html) ищет любую запись по provenance.json.gz.
- Свежесть: инкрементальный кэш проб (пересборка — минуты, а не часы), автопересборки в CI.
- Сообщество: добавление доменов через community/*.txt и PR с авто-линтом (check-community).

## Статус

- [x] M0 — скелет: конфиг источников, сбор, provenance, исключения, CLI, тесты
- [x] M1 — пробы (DNS/NS + опц. HTTPS), резолвинг IP, суммаризация CIDR (с учётом ASN),
      интеграция с routeforge (rule-sets JSON), CI-workflow
- [x] M2 — подписки: Throne (полный/минимальный профиль), sing-box/Hiddify конфиг,
      Clash Meta, v2rayN-сниппет, манифест subscriptions.json, сайт index.html (RU/EN, автогенерация),
      релиз-пайплайн (.srs через pinned sing-box, тег owf-latest)
- [x] M2.5 — конвертеры: geoip.dat (xray-geoip, job convert в CI), geoip.db/geosite.db
      (generate-geoip-geosite), команда geo-dat готовит входы
- [x] M3 — сообщество: issue-шаблон, линт community/*.txt в тестах CI, страница «почему в базе»
      (site/check.html + provenance.json.gz), деплой на GitHub Pages (job pages)

## Подписки / как подключить

Все ссылки — по шаблону: https://github.com/acc-holo-dev/open-world-filter/releases/latest/download/
Подписки содержат ТОЛЬКО правила; прокси-ноды вставляешь свои.

### Throne (VPN Client, sing-box-based)
- route-profile-throne-full.json — полный профиль: hijack-dns + наши rule-sets (domains+ips) -> proxy
- route-profile-throne-minimal.json — минимальный профиль
Импорт: настройки клиента -> импортировать профиль по URL.

### sing-box / Hiddify
- sing-box-config.json — конфиг с rule_set (binary .srs) и правилом proxy
- sing-box-route-snippet.json / sing-box-rule-sets-snippet.json — фрагменты
- proxy-domains.srs / proxy-ips.srs — сами rule-sets

### Clash Meta
- clash-meta.yaml — rule-providers (text) на наши .lst: owf-domains (domain), owf-ips (ipcidr)

### v2rayN / Xray
- v2rayn-routing.json — сниппет routing c ext:geoip.dat:owf / ext:geosite.dat:owf
- geoip.dat / geosite.dat — категория owf; geoip.db / geosite.db — для sing-box (Hiddify)

### «Почему в базе»
- site/check.html (или https://<owner>.github.io/open-world-filter/check.html) — ищи домен/IP,
  покажет источники, дату, статус пробы. Данные: out/provenance.json.gz (public в Releases).

## Сообщество (M3)

- .github/ISSUE_TEMPLATE/community-data.md — шаблон «Добавить/убрать домены или IP»
- community/additions.txt — домены/CIDR сообщества (tier community)
- community/exclusions.txt — исключения (!suffix: / !domain: / голое имя)
- python -m pipeline check-community — линт правок, запускается в CI на каждый PR
- Для GitHub Pages включи в настройках репозитория: Settings -> Pages -> Source: GitHub Actions

## Конвертеры форматов (M2.5)

    python -m pipeline geo-dat    # входы: out/convert-input/ (include-ip-owf.lst и т.п. + owf-geoip.json)

- geoip.dat  — xray-geoip (tools/xray-geoip, Go): go build + ./xray-geoip -c out/convert-input/owf-geoip.json
- geoip.db / geosite.db — generate-geoip-geosite (Dunamis4tw): gen -i out/convert-input -o out/geo-db
- Сборка обоих — джоба convert в CI (setup-go); локально нужен Go toolchain

## Быстрый старт

    python -m venv .venv
    .venv\Scripts\python -m pip install dnspython aiohttp   # Windows
    # .venv/bin/python -m pip install dnspython aiohttp       # Linux/macOS

    .venv\Scripts\python -m pipeline all --offline          # только локальные community-источники
    .venv\Scripts\python -m pipeline all --workers 512 --provenance   # полный прогон
    python -m routeforge build --root open-world-filter --strict --no-cache
    python -m pipeline subscriptions

    python -m unittest discover -s tests -v                   # тесты (stdlib)

## Команды конвейера

    build          скачать источники -> исключения -> entries.jsonl (provenance)
    probe          DNS/NS пробы; кэш out/probe-cache.json (инкрементально, TTL по статусу)
                   --limit N --workers N --https --no-ns
    resolve        IP-инвентарь: A-записи из кэша проб + IP/CIDR источников -> ips-all.lst
                   --download-geolite (GeoLite2-ASN.mmdb, нужен pip install geoip2)
    summarize      суммаризация IP -> минимальные CIDR; с ASN-группами, если есть asn-map.json
    emit           политика (dead исключается, --keep-dead оставляет) -> owf-*.lst + forge.toml
                   --provenance: писать out/provenance.json.gz («почему в базе»)
    subscriptions  подписки: clash-meta, v2rayn, subscriptions.json + site/index.html
    check-community линт community/*.txt (CI на PR)
    geo-dat        входы для конвертеров .dat/.db
    all            build -> probe -> resolve -> summarize -> emit -> subscriptions

Статусы проб: alive | empty (имя есть, A нет) | dead (NXDOMAIN) | error (неизвестно — НЕ мёртвый).
Политика emit: dead выбрасывается; empty/error/parked остаются; всё — в emit-report.json.

## Вендор routeforge

Для самодостаточности публичного CI копия пакета routeforge лежит в ./routeforge
(обновляется из acc-holo-dev/throne-route-forge, репо приватное). Версия: см. git history.

## Интеграция с routeforge

emit генерирует forge.toml (file:// ссылки на свежие списки); routeforge собирает
rule-sets (.json, затем .srs в CI) и профили из open-world-filter/templates/ (Throne, sing-box):

    python -m routeforge build --root open-world-filter --strict --no-cache

## Модель данных

raw-entries.jsonl — записи из источников; entries.jsonl — после исключений и флагов.
Каждая запись: value, kind (domain|ip|cidr|exclusion), tier (auto|community),
flags (heuristic:...), evidence[] (source, fetched_at, url, reason).
probe-cache.json: domain -> {status, ips[], ns[], parked, https, checked_at}.
provenance.json.gz: value -> {kind, tier, flags, evidence[], probe} — для site/check.html.

---
A transparent pipeline for RKN-blocked and geo-blocked-from-RU domains/IPs.
Rules & subscriptions for Throne, sing-box/Hiddify, Clash Meta, v2rayN, Xray.
Evidence-based inclusion, full provenance, incremental probes, routeforge-powered builds.