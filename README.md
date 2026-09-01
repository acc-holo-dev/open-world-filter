# Open World Filter

Прозрачные списки блокировок РКН и сайтов, недоступных из РФ, — плюс готовые подписки
для **Throne**, **sing-box/Hiddify**, **Clash Meta**, **v2rayN** и **Xray**.
У каждой записи есть провенанс: откуда она взялась, когда и почему, — в списках нет ничего «магического».

## Как подключить

Три шага — и всё работает:

1. Открой [последний релиз](https://github.com/acc-holo-dev/open-world-filter/releases/latest).
2. Скопируй ссылку своей подписки (в списке файлов — кнопка Download):
   - `route-profile-throne-full.json` — полный профиль Throne (hijack-DNS + наши правила);
   - `route-profile-throne-minimal.json` — минимальный профиль Throne;
   - `sing-box-config.json` — конфиг sing-box / Hiddify;
   - `clash-meta.yaml` — конфиг Clash Meta (rule-providers);
   - `v2rayn-routing.json` — сниппет routing для v2rayN / Xray;
   - `geoip.dat` / `geosite.dat` — базы для Xray (категория `owf`).
3. Вставь ссылку в свой клиент — подписка установится и дальше обновляется сама.

Подписки содержат только правила маршрутизации: прокси-ноды подставляешь свои.

## Почему в базе

Любую запись можно проверить: открой страницу «почему в базе» ([site/check.html](site/check.html))
и введи домен или IP — увидишь источники (реестр РКН, antifilter, OONI, правки сообщества),
дату добавления и статус пробы доступности (DNS/NS + опционально HTTPS). Каждая запись попадает
в список с доказательствами, а не по «авторитетному мнению».

## Добавить свой сайт

    python -m pipeline добавить example.com

После установки (см. «Разработка») команда триммит и приводит к нижнему регистру, проверяет,
что запись — домен/IP/CIDR (`203.0.113.5`, `203.0.113.0/24`), и аккуратно дописывает её в
`community/additions.txt`. Исключения живут в `community/exclusions.txt`. Отправь PR —
авто-линт `check-community` проверит формат правки прямо в CI.

## Разработка

    pip install dnspython aiohttp
    pip install git+https://github.com/acc-holo-dev/open-world-filter-source.git   # мастерская
    python -m pipeline all                 # полный конвейер: build -> probe -> resolve -> summarize -> emit -> subscriptions
    owf-source собрать --root .            # rule-sets и профили из templates/ (мастерская)
    python -m pipeline subscriptions       # подписки (clash-meta, v2rayn) + сайт index.html
    python -m unittest discover -s tests   # тесты (stdlib)

Конвейер (`pipeline/`) работает на stdlib; `dnspython`/`aiohttp` нужны только для проб доступности.
Мастерская (`open-world-filter-source`) ставится через pip из git-репозитория и генерирует
rule-sets и профили Throne/sing-box из `templates/` — однонаправленная зависимость, без копий кода.

## Команды конвейера

    collect          скачать источники -> out/raw-entries.jsonl
    classify         применить исключения -> out/entries.jsonl
    build            collect + classify одним заходом
    probe            DNS/NS-пробы (--https, --workers N) -> out/probe-cache.json
    resolve          IP-инвентарь (+ASN, --download-geolite) -> out/ips-all.lst
    summarize        IP -> минимальные CIDR (с учётом ASN) -> out/ipsum.lst
    emit             политика + итоговые списки + forge.toml для мастерской
    subscriptions    подписки (clash-meta, v2rayn) + сайт index.html
    check-community  линт community/*.txt (авто-ревью PR в CI)
    geo-dat          входы для конвертеров geoip.dat / geosite.dat
    all              build -> probe -> resolve -> summarize -> emit -> subscriptions
    добавить         добавить домен/IP/CIDR в community/additions.txt (правка -> PR)

Общие флаги: `--root <путь>`, `--offline` (только локальные источники), `--strict`,
`--verbose`, `--provenance` (писать `out/provenance.json.gz` для страницы «почему в базе»).