# Tools (M2)

Вендоренные конвертеры для форматов клиентов (исходники из Re-filter-lists, лицензии оригиналов).

## xray-geoip (Go) — geoip.dat / geosite.dat для Xray/V2Ray

Исходники: open-world-filter/tools/xray-geoip (из Re-filter-lists-main/src/xray-geoip).

    go build -o xray-geoip ./...

Формат исходников конвертера (см. xray-geoip/config.json): на вход — plain-text списки,
категория присваивается по правилам конфига. Для нашего конвейера готовим два файла:

    owf-ips.lst        (CIDR)     -> категория 'owf' в geoip.dat
    owf-domains.lst    (домены)   -> категория 'owf' в geosite.dat

В CI (setup-go) команда сборки добавляется в workflow по мере готовности;
локально для проверки нужен Go toolchain (в этом окружении отсутствует).

## geoip.db / geosite.db (sing-box)

sing-box компилирует .srs из наших JSON rule-sets:

    sing-box rule-set compile --output proxy-domains.srs release-assets/proxy-domains.json
    sing-box rule-set compile --output proxy-ips.srs     release-assets/proxy-ips.json

Сборку .db (geoip.db/geosite.db) делают инструменты Dunamis4tw/generate-geoip-geosite;
список включим в CI на этапе M2.5 (см. README -> Статус).

## Кэш проб и ASN

GeoLite2-ASN.mmdb (опционально, для ASN-аннотации в resolve --download-geolite)
складывается в open-world-filter/tools/GeoLite2-ASN.mmdb.
