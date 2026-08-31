# Site (M2)

Статичный сайт open-world-filter (RU + EN).

- index.html генерируется автоматически:

    python -m pipeline subscriptions

  (пишется в open-world-filter/site/index.html из манифеста out/subscriptions/subscriptions.json).
- Содержит ссылки на все подписки и краткие инструкции для Hiddify / Clash Meta / v2rayN / Throne.
- Деплой на GitHub Pages добавим в M3 (pages-deploy шаг в workflow).
