# CAnttRUst

![Медведь-вор — иконка CAnttRUst](src/ui/icons/icon-128.png)

CAnttRUst — экспериментальное расширение Firefox 142+, которое ограничивает доверие к **Russian Trusted Root CA** зонами `.ru`, `.su` и `.рф`, а для подходящих сайтов дополнительно проверяет встроенные SCT российских Certificate Transparency-логов.

Расширение не меняет системное хранилище сертификатов. Оно проверяет только переходы верхнего уровня (`main_frame`) по HTTPS и показывает собственную страницу предупреждения до передачи ответа сайту.

## Что защищается

- Совпадение CA определяется по SHA-256 от DER сертификата в цепочке, а не по имени издателя.
- За пределами `.ru`, `.su` и `.рф` соединение через защищаемый CA блокируется.
- В разрешённых зонах требуется криптографически корректный встроенный SCT из зафиксированного списка российских CT-логов.
- IP-адреса и `localhost` не считаются российскими DNS-зонами.
- Исключение можно выдать только точному DNS-хосту; одноразовый обход живёт в памяти 60 секунд и привязан к вкладке, режиму инкогнито, URL и хосту.
- URL не сохраняются на диск и не передаются наружу.

Текущая политика CA: `src/policy/protected-cas.json`. Текущий снимок CT: `src/policy/ct/yandex-nuc-log-list.json`.

## Установка: вариант 1 — GitHub Releases

Это основной сценарий самостоятельного распространения:

1. Откройте [Releases](https://github.com/ISAIandCO/CAnttRUst/releases).
2. Скачайте `canttrust-<версия>-firefox.xpi` и `SHA256SUMS.txt`.
3. Сверьте SHA-256 и откройте XPI в Firefox.

Обычный Firefox устанавливает постоянное расширение только после подписи Mozilla. Поэтому workflow `Release signed XPI` отправляет self-hosted сборку в AMO как **unlisted**, получает подписанный XPI и сразу создаёт GitHub Release. Вместе с ним публикуется `updates.json` с SHA-256 подписанного XPI. Установленная self-hosted версия получает дальнейшие релизы через штатное автообновление Firefox.

Администратору репозитория нужно один раз добавить GitHub Secrets `AMO_JWT_ISSUER` и `AMO_JWT_SECRET`, затем вручную запустить `.github/workflows/release-github.yml` на нужном коммите.

## Установка: вариант 2 — каталог AMO

Workflow `Publish to AMO` (`.github/workflows/publish-amo.yml`) оставлен отдельным и запускается вручную, когда проект будет готов к модерации магазина. Он собирает тот же исходный код без стороннего `update_url`, прикладывает исходный архив и отправляет listed-версию в AMO. Отказ или задержка модерации не влияет на GitHub Releases.

AMO требует уникальный номер для каждой listed/unlisted-загрузки. Перед будущей отправкой в магазин нужно увеличить одинаковую версию в `package.json` и `manifest.firefox.json`; повторно публиковать уже подписанную unlisted-версию как listed нельзя.

## Локальная разработка

Требуется Node.js 22.22.2 или новее.

```bash
npm ci
npm run build:firefox
npm run build:self-hosted
npm run package:firefox
```

Результаты:

- `dist/firefox/` — распакованное расширение для `about:debugging`;
- `artifacts/canttrust-<версия>-firefox.zip` — неподписанный пакет для проверки;
- подписанный `.xpi` создаётся только релизным workflow через Mozilla.

Основные проверки:

```bash
npm run typecheck
npm test
npm run verify:policy
npm run scan:bundle
npm run check:reproducible
```

Workflow `Monitor CT policy` ежедневно сверяет принятые российские логи с источником Yandex. При изменении он создаёт одно открытое GitHub Issue и прикладывает новый JSON с diff; доверие к новым логам автоматически не включается. Ручное обновление также требует просмотра diff:

```bash
node scripts/update-ct-policy.mjs
npm run verify:policy
```

## Ограничения

- Firefox может не вернуть полную цепочку или DER-сертификаты; до совпадения защищаемого CA ошибка обрабатывается fail-open, после совпадения — fail-closed с предупреждением.
- Проверяются только встроенные SCT в leaf-сертификате. TLS/OCSP SCT в версии 0.1.0 не используются.
- Расширение не заменяет штатную проверку TLS Firefox и не отменяет обычные ошибки сертификатов.
- Политика CT является снимком и требует сопровождаемого обновления при ротации логов.

Архитектура и границы доверия описаны в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), модель угроз — в [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), инструкция по проверкам — в [docs/TESTING.md](docs/TESTING.md). Политика приватности находится в [PRIVACY.md](PRIVACY.md).

Лицензия: GPL-3.0-only.
