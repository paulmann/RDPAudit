# План реализации: веб-интерфейс 1st-RDPMon (HTML/JS) на IIS для RDPAudit 2.0

Готов для передачи в новый диалог SagaAI как ТЗ. Основан на read-only анализе канона
`C:/1st_RdpMON/Service`  и HTML/JS-референса `C:/AutoClaw/RDP-Web`.
Файлы канона в рамках подготовки плана не изменялись.

## 1. Цель и область

Дать оператору RDPAudit постоянный веб-интерфейс в стиле 1st-RDPMon, раздаваемый IIS
на хосте службы и работающий поверх уже реализованного REST-слоя Backlog #3
(`src/RdpAudit.Service/RestApi`, Kestrel HTTPS, Bearer-аутентификация). В Configurator
появляется новая вкладка `Web Access` с:

- чекбоксами показа и управления;
- живым статусом: веб вверх/вниз, установлен ли IIS, параметры IIS-приложения;
- кнопками `Install IIS` и `Configure IIS`;
- открытием веб-интерфейса по URL.

Основной контур MVP — просмотр данных. Действия управления добавляются отдельной
фазой, так как текущий REST-слой Backlog #3 сознательно read-only.

## 2. Исходная база (подтверждено анализом)

### 2.1 REST-слой уже существует

- `Sources` в `src/RdpAudit.Service/RestApi`: `RestApiEndpoints`, `RestApiHostedService`,
  `RestApiPlanBuilder`, `RestApiSecurityHeaders`, `RestApiBearerAuth`, `RestApiRateLimit`,
  `RestApiProblem`, `RestApiHealthService`, `RestApiOpenApiDocument`.
- Эндпоинты GET/HEAD: `/healthz`, `/api/status`, `/api/alerts`, `/api/sessions`,
  `/api/config`, `/api/events`, `/openapi/v1.json`.
- Чтение данных идёт через `IpcDispatcher`, используя существующие `IpcCommand`
  (`GetStatus=1`, `GetRecentAlerts=3`, `GetSessions=5`, `GetSettings=9` и др.) и
  `IPagedEventReader`/`ReadPageAsync`.
- `ApiOptions` (`src/RdpAudit.Core/Config/ApiOptions.cs`): `Enabled=false` по умолчанию,
  `Token` (DPAPI), `ListenAddress=127.0.0.1`, `Port=8443`, `Thumbprint`/`Subject`,
  `AllowInsecureLoopback`, `MaxConnections`, `RateLimitPerMinute`; резолвится с клампами.
- `IpcCommand` — append-only enum (`src/RdpAudit.Core/Ipc/IpcCommand.cs`), заняты
  ординалы 0..70 (`GetAlertsForIp=70` в финале Stage SIEM), свободны 71+.
- `ServiceStatus` (`src/RdpAudit.Core/Ipc/ServiceStatus.cs`) НЕ содержит полей web/IIS;
  расширяется в рамках задачи.
- Статики и NTLM/Kestrel UI не раздаются; UI отсутствует.

### 2.2 Референс 1st-RDPMon

- Версия 3.2.0, MIT, генерирует статический отчёт: `TEMPLATE_VARS` (GENERATION_TIME,
  TOTAL_RECORDS, AUTO_REFRESH_INTERVAL, DATABASE_PATH, REPORT_ID) встраиваются в HTML,
  а `DATA_JSON` разбирается через `parsePowerShellJSON` внутри
  `assets/js/1st_rdpmon-app.js`.
- Наборы данных: `AddrData[]`, `SessionData[]`, `PropData[]`, `DatabaseStats`,
  `EnhancedData.ChartData`.
- `fetch`/XHR отсутствуют, REST не используется; автообновление трогает только часы.
- Кнопки block/copy/AbuseIPDB/WHOIS — клиентские действия без вызова REST.
- Вывод: сохраняем визуальную оболочку и заменяем источник данных на адаптер `fetch`
  под REST-канон; action-кнопки в MVP скрываем или оставляем только безопасные
  локальные действия (copy), чтобы в UI не было бездействующих элементов.

### 2.3 Паттерны Configurator

- `MainForm.BuildOrderedPages()` + публичный `OrderedPageTitles` — фиксированный
  порядок 17 вкладок, `Settings` всегда последняя; тест
  `tests/RdpAudit.Configurator.Tests/MainFormTabOrderTests.cs`.
- Страница — `TabPage` + `IpcClient.SendDetailedAsync<T>(IpcCommand...)` + `StatusStrip` +
  `SetControlsEnabled`/`SetStatus` (пример `EventCollectionPage.cs`,
  `DataGridViewCheckBoxColumn` для чекбоксов).
- `SettingsPage` сохраняет настройки через `IpcCommand.SaveSettings` сырым JSON.
- Привилегированные операции: `Configuration/Services/InstallationService.cs` —
  `ElevationGuard.Check()`, `sc.exe` через `ProcessStartInfo` (ArgumentList, без
  shell), исход `InstallationOutcome` со `Steps/Warnings/Errors`; открытие URL —
  `Process.Start(new ProcessStartInfo(url) )` в `OverviewPage`.
- Имеющиеся REST-тесты (`tests/RdpAudit.Service.Tests`): `RestApiIntegrationTests`,
  `RestApiScenarioTests`, `RestApiBearerAuthTests`, `RestApiRateLimitTests`,
  `ApiOptionsTests`, `ApiTokenResolverTests` — это готовые образцы для новых тестов.

## 3. Целевая архитектура (рекомендуемая)

IIS раздаёт статический HTML/JS через тонкий ASP.NET Core host-proxy
`RdpAudit.Web`, который:

- обслуживает `wwwroot` (адаптированный 1st-RDPMon);
- маршрутизирует `/api/*` → `https://127.0.0.1:8443` (Kestrel службы) через YARP;
- сам подставляет заголовок `Authorization: Bearer <token>` из общего хранилища
  секретов, поэтому токен НЕ попадает в браузер;
- работает в IIS (AspNetCoreModuleV2, InProcess), не поднимая второй Kestrel.

Схема:

```
Браузер (оператор)
   | HTTPS :443 (или HTTP :8080 в тестовом режиме)
   v
IIS site RdpAudit (Windows Authentication опционально)
   |
   v
RdpAudit.Web (статика wwwroot + YARP /api Proxy)
   | 127.0.0.1:8443 + Bearer из DPAPI-хранилища
   v
RdpAudit.Service (Kestrel REST Backlog #3, IpcDispatcher)
```

Альтернатива (для сред, где новый host-процесс нежелателен): чистые статические
файлы + модули IIS URL Rewrite + ARR. Она требует установки ARR, а токен приходится
хранить в конфигурации правила — безопаснее считать её запасным вариантом.

## 4. Ключевые проектные решения

1. **REST остаётся loopback-first.** Kestrel слушает `127.0.0.1:8443`; наружу ходит
   только IIS. `ApiOptions.Enabled=true` включается только при включении веб-интерфейса.
2. **Общий токен-хранилище через machine-scope DPAPI.** Токен Web-прокси хранится в
   `C:/ProgramData/RdpAudit/WebUI/secrets/token.dat` с ACL для Administrators,
   SYSTEM и пула приложения. Существующий `ApiTokenResolver` расширяется вторичным
   источником, либо токен службы переводится на machine-scope. Не хранить токен в
   исходниках/web.config/HTML.
3. **Прокси вместо прямого доступа браузера к Kestrel.** Токен не покидает хост;
   CORS не нужен; внешний порт один; возможен Windows Authentication на IIS.
4. **Весь UI-рендеринг — DOM API/textContent.** IP-адреса и строки из БД не
   вставляются через `innerHTML`; защита от HTML-инъекций из данных событий.
5. **«Управление» — отдельный флажок и отдельная фаза.** Пока канон REST read-only,
   чекбокс управления виден, но заблокирован с пояснением; разблокируется только
   после появления write-эндпоинтов (Phase 4).
6. **IIS provisioning идемпотентен и неинтерактивен.** Повторный запуск кнопок не
   ломает существующую конфигурацию; результаты показываются списком шагов как в
   `InstallationOutcome`.

## 5. REST-контракт и маппинг под старый 1st-RDPMon

| Данные 1st-RDPMon | Источник REST | Статус |
| --- | --- | --- |
| GENERATION_TIME / DatabaseStats | `/api/status` | уже есть |
| SessionData[] | `/api/sessions` | уже есть |
| Последние алерты | `/api/alerts` | уже есть |
| PropData[] (свойства установки) | `/api/config` с фильтрацией секретов | уже есть, требует безопасной проекции |
| AddrData[] (агрегат по IP) | новый read-only `/api/addresses` | добавить в Phase 1 |
| EnhancedData.ChartData | новый read-only `/api/attacks` (или агрегат из `/api/events`) | добавить в Phase 1 по выбору |
| Автообновление | периодический `fetch` тех же GET | клиентская логика |

Новые эндпоинты — строго GET/HEAD, используют существующие `IpcCommand.GetAddresses`/
`GetOverviewSummary`/`GetAttackStats` и не меняют ординалы 0..70. Swagger
`/openapi/v1.json` обновляется автоматически.

## 6. Пошаговый план реализации (для нового диалога SagaAI)

### Step 1 — Включить и проверить REST-слой
- Изменить `ApiOptions.Enabled=false` → включаемо через конфигурацию; сохранить
  fail-closed по умолчанию. Задокументировать токен и TLS-настройки.
- verification: интеграционный тест `/healthz` и `/api/status` с Bearer; существующие
  `RestApi*Tests` зелёные.

### Step 2 — DPAPI token vault для Web-прокси
- Новый `TokenVault` в `RdpAudit.Core.Security` или расширение `ApiTokenResolver`:
  machine-scope DPAPI, ACL, ротация токена. Написать тесты с `ProtectedData` под
  Windows-only.
- verification: юнит-тесты encrypt/decrypt, отказ при неверном ACL/повреждении файла.

### Step 3 — Новые read-only эндпоинты `/api/addresses` (и при необходимости `/api/attacks`)
- Добавить в `RestApiEndpoints.cs` маршруты, использующие существующие IPC-обработчики.
- verification: `RestApiIntegrationTests`/`RestApiScenarioTests` на каждый эндпоинт +
  скан-тест OpenAPI (`RestOpenApiDriftScenarioTests`).

### Step 4 — Проект `RdpAudit.Web`
- Новый проект `src/RdpAudit.Web/` (ASP.NET Core, InProcess под IIS):
  - `wwwroot/index.html` и `assets/js/app.js`, `assets/css` на базе референса;
  - YARP-прокси `/api` на `https://127.0.0.1:8443`;
  - загрузка токена из vault, добавление Bearer-заголовка;
  - healthz-редирект для статуса.
- verification: интеграционный тест с `TestServer` и фейковым бэкендом — заголовок
  подставлен, статика отдаётся, ошибки бэкенда транслируются корректно.

### Step 5 — Адаптация HTML/JS под REST
- Заменить `parsePowerShellJSON` на `fetch('/api/status')` + `/api/sessions` и др.;
  полиинг с backoff; действие copy остаётся, бесполезные action-кнопки скрываются.
  Рендеринг только через DOM API/textContent.
- verification: JS-юнит/смоук на статическом harness; ручной прогон локально.

### Step 6 — Публикация WebUI в заданную папку
- `ProgramData/RdpAudit/WebUI` (или подпапка Program Files) + ACL. `publish.ps1`
  копирует вывод `RdpAudit.Web` рядом с дистрибутивом службы.
- verification: тест копирования с SHA-256, права доступа для пула приложения.

### Step 7 — Сервисы Configurator для IIS
- Новые классы в `src/RdpAudit.Configurator/Services/`:
  `IisFeatureDetector`, `IisFeatureInstaller` (dism/
  `Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -All -NoRestart`),
  `IisSiteManager` (Microsoft.Web.Administration: site `RdpAudit`, app pool
  `RdpAuditWebUi`, binding, ACL, ASP.NET Core module), `WebHealthProbe` (HttpClient
  к `/healthz`), `WebUiPublishService`. Все повторяют паттерн `InstallationResult` и
  `ElevationGuard.Check()`.
- verification: юнит-тесты с заглушками DISM, winget и детектора модуля (ServerManager-ветка
  удалена вместе с зависимостью от Windows PowerShell, заглушать её больше нечего); отсутствие побочных
  эффектов на машине без прав.

### Step 8 — Вкладка `Web Access`
- Новый `src/RdpAudit.Configurator/Forms/WebAccessPage.cs` (`TabPage`):
  - GroupBox «Web UI»: checkbox `Show Web UI` (показ), checkbox `Allow remote
    management via Web` (управление; заблокирован до Phase 4), checkbox
    `Expose on LAN` (внешний binding; по умолчанию off), кнопка `Open Web UI`.
  - Панель статуса: URL + Up/Down через `WebHealthProbe`; блок IIS: установлен ли
    компонент; параметры приложения: site name, app pool, physical path, binding,
    target REST URL, состояние сайта/пула; кнопки `Refresh`.
  - Кнопки `Install IIS` и `Configure IIS` с прогресс-списком, подтверждением и
    индикацией перезагрузки при необходимости.
- verification: тесты состояния чекбоксов/заглушенного здоровья; кнопки блокируются
  при занятости и выдают осмысленные статусы.

### Step 9 — Интеграция вкладки в MainForm
- Вставить `WebAccessPage` в `BuildOrderedPages()` перед `SettingsPage` и в
  `OrderedPageTitles`; обновить `MainFormTabOrderTests`.
- verification: тест порядка; проверка контракта доступности кнопок (цвет следует за `Enabled`:
  доступна — зелёная, недоступна — тёмно-красная), а не только визуальный осмотр темизации.

### Step 10 — Install IIS workflow
- Кнопка `Install IIS` исполняет единый план `IisInstallPlan` — тот же список, который окно
  прогресса (`IisInstallProgressDialog`) показывает до запуска, с галочкой или крестиком по
  каждому пункту. Порядок: elevation → статические функции IIS через
  `dism /Online /Enable-Feature /NoRestart` → средства управления IIS, дающие `appcmd.exe` для
  шага Configure IIS → ASP.NET Core Hosting Bundle
  (`winget install --id Microsoft.DotNet.HostingBundle.8 --exact --silent`) как единственный
  источник нативного `AspNetCoreModuleV2` → проверка фактического результата.
- Идемпотентность: уже установленный Hosting Bundle распознаётся по файлу модуля, и winget в этом
  случае не вызывается; повторный запуск не создаёт дублей.
- Exit code 3010 (успех + требуется перезагрузка) даёт предупреждение, а не успех; неподтверждённый
  пункт тоже сообщается как warning, чтобы оператор знал, что именно нужно проверить.
- verification: автотесты построения команд и состава плана; ручной сценарный прогон на чистом VM.

### Step 11 — Configure IIS workflow
- Кнопка `Configure IIS` создаёт/обновляет site/app pool, копирует статику,
  настраивает binding и Windows Authentication; при отсутствии HTTPS-сертификата
  предлагает dev-режим HTTP или генерацию self-signed (с явным предупреждением).
- verification: автотест идемпотентности; сценарный тест install→configure→open.

### Step 12 — Безопасность и hardening
- Kestrel остаётся loopback; firewall-порт наружу открывается только при явном
  включении `Expose on LAN`; токен не логируется; rate limit остаётся; проверка
  отсутствия CORS и прямого доступа к Kestrel извне.
- verification: adversarial self-review + тест попытки доступа без Bearer/с чужим
  доменом.

### Step 13 — Документация
- Обновить SPEC (раздел веб-доступа), ARCHITECTURE (схема IIS/proxy), README
  (инструкция оператора), документацию REST (`docs/51-rest-api.md`), создать/обновить
  PROJECT_MAP.md.
- verification: git diff, вычитка, отсутствие устаревших утверждений.

### Step 14 — Финальная проверка и acceptance
- Полный тестовый прогон канона (все таргетные сьюты) + сценарные тесты. Проверить,
  что в диалоге не осталось временных файлов вне `scratch`.
- verification: acceptance checklist ниже.

## 7. Acceptance criteria

- `/openapi/v1.json` корректен после добавления эндпоинтов, дрейф-тест зелёный.
- Вкладка `Web Access` появляется перед `Settings`, порядок вкладок не меняется.
- Статус показывает: web up/down (URL/healthz), IIS installed/absent,
  параметры сайта/пула даже до конфигурации (с пояснением отсутствия).
- `Install IIS` работает под UAC и идемпотентно; `Configure IIS` создаёт рабочий site
  и рабочий URL без ручных действий по токену.
- В браузере после открытия URL видны актуальные данные службы; F5 обновляет данные;
  IP-строки не вставляются как HTML.
- Токен не виден в браузере, логах и web.config и не уходит за пределы хоста.
- Все существующие тесты канона проходят; ключевые изменения покрыты юнит-
  and интеграционными тестами.

## 8. Риски и как их закрываем

- **Home/недоступный IIS.** Home-редакции не поддерживают IIS-WebServer: кнопка
  отключается с объяснением, вместо неё предлагается локальный вариант запуска
  только через Kestrel (не MVP).
- **Разделение секрета.** DPAPI machine-scope решает доступ для пула приложения;
  тесты на Windows обязательны.
- **Read-only REST против чекбокса управления.** Чекбокс явно сообщает про отсутствие
  write-эндпоинтов и указывает на Phase 4.
- **Порт/сертификат.** Dev-режим через HTTP :8080, production через HTTPS с
  существующим или self-signed сертификатом и предупреждением.
- **Перезагрузка после DISM.** Отображаем состояние и сохраняем прогресс; выводим
  точную подсказку после перезапуска.
- **Регрессии тестов канона.** Перед каждым изменениям REST/IpcCommand — полная
  регрессия; ординалы 0..70 не трогаем.

## 9. Запрос для нового диалога (сформулирован после утверждения плана)

«Реализуй утверждённый план `Plan_WebUI_1st-RDPMon_IIS_RdpAudit.md`: добавь в
RDPAudit IIS-раздаваемый HTML/JS-интерфейс 1st-RDPMon поверх REST Backlog #3 и
вкладку Configurator `Web Access` с чекбоксами показа/управления, статусом
веб/IIS и кнопками Install IIS и Configure IIS. Канон — `C:/1st_RdpMON/Service`,
референс HTML — `C:/AutoClaw/RDP-Web`. Соблюдай append-only ABI IpcCommand,
security-модель из плана и покрывай изменения тестами.»

---