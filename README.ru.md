# RDPAudit — Windows RDP Security Monitoring & Auto-Block Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/paulmann/RDPAudit)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

> **RDPAudit** — это production-ready платформа мониторинга и реагирования на RDP-угрозы для Windows.  
> Состоит из **Windows Service** (фоновый сборщик событий + 21 правило тревог + автоблокировка) и **WinForms Configurator** (GUI для управления, просмотра статистики и настройки).

---

## Оглавление

- [1. Обзор продукта](#1-обзор-продукта)
  - [1.1. Назначение](#11-назначение)
  - [1.2. Архитектура решения](#12-архитектура-решения)
  - [1.3. Ключевые возможности](#13-ключевые-возможности)
- [2. Системные требования](#2-системные-требования)
  - [2.1. Минимальные требования](#21-минимальные-требования)
  - [2.2. Требования к аудиту Windows](#22-требования-к-аудиту-windows)
- [3. Структура решения](#3-структура-решения)
  - [3.1. Проекты и слои](#31-проекты-и-слои)
  - [3.2. Дерево директорий](#32-дерево-директорий)
- [4. Быстрый старт](#4-быстрый-старт)
  - [4.1. Сборка](#41-сборка)
  - [4.2. Установка сервиса](#42-установка-сервиса)
  - [4.3. Первый запуск Configurator](#43-первый-запуск-configurator)
- [5. RdpAudit.Service — Служба мониторинга](#5-rdpauditservice--служба-мониторинга)
  - [5.1. Сбор событий](#51-сбор-событий)
  - [5.2. Отслеживаемые Event ID](#52-отслеживаемые-event-id)
  - [5.3. Хранилище данных (SQLite)](#53-хранилище-данных-sqlite)
  - [5.4. Система тревог — 21 правило](#54-система-тревог--21-правило)
  - [5.5. Автоблокировка Windows Firewall](#55-автоблокировка-windows-firewall)
  - [5.6. IPC через Named Pipe](#56-ipc-через-named-pipe)
  - [5.7. Надёжность и устойчивость](#57-надёжность-и-устойчивость)
- [6. RdpAudit.Configurator — GUI](#6-rdpauditconfigurator--gui)
  - [6.1. Вкладка Overview](#61-вкладка-overview)
  - [6.2. Вкладка Prerequisites](#62-вкладка-prerequisites)
  - [6.3. Вкладка Audit Policy](#63-вкладка-audit-policy)
  - [6.4. Вкладка Service](#64-вкладка-service)
  - [6.5. Вкладка Settings](#65-вкладка-settings)
  - [6.6. Вкладка Live Events](#66-вкладка-live-events)
  - [6.7. Вкладка Firewall](#67-вкладка-firewall)
  - [6.8. Вкладка Attack Statistics](#68-вкладка-attack-statistics)
  - [6.9. Вкладка Remote RDP Clients](#69-вкладка-remote-rdp-clients)
  - [6.10. Вкладка AbuseIPDB](#610-вкладка-abuseipdb)
  - [6.11. Вкладка MikroTik](#611-вкладка-mikrotik)
  - [6.12. Вкладка Logs](#612-вкладка-logs)
  - [6.13. Вкладка Diagnostics](#613-вкладка-diagnostics)
- [7. RdpAudit.Core — Общая библиотека](#7-rdpauditcore--общая-библиотека)
  - [7.1. Модели данных](#71-модели-данных)
  - [7.2. Entity Framework Core & Миграции](#72-entity-framework-core--миграции)
  - [7.3. IPC-контракты (MessagePack)](#73-ipc-контракты-messagepack)
- [8. Интеграции с внешними системами](#8-интеграции-с-внешними-системами)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. Механизм автоблокировки](#9-механизм-автоблокировки)
  - [9.1. Порог срабатывания](#91-порог-срабатывания)
  - [9.2. Windows Firewall (локальный)](#92-windows-firewall-локальный)
  - [9.3. MikroTik Firewall (удалённый)](#93-mikrotik-firewall-удалённый)
  - [9.4. Whitelist — защита доверенных IP](#94-whitelist--защита-доверенных-ip)
- [10. Обслуживание данных](#10-обслуживание-данных)
  - [10.1. Политика хранения (Retention Pruning)](#101-политика-хранения-retention-pruning)
  - [10.2. Резервное копирование и восстановление](#102-резервное-копирование-и-восстановление)
- [11. Безопасность и аудит](#11-безопасность-и-аудит)
  - [11.1. Разграничение прав](#111-разграничение-прав)
  - [11.2. SACL-конфигурация](#112-sacl-конфигурация)
  - [11.3. Защита секретов (DPAPI)](#113-защита-секретов-dpapi)
- [12. Конфигурация](#12-конфигурация)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. Переменные окружения](#122-переменные-окружения)
- [13. Отладка и диагностика](#13-отладка-и-диагностика)
  - [13.1. Консольный режим](#131-консольный-режим)
  - [13.2. Логи Serilog](#132-логи-serilog)
  - [13.3. SQLite-база напрямую](#133-sqlite-база-напрямую)
  - [13.4. Вкладка Diagnostics](#134-вкладка-diagnostics)
- [14. Сборка и тестирование](#14-сборка-и-тестирование)
  - [14.1. Сборка](#141-сборка)
  - [14.2. Тесты](#142-тесты)
  - [14.3. Publish](#143-publish)
- [15. Устранение неисправностей](#15-устранение-неисправностей)
- [16. Дорожная карта (v2.0 → v3.0)](#16-дорожная-карта-v20--v30)
- [17. Лицензия и автор](#17-лицензия-и-автор)

---

## 1. Обзор продукта

### 1.1. Назначение

**RDPAudit** решает задачу непрерывного мониторинга RDP-активности на Windows-серверах и рабочих станциях. Продукт работает в фоне как системная служба — даже при отсутствии залогиненных пользователей — записывает все попытки подключения, аутентификации и изменения системы, оценивает угрозы по 21 правилу и автоматически блокирует атакующих через Windows Firewall и/или MikroTik RouterOS.

**Типичные сценарии применения:**
- Защита RDP-портов, открытых в Интернет, от брутфорс-атак
- Аудит соответствия требованиям SOC2 / ISO 27001 по доступу к серверам
- Обнаружение компрометации учётных записей (успешный вход после серии неудач)
- Выявление backdoor через accessibility binaries (Sticky Keys, Utilman)
- Обнаружение атак на LSA/LSASS, Kerberos spraying, изменения RDP-порта
- Интеграция с MikroTik: единый blocklist на уровне пограничного маршрутизатора

### 1.2. Архитектура решения

```
┌──────────────────────────────────────────────────────────────────┐
│                     Windows Event Log                            │
│  Security │ TerminalServices-RemoteConnectionManager │ LocalSession│
└───────────────────────────┬──────────────────────────────────────┘
                            │  EventLogWatcher
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│               RdpAudit.Service  (Windows Service)                │
│                                                                  │
│  EventCollectorWorker ──► EventNormalizerWorker                  │
│                                   │                             │
│                                   ▼                             │
│                         AlertEvaluatorWorker ──► 21 Alert Rules  │
│                                   │                             │
│                                   ▼                             │
│                         FirewallAutoBlockWorker                  │
│                         (Windows FW + MikroTik REST)             │
│                                   │                             │
│                                   ▼                             │
│                    SQLite  (WAL, %ProgramData%\RdpAudit)         │
│                                   │                             │
│                         Named Pipe IPC Server                    │
└───────────────────────────────────┬──────────────────────────────┘
                                    │  MessagePack over NamedPipe
                                    ▼
┌──────────────────────────────────────────────────────────────────┐
│              RdpAudit.Configurator  (WinForms GUI)               │
│                                                                  │
│  Overview │ Prerequisites │ AuditPolicy │ Service │ Settings     │
│  LiveEvents │ Firewall │ AttackStatistics │ RemoteRdpClients     │
│  AbuseIPDB │ MikroTik │ Logs │ Diagnostics                       │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3. Ключевые возможности

- **Мониторинг в реальном времени** — `EventLogWatcher` подписывается на события без опроса
- **21 правило обнаружения угроз** — от брутфорса до LSASS-атак и Kerberos Spraying
- **Автоблокировка** — per-IP правила Windows Firewall, идемпотентные, с возможностью ручной отмены
- **Интеграция MikroTik** — управление address-list через RouterOS v7 REST API с DPAPI-шифрованием учётных данных
- **Репортинг в AbuseIPDB** — автоматическая отправка данных об атакующих IP с локальной дедупликацией
- **Статистика угроз** — агрегация по IP, стране, временным интервалам, уровню угрозы
- **Корреляция сессий и IP** — связывание RDP-сессий с источниковыми IP-адресами
- **Retention Pruning** — автоматическая очистка устаревших данных с защитой от SQLITE_BUSY
- **Backup/Restore** — снапшоты конфигурации с DPAPI-конвертами (без plaintext-секретов)
- **Named Pipe IPC** — защищённый канал между сервисом и GUI, только для BUILTIN\Administrators

---

## 2. Системные требования

### 2.1. Минимальные требования

| Компонент | Требование |
|-----------|-----------|
| ОС | Windows 10 / Windows Server 2016 или новее (x64) |
| .NET Runtime | .NET 8.0 (Windows, x64) |
| Права | Локальный администратор для установки службы |
| Диск | 200 МБ для бинарников + место для БД (растёт ~1 МБ/1000 событий) |
| ОЗУ | 64 МБ для службы в рабочем режиме |

### 2.2. Требования к аудиту Windows

RDPAudit использует Windows Security Audit для получения событий. Для корректной работы необходимы:

| Категория аудита | GUID подкатегории | Зачем |
|-----------------|-------------------|-------|
| Logon / Logoff | `{0CCE9215-69AE-11D9-BED3-505054503030}` | Events 4624, 4625, 4634 |
| Account Logon | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Kerberos events |
| Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | Event 4688 (LSASS access) |
| Object Access | `{0CCE9217-69AE-11D9-BED3-505054503030}` | SACL events 4656, 4663 |
| Policy Change | `{0CCE922F-69AE-11D9-BED3-505054503030}` | Event 4954 (FW rule change) |

Configurator настраивает политику аудита автоматически через `auditpol.exe` с GUID-идентификаторами (locale-independent).

---

## 3. Структура решения

### 3.1. Проекты и слои

| Проект | Тип | Назначение |
|--------|-----|-----------|
| `RdpAudit.Core` | Class Library (net8.0-windows) | Сущности, EF Core DbContext, миграции, IPC-контракты (MessagePack), общие утилиты |
| `RdpAudit.Service` | Worker Service (net8.0-windows, win-x64) | Сборщик событий, нормализатор, движок тревог, автоблокировка, IPC-сервер |
| `RdpAudit.Configurator` | WinForms App (net8.0-windows) | GUI: все вкладки, IPC-клиент, prerequisite-проверки, управление сервисом |
| `RdpAudit.Core.Tests` | xUnit | Юнит-тесты моделей и утилит |
| `RdpAudit.Service.Tests` | xUnit | Юнит-тесты правил тревог (threshold + whitelist + zero-alloc) |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | Бенчмарки горячих путей |

### 3.2. Дерево директорий

```
RdpAudit.sln
├── src/
│   ├── RdpAudit.Core/
│   │   ├── Models/              — 28 сущностей и перечислений
│   │   ├── Data/                — AppDbContext, EF Core миграции
│   │   ├── IPC/                 — MessagePack-контракты запросов/ответов
│   │   └── Services/            — Общие сервисы (geo, scoring, formatting)
│   ├── RdpAudit.Service/
│   │   ├── Workers/             — BackgroundService-воркеры
│   │   ├── Alerts/              — 21 правило тревог
│   │   ├── Firewall/            — Провайдеры Windows FW и MikroTik
│   │   ├── Collectors/          — EventLogWatcher-обёртки
│   │   └── Program.cs           — DI, Serilog, HostBuilder
│   └── RdpAudit.Configurator/
│       ├── Forms/               — 13 страниц (TabPage) GUI
│       ├── IPC/                 — Named Pipe клиент
│       └── Program.cs           — requireAdministrator, DPI-aware
├── tests/
│   ├── RdpAudit.Core.Tests/
│   ├── RdpAudit.Service.Tests/
│   └── RdpAudit.Benchmarks/
├── docs/
│   ├── 90-windows-validation.md
│   └── 91-troubleshooting.md
└── publish.ps1
```

---

## 4. Быстрый старт

### 4.1. Сборка

```powershell
# Требует .NET 8 SDK
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. Установка сервиса

```powershell
# Опубликовать бинарники
./publish.ps1

# Скопировать Service в Program Files
Copy-Item -Recurse publish/Service "$env:ProgramFiles\RdpAudit\Service"

# Установить как Windows Service (через Configurator или вручную)
sc.exe create RdpAudit binPath= "$env:ProgramFiles\RdpAudit\Service\RdpAudit.Service.exe" start= auto
sc.exe description RdpAudit "RDP Security Monitoring & Auto-Block Service"
sc.exe start RdpAudit
```

### 4.3. Первый запуск Configurator

```powershell
# Запустить от имени Администратора
publish/Configurator/RdpAudit.Configurator.exe
```

При первом запуске Configurator:
1. Вкладка **Prerequisites** — проверяет и при необходимости включает нужные каналы EventLog
2. Вкладка **Audit Policy** — применяет политику аудита через `auditpol.exe` с GUID (независимо от локали)
3. Вкладка **Service** — устанавливает, запускает и контролирует статус Windows Service
4. Вкладка **Settings** — настраивает пороги тревог, whitelist IP, параметры интеграций

---

## 5. RdpAudit.Service — Служба мониторинга

### 5.1. Сбор событий

Служба использует `System.Diagnostics.Eventing.Reader.EventLogWatcher` для подписки на события в режиме реального времени (push-модель, без опроса). Абстракция `IEventSource` позволяет заменить реализацию на прямой ETW (`OpenTrace`/`ProcessTrace`) в v3.0 без изменения бизнес-логики.

**Отслеживаемые каналы:**
- `Security` — события входа, выхода, доступа к объектам, смены политик
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` — RDP-соединения (Event 1149)
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` — сессии (Events 21, 23, 24, 25)

### 5.2. Отслеживаемые Event ID

| Event ID | Канал | Описание |
|----------|-------|----------|
| 4624 | Security | Успешный вход (тип 10 = RemoteInteractive) |
| 4625 | Security | Неудачный вход |
| 4634 | Security | Выход из системы |
| 4647 | Security | Инициированный пользователем выход |
| 4648 | Security | Вход с явными учётными данными |
| 4688 | Security | Создание процесса (для LSASS access) |
| 4720 | Security | Создание учётной записи |
| 4723 / 4724 | Security | Изменение / сброс пароля |
| 4740 | Security | Блокировка учётной записи |
| 4769 | Security | Запрос Kerberos Service Ticket |
| 4771 | Security | Ошибка Kerberos Pre-auth |
| 4776 | Security | NTLM-аутентификация |
| 4954 | Security | Изменение правил Windows Firewall |
| 1149 | TerminalServices-RCM | RDP-подключение (с IP-адресом источника) |
| 21, 23, 24, 25 | TerminalServices-LSM | Начало, восстановление, отключение, завершение сессии |

### 5.3. Хранилище данных (SQLite)

База данных находится по адресу `%ProgramData%\RdpAudit\rdpaudit.db`.

**Настройки SQLite:**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**Ключевые таблицы:**

| Таблица | Назначение |
|---------|-----------|
| `RawEvents` | Все нормализованные события (EventId, TimeUtc, SourceIp, UserId, Payload) |
| `RdpConnectionFacts` | Факты RDP-подключений с IP, пользователем, статусом |
| `AuthAttemptFacts` | Факты попыток аутентификации (успех/неудача) |
| `Sessions` | RDP-сессии с временными метками и статусом |
| `SessionIpCorrelations` | Связь Session ID → Source IP |
| `AttackStats` | Агрегированная статистика атак по IP |
| `ActiveBlocks` | Активные автоблокировки (IP, причина, время, провайдер) |
| `Alerts` | Сработавшие тревоги (RuleId, Severity, Details) |
| `WhitelistEntries` | Доверенные IP/CIDR, исключённые из автоблокировки |
| `BlocklistEntries` | Постоянные правила блокировки и их источники |
| `AbuseIpDbReportHistory` | История репортов в AbuseIPDB (дедупликация) |
| `OperationLogs` | Лог операций сервиса (для вкладки Logs в GUI) |
| `DbProps` | Хранилище ключ-значение для метаданных БД |
| `Bookmarks` | Закладки прогресса обработки событий (crash recovery) |
| `LoginRules` | Правила ограничения входа по времени суток / дням |

**Пакетная запись:** служба использует `SqliteCommand` с явной транзакцией, батчи по 1000+ строк за один `COMMIT`.

**Bookmark-устойчивость:** позиция обработки сохраняется каждые 100 событий И каждые 30 секунд — не более 99 событий теряется при сбое.

### 5.4. Система тревог — 21 правило

Все правила реализуют интерфейс `AlertRuleBase` и оцениваются в `AlertEvaluatorWorker`.

| # | RuleId | Severity | Описание |
|---|--------|----------|----------|
| 1 | `BRUTE_FORCE` | High | Превышение порога неудачных входов с одного IP |
| 2 | `BRUTE_FORCE_NTLM` | High | NTLM brute-force с cooldown для предотвращения alert flood |
| 3 | `KERBEROS_SPRAY` | High | Kerberos password spraying (Event 4771 / 4769) |
| 4 | `SUCCESSFUL_AFTER_FAILS` | Medium | Успешный вход после серии неудач — возможная компрометация |
| 5 | `OFF_HOURS_LOGIN` | Medium | Вход в нерабочее время (UTC, настраиваемое расписание) |
| 6 | `ACCOUNT_LOCKOUT` | Medium | Блокировка учётной записи (Event 4740) |
| 7 | `NEW_ACCOUNT_CREATED` | Medium | Создание нового аккаунта (Event 4720) |
| 8 | `PASSWORD_RESET` | Low | Смена/сброс пароля (Events 4723, 4724) |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | High | Перебор имён пользователей с одного IP |
| 10 | `STICKY_KEYS_BACKDOOR` | Critical | Запуск cmd.exe/powershell вместо sethc.exe/utilman (Event 4688 + IFEO) |
| 11 | `LSASS_ACCESS` | Critical | Доступ к LSASS с подозрительной маской доступа (Event 4656, bitwise) |
| 12 | `LSASS_PPL_TAMPER` | Critical | Попытка отключить PPL-защиту LSASS (реестр LSA) |
| 13 | `RDP_PORT_CHANGED` | High | Изменение порта RDP (реестр `TerminalServer-TCP`) |
| 14 | `FIREWALL_RULE_CHANGED` | Medium | Изменение правил Windows Firewall (Event 4954) |
| 15 | `EXPLICIT_CREDENTIALS` | Medium | Вход с явными учётными данными (Event 4648, runas-pattern) |
| 16 | `LOGON_TYPE_NETWORK` | Low | Сетевой вход на защищённый ресурс |
| 17 | `CONCURRENT_SESSIONS` | Low | Превышение допустимого числа одновременных сессий |
| 18 | `GEO_ANOMALY` | Medium | Вход из страны, не включённой в allow-list |
| 19 | `IP_REPUTATION` | High | IP попал в публичные blocklist (загружаемые через `BlocklistSource`) |
| 20 | `SESSION_HIJACK_SUSPECT` | High | Несоответствие Session ID и IP-адреса источника |
| 21 | `RAPID_RECONNECT` | Medium | Подозрительно частые переподключения с одного IP |

### 5.5. Автоблокировка Windows Firewall

При срабатывании правил `BRUTE_FORCE`, `BRUTE_FORCE_NTLM`, `IP_REPUTATION` и настраиваемого порога:

```powershell
# Служба вызывает эквивалент (через netsh / Windows Firewall COM API):
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

Реализация:
- **Идемпотентна** — повторное добавление для уже заблокированного IP не создаёт дублей
- **Санитизирует аргументы** — IP-адрес проверяется до передачи в shell
- **Reversible** — блокировка снимается из вкладки Firewall или по истечению TTL
- **Журналируется** — все операции блокировки записываются в `ActiveBlocks` и `OperationLogs`

### 5.6. IPC через Named Pipe

Канал: `\\.\pipe\RdpAuditService`

ACL: только `BUILTIN\Administrators` (устанавливается через `PipeAccessRule`).

Протокол: MessagePack-сериализованные запросы/ответы (`IPC/` в `RdpAudit.Core`).

Жёсткий дедлайн на подключение: предотвращает зависание GUI при недоступности сервиса.

Атомарное сохранение настроек: GUI отправляет изменения через IPC — сервис применяет их как единую транзакцию, без прямого доступа GUI к файлам конфигурации.

### 5.7. Надёжность и устойчивость

- **Exponential backoff** при ошибках БД (`SQLITE_BUSY`)
- **CancellationToken** на всех async-путях, нет `.Result` и `.Wait()`
- **Graceful shutdown** — все воркеры корректно завершаются при `StopAsync`
- **EF Core Migrations** применяются при старте (не только `EnsureCreated`)
- **EventLog source** регистрируется при установке сервиса

---

## 6. RdpAudit.Configurator — GUI

Запускается с манифестом `requireAdministrator`, DPI-aware. Взаимодействует с сервисом исключительно через Named Pipe IPC.

### 6.1. Вкладка Overview

Сводная панель состояния: статус сервиса, число активных блокировок, последние тревоги, счётчик событий за сутки. Предоставляет быстрый доступ к запуску/остановке сервиса.

### 6.2. Вкладка Prerequisites

Автоматически проверяет условия, необходимые для работы сервиса:
- Включён ли канал `Security` EventLog
- Включены ли каналы TerminalServices (RCM и LSM)
- Включена ли политика аудита для нужных подкатегорий
- Установлена ли служба

Для каждого пункта отображается статус и кнопка «Fix» с немедленным применением.

### 6.3. Вкладка Audit Policy

Отображает текущее состояние политики аудита Windows, полученное через `auditpol.exe /get /category:*`. Применяет нужные подкатегории через `auditpol.exe` с **GUID** (работает на любой локали Windows).

Настраивает SACL для:
- Accessibility binaries (sethc.exe, utilman.exe, osk.exe) в IFEO
- Ключа реестра `TerminalServer-TCP` (RDP-порт)
- Ключей LSA (PPL-защита LSASS)

### 6.4. Вкладка Service

- Установка / удаление сервиса (`sc.exe create/delete`)
- Запуск / остановка / перезапуск
- Отображение текущего статуса и PID
- Настройка типа запуска (Automatic / Manual)

### 6.5. Вкладка Settings

Полная настройка параметров сервиса через IPC:
- Пороги тревог (количество неудачных входов, интервал подсчёта)
- Расписание «рабочих часов» для `OFF_HOURS_LOGIN`
- Период retention для каждого типа данных
- Настройки AbuseIPDB (API key, категории отчётов)
- Настройки MikroTik (адрес, учётные данные, TLS)
- Параметры геофильтрации

Изменения отправляются как атомарная транзакция через IPC — сервис применяет их без перезапуска.

### 6.6. Вкладка Live Events

Потоковый вывод событий в реальном времени (tail-режим). Раскраска по типу события:
- 🔴 Красный — неудачные входы, тревоги Critical/High
- 🟡 Жёлтый — предупреждения Medium
- 🟢 Зелёный — успешные входы, информационные события

Поддерживает фильтрацию по EventId и IP-адресу.

### 6.7. Вкладка Firewall

Отображает все активные правила блокировки (`ActiveBlocks`):
- IP-адрес, причина, дата блокировки, провайдер (Windows FW / MikroTik)
- Ручное добавление IP в blocklist
- Снятие блокировки с подтверждением (деструктивное действие — кнопка «No» по умолчанию)
- Импорт/экспорт blocklist

### 6.8. Вкладка Attack Statistics

Агрегированная статистика атак (`AttackStats`):
- Топ-N атакующих IP с числом попыток, уровнем угрозы (`AttackThreatLevel`), страной
- График активности по часам/дням
- Тепловая карта по странам
- Экспорт в CSV

Уровни угрозы (из `AttackThreatScoring`): `Low` → `Medium` → `High` → `Critical`, рассчитываются на основе числа попыток, разнообразия имён пользователей, времени активности и наличия в публичных blocklist.

### 6.9. Вкладка Remote RDP Clients

История подключений (`RdpConnectionFacts` + `SessionIpCorrelations`):
- Список уникальных IP с числом успешных и неудачных подключений
- Цветовая индикация: 🟢 зелёный — легитимные, 🔴 красный — высокоинтенсивные атаки, 🟡 жёлтый — низкоинтенсивные
- Детализация по IP: список сессий, имён пользователей, временных меток

### 6.10. Вкладка AbuseIPDB

Управление интеграцией с [AbuseIPDB](https://www.abuseipdb.com/):
- Настройка API-ключа (хранится с DPAPI-шифрованием)
- Ручная и автоматическая отправка репортов
- История отправленных репортов с дедупликацией
- Учёт rate-limit API (1000 репортов/сутки на бесплатном тарифе)
- Не отображает и не копирует API-ключ в plaintext в UI

### 6.11. Вкладка MikroTik

Управление интеграцией с MikroTik RouterOS v7:
- Настройка адреса, порта, учётных данных (DPAPI), TLS-проверки
- Просмотр текущего address-list на роутере
- Синхронизация blocklist: добавление/удаление записей через REST API
- Идемпотентное управление правилами (не создаёт дубли)
- Тест соединения с диагностическими сообщениями

### 6.12. Вкладка Logs

Просмотр журнала операций сервиса (`OperationLogs`) с фильтрацией по уровню серьёзности:
- `Info` — штатные операции
- `Warning` — некритичные аномалии
- `Error` — ошибки, требующие внимания
- `Critical` — критические инциденты безопасности

### 6.13. Вкладка Diagnostics

Инструменты диагностики для операторов:
- Статус компонентов сервиса (Workers, DB connection, IPC)
- Счётчики производительности (события в секунду, очередь воркеров)
- Размер и состояние БД SQLite
- Проверка связи с внешними сервисами (AbuseIPDB API, MikroTik REST)
- Экспорт диагностического дампа для поддержки

---

## 7. RdpAudit.Core — Общая библиотека

### 7.1. Модели данных

Основные сущности (все в `src/RdpAudit.Core/Models/`):

| Класс | Описание |
|-------|----------|
| `RdpConnectionFact` | Факт RDP-подключения: IP, пользователь, статус, время |
| `AuthAttemptFact` | Факт попытки аутентификации |
| `Session` | RDP-сессия: SessionId, StartTime, EndTime, статус |
| `SessionIpCorrelation` | Связь Session ↔ Source IP |
| `AttackStat` | Статистика атак по IP (счётчики, временные метки) |
| `AttackThreatLevel` | Перечисление уровней угрозы: Low/Medium/High/Critical |
| `AttackThreatScoring` | Алгоритм расчёта уровня угрозы |
| `AttackStatProjection` | DTO для отображения в GUI |
| `ActiveBlock` | Активная автоблокировка |
| `ActiveBlockStatus` | Перечисление статусов блокировки |
| `BlocklistEntry` | Запись в blocklist |
| `BlocklistSource` | Источник blocklist (builtin, AbuseIPDB, manual) |
| `WhitelistEntry` | Запись в whitelist (IP или CIDR) |
| `Alert` | Сработавшая тревога |
| `AlertSeverity` | Перечисление: Low/Medium/High/Critical |
| `AbuseReport` | Репорт, отправленный в AbuseIPDB |
| `AbuseIpDbReportHistory` | История репортов (дедупликация) |
| `RawEvent` | Нормализованное событие EventLog |
| `OperationLog` | Запись журнала операций сервиса |
| `LoginRule` | Правило ограничения входа (время, дни недели) |
| `Bookmark` | Закладка прогресса обработки событий |
| `DbProp` | Ключ-значение в таблице свойств БД |
| `Address` | IP-адрес с геолокацией |
| `UnresolvedIpReason` | Причина невозможности разрешить IP |

### 7.2. Entity Framework Core & Миграции

- EF Core 8 + `Microsoft.EntityFrameworkCore.Sqlite`
- `AppDbContext` настроен на SQLite с WAL
- Миграции применяются автоматически при старте сервиса (`context.Database.MigrateAsync()`)
- EF Core используется ТОЛЬКО для конфигурации, миграций и чтения в GUI
- Запись в горячем пути — только raw `SqliteCommand` с явными транзакциями

### 7.3. IPC-контракты (MessagePack)

Все запросы и ответы между Configurator и Service сериализованы через **MessagePack** (библиотека `MessagePack v2.5.301`). Контракты определены в `RdpAudit.Core/IPC/`:

- `GetStatusRequest` / `GetStatusResponse` — состояние сервиса
- `GetEventsRequest` / `GetEventsResponse` — потоковая выдача событий
- `GetFirewallBlocksRequest` / `GetFirewallBlocksResponse` — список блокировок
- `AddBlockRequest` / `AddBlockResponse` — добавление блокировки
- `RemoveBlockRequest` / `RemoveBlockResponse` — снятие блокировки
- `GetSettingsRequest` / `GetSettingsResponse` — чтение конфигурации
- `SaveSettingsRequest` / `SaveSettingsResponse` — атомарное сохранение конфигурации
- `GetAttackStatsRequest` / `GetAttackStatsResponse` — статистика атак
- `GetOperationLogsRequest` / `GetOperationLogsResponse` — журнал операций

---

## 8. Интеграции с внешними системами

### 8.1. AbuseIPDB

**Что делает:** автоматически репортит атакующие IP-адреса в базу данных [AbuseIPDB](https://www.abuseipdb.com/) при срабатывании правил брутфорса или высокого уровня угрозы.

**Реализация:**
- API-ключ хранится в `appsettings.json` в DPAPI-конверте, plaintext никогда не записывается
- Локальная дедупликация: таблица `AbuseIpDbReportHistory` предотвращает повторный репорт одного IP
- Учёт rate-limit: счётчик суточных репортов, при достижении лимита — backoff до следующих суток
- Категории репортов настраиваемые (18 = Brute-Force, 22 = Hacking по умолчанию)

### 8.2. MikroTik RouterOS v7

**Что делает:** при автоблокировке добавляет IP в address-list на MikroTik-роутере через RouterOS v7 REST API, что позволяет блокировать трафик на периметре до достижения Windows-сервера.

**Реализация:**
- REST API: `https://<router>/rest/ip/firewall/address-list`
- TLS-верификация настраиваема (можно отключить для self-signed сертификатов)
- Учётные данные шифруются DPAPI, хранятся в `appsettings.json`
- Идемпотентность: перед добавлением проверяет наличие записи
- Удаление записей при снятии блокировки через GUI
- При недоступности роутера — fallback на Windows Firewall, операция журналируется

---

## 9. Механизм автоблокировки

### 9.1. Порог срабатывания

По умолчанию:
- **10 неудачных входов** с одного IP за **10 минут** → автоблокировка
- Пороги настраиваются на вкладке **Settings**
- Блокировка не срабатывает для IP из **Whitelist**

### 9.2. Windows Firewall (локальный)

```
Провайдер: WindowsFirewallProvider
Действие:  Создать inbound-правило "RdpAudit_Block_<IP>" (block, any protocol)
Reversal:  Удалить правило по имени
Проверка:  netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. MikroTik Firewall (удалённый)

```
Провайдер: MikroTikFirewallProvider
Действие:  PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reversal:  DELETE /rest/ip/firewall/address-list/<id>
Проверка:  GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. Whitelist — защита доверенных IP

- Поддерживаются одиночные IP (`192.168.1.1`) и CIDR-диапазоны (`10.0.0.0/8`)
- Whitelist проверяется ДО применения любой блокировки
- Настраивается на вкладке **Settings** и хранится в таблице `WhitelistEntries`
- Хранит метку — кто и когда добавил запись

---

## 10. Обслуживание данных

### 10.1. Политика хранения (Retention Pruning)

`RetentionPrunerWorker` запускается по расписанию и удаляет устаревшие записи:

| Таблица | Retention по умолчанию | Настраиваемо |
|---------|----------------------|-------------|
| `RawEvents` | 90 дней | Да |
| `Alerts` | 180 дней | Да |
| `AbuseIpDbReportHistory` | 365 дней | Да |
| `ActiveBlocks` (неактивные) | 30 дней | Да |
| `AttackStats` | 365 дней | Да |

**Технические детали:**
- Удаление батчами (по 1000 строк) во избежание длительной блокировки WAL
- Экспоненциальный backoff при `SQLITE_BUSY`
- CancellationToken на всех операциях
- Операция журналируется в `OperationLogs`

### 10.2. Резервное копирование и восстановление

`BackupRestoreWorker` создаёт снапшоты конфигурации:

**В снапшот включается:**
- `appsettings.json` — только DPAPI-конверты, без plaintext секретов
- Экспорт политики аудита (`auditpol /backup`)
- Ключи реестра RdpAudit (IFEO, RDP-TCP, LSA, audit policy)
- Конфигурация сервиса (`sc.exe qc`)

**В снапшот НЕ включается:**
- База данных событий (`rdpaudit.db`) — только конфигурация

**Restore:** перед восстановлением автоматически создаётся pre-restore safety snapshot. Операция никогда не трогает базу данных событий.

---

## 11. Безопасность и аудит

### 11.1. Разграничение прав

| Компонент | Права |
|-----------|-------|
| `RdpAudit.Service` | SYSTEM или выделенный сервисный аккаунт |
| Named Pipe IPC | Только `BUILTIN\Administrators` |
| `RdpAudit.Configurator` | `requireAdministrator` (manifest) |
| SQLite DB | ACL: только SYSTEM + Administrators |
| `appsettings.json` | ACL: только SYSTEM + Administrators |

### 11.2. SACL-конфигурация

Configurator настраивает SACL (System Access Control Lists) для обнаружения попыток манипуляции:

- **IFEO accessibility keys** (`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`) — обнаружение Sticky Keys backdoor
- **`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`** — обнаружение смены RDP-порта
- **`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`** — обнаружение отключения PPL для LSASS

### 11.3. Защита секретов (DPAPI)

- Все API-ключи (AbuseIPDB) и учётные данные (MikroTik) шифруются **Windows DPAPI** (`ProtectedData.Protect`, scope: `LocalMachine`)
- В `appsettings.json` хранятся только Base64-encoded DPAPI-конверты
- GUI никогда не отображает и не копирует секреты в plaintext
- Backup включает только DPAPI-конверты — при восстановлении на другой машине секреты потребуют повторного ввода

---

## 12. Конфигурация

### 12.1. appsettings.json

```jsonc
{
  "RdpAudit": {
    "DatabasePath": "%ProgramData%\\RdpAudit\\rdpaudit.db",
    "EnabledEventIds": [4624, 4625, 4634, 4648, 4688, 4720, 4723, 4724, 4740, 4769, 4771, 4776, 4954, 1149, 21, 23, 24, 25],
    "AlertRules": {
      "BruteForce": {
        "IsEnabled": true,
        "FailThreshold": 10,
        "WindowSeconds": 600
      },
      "OffHoursLogin": {
        "IsEnabled": true,
        "WorkHoursStart": "08:00",
        "WorkHoursEnd": "20:00",
        "WorkDays": ["Monday","Tuesday","Wednesday","Thursday","Friday"],
        "TimeZoneId": "UTC"
      }
      // ... остальные правила
    },
    "AutoBlock": {
      "IsEnabled": true,
      "Providers": ["WindowsFirewall"],  // + "MikroTik" при настройке
      "BlockTtlHours": 0                 // 0 = permanent
    },
    "Retention": {
      "RawEventsDays": 90,
      "AlertsDays": 180,
      "AttackStatsDays": 365
    },
    "AbuseIpDb": {
      "IsEnabled": false,
      "ApiKeyDpapi": "",  // DPAPI-конверт
      "Categories": [18, 22]
    },
    "MikroTik": {
      "IsEnabled": false,
      "Address": "",
      "Port": 443,
      "UsernameDpapi": "",  // DPAPI-конверт
      "PasswordDpapi": "",  // DPAPI-конверт
      "VerifyTls": true,
      "AddressListName": "RdpAudit-Blocklist"
    }
  },
  "Serilog": {
    "MinimumLevel": { "Default": "Information" },
    "WriteTo": [
      { "Name": "File", "Args": { "path": "%ProgramData%\\RdpAudit\\logs\\rdpaudit-.log", "rollingInterval": "Day" } },
      { "Name": "EventLog", "Args": { "source": "RdpAudit", "logName": "Application" } }
    ]
  }
}
```

### 12.2. Переменные окружения

Для переопределения конфигурации без редактирования файла (полезно для CI/CD и отладки):

```
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. Отладка и диагностика

### 13.1. Консольный режим

При запуске с подключённым отладчиком (`Debugger.IsAttached`) сервис работает как **консольное приложение**, а не Windows Service. Это позволяет прикрепить VS/Rider без установки сервиса:

```powershell
# Запустить как консоль (без установки сервиса)
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Логи Serilog

Логи записываются в:
- **Файл:** `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log` (ротация по дням)
- **Windows Event Log:** `Application`, источник `RdpAudit`

Уровень `Debug` включается через переменную окружения:
```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. SQLite-база напрямую

```powershell
# Открыть в DB Browser for SQLite
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

Полезные запросы:
```sql
-- Последние 100 событий
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

-- Активные блокировки
SELECT * FROM ActiveBlocks WHERE Status = 'Active';

-- Топ атакующих IP
SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats GROUP BY SourceIp ORDER BY Fails DESC LIMIT 20;
```

### 13.4. Вкладка Diagnostics

GUI-инструмент в Configurator показывает:
- Живые счётчики событий в секунду
- Статус каждого Background Worker
- Состояние IPC-соединения
- Размер и фрагментацию БД
- Пинг внешних API

---

## 14. Сборка и тестирование

### 14.1. Сборка

```powershell
# Полная сборка
dotnet build RdpAudit.sln -c Release

# Только Service
dotnet build src/RdpAudit.Service/RdpAudit.Service.csproj -c Release
```

### 14.2. Тесты

```powershell
# Все тесты
dotnet test RdpAudit.sln -c Release

# С покрытием
dotnet test RdpAudit.sln -c Release --collect:"XPlat Code Coverage"

# Только service-тесты
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj
```

Каждый тест правила тревоги проверяет:
1. Граничные условия порога срабатывания
2. Корректное игнорирование IP из whitelist
3. Нулевое выделение памяти на хипе (`GC.GetAllocatedBytesForCurrentThread` delta == 0 на 10k итерациях)

### 14.3. Publish

```powershell
# Публикует Service и Configurator в ./publish/
./publish.ps1
```

Результат:
```
publish/
├── Service/     — все файлы RdpAudit.Service (SelfContained=false, win-x64)
└── Configurator/ — все файлы RdpAudit.Configurator
```

---

## 15. Устранение неисправностей

Подробные решения типовых проблем: [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| Симптом | Первый шаг диагностики |
|---------|----------------------|
| Служба не стартует | `sc.exe query RdpAudit` → `eventvwr.msc` → Application log, источник RdpAudit |
| Нет событий в Live Events | Вкладка Prerequisites → проверить статус аудита |
| GUI не подключается к сервису | Убедиться, что сервис запущен; проверить ACL пайпа: `Get-Acl \\.\pipe\RdpAuditService` |
| `sc.exe error 1639` | Путь к exe содержит пробелы — заключить в кавычки |
| AbuseIPDB HTTP 429 | Rate-limit исчерпан; счётчик сбросится в полночь UTC |
| MikroTik TLS error | Установить `VerifyTls: false` для self-signed или импортировать сертификат |
| `SQLITE_BUSY` в логах | Нормально при кратковременной конкуренции; exponential backoff срабатывает автоматически |
| Политика аудита показывает `?` | Запустить `auditpol /get /category:*` от SYSTEM; вкладка Audit Policy → Apply |
| ProgramData ACL проблемы | `icacls "%ProgramData%\RdpAudit" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F"` |

Руководство по ручной валидации на Windows-хосте перед деплоем: [`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. Дорожная карта (v2.0 → v3.0)

| Функция | Статус |
|---------|--------|
| ETW-провайдер (`OpenTrace`/`ProcessTrace`) вместо `EventLogWatcher` | Запланировано v3.0 |
| Прямой парсинг EVTX через `Span<byte>` (bypass XML) | Запланировано v3.0 |
| Lock-free MPMC Ring Buffer (10M events/sec) | Запланировано v3.0 |
| SIMD IPv4/CIDR matching (`Sse42`, `Avx2`) | Запланировано v3.0 |
| Zero-alloc нормализация (`ref struct` парсеры) | Запланировано v3.0 |
| NDIS LWF фильтр для перехвата MS-RDPBCGR/RDPEUDP на уровне сети | Исследование |
| Web UI (Blazor Server) как альтернатива WinForms | Запланировано v3.0 |
| Интеграция Elastic/OpenSearch для SIEM | Roadmap |
| Multi-server aggregation через central collector | Roadmap |

---

## 17. Лицензия и автор

**Лицензия:** [MIT License](LICENSE) — свободное использование, модификация и распространение с сохранением copyright-нотиса.

**Автор:** Mikhail Deynekin
- 🌐 Website: [deynekin.com](https://deynekin.com)
- 📧 Email: [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- 🐙 GitHub: [github.com/paulmann](https://github.com/paulmann)

**Репозиторий:** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**Сопутствующие ресурсы:**
- [Техническая спецификация v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Техническая спецификация v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [Issues & Feature Requests](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. Released under the [MIT License](LICENSE).
