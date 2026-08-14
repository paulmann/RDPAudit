# Задание для Perplexity Computer: RDPAudit 2.0 — IEventSource + EtwRealtimeSource

## Роль и контекст

Ты **Principal Windows Security Platform Architect & Lead Systems Security Engineer** с 20+ годами C#/.NET, C++ и Windows kernel-mode опыта. Ты строил production SIEM-агенты, ETW TI consumers, NDIS LWF filters, MS-RDPBCGR/RDPEUDP анализаторы. Проектируешь под adversarial-условия: log floods 100k+ EPS, anti-forensics, nation-state actors. Каждая строка проходит code review Windows Internals-эксперта и SOC2-аудит.

Продолжаем эволюцию **RDPAudit 1.0 → 2.0**. Репозиторий: **https://github.com/paulmann/RDPAudit**. Работаем **исключительно** на ветке `feature/rdpaudit-2.0-event-collection` — `main` **не трогать**. GitHub REST API only (username `paulmann`, token из user_background). Никакого браузера.

**HEAD ветки на момент старта:** `64517423086f613852d163103171dab7fb616176`.

## Текущее состояние (что закрыто ранее)

Инфраструктура ingest'а стабилизирована:
- `MpmcEventChannel` v2.0.3: single-shot evict+retry, honest `_hardDropCount`, `OverflowBreakdown()`
- `MpmcEventChannelTests`: убран `SpinWait`-паразит, `Task.Run` без `cts.Token`, богатый Assert.Fail message
- `ShardWriterTests`: 2000-iter warm-up + `GC.Collect()` перед alloc-измерением
- `install.ps1 -DebugTests`: full hang/crash dumps + `--diag` + `DOTNET_TieredCompilation=0` + EnvDump

**Windows regression: 743/743 pass, сервис поднимается, install чист.**

## Цель этого задания

Заменить legacy v1.0 scaffolding `EventLogWatcher` на **ETW-first ingestion** через абстракцию `IEventSource`, сохранив полную backward-compatibility. Новый путь должен:

1. Исключить `EventRecord.ToXml()` из hot path (∼2–4 KB managed string + XmlDocument alloc на событие).
2. Устранить bottleneck `wevtapi.dll` single-threaded callback pump.
3. Читать `EVENT_RECORD.UserData` как `ReadOnlySpan<byte>`, извлекать SID/TSID из `EventHeader.ExtendedData` без marshaling.
4. Поддержать hot-swap двух реализаций через флаг конфигурации `RdpAudit:UseEtw`.

**Целевая нагрузка:** 10M events/sec sustained ingestion на 16-core commodity server.

## Non-negotiable инварианты (RDPAudit 2.0 Core Directives)

**Zero-alloc hot path.** `ReadBatchAsync`, парсинг `EVENT_RECORD`, извлечение SID/TSID/IP **не аллоцируют на managed heap**. Разрешены: `Span<T>`, `ReadOnlySpan<T>`, `ref struct`, `stackalloc`, `ArrayPool<byte>.Shared`, `SearchValues<T>`. Запрещены на hot path: `new` (кроме stackalloc/pool rent), `ToString()`, `.Select()/.Where()/.Any()`, string interpolation `$"..."`, LINQ, `XmlDocument`, `Regex`.

**P/Invoke:** только `[LibraryImport]` (source-generated), никогда `[DllImport]`. Каждый OS handle обёрнут в `SafeHandle`-подкласс. Никаких голых `IntPtr` в публичном API. Проверка `Marshal.GetLastPInvokeError()` после каждого interop-вызова с `SetLastError=true`.

**Endianness:** RDP-payload'ы little-endian. Использовать `BinaryPrimitives.ReadUInt32LittleEndian(span)`, никогда `BitConverter`.

**CancellationToken:** пропагируется в каждый async метод. Никаких `.Result`, `.Wait()`, `Task.Run` без токена. `ValueTask` для sync-completion.

**UTC внутри.** Local time — только UI-слой.

**Nullable enable.** Warnings as errors.

**TABS для отступов.** English identifiers/comments/logs/XML docs.

**Structured logging:** `ILogger<T>` с именованными свойствами (`{Channel}`, `{EventId}`), никогда `$"..."` в `Log.*`.

## Обязательный заголовок файлов

Каждый полный `.cs`-файл начинается **точно** так:

```csharp
/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: <X.Y.Z>
// File   : <FileName>.cs
// Project: <ProjectName> (RdpAudit.<Layer>)
// Purpose: <Одно предложение — что делает и зачем существует>
// Depends: <Ключевые типы/интерфейсы, comma-separated>
// Extends: <Что менять здесь при добавлении новой ETW-провайдер-цели/канала>
```

Функции/сниппеты — только `// Version: X.Y.Z` над функцией, без author header.

**Banner-комментарии** обязательны в нетривиальных классах:
```
// ── Fields & DI ──────────────────────────────────────────────────────────────
// ── Construction ─────────────────────────────────────────────────────────────
// ── Public API ───────────────────────────────────────────────────────────────
// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────
// ── Core Logic ───────────────────────────────────────────────────────────────
// ── Error Handling & Retry ───────────────────────────────────────────────────
// ── Disposal & Pool Returns ──────────────────────────────────────────────────
```

## Архитектура шага (детальная декомпозиция)

### 1. `RdpAudit.Core.Events.IEventSource` — контракт

**Файл:** `src/RdpAudit.Core/Events/IEventSource.cs`

**Контракт:**
```csharp
public interface IEventSource : IAsyncDisposable
{
	/// <summary>Fills the provided buffer with up to buffer.Length events. Returns the
	/// number actually written. Zero means "no events currently available"; -1 means
	/// the source was cancelled or terminated. MUST NOT allocate on the managed heap
	/// beyond one-shot bootstrap.</summary>
	ValueTask<int> ReadBatchAsync(Memory<RawEventRef> buffer, CancellationToken ct);

	/// <summary>Starts the underlying pump (subscribes EventLogWatcher / opens ETW
	/// session). Idempotent. Must be called before ReadBatchAsync.</summary>
	ValueTask StartAsync(CancellationToken ct);

	/// <summary>Cooperative stop. Waits for the pump to drain remaining callbacks
	/// (bounded, default 5 s). Safe to call multiple times.</summary>
	ValueTask StopAsync(CancellationToken ct);

	/// <summary>Non-negative running counter of events dropped due to consumer
	/// back-pressure since Start. Snapshot-safe under concurrent read.</summary>
	long DroppedEventCount { get; }

	/// <summary>Diagnostic label for logs/telemetry: "EventLogWatcher" or "ETW".</summary>
	string SourceName { get; }
}
```

### 2. `RawEventRef` — DTO нулевой стоимости

**Файл:** `src/RdpAudit.Core/Events/RawEventRef.cs`

**Требования:**
- `readonly struct`, `[StructLayout(LayoutKind.Sequential)]`, cache-line-friendly (≤ 64 байт полезной нагрузки-метаданных + указатель на pooled payload)
- Поля: `int EventId`, `long TimeUtcTicks`, `ushort ProviderIndex` (индекс в статическом каталоге провайдеров, не строка!), `ushort PayloadLength`, `uint ProcessId`, `uint ThreadId`, `Guid ActivityId`
- `ReadOnlySpan<byte> Payload => ...` — указатель на ArrayPool-rented буфер (владение переходит consumer'у; consumer возвращает буфер после парсинга)
- `int PayloadPoolToken` — ключ для возврата в pool
- Никакого string / object внутри

### 3. `EventProviderCatalog` — статическая таблица

**Файл:** `src/RdpAudit.Core/Events/EventProviderCatalog.cs`

Три GUID'а провайдеров + числовой индекс, чтобы `RawEventRef` держал `ushort ProviderIndex`, а не string:

```csharp
// TerminalServices-RemoteConnectionManager
public static readonly Guid TsRcm = new("C76BAA63-AE81-421C-B425-340B4B24157F");
// Security-Auditing
public static readonly Guid SecAudit = new("54849625-5478-4994-A5BA-3E3B0328C30D");
// TerminalServices-LocalSessionManager
public static readonly Guid TsLsm = new("5D896912-022D-40AA-A3A8-4FA5515C76D7");
```

+ `TryGetIndex(in Guid, out ushort)` / `GetGuid(ushort)`. Массив на 8 слотов (запас на будущие каналы), lookup через `MemoryMarshal.Cast<Guid, Vector128<byte>>` + `Sse2.CompareEqual` если MSFT-провайдеры уложатся в SIMD-таблицу; иначе — простой switch, критерий: <20 ns/call.

**Проверь фактические GUID'ы через `logman query providers` на живой Windows-машине** — я привёл каноничные значения из документации, но пусть код verify'ит их в unit-тесте против `EventLogSession`.

### 4. `EventLogWatcherSource` — compat-реализация v1.0

**Файл:** `src/RdpAudit.Service/Collectors/EventLogWatcherSource.cs`

- Обёртка вокруг существующего кода `EventCollectorWorker` (см. skill `rdpaudit-developer` §3.1–3.3 — паттерн `EventLogWatcher` + XPath + bookmark).
- `ReadBatchAsync` дренирует внутренний `Channel<RawEventRef>` (bounded, DropOldest, capacity=8192). Callback-writer `OnEventRecordWritten` **синхронно** внутри callback'а:
  1. Читает `EventRecord.Id`, `TimeCreated`, `ProviderId`
  2. Рентит `byte[]` из `ArrayPool<byte>.Shared` под `ToXml()` UTF-8 bytes (compat-режим сохраняет XML — оптимизация только у ETW-варианта)
  3. `TryWrite` в channel; при overflow `Interlocked.Increment(ref _droppedCount)`
- `ProviderIndex` — из `EventProviderCatalog.TryGetIndex(rec.ProviderId)`.
- Bookmark serialization — по паттерну из skill (§3.3, reflection на `_xmlString`).
- Метка `SourceName => "EventLogWatcher"`.

### 5. `EtwRealtimeSource` — production-путь

**Файл:** `src/RdpAudit.Service/Collectors/EtwRealtimeSource.cs`

**P/Invoke:** отдельный файл `src/RdpAudit.Core/Interop/EtwNativeMethods.cs` с `[LibraryImport("advapi32.dll", SetLastError = true)]` для:
- `StartTrace` / `StopTrace` / `ControlTrace`
- `EnableTraceEx2`
- `OpenTrace` (Unicode: `OpenTraceW`)
- `ProcessTrace`
- `CloseTrace`

**Структуры:** `EVENT_TRACE_LOGFILE`, `EVENT_TRACE_PROPERTIES`, `EVENT_RECORD`, `EVENT_HEADER`, `EVENT_HEADER_EXTENDED_DATA_ITEM`, `EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID`, `EVENT_EXTENDED_ITEM_SID`, `EVENT_EXTENDED_ITEM_TS_ID` — все `[StructLayout(LayoutKind.Sequential)]`, blittable, никаких `string`-полей (только `char*` / `byte*`).

**SafeHandle:** `EtwTraceHandle : SafeHandleZeroOrMinusOneIsInvalid` — обёртка над `TRACEHANDLE` (ulong). `ReleaseHandle` вызывает `CloseTrace`.

**Session lifecycle:**
1. `StartAsync`:
   - Создать real-time ETW session `RdpAudit_RealtimeSession` (`StartTrace` с `EVENT_TRACE_REAL_TIME_MODE`).
   - Enable три провайдера через `EnableTraceEx2` с уровнем `TRACE_LEVEL_INFORMATION` и match-any-keyword для нужных подмножеств (Security-Auditing требует правильный keyword mask — уточнить через `logman query providers Microsoft-Windows-Security-Auditing`).
   - Открыть `OpenTraceW` с `EventRecordCallback = &OnEventRecord` (unmanaged callback, `[UnmanagedCallersOnly]`).
   - Запустить `ProcessTrace` в **выделенном потоке** (`new Thread(...) { IsBackground = true, Name = "RdpAudit-ETW-Pump" }`), не через ThreadPool.
2. `OnEventRecord` (unmanaged callback):
   - Читает `EVENT_RECORD*` (unsafe).
   - Rents `byte[]` из `ArrayPool<byte>.Shared` размера `UserDataLength`.
   - `new ReadOnlySpan<byte>(record->UserData, record->UserDataLength).CopyTo(rented)`.
   - Проходит `ExtendedData` items linked list, ищет `EVENT_HEADER_EXT_TYPE_SID`, `EVENT_HEADER_EXT_TYPE_TS_ID` — извлекает без marshaling (просто offset в `Span<byte>`).
   - Заполняет `RawEventRef` (stack-local), `TryWrite` в bounded `MpmcEventChannel` (переиспользуем наш v2.0.3).
   - При overflow `Interlocked.Increment(ref _droppedCount)` + возврат буфера в pool.
3. `ReadBatchAsync`: дренирует `MpmcEventChannel`.
4. `StopAsync`: `ControlTrace(EVENT_TRACE_CONTROL_STOP)` → `CloseTrace` → `Thread.Join(5000)`.

**Критично:** ETW callback вызывается на native thread с **отсутствием managed context** до первого GC-safe pointа. `[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]` для callback'а. Внутри — **никаких managed allocations кроме ArrayPool rent** (pool сам не аллоцирует горячо).

**Cooldown/restart:** если `ProcessTrace` возвращает ошибку (session killed извне, `ERROR_WMI_INSTANCE_NOT_FOUND` = 4201), реализовать exponential backoff restart (2s → 4s → 8s → max 60s) с `ILogger` warning'ами.

### 6. DI-swap

**Файл:** `src/RdpAudit.Service/Program.cs` (модификация)

```csharp
// Version: 2.1.0
builder.Services.Configure<RdpAuditOptions>(builder.Configuration.GetSection("RdpAudit"));

builder.Services.AddSingleton<IEventSource>(sp =>
{
	var opts = sp.GetRequiredService<IOptions<RdpAuditOptions>>().Value;
	var logger = sp.GetRequiredService<ILoggerFactory>();
	return opts.UseEtw
		? new EtwRealtimeSource(sp.GetRequiredService<ILogger<EtwRealtimeSource>>(), opts)
		: new EventLogWatcherSource(sp.GetRequiredService<ILogger<EventLogWatcherSource>>(), opts);
});
```

Добавить в `RdpAuditOptions` bool `UseEtw` (default: `false` в v2.1.0-preview, переключение на `true` в v2.2.0 после недели production-canary).

`appsettings.json`:
```json
{
	"RdpAudit": {
		"UseEtw": false,
		"EtwSessionName": "RdpAudit_RealtimeSession",
		"EtwBufferSizeKb": 64,
		"EtwMinBuffers": 32,
		"EtwMaxBuffers": 128
	}
}
```

`EventCollectorHost` (BackgroundService) больше не создаёт `EventLogWatcher` напрямую — теперь только:
```csharp
await _source.StartAsync(stoppingToken);
try
{
	while (!stoppingToken.IsCancellationRequested)
	{
		int read = await _source.ReadBatchAsync(_batchBuffer, stoppingToken);
		if (read <= 0) { await Task.Delay(10, stoppingToken); continue; }
		await _pipeline.PublishAsync(_batchBuffer.Slice(0, read), stoppingToken);
	}
}
finally
{
	await _source.StopAsync(CancellationToken.None);
}
```

### 7. Тесты

**Проект:** `tests/RdpAudit.Service.Tests/` (уже существует).

**Обязательные тест-файлы:**

#### 7.1 `EventProviderCatalogTests.cs`
- GUID'ы совпадают с реальным `logman query providers` output (unit-тест НЕ должен запускать logman — используем hardcoded expected + свежепроверенные значения; проверка через `EventLogSession.GetProviderNames()` только на Windows, `[SkippableFact(OSPlatform.Windows)]`).
- `TryGetIndex` возвращает стабильный индекс.
- Round-trip: `GetGuid(TryGetIndex(g))` == `g`.

#### 7.2 `RawEventRefLayoutTests.cs`
- `Marshal.SizeOf<RawEventRef>()` укладывается в one cache line (≤64B, allow один pointer overflow).
- `[FieldOffset]` (если union) корректен.

#### 7.3 `EtwRecordParserTests.cs` — критический
**Fixtures:** `tests/RdpAudit.Service.Tests/Fixtures/etw/` — реальные dumps:
- `security_4624_networkLogon.etl.hex` — Security 4624 (successful logon), LogonType=3, с TargetUserSid + IpAddress в UserData
- `security_4625_failedNetworkLogon.etl.hex` — 4625 с SubStatus=0xC000006A (wrong password)
- `security_4776_credentialValidation.etl.hex` — 4776 NTLM auth attempt
- `tsrcm_1149_authSuccess.etl.hex` — TerminalServices RemoteConnectionManager 1149
- `tslsm_21_sessionLogon.etl.hex` — LocalSessionManager 21

**Как собрать fixtures:** на живой Windows-машине через `logman`:
```powershell
logman create trace RdpAuditFixture -o C:\temp\rdpaudit_fixture.etl -ets
logman update RdpAuditFixture -p "Microsoft-Windows-Security-Auditing" 0x8010000000000000 win:Informational -ets
# ... RDP-events (mstsc + fail + success) ...
logman stop RdpAuditFixture -ets
```
Затем hex-dump `.etl` bytes в фикстуру. **Сформировать fixtures — user сделает локально, code должен корректно парсить.** Fixture-loader читает hex → `byte[]`.

**Проверки:**
- `EventId` из `EVENT_HEADER.EventDescriptor.Id`
- `TimeUtcTicks` из `EVENT_HEADER.TimeStamp`
- Provider identified through catalog
- SID extracted from ExtendedData bytes (не string, а `Span<byte>` → hex/SDDL опционально)
- IPv4/IPv6 extracted from UserData at correct offset per manifest
- `GC.GetAllocatedBytesForCurrentThread` delta == 0 после 10 000 повторных парсингов одной фикстуры

#### 7.4 `EventLogWatcherSourceTests.cs`
- StartAsync → StopAsync idempotent
- `[SkippableFact(OSPlatform.Windows)]` — генерирует Security event через `EventLog.WriteEntry` или synthetic Application-log entry (Security канал требует SYSTEM), проверяет `ReadBatchAsync` его отдаёт
- `DroppedEventCount` растёт под искусственной нагрузкой (100k events → mock consumer, читающий 1/сек)

#### 7.5 `EtwRealtimeSourceIntegrationTests.cs` — Windows-only, `[SkippableFact]`
- Использует `System.Diagnostics.Tracing.EventSource` (managed ETW writer) с собственным GUID (тестовый провайдер, не Security!) — регистрирует его на лету, пишет N событий, `EtwRealtimeSource` должен их вычитать.
- Проверка: `ReadBatchAsync` возвращает > 0 в течение 5 сек, `EventId` совпадает, `Payload` содержит ожидаемые bytes.

**НЕ использовать реальные Security/TSRCM провайдеры в integration-тесте** — требуют admin + меняют настоящие audit logs.

#### 7.6 `EtwCallbackAllocationTests.cs`
- BenchmarkDotNet-friendly (или `GC.GetAllocatedBytesForCurrentThread`-assert) — 10 000 симулированных callback'ов через unsafe `EVENT_RECORD` в stackalloc, проверить: **0 байт managed alloc** (кроме ArrayPool rent, который считается санкционированным).

### 8. Логи и диагностика

**ILogger scope:** каждый лог из `EtwRealtimeSource` идёт со scope `{SessionName}={_sessionName}, {ProviderCount}=3`.

**Structured events:**
- `LogInformation("ETW session {SessionName} started, providers={ProviderCount}, buffers={BufferCount}x{BufferSizeKb}KB")`
- `LogWarning("ETW event dropped: {DroppedTotal} since start, source={SourceName}")` — throttled раз в 5 сек через `PeriodicTimer`
- `LogCritical(ex, "ProcessTrace terminated unexpectedly, restart in {BackoffSeconds}s")`

**Метрики (для будущего OpenTelemetry-шага):** IHostedService считает `_eventsProcessed`, `_droppedEvents`, `_lastEventLagMs` — хранить в `Interlocked`-полях, экспонировать через IPC (следующий шаг).

### 9. Prerequisite Check (для Configurator)

**Файл:** `src/RdpAudit.Service/Startup/EtwPrerequisiteChecker.cs`

Перед `StartAsync` в ETW-режиме проверить:
1. Процесс запущен от `SYSTEM` или в группе `Performance Log Users` (иначе `EnableTraceEx2` вернёт `ERROR_ACCESS_DENIED = 5`).
2. Провайдер зарегистрирован (`EventLogSession.GlobalSession.GetLogNames()` + provider enumeration).
3. Windows build ≥ 10.0.14393 (`EnableTraceEx2` требует Win10 Anniversary+).

Если проверка не пройдена — `LogCritical` + fallback на `EventLogWatcherSource` **автоматически**, с warning в telemetry. Никогда не крашить сервис.

## Порядок реализации (строго по шагам, commit-per-step)

Каждый шаг — **отдельный commit через GitHub REST API** на ветку `feature/rdpaudit-2.0-event-collection`, с осмысленным commit message (**без em-dash**). После каждого — сборка `dotnet build -c Release`, тесты `dotnet test -c Release`, только потом push.

1. **`RawEventRef` + `EventProviderCatalog` + unit-тесты каталога** → commit `feat(events): add RawEventRef DTO and provider catalog`.
2. **`IEventSource` interface** → commit `feat(events): add IEventSource abstraction contract`.
3. **`EventLogWatcherSource` (compat)** + миграция существующего `EventCollectorWorker` на новый интерфейс → commit `refactor(events): wrap EventLogWatcher behind IEventSource`.
4. **DI-swap + `RdpAudit:UseEtw=false` default** → commit `feat(events): add UseEtw configuration flag with EventLogWatcher default`.
5. **`EtwNativeMethods` P/Invoke + SafeHandle** → commit `feat(interop): add ETW LibraryImport bindings`.
6. **`EtwRealtimeSource` skeleton (Start/Stop, no callback yet)** → commit `feat(events): add EtwRealtimeSource session lifecycle`.
7. **Callback + `RawEventRef` parsing + ArrayPool** → commit `feat(events): implement zero-alloc ETW callback pump`.
8. **`EtwPrerequisiteChecker` + graceful fallback** → commit `feat(events): add ETW prerequisite check with fallback`.
9. **Все test-файлы (7.1–7.6)** → commit `test(events): add IEventSource unit and integration tests`.
10. **Обновление `README.md`** секция "Ingestion mode" — как переключать `UseEtw`, требования → commit `docs: describe ETW ingestion mode and prerequisites`.

## Quality Gate перед финальным push

Обязательно проверить **всё** до объявления шага завершённым:

1. `dotnet build RdpAudit.sln -c Release --nologo` — **0 warnings, 0 errors**.
2. `dotnet test -c Release --nologo` на Linux — все тесты кроме `[SkippableFact(OSPlatform.Windows)]` проходят (Windows-only skip'ятся).
3. `GC.GetAllocatedBytesForCurrentThread` в `EtwCallbackAllocationTests` == **0** после 10k итераций (после warm-up).
4. Все файлы имеют корректный header (`Version:`, `File:`, `Project:`, `Purpose:`, `Depends:`, `Extends:`).
5. Ни одного `[DllImport]` — только `[LibraryImport]`.
6. Ни одного `IntPtr` в публичном API (только внутри `SafeHandle`).
7. Ни одного `.Result` / `.Wait()` / `Task.Run(...)` без `CancellationToken`.
8. Ни одного `ToXml()`, `XmlDocument`, `Regex`, `string.Split`, LINQ на hot path (`ReadBatchAsync`, callback, парсеры).
9. Все `SafeHandle`-подклассы имеют корректный `ReleaseHandle` возвращающий `bool`.
10. Nullable annotations корректны, `<Nullable>enable</Nullable>` во всех `.csproj`.

## Verification на Linux dev-машине

Полный ETW-путь **не заработает на Linux** (`advapi32.dll` отсутствует), но должно работать:
- Компиляция всех проектов (`net8.0-windows` TFM для Service, `net8.0` для Core).
- Все Core-тесты (`RawEventRef`, `EventProviderCatalog`, парсер фикстур через hex-dumps — фикстуры это `byte[]`, они читаются везде).
- `EventLogWatcherSourceTests` и `EtwRealtimeSourceIntegrationTests` — skipped через `[SkippableFact(OSPlatform.Windows)]`.

## Что запрещено сделать в этом шаге

- **Не трогать** `main`. Всё — на `feature/rdpaudit-2.0-event-collection`.
- **Не запускать CI-polling loops** — user тестирует локально на Windows и присылает результаты.
- **Не переписывать** уже стабилизированный `MpmcEventChannel` v2.0.3 / `ShardWriter` / `install.ps1`.
- **Не добавлять** новые NuGet-зависимости без явной необходимости. Если нужен `System.Diagnostics.Tracing` расширенный — использовать built-in .NET 8 API.
- **Не создавать** `.md`-документацию поверх заголовков внутри `.cs`. Только README-секцию в шаге 10.
- **Не менять** commit messages в стиле с em-dash. Использовать обычные ASCII `-`.

## Финальный отчёт после реализации

Ответить пользователю на русском, в структурированном формате:

1. **Что сделано** — список из 10 коммитов с SHA и одной строкой описания каждого.
2. **HEAD ветки** после всех push'ей.
3. **Как проверить локально на Windows:**
   ```powershell
   .\install.ps1 -DebugTests
   # ожидаемо: 743 -> ~760 тестов, все pass
   # затем переключить режим:
   # отредактировать %ProgramData%\RdpAudit\appsettings.json -> "UseEtw": true
   # перезапустить: Restart-Service RdpAuditService
   # проверить журнал: Get-Content C:\1st_RdpMON\logs\rdpaudit-service-*.log -Tail 50
   ```
4. **Известные ограничения** (Security-Auditing keyword mask, требование SYSTEM/PLU, fallback path).
5. **Следующий шаг** — Zero-alloc EVTX parser (пункт №8 общего плана).

---

**Начинай реализацию, коммит-за-коммитом, с локальной сборкой и тестами перед каждым push. Отчитывайся по факту завершения всех 10 коммитов одним финальным сообщением. Если наткнёшься на архитектурное решение, которое имеет два равноправных пути — коротко сформулируй trade-off и выбери один, не задавая уточняющий вопрос до конца работы (кроме случая, когда неверный выбор потребует полного переписывания шага).**
