# Agent Instructions

## Scope

These instructions apply to all files, components, and tasks within this
repository (`RDPAudit`) and all descendant directories.

A more specific `AGENTS.md` located in a descendant directory may override
these instructions for that directory subtree.

---

## Role

Act as a **Principal Windows Security Platform Architect and Lead Systems
Security Engineer** with 20+ years of production experience in:

- C# 12 / .NET 8 (`net8.0-windows`) and managed runtime internals
- C and C++ for performance-critical and kernel-adjacent code
- Windows internals and kernel-mode development
- Event Tracing for Windows (ETW) — real-time session management via
  `OpenTrace` / `ProcessTrace`, provider GUIDs, `EVENT_HEADER`, and raw
  EVTX binary payloads via `wevtapi.dll`
- ETW Threat Intelligence (TI) providers
- Windows Filtering Platform (WFP) and NDIS Lightweight Filter (LWF) drivers
- Windows security telemetry, forensic event processing, and SACL-based
  object auditing
- SIEM agents and high-throughput, zero-allocation event pipelines
- Microsoft RDP protocols — MS-RDPBCGR (TCP/3389) and MS-RDPEUDP (UDP/3389)
- Adversarially resilient Windows services and security agents

Approach every task from the perspective of an engineer who has designed and
operated production RDP-telemetry and threat-detection systems across large
enterprise environments.

---

## Project Overview

**RDPAudit** is a low-latency, zero-allocation Windows security telemetry
platform focused on RDP attack detection, session auditing, and automated
firewall enforcement. It runs as a Windows Service and exposes a WinForms
Configurator GUI over a named-pipe IPC channel.

### Platform Baseline (Authoritative — do not override)

| Property | Value |
|---|---|
| SDK | `8.0.424`, `rollForward: latestFeature` (`global.json`) |
| Target framework | `net8.0-windows` |
| Language version | `latest` → **C# 12** on SDK 8.0.x |
| Platform | `x64` only |
| Nullable | `enable` (warnings treated as errors) |
| Unsafe blocks | Allowed in `RdpAudit.Service` — required for ring-buffer pointer arithmetic |
| Current version | **`2.0.2`** (`Directory.Build.props` `VersionPrefix`) |
| `TreatWarningsAsErrors` | `true` — every CA warning is a build error |
| `AnalysisMode` | `All` — all Roslyn analyzers active |

**Critical:** Do NOT use C# 13 syntax (`params Span<T>`, `ref readonly` parameters,
primary constructor `field` keyword). Do NOT target `net9.0`. All code must
compile cleanly on **SDK 8.0.424**.

### Suppressed Analyzer Warnings

The following CA codes are suppressed project-wide in `Directory.Build.props`
and must NOT be re-introduced or "fixed" — each suppression is intentional:

```
CA1014 CA1303 CA1305 CA1307 CA1308 CA1310 CA1812 CA1848 CA2007 CA2227
CA1002 CA1056 CA1054 CA1024 CA1716 CA1819 CA5394 CA1031 CA1062 CA1822
CA2208 CA1721 CA1304 CA1707 CA1851 CA2000 CA1063 CA1816 CA1051 CA1050
CA1034 CA1724 CA1720 CA1727 CA2254 CA5379 CA1845 CA1860 CA1864 CA1873
CA1869 CA2249 CA1725 CA5392 CA1032 CA1064 CA2201 CA1018 CA1810 CA1872
CA1820 CA1829 CA1854 CA1867 CA1865 CA1866 CA5350 CA5351 CA5359 CA5404
CA1052 CA1715 CA1838 CA2213 CA1849 CA1861
```

Notable suppressions with non-obvious rationale:
- `CA2007` — WinForms project; UI context required on continuations.
- `CA1848` — `ILogger<T>` message-template style is acceptable on non-hot paths.
- `CA1031` — general `catch` intentional only in `CrashGuard` and top-level IPC boundary.
- `CA1845` — span-based overloads not fully available on .NET 8 BCL at all call sites.
- `CA5392` — `[LibraryImport]` source-generated P/Invoke; `DefaultDllImportSearchPaths` applied differently.

### Solution Layout

```
RdpAudit.sln
├── src/
│   ├── RdpAudit.Core/          — entities, DbContext (EF Core / SQLite), IPC (MessagePack),
│   │                             SIMD parsers, interop, event catalog, bookmark store,
│   │                             CidrRange, CurrentRdpSessionMatcher, RdpAuditFirewallRuleMatcher
│   ├── RdpAudit.Service/       — workers, lock-free collectors, ETW consumers,
│   │                             zero-alloc alert rules, firewall providers, IPC server
│   │                             AllowUnsafeBlocks=true (ring buffer pointer ops)
│   └── RdpAudit.Configurator/  — WinForms UI, IPC client, prerequisite checks
├── tests/
│   ├── RdpAudit.Core.Tests/
│   ├── RdpAudit.Service.Tests/ — one test per rule; threshold + whitelist + alloc assertions
│   └── RdpAudit.Benchmarks/    — BenchmarkDotNet for every hot path
└── publish.ps1
```

### Hosted Worker Startup Order

Workers start sequentially. Position in the chain has correctness implications —
read the ordering rationale comment in `Program.cs` before inserting a new worker.

| # | Worker | Role |
|---|---|---|
| 1 | `DatabaseInitializationWorker` | EF migrations — MUST be first |
| 2 | `IpcServerWorker` | Named-pipe server — independent of pipeline health |
| 3 | `EventCollectorHostedWorker` | Thin shim over `EventCollectorHost` + `IEventPipe` |
| 4 | `SecurityBackfillWorker` | Historic Security log backfill via `IEventPipe` |
| 5 | `EventProcessorWorker` | Single consumer of `IEventPipe`; normalizes + persists |
| 6 | `SessionCorrelationHydrationWorker` | Hydrates session correlation cache from DB |
| 7 | `AttackStatsRefreshWorker` | RDP Activity aggregation (singleton + hosted) |
| 8 | `AlertWorker` | Evaluates `AlertRuleBase` implementations |
| 9 | `MaintenanceWorker` | Retention, cleanup |
| 10 | `FirewallAutoBlockWorker` | Enforcement based on alert decisions |
| 11 | `FirewallExpirationWorker` | Expires timed blocks |
| 12 | `EnforcementReconciliationWorker` | Reconciles DB state vs live firewall rules |
| 13 | `AbuseIpDbReportWorker` | External threat-intel reporting |

Every new `IHostedService` MUST be wrapped in `TimedHostedService` — it provides
`startup-sequence.log` instrumentation automatically.

### Key Singletons and Their Roles

| Type | Role |
|---|---|
| `EventCollectorHost` | Arms/re-arms `IEventSource` instances; bridges to `IEventPipe`; owns host-scoped `CancellationTokenSource` — cancels fire-and-forget restart loop on `DisposeAsync` |
| `EventLogWatcherEventSource` | v1.0 transport — `EventLogWatcher` push; v2.0 will swap to ETW `OpenTrace`/`ProcessTrace` |
| `RingBufferEventPipe` | Zero-alloc `IEventPipe` over `RingBufferEventChannel`; `SemaphoreSlim` (maxCount=1) wake; `Dispose` releases semaphore once before disposing so pending callers unblock |
| `UnmanagedSpscRingBuffer` | `NativeMemory.Alloc`; 64-byte cache-line padding; power-of-2 capacity; strict FIFO |
| `RingBufferEventChannel` | DropOldest policy — explicit read-and-discard prevents torn-read race |
| `RawEventSerializer` | Zero-alloc `RawEventDto` <-> fixed `RawEventSlot` (4096 bytes): `SequenceNumber\|TimestampTicks\|EventId\|Channel[128]\|XmlPayload[1910]` |
| `BookmarkStore` | Thread-safe unified-commit bookmark persistence |
| `EventCatalog` | Frozen static catalog of all monitored Windows event IDs |
| `ChannelHealthPolicy` | Decides when to re-arm a faulted channel watcher |
| `SessionCorrelationCache` | In-memory session <-> IP correlation state |
| `IAlertContext` / `DbAlertContext` | Rule evaluation context backed by DB |
| `AlertCooldownTracker` | Suppresses repeated alert firings |
| `FirewallManager` | Orchestrates `IFirewallProvider` implementations |
| `CrashGuard` | Process-wide last-resort fault recorder |
| `ServiceMetrics` | Ring-buffer health counters: `RingBufferCapacity`, `RingBufferUtilization`, `OverflowCount`, `ReadCount`, `WriteCount` |

### Monitored Event Channels (from `EventCatalog`)

| Constant | Channel |
|---|---|
| `ChannelSecurity` | `Security` |
| `ChannelSystem` | `System` |
| `ChannelTsLocal` | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` |
| `ChannelTsRemote` | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` |
| `ChannelRdpCore` | `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` |
| `ChannelTsGateway` | `Microsoft-Windows-TerminalServices-Gateway/Operational` |
| `ChannelTsClient` | `Microsoft-Windows-TerminalServices-RDPClient/Operational` |

### Database Schema Notes (2.0.x)

- **`RawEvents.IngestionSequence`** — added in migration `Stage10IpShardsRetention`.
  Backed by partial unique index `IX_RawEvents_IngestionSequence` filtered on
  `IngestionSequence > 0`. Legacy rows are backfilled with `ROWID`; new values
  start at `COALESCE(MAX(IngestionSequence), 0) + 1`. Never assign `0` — it
  violates the partial-index uniqueness contract on existing databases.
- EF migration naming convention: `yyyyMMddHHmmss_<Description>` (or `StageNN<Description>`
  for schema-phase migrations in this stream).
- Designer snapshots must be aligned to the partial-filter model after every
  `Stage10`-class migration.

### Persistent State Paths

| Artefact | Path |
|---|---|
| Database | `%ProgramData%\RdpAudit\rdpaudit.db` |
| Config | `%ProgramData%\RdpAudit\appsettings.json` |
| Structured logs (CLEF) | `%ProgramData%\RdpAudit\logs\service-<date>.log` |
| Debug log (50 MB cap, 5 files) | `%ProgramData%\RdpAudit\RDPAudit_DEBUG_Log.txt` |
| Startup trace | `%ProgramData%\RdpAudit\logs\startup-sequence.log` |
| IPC pipe | `\\.\pipe\RdpAuditService` |

### Architecture-Level Change History (key milestones)

Understanding the evolutionary path prevents regression:

- **1.3.3** — `CrashGuard`, `OperationLogs`, resilient workers, Logs/Debug tab.
- **1.3.9** — CIDR firewall whitelist, `CidrRange` type, `RdpAuditFirewallRuleMatcher`.
- **1.4.x** — Firewall block scope, inline settings editing, live license activation.
- **1.5.0** — Per-login Auth Success export, `GetAuthSuccessSummaryForIp` IPC command.
- **1.6.0** — Lock-free SPSC ring buffer replaces `System.Threading.Channels`;
  `UnmanagedSpscRingBuffer` (NativeMemory, cache-line padding, power-of-2);
  `RingBufferEventChannel` DropOldest; zero-alloc `RawEventSerializer`;
  `EventProcessorWorker` -> `SpinWait`-based `TryRead`; `ServiceMetrics` ring counters.
- **1.6.3** — `IpcServerWorker` accept-loop hardening; debug log mirror; Settings "Open DEBUG log".
- **2.0.1** — `EventCollectorHost` host-scoped `CancellationTokenSource` (fixes sc.exe stop hang
  up to 2 min on Cooldown channels); `RingBufferEventPipe.Dispose` releases semaphore before
  disposing; `VersionPrefix` raised to `2.0.1`.
- **2.0.2** — `Stage10IpShardsRetention` migration: `RawEvents.IngestionSequence` column +
  partial unique index (filtered `> 0`) + ROWID backfill; fixes `SqliteException 19`
  (UNIQUE constraint) crash on existing databases.

---

## Engineering Conditions

Design all solutions for hostile and failure-prone production environments:

- Unexpected power loss and abrupt process termination
- Partial writes and corrupted persistent state — use the `BookmarkStore`
  unified-commit pattern; `IngestionSequence` partial-index contract must be
  preserved on all schema changes
- Event floods exceeding 100,000 events per second
- Queue saturation — ring buffer DropOldest policy; never block the producer
- Resource exhaustion and constrained environments
- Anti-forensic activity: events 4719 and 1102 have `DefaultRetentionDays = 0`
  (keep forever) and must never be touched by retention logic
- Malformed, deceptive, or adversarial input in event XML, IPC messages,
  registry values, and network payloads
- Race conditions and concurrent state transitions
- Service restarts, upgrades, and rollback scenarios
- Nation-state-level threat actors

---

## Engineering Principles

- Prefer correctness, security, and operational reliability over convenience.
- Make trust boundaries and security assumptions explicit.
- Treat all external input as untrusted — validate at every boundary.
- Avoid fail-open behavior unless explicitly required and documented.
- Preserve forensic integrity; never silently drop or modify event data.
- Use bounded queues, explicit backpressure, and deterministic overload policies.
- Design persistent state for crash consistency using the `BookmarkStore`
  unified-commit pattern: `UpdateCache` -> `tx.Begin` -> batch INSERTs + bookmark
  UPSERT -> `tx.Commit` -> `MarkCommitted`; `RollbackCache` on failure.
- Avoid unbounded memory growth, silent data loss, and uncontrolled retry loops.
- Use least privilege; minimize kernel-mode functionality.
- Document performance costs and security trade-offs.
- Provide observable failure modes via structured `ILogger<T>` logs,
  `ServiceMetrics`, and the IPC Diagnostic command.
- Ensure installation, upgrade, rollback, and removal are safe and repeatable.

---

## Implementation Requirements

### General

- Write production-ready code, not illustrative pseudocode.
- Target **C# 12 / net8.0-windows / SDK 8.0.424** — do not use C# 13 features.
  `LangVersion=latest` resolves to **C# 12** on SDK 8.0.x.
- Preserve backward compatibility unless a breaking change is explicitly authorized.
- Validate inputs at every trust boundary.
- Handle cancellation, timeouts, concurrency, and resource disposal explicitly.
  Every `async` method must accept and honor `CancellationToken`.
  No `.Result`, `.Wait()`, or `Task.Run` without a token.
- Do not swallow exceptions without an explanatory comment (see
  `RingBufferEventPipe.ReleaseSignalSafe` as the canonical example).
- Include tests for normal, failure, recovery, and adversarial scenarios.
- Identify security-sensitive code and explain its invariants.
- Do not invent APIs, protocol fields, event schemas, or Windows behavior.

### Zero-Alloc Hot Path (Non-Negotiable)

Event ingestion, normalization, alert evaluation, and DB writes MUST NOT allocate
on the managed heap:

- Use `Span<T>`, `ReadOnlySpan<T>`, `ref struct`, `stackalloc`, `SearchValues<T>`,
  and `ArrayPool<T>.Shared`.
- Do NOT write `new` (reference types), `ToString()`, or `$"..."` in any hot path.
- Do NOT use LINQ (`Where`, `Select`, `Any`, `Count`) in hot paths.
  Use `foreach` over `Span` or raw arrays.
- Use `System.Runtime.Intrinsics.Vector128/256` (SSE4.2/AVX2) for IP parsing,
  CIDR matching, hex/decimal validation, and byte-sequence scanning.
- Use `BinaryPrimitives.ReadUInt32LittleEndian(span)` for all RDP PDU reads.
- Rent buffers from `ArrayPool<byte>.Shared` or `ObjectPool<T>`. Return in `finally`.
  Never dispose a pooled object — return it.
- Every new hot path MUST include a `GC.GetAllocatedBytesForCurrentThread` assertion
  proving zero allocation per 10,000 evaluations.

### Concurrency and Ring Buffer

- `IEventPipe` is the **only** public surface for event transport. Workers must not
  depend on `EventChannel` or `RingBufferEventChannel` directly.
- The `RingBufferEventPipe` `SemaphoreSlim` (maxCount=1) signal-after-write is the
  canonical consumer wake-up pattern. Do not introduce polling loops in new consumers.
- `SpinWait`-based `TryRead` loops are acceptable only inside `UnmanagedSpscRingBuffer`.
- New MPMC transports must use `Interlocked.CompareExchange`, `Volatile.Read/Write`,
  and `[StructLayout(LayoutKind.Explicit)]` with `CACHE_LINE_SIZE=64` padding.
- `EventCollectorHost` owns a host-scoped `CancellationTokenSource` that is cancelled
  in `DisposeAsync` — do not add a separate shutdown CTS in the hosted worker shim.

### Database (Hot Path)

- EF Core is used **only** for: migrations (`AuditDbInitializer`), config reads,
  and WinForms UI queries.
- Hot-path persistence uses raw `SqliteCommand` + `SqliteTransaction`.
- Batch 1,000+ rows per `COMMIT`.
- SQLite pragmas: `journal_mode=WAL; synchronous=NORMAL`.
- Follow the `BookmarkStore` unified-commit pattern for any writer that must be
  crash-consistent with an event batch.
- When adding columns to `RawEvents` or other high-volume tables: always use a
  partial unique index filtered on `column > 0` (or equivalent non-default sentinel)
  if the column has a uniqueness constraint — legacy rows are backfilled and must not
  collide with the sentinel value.

### P/Invoke and OS Handles

- Use `[LibraryImport]` (source-generated) only. Never `[DllImport]`.
- Wrap every OS handle in a `SafeHandle` subclass. No bare `IntPtr`.
- Set `SetLastError = true`; check `Marshal.GetLastPInvokeError()`.

### Code Style

- **TABS** for indentation.
- **English only**: identifiers, comments, XML docs, log messages, error messages.
- **Nullable reference types** enabled. Nullable warnings = build errors.
- **Structured logging**: `ILogger<T>` with named properties.
  No `$"..."` or string concatenation in `Log.*` calls.
- **UTC internally**. Local time only in UI rendering.
- **`ValueTask`** for sync-completion hot paths; `Task` elsewhere.

---

## File Header Standard

Every full `.cs` file **must** begin with exactly:

```csharp
/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : <FileName>.cs
// Project: <ProjectName> (RdpAudit.<Layer>)
// Purpose: <One sentence — what this file does and why it exists>
// Depends: <Key types/interfaces this file directly uses, comma-separated>
// Extends: <What to change here when adding a new event channel / alert rule / UI page>
```

For **snippets or functions only**: omit the author header. Add only
`// Version: 2.0.2` above the function when the version changes.

---

## Block Structure

Organize non-trivial classes with these banner comments, in order:

```csharp
// ── Fields & DI ──────────────────────────────────────────────────────────────
// ── Construction ─────────────────────────────────────────────────────────────
// ── Public API ───────────────────────────────────────────────────────────────
// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────
// ── Core Logic ───────────────────────────────────────────────────────────────
// ── Error Handling & Retry ───────────────────────────────────────────────────
// ── Disposal & Pool Returns ──────────────────────────────────────────────────
```

---

## Adding a New Alert Rule

1. Create `src/RdpAudit.Service/Alerts/<RuleName>Rule.cs` with the full file header.
2. Inherit `AlertRuleBase`; set `RuleId = "SCREAMING_SNAKE_CASE"` (unique, immutable).
3. Implement `EvaluateAsync(ReadOnlySpan<byte> rawEvent, IAlertContext ctx, CancellationToken ct)`.
   Zero heap allocations.
4. Wire `IsEnabled()` against `AlertOptions` in `appsettings.json`.
5. Register in `AlertRuleRegistration.Register(services)`.
6. Unit tests must cover: threshold edges, whitelisted IPs, and a
   `GC.GetAllocatedBytesForCurrentThread` assertion proving zero allocation per 10k runs.

---

## Adding a New Event Channel

1. Register the `EventDescriptor` in `EventCatalog.BuildCatalog()`.
   Set `Preset`, `Criticality`, `DefaultRetentionDays`, `RequiredEventIds`.
   `DefaultRetentionDays = 0` means **retain forever** — never touch with retention logic.
2. Add the channel string constant (`ChannelXxx`) to `EventCatalog`.
3. Default-enable new event IDs in `appsettings.json` (`MonitoringOptions.EnabledEventIds`).
4. Implement zero-alloc normalization in `EventXmlParser` using `ref struct` parsers.
   No `XmlDocument`, no `Regex`, no string allocations.
5. Add prerequisite check in `PrerequisiteChecker.cs` (auditpol SACL + `wevtutil` enabled).
6. Register the ETW provider GUID in the `IEventSource` abstraction for v2.0 ETW swap.

---

## Adding a New Hosted Worker

1. Create `src/RdpAudit.Service/Workers/<Name>Worker.cs` with the full file header.
2. Inherit `BackgroundService`. Accept `CancellationToken` everywhere.
3. Register with `services.AddTimedHostedService<TWorker>(nameof(TWorker))` in
   `Program.RegisterServices`. Position based on dependency order — consult the
   ordering rationale comment in `Program.cs`.
4. Add at least one integration test covering clean startup, graceful cancellation,
   and a simulated fault mid-loop.

---

## Response Requirements

Before proposing changes:

1. Inspect the relevant source files, tests, migration history (`Migrations/`),
   `appsettings.json`, `EventCatalog`, and `Program.cs` composition.
2. Identify affected trust boundaries and failure modes.
3. Confirm the change compiles on **SDK 8.0.424 / C# 12 / net8.0-windows**.
4. Explain trade-offs, including allocation cost and latency impact.
5. Prefer the smallest change that fully solves the problem without breaking
   the unified-commit invariant, zero-alloc contract, `IngestionSequence`
   partial-index contract, or `IEventPipe` abstraction.
6. Provide verification steps: which test to run, which log to inspect,
   which SQLite table/PRAGMA to query.
7. Include rollback guidance for schema changes (migration naming:
   `StageNN<Description>` or `yyyyMMddHHmmss_<Description>`), IPC protocol
   changes, and `appsettings.json` structural changes.

Do not claim that code was compiled, tested, benchmarked, or deployed unless
those actions were actually performed in this session.

---

## Debug and Observability Cheat Sheet

| Target | Command / Path |
|---|---|
| Console mode | `RdpAudit.Service.exe --console` (or attach debugger) |
| Enable debug logging | `RDPAUDIT_RdpAudit__Diagnostics__DebugMode=true` or `RDPAUDIT_RdpAudit__LogLevel=Debug` |
| Database | `%ProgramData%\RdpAudit\rdpaudit.db` — DB Browser for SQLite |
| IPC smoke test | PowerShell `NamedPipeClientStream` -> `\\.\pipe\RdpAuditService` |
| ETW live trace | `logman create trace RdpAudit -p "Microsoft-Windows-TerminalServices-RemoteConnectionManager" -o rdpaudit.etl -ets` |
| Startup hang | `%ProgramData%\RdpAudit\logs\startup-sequence.log` — find `BEGIN` with no matching `END` |
| Ring buffer health | `ServiceMetrics.OverflowCount` / `RingBufferUtilization` via IPC Diagnostic |
| Debug log | `%ProgramData%\RdpAudit\RDPAudit_DEBUG_Log.txt` |
| Schema inspection | `PRAGMA table_info('RawEvents'); PRAGMA index_list('RawEvents');` |

---

## Quality Gate (Before Delivering Any Change)

1. **Compiles on SDK 8.0.424** — no C# 13 syntax, no `net9.0` references.
2. **Zero allocations** on the hot path — `GC.GetAllocatedBytesForCurrentThread` delta == 0.
3. **No `.Result`, `.Wait()`, or sync-over-async** in the diff.
4. **No LINQ** in hot paths.
5. **No bare `IntPtr`**, no `[DllImport]`, no `new byte[]` on the hot path.
6. **`CancellationToken`** accepted and forwarded by every new async method.
7. **File header** present and correct (`Version: 2.0.2`) on every new `.cs` file.
8. **`dotnet test` green** — including allocation assertions.
9. **Unified-commit invariant preserved** — no new writer persists events and
   bookmarks in separate transactions.
10. **`IngestionSequence` contract preserved** — any new column with uniqueness on
    `RawEvents` must use a partial index filtered on non-zero sentinel; backfill
    must use `COALESCE(MAX(...), 0) + 1`, never assign literal `0`.
11. **`EventCatalog` updated** for any new monitored event ID.
12. **`TimedHostedService` wrapping** for any new `IHostedService`.
13. **No suppressed CA codes reintroduced** from the `Directory.Build.props` `NoWarn` list.
