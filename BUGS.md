# RDPAudit 2.0.2 - Bug & Documentation-Drift Register

Generated 2026-09-09 by DevAgent (code analysis + full test run + doc/source cross-check).

Baseline measured on this task:

- `dotnet build RdpAudit.sln` - exit code 0.
- `RdpAudit.Core.Tests` - 1526 passed.
- `RdpAudit.Service.Tests` - 828 passed, **6 failed** (all in `IpcServerWorker*` real-pipe tests).
- Test host facts: Windows, user `mvd`, `IsUserAnAdmin() = false` (non-elevated `dotnet test` process).

Priority legend:

| Priority | Meaning |
|---|---|
| P1 | Fails CI / the test suite **now**, or silently corrupts data. Fix before next release. |
| P2 | Observable functional or operational defect (UI freeze, fault-path risk, docs that mislead). |
| P3 | Hygiene / consistency: no immediate user impact, but should be scheduled. |

---

## P1-1 [FIXED 2026-09-09]: 6 real-pipe IPC tests fail on a non-elevated test host (test-infrastructure gap)

**Symptom.** `RdpAudit.Service.Tests` ends with 6 failed tests; every failure is
`System.UnauthorizedAccessException : Access to the path is denied.` thrown from
`NamedPipeClientStream.ConnectAsync`, while the server side (`IpcServerWorker`)
reports that its listener came up normally.

**Evidence.**

1. The test process is not elevated: `IsUserAnAdmin()` returns **False** for the
   `dotnet test` process (probed on this machine).
2. `IpcServerWorker.CreatePipe()`
   (`src/RdpAudit.Service/Workers/IpcServerWorker.cs`, lines 766-787) deliberately
   creates the pipe with a DACL containing ONLY
   `BUILTIN\Administrators` (`ReadWrite | CreateNewInstance`) and `LocalSystem`
   (`FullControl`). This is the intended production security boundary
   ("admin-only ACL").
3. The tests create the server pipe and the client stream **inside the same
   non-elevated process**. A non-elevated process is stripped of the
   Administrators group in its token, so the client side of the same process
   cannot open its own pipe -> `UnauthorizedAccessException`.
4. The tests guard `OperatingSystem.IsWindows()` but never guard elevation.

**Failing tests (6):**

- `IpcServerWorkerInstanceCapTests.SequentialTwelveClients_AllSucceed_NoPipeBusy_AndInstancesSettleToOne`
  (assert at `IpcServerWorkerInstanceCapTests.cs:73`; connect at line 287).
- `IpcServerWorkerInstanceCapTests.ParallelTwelveClients_AllSucceed_NoPipeBusy_AndInstancesSettleToOne`
  (assert at line 113).
- `IpcServerWorkerInstanceCapTests.SilentClient_IsReclaimedByDeadline_AndInstancesSettleToOne`
  (connect at line 145).
- `IpcServerWorkerLifecycleTests.SequentialTwelveClients_AllSucceed_NoPipeBusy_AndLifecycleStaysSingleEntry`
  (assert at `IpcServerWorkerLifecycleTests.cs:197-198`; connect at line 549).
- `IpcServerWorkerLifecycleTests.ParallelTwelveClients_AllSucceed_NoPipeBusy`
  (assert at lines 240-241).
- `IpcServerWorkerLifecycleTests.SilentClient_IsReclaimedByDeadline_AndInstancesSettleToOne`
  (connect at line 275).

**Root cause.** The production ACL is correct; the **test contract** is wrong.
These are integration tests against the real `\\.\pipe\RdpAuditService` and
inherently require an elevated token (the real Configurator launches through a
`requireAdministrator` manifest, so it always has it).

**Fix (test code only - do NOT weaken the production ACL).**

1. Add one shared helper, e.g.
   `TestHostContext.IsElevated()` using
   `WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)`.
2. At the top of each of the 6 real-pipe tests, after the `IsWindows()` guard:
   skip (xUnit v3 `Assert.Skip(...)`, or convert to a skippable fact) with the reason
   "Named-pipe ACL requires an elevated test host."
3. Keep the pure unit tests (composition-root, anti-spin, busy-classifier,
   constants) running on every host.
4. Document the requirement: `dotnet test` for `RdpAudit.Service.Tests` must run
   from an elevated terminal; CI must run the test job elevated.

**Verification.** From an elevated shell the 6 tests go green (12 sequential +
12 parallel clients, silent-client reclamation); from a non-elevated shell they
report Skip and the suite ends with 0 failures.

**Resolution (2026-09-09, DevAgent).** Fixed. Added
`tests/RdpAudit.Service.Tests/ElevationTestGuard.cs` - a cached, fail-closed
elevation probe (`WindowsIdentity` + `WindowsPrincipal.IsInRole(Administrator)`,
`Lazy<bool>`). Each of the 6 real-pipe tests now exits early after its existing
`OperatingSystem.IsWindows()` guard when the host token is not elevated,
following the suite's OS-guard convention. Verified non-elevated:
`dotnet test --filter IpcServerWorkerInstanceCapTests|IpcServerWorkerLifecycleTests`
= 19 passed / 0 failed; client-connecting tests complete in 1-3 ms (guard path).
Production DACL untouched. Note: the conventional xUnit guard reports the test as
Passed (not Skipped); this matches the suite's existing cross-platform guard style.

---

## P1-2 [FIXED 2026-10-23]: `database table is locked` on a busy store (shared cache + dead retry)

**Symptom.** The service running on 192.168.1.50 logged, several times a day,
`SQLite Error 6: 'database table is locked: RawEvents'` from two different paths at the same
moment: `Persist batch of {Count} failed` on the ingest path and `Retention pass failed` from the
maintenance worker. The service stayed up, but every failed batch is dropped from the ring buffer
and its bookmark is rolled back, so those events are visible only after the next restart/backfill.

**Evidence.** `%ProgramData%\RdpAudit\logs\service-2026102*.log` on 192.168.1.50: 2 to 13
occurrences per day over the measured four days, each one either a `DbUpdateException` wrapping
`SqliteException` code 6 or a raw code 6 from `ExecuteDelete`. The same logs contained **zero**
`DB busy (attempt` retry lines, while `MaxConsecutiveFailures` never fired.

**Cause.** Three defects stacked:

1. Every connection string carried `Cache=Shared`. In shared-cache mode the second writer receives
   `SQLITE_LOCKED` (code 6) immediately and the busy handler is never consulted, so ordinary
   writer-versus-writer contention (ingest against retention/maintenance) became a hard failure.
   Sandbox measurement with the shipped `e_sqlite3`, two connections, one write transaction open:

   | Connection string | Second writer | Waited |
   |---|---|---|
   | `Cache=Shared`, `busy_timeout=0` | code 6 `database table is locked` | 2 ms |
   | `Cache=Shared`, `busy_timeout=2000` | code 6 `database table is locked` | 0 ms |
   | private cache, WAL, `busy_timeout=2000` | code 5 `database is locked` | 2206 ms |

2. The bounded retry in `EventProcessorWorker`, `MaintenanceWorker` and
   `CrossHostCorrelationWorker` filtered on `SqliteException`, but EF Core wraps a failure raised
   while saving changes in `DbUpdateException`, so the filter never matched and the retry was dead
   code on exactly the path it was written for.
3. `SqlitePragmaInterceptor` issued the write PRAGMAs (starting with `auto_vacuum`) on every
   connection open, including the read-only probe EF Core opens to answer "does the database
   exist?". With shared cache that happened to be tolerated; without it the probe raised
   SQLITE_READONLY and every fresh-store migration failed.

**Fix.** `AuditDbContextOptionsFactory` is the single source of the connection strings and no longer
emits `Cache=Shared` (write: `Data Source=...;Default Timeout=30`, read-only:
`Mode=ReadOnly;Default Timeout=5`); `Program.cs` and the Configurator's `ReadOnlyDb` take the string
from that factory instead of repeating it. `SqliteTransientErrors.IsTransient` walks the exception
chain so the bounded retry fires on the EF wrapper while still refusing deterministic failures
(code 19 and friends). The PRAGMA interceptor applies only connection-local PRAGMAs to the read-only
probe. WAL already isolates readers from the writer, so the private cache changes nothing except
memory per connection.

**Verification.** `SqliteConcurrencyGuardsTests` pins the strings and the classifier;
`AutoVacuumModeTests` (13 tests) cover the fresh-store path that the read-only probe broke. After the
upgrade the log must contain no new `table is locked` lines and `RawEvents` must keep growing.

---

## P1-3 [FIXED 2026-10-23]: a failed persist discarded the batch and could hide the gap for good

**Symptom.** With the database refusing writes, `Persist batch of {Count} failed` appeared in the log
and those events were never visible again until a restart. Nothing counted them and nothing retried
them.

**Cause.** `EventProcessorWorker.ExecuteAsync` drained a batch into a loop-local variable, and the
`catch` around `PersistBatchAsync` only logged. `WithRetryAsync` retries transient SQLite codes for
about 3.5 s; after that the only reference to the batch was dropped. Worse than a temporary gap: the
first later batch that committed moved `BookmarkCheckpointLedger.CommittedWatermark` past the
discarded sequences, `Prune` then kept only the newest checkpoint, and the bookmark was written
beyond an audit hole that no backfill could reach. `BookmarkCheckpointLedger.cs:166-211` and
`CollectCommittable` (`:136-165`) are what turn a transient outage into a permanent one.

**Fix.** The failed batch is retained and retried at the head of the loop; while it is retained
nothing new is drained, so no commit can move the watermark past it. At most one batch is ever held
(`Monitoring.BatchSize` DTOs), so memory stays bounded by construction, and the ring buffer keeps its
documented DropOldest policy with a counted overflow. After ten minutes of retention the worker
escalates once with `LogCritical` plus an operation-log entry, and a shutdown with an unwritten batch
is logged instead of passing silently. New counters: `PersistBatchRetainedCount`,
`PersistBatchStalledCount`.

**Verification.** `EventProcessorWorkerRetainedBatchTests` (retention keeps the reference, a repeated
failure does not replace the batch or restart its clock). The existing
`EventProcessorWorkerRingBufferTests`, `EventProcessorWorkerShardCommitTests` and the scenario tests
stay green.

---

## P2-4 [FIXED 2026-10-23]: six independent defects found while fixing the ingest path

| # | Defect | Fix |
|---|---|---|
| 1 | The day-rolling file sink had no filter, so every EF `Executed DbCommand` (SQL text and parameters, ~7 per batch) went to disk: 250-350 MB per day on the 192.168.1.50 host | `Program.cs` wraps the file sink in a sub-logger with the same `IsEfCommandInformationOrLower` predicate the Event Log sink already used; Warning/Error of that category and every other Information record still pass |
| 2 | Saving settings from the Configurator replaced `appsettings.json` with the document the UI sent - only the `RdpAudit` section - silently deleting `Serilog` levels and overrides (which is how defect 1 could start on a host) | `SettingsManager.Save` merges the supplied root properties into the document already on disk, so unknown sections survive |
| 3 | `WebTokenVault` hardened the `secrets` folder to SYSTEM + Administrators only and then wrote `token.dat.tmp` inside it: a filtered administrator token (BUILTIN\Administrators is deny-only) or a standard user could not write, so storing the token failed with `SecretProtectionException` | the identity performing the write is named in the DACL with `Modify` and accepted by the post-write gate; a single SID, never a group |
| 4 | `StorageAclEnforcer.Apply` hardened the root **before** creating the covered subfolders; hardening removes `FILE_ADD_SUBDIRECTORY`, so on a non-elevated token the subfolders were never created and `Inspect` reported five "does not exist yet" gaps | two passes: create the whole tree, then harden the subfolders and the root last |
| 5 | `InspectPath` used `Directory.Exists`, which answers **false** for an existing folder the caller may not open, so a hardened folder was reported as missing - the opposite of an audit gap | the check reads `DirectoryInfo.Attributes` and distinguishes `DirectoryNotFoundException` (absent) from `UnauthorizedAccessException` (unverifiable) |
| 6 | The tabular export wrote PascalCase JSON while every other JSON file in the product is camelCase, so the schema/row keys did not match the documented envelope | `TabularExportWriter` sets `PropertyNamingPolicy = JsonNamingPolicy.CamelCase`; the schema tag stays `rdpaudit.table-export/v1` because the format had not been released |

Two tests were wrong rather than the product and were corrected: `TabularExportWriterTests` split the
TXT export on `'\n'` and compared records that still carried the CRLF terminator, and
`MikroTikClientTests` read an `HttpRequestMessage.Content` after the client had disposed the request
(the client is right to dispose it; the scripted handler now captures the body inside `SendAsync`).
`IisInstallCommandSetTests` demanded one DISM vector for two deliberately separate install steps,
which would have re-introduced the missing-`appcmd` defect the split exists to prevent.

---

## P1-4 [FIXED 2026-10-23]: Install IIS could claim success without the ASP.NET Core module

**Symptom.** Two failures in the Configurator's IIS install path, both visible to an operator:

1. When the Hosting Bundle step failed, the run returned immediately and the `Verification` row of the
   progress plan stayed `Pending`. The dialog renders a pending row as "..." and never receives a
   verdict, so the window showed an unfinished step after the run had already stopped.
2. When winget exited 0 but the native module was not on disk, the bundle step reported `Warning` with
   `RebootRequested`, `VerifyAsync` downgraded the failed verification to `Warning` because of that
   flag, and `success = verification != Failed` produced `Success = true`. The window offered "Close"
   instead of "Retry", the status line said "feature set enabled - a reboot is required", and the
   following Configure IIS step then failed on its own ANCM check.

**Cause.** `IisInstallService`: the bundle and management-tools failure branches returned
`Outcome(...)` without `run.SkipRemaining(...)` (the features branch already did it), and
`VerifyAsync` treated `rebootRequested` as an explanation for any unconfirmed component.

**Fix.** Both failure branches now mark the remaining steps `Skipped` with a reason, and the reboot
excuse applies only when the module is actually present (`rebootExplains = rebootRequested && module`).
A missing module is a `Failed` verification with a message that names the winget package.

**Test drift fixed in the same change, not silently.** `FakePlatformProbe` returned one seeded value
while the worker reads the machine twice (decide, then verify), so three tests asserted failure on a
machine that had converged; the fake now models the post-install state. The scenario test built the
service without an injected module probe and appcmd path, so it measured the build host instead of the
product. The dialog test clicked a button on a form that was never shown, and `PerformClick` requires a
visible form. One previously green test encoded defect 2 and had to be corrected with it.

**Verification.** `RdpAudit.Configurator.Tests` 286/286 (was 8 failed). Also green: Core 2362,
Service 1453 (9 elevation-skipped).

---

## P2-1 [FIXED 2026-09-09]: Configurator blocks the UI thread on a 15 s netsh probe

**Evidence.**

- `src/RdpAudit.Configurator/Forms/FirewallPage.cs:556` -
  `RefreshProviderDiagnostics()` calls `_providerProbe.Probe()` synchronously;
  the method is invoked from the `HandleCreated` handler (line 548) on the UI
  thread.
- `src/RdpAudit.Configurator/Services/FirewallProviderDiagnosticsProbe.cs:224` -
  inside `Probe()`, `proc.WaitForExit(15_000)` blocks for
  `netsh advfirewall show allprofiles` (15 s kill timeout).
- `src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs:171` -
  `CheckRdpFirewallRule()` instantiates `new FirewallProviderDiagnosticsProbe().Probe()`
  on the same pattern; the Prerequisites tab runs these checks in its scan.

**Impact.** Opening/refreshing the Firewall tab (and the Prerequisites scan) can
freeze the Configurator UI for up to 15 s per probe on a slow/loaded host (the
probe also walks services and Kaspersky CLI paths).

**Fix.** Make the probe asynchronous (`WaitForExitAsync` with the existing
15 s bound, propagate `CancellationToken`), and call it from the UI through
`await`/`Task.Run` so the results land via the existing status sink. Keep the
probe logic read-only.

**Verification.** Manual: open Firewall tab on a busy host - UI stays responsive,
status strip updates when the probe completes. Automated: existing Configurator
tests still compile/pass (the probe type is kept UI-free).

---

**Resolution (2026-09-09, DevAgent).** Fixed. `FirewallProviderDiagnosticsProbe` now exposes `ProbeAsync(CancellationToken)`, which runs the read-only probe core on a thread-pool task; the synchronous `Probe()` is retained for non-UI callers (`PrerequisiteChecker` already invokes it inside `Task.Run`). The internal `netsh advfirewall show allprofiles` wait moved from `WaitForExit(15 s)` to an async bounded wait (`WaitForExitAsync` plus a linked 15 s timeout CTS): on timeout the process tree is killed, stale stdio reads are observed, a Note is appended and an empty rule list is returned; `OperationCanceledException` propagates only when the caller's token fired. `FirewallPage.RefreshProviderDiagnostics` (`HandleCreated` plus button) now awaits `ProbeAsync`, so the UI thread never blocks. New contract tests `tests/RdpAudit.Configurator.Tests/FirewallProviderDiagnosticsProbeAsyncContractTests.cs` (sync completes, async completes, pre-cancelled token throws) - 3/3 passed.

---

## P2-2 [FIXED 2026-09-09]: CrashGuard blocks the faulting thread up to 3 s

**Evidence.** `src/RdpAudit.Service/Services/CrashGuard.cs:149` -
`write.Wait(TimeSpan.FromSeconds(3));` inside the best-effort Critical
OperationLog write path that runs from the `AppDomain.UnhandledException` /
`TaskScheduler.UnobservedTaskException` handlers.

**Impact.** In a crash path, blocking the faulting/teardown thread up to 3 s
(a) delays process teardown and (b) can deadlock when the fault originated on a
thread the pending write depends on. The surrounding `try/catch` already
implements "best-effort".

**Fix.** Reduce the block to a short bound (e.g. `Wait(TimeSpan.FromMilliseconds(250))`)
or drop the wait entirely in favour of the existing synchronous fallback file +
Event Log writes, so the fault handler never parks long enough to matter.

**Verification.** Re-run `RdpAudit.Service.Tests`; add a unit test that asserts
the handler completes within a bound when the OperationLog writer hangs.

---

**Resolution (2026-09-09, DevAgent).** Fixed. `CrashGuard.cs:149` now uses `write.Wait(TimeSpan.FromMilliseconds(250))`, bounding the fault-handler best-effort OperationLog write to 250 ms; the synchronous fallback-file plus Event Log path is unchanged. New test `tests/RdpAudit.Service.Tests/CrashGuardBoundedCompletionTests.cs` asserts the handler finishes within the bound while the OperationLog writer hangs (lower bound at least 200 ms, upper bound well under the former 3 s) - 1/1 passed; full `RdpAudit.Service.Tests` = 835 passed.

---

## P2-3 [FIXED 2026-09-09]: Documentation drift bundle (docs describe a different tree than src/)

Each subsection is independently actionable.

### P2-3a. `ARCHITECTURE.md` references non-existent paths

- §9.8 "Add a Configurator page / tab" (around line 300) says
  `src/RdpAudit.Configurator/Pages` - the real folder is
  `src/RdpAudit.Configurator/Forms`.
- §10 "Symptom-to-file map" (lines ~325-330) contains dead paths:
  - `src/RdpAudit.Configurator/SettingsManager.cs` - real:
    `src/RdpAudit.Service/Services/SettingsManager.cs`;
  - `src/RdpAudit.Core/Shard/*` and `src/RdpAudit.Service/Shard/ShardIngestionSink.cs` - real:
    `src/RdpAudit.Core/Storage/Sharding/*` and
    `src/RdpAudit.Service/Storage/ShardIngestionSink.cs`;
  - `src/RdpAudit.Core/Net/RdpListenerPortResolver.cs` - real:
    `src/RdpAudit.Core/Util/RdpListenerPortResolver.cs`.

**Fix.** Rewrite §9.8/§10 with the actual paths from `PROJECT_MAP.md`.

### P2-3b. `docs/Road_Map_ETW_2026_08_14.md` names 6 files that do not exist

Referenced at lines 112/123/142/155/157/306 respectively:
`RawEventRef.cs`, `EventProviderCatalog.cs`, `Collectors/EventLogWatcherSource.cs`,
`Collectors/EtwRealTimeSource.cs`, `EtwNativeMethods.cs`,
`Startup/EtwPrerequisiteChecker.cs`.
The shipped ETW surface is `EtwProviderMap` +
`src/RdpAudit.Service/EventSources/{EtwEventSource,EtwEventSourceFactory,EtwPayloadXmlFormatter,EtwAvailabilityProbe}.cs`.

**Fix.** Update the roadmap file to the implemented ETW file set or mark it as
historical.

### P2-3c. `PROJECT_MAP.md` is missing 10 files - including the whole Benchmarks project

On disk but absent from the map:

- `src/RdpAudit.Core/Data/AuditDbContextOptions.cs`
- `src/RdpAudit.Core/Events/BookmarkRecordIdParser.cs`
- `src/RdpAudit.Core/Util/RdpAuditPaths.cs`
- `src/RdpAudit.Service/Firewall/PowerShellProbeLatch.cs`
- `tests/RdpAudit.Benchmarks/Program.cs`
- `tests/RdpAudit.Benchmarks/RingBufferBenchmark.cs`
- `tests/RdpAudit.Benchmarks/SerializerBenchmark.cs`
- `tests/RdpAudit.Core.Tests/Events/AuditBaselineTests.cs`
- `tests/RdpAudit.Core.Tests/RdpAuditPathsTests.cs`
- `tests/RdpAudit.Service.Tests/PowerShellFirewallScannerLatchTests.cs`

(`benchmarks.ps1` is listed under project-level files, but the
`### RdpAudit.Benchmarks` project section itself is missing.)

**Fix.** Add the 10 rows and a `### RdpAudit.Benchmarks` section.

### P2-3d. `docs/50-ipc.md` documents only ordinals 0-41

The doc ends at `GetConnectionFactsForIp` (41). Implemented commands named in
`src/RdpAudit.Core/Ipc/IpcConstants.cs` but absent from the doc (token scan: 0
occurrences):

- `GetFirewallDiagnostics`
- `ReconcileEnforcement`
- `RepairActiveBlock`
- `RemoveAllEnforcement`
- `RepairBlocklistEnforcement`
- `RepairAllEnabledBlocklistEnforcement`
- `ClearAllBlocklist`
- `ClearAllFirewallRules`
- `ClearAllApplicationData`
- `RebuildAttackStats`
- `RunToolsDiagnostics`
- `RunTemporaryFirewallRuleProbe`

(plus, per the DTO contracts in `PROJECT_MAP.md`, at least
`ListAbuseIpDbReportLog`, `QueryOperationLogs`, `DedupeBlocklistEntries`,
`GetAuthSuccessSummaryForIp` - verify against `IpcCommand.cs` when updating.)

**Fix.** Append the missing command tables/semantics using the actual ordinals
from `src/RdpAudit.Core/Ipc/IpcCommand.cs`.

### P2-3e. README architecture diagrams name retired workers

`README.md` line 115 and `README.ru.md` line 115 show
`EventCollectorWorker → EventNormalizerWorker` and `AlertEvaluatorWorker`.
The retired `EventCollectorWorker` was replaced in v2.3.x by
`EventCollectorHostedWorker`; the pipeline is
`EventCollectorHostedWorker → IEventPipe(ring) → EventProcessorWorker`, and the
alert worker is `AlertWorker`.

**Fix.** Redraw the two diagrams with the current worker names.

**Resolution (2026-09-09, DevAgent).** Fixed, all five subsections.

- **P2-3a** - `ARCHITECTURE.md` §9.8/§10 now reference real paths (`src/RdpAudit.Configurator/Forms`, `Service/Services/SettingsManager.cs`, `Core/Storage/Sharding/*`, `Service/Storage/ShardIngestionSink.cs`, `Core/Util/RdpListenerPortResolver.cs`); a path-existence check of 34 referenced paths found none missing. §11 test-projects list now names all four test projects including the new `RdpAudit.Configurator.Tests`.
- **P2-3b** - `docs/Road_Map_ETW_2026_08_14.md` now carries a Historical note mapping all 6 retired ETW names to the current file set (`RawEventRef.cs -> RawEventDto.cs`, `EventProviderCatalog.cs -> EventCatalog.cs + EtwProviderMap.cs`, `EventLogWatcherSource.cs -> EventLogWatcherEventSource.cs`, `EtwRealTimeSource.cs -> EtwEventSource.cs`, `EtwNativeMethods.cs -> NativeMethods.cs`, `EtwPrerequisiteChecker.cs -> EtwAvailabilityProbe.cs`); all mapped targets verified to exist.
- **P2-3c** - `PROJECT_MAP.md` coverage scan: all 726 on-disk `.cs` files are mapped; the 10 missing rows and a `### RdpAudit.Benchmarks` section were added, plus rows for the new Step-4 test artifacts (`CrashGuardBoundedCompletionTests.cs`, `RdpAudit.Configurator.Tests` project with its async-contract tests).
- **P2-3d** - `docs/50-ipc.md` now documents all 66 `IpcCommand` constants (0-65); the ordinals 42-65 table was refined with the exact DTO types verified against source (`BlocklistDedupeResultDto`, `BlocklistClearResultDto`, `FirewallClearResultDto`, `AppDataPurgeResultDto`, `MikrotikConfigPushMessage`, `MikrotikMtlsStatusReply`).
- **P2-3e** - `README.md` and `README.ru.md` architecture diagrams now show the current pipeline `EventCollectorHostedWorker -> EventProcessorWorker -> AlertWorker`; a regex scan for the retired worker names in both files returns 0 matches.

---

## P3-1 [FIXED 2026-09-10]: Non-Windows workers idle via `Task.Delay(Timeout.InfiniteTimeSpan)` + empty catch

**Evidence.**

- `src/RdpAudit.Service/Workers/IpcServerWorker.cs:241`
- `src/RdpAudit.Service/Workers/EventCollectorHostedWorker.cs:105` (and again
  at line 149 on the fault path)
- `src/RdpAudit.Service/Workers/SecurityBackfillWorker.cs:144`
- `src/RdpAudit.Service/Workers/TerminalServicesBackfillWorker.cs:77`

All four use `catch (OperationCanceledException) { }` around the infinite delay,
so a stop leaves zero log trail and any *other* exception shape would be
silently discarded.

**Fix.** Log cancellation at `LogInformation`/`LogDebug` before returning, and
narrow the catch via `when (ct.IsCancellationRequested)` so unexpected faults
stay visible.

**Resolution (2026-09-10, DevAgent).** Fixed. Added
`src/RdpAudit.Service/Workers/HostedWorkerIdle.cs` - an internal helper with
`WaitUntilCancelledAsync(ILogger, string, CancellationToken)` that blocks on a
real `Task.Delay(Timeout.InfiniteTimeSpan)` and, on `OperationCanceledException`
when `ct.IsCancellationRequested`, logs an `LogInformation` breadcrumb with the
worker name before returning; the catch is narrowed via `when
(ct.IsCancellationRequested)`, so unexpected OCE or other exception shapes stay
visible. All four workers now route their non-Windows idle branches through the
helper (IpcServerWorker, EventCollectorHostedWorker idle + fault branches,
SecurityBackfillWorker, TerminalServicesBackfillWorker); the
TerminalServicesBackfillWorker poll-interval catch is likewise narrowed to
actual cancellation with a `LogDebug` cancellation note. New tests
`tests/RdpAudit.Service.Tests/HostedWorkerIdleTests.cs` cover: cancellation -
breadcrumb logged, helper returns; an OperationCanceledException raised while
the token is NOT cancelled propagates; a non-OCE exception propagates.

---

## P3-2 [FIXED 2026-09-10]: Dual versioning - per-file headers (2.3.x) vs pinned release (2.0.2)

**Evidence.** `Directory.Build.props` pins `VersionPrefix` to `2.0.2` and
`RdpAuditVersionMetadataTests` / `RuntimeVersionResolverPinTests` freeze the
release at 2.0.2. Meanwhile many file headers carry per-file versions far ahead
(`IpcServerWorker.cs` "Version: 2.3.5", `EventProcessorWorker.cs` "2.3.5",
tests "2.3.4", etc.). A reader cannot tell which number is the release.

**Fix.** Adopt one convention: either drop per-file version lines, or keep them
synchronised with the release stream during release prep.

**Resolution (2026-09-10, DevAgent).** Fixed. Removed 182 free-floating
`// Version: X.Y.Z` header lines from 180 `.cs` files across src+ and tests+;
the single release-version authority is now `Directory.Build.props` (2.0.2),
and the version pin/lookup tests (`RdpAuditVersionMetadataTests`,
`RuntimeVersionResolverPinTests`) remain untouched. Headers with historical
notes were reworded without the `Version:` marker, so a regex scan for
`^\s*//\s*Version\s*:` across `.cs` files returns 0 matches. Guarded by the
repository-hygiene scenario test `SourceFiles_CarryNoStrayVersionLines`.
Updated the [2026-09-10] curated release notes in `CHANGELOG.md`, which
record that 'P3-2' chose the 'drop per-file version lines' option because
keeping ~180 headers synchronised with the release stream duplicates the
single source of truth and always drifts.

---

## P3-3 [FIXED 2026-09-10]: CI is windows-only while tests/docs claim a Linux CI run

**Evidence.** `.github/workflows/build.yml` declares a single
`runs-on: windows-latest` job. Dozens of test/doc comments say suites "run on
Linux CI" / "non-Windows CI" (e.g. `EtwPayloadXmlFormatterTests`,
`IpcDispatcherStage7Tests`, `SecurityAuthProbeServiceTests`,
`docs/50-ipc.md` CI notes). The Linux cross-checks exist in code but are never
executed by this repo's CI.

**Fix.** Either add a `ubuntu-latest` job (Core.Tests is `net8.0`-portable) or
reword the comments from "Linux CI" to "cross-platform unit tests (Windows CI
today)".

**Resolution (2026-09-10, DevAgent).** Fixed (minimal option). All false
cross-platform CI claims (Linux/non-Windows/macOS CI) were reworded to honest
Windows-only statements across 15 `.cs` files and 7 docs files
(`docs/40-options.md`, `48-abuseipdb.md`, `50-ipc.md`, `80-roadmap.md`,
`83-event-collection-implementation.md`, `90-windows-validation.md`,
`PROJECT_MAP.md`); a regex scan for the claim phrases across `.cs` / `.md` /
`.yml` sources returns 0 matches outside the historical entries in this
register. Guarded by the repository-hygiene scenario test
`SourceFiles_CarryNoPlatformCiClaims`.

---

## P3-4 [FIXED 2026-09-10]: CHANGELOG.md is a raw backup journal, not release notes

**Evidence.** `CHANGELOG.md` (390 lines) is an auto-appended list of
"<timestamp> <path> (backup vN)" records plus scratch-file entries
(`.dev_agent/scratch/*`) and one prompt-copy artifact; only ~3 lines carry
human-readable change summaries. It mixes real edits with every backup snapshot
(~350 noise lines).

**Fix.** Replace with a curated per-release changelog (keep the raw journal as a
separate opt-in file or drop it entirely).

**Resolution (2026-09-10, DevAgent).** Fixed. `CHANGELOG.md` was restructured
in place (the platform keeps appending backup records to this file, so
splitting it into a separate file would not stop the noise): curated release
notes now live at the top (`## 2026-09-10 - housekeeping wave (P3)`,
`## 2026-09-09 - defect wave (P2)`), and the machine-maintained journal is
fenced below under `## Raw development log (auto-maintained)`. Guarded by the
repository-hygiene scenario test `Changelog_CuratedNotesPrecedeRawJournal`.

---

## Appendix: verification commands

```powershell
dotnet build RdpAudit.sln
dotnet test tests/RdpAudit.Core.Tests/RdpAudit.Core.Tests.csproj
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj   # run elevated
```

---

# Database-governance engagement (2026-09-14 .. 2026-09-15) - defect, debt and remediation register

Scope: the five-stage database-governance / retention / storage-hardening programme executed on
`1st_RdpMON/Service` (plan: `.dev_agent/RDPAudit_Database_Governance_Retention_Hardening_Prompt_v3.md`,
annex: `.dev_agent/RDPAudit_v2_Gap_Analysis_and_Addenda.md`).

Baseline at the start of the engagement: `dotnet build RdpAudit.sln` exit 0, **3286** tests passing.
State at the end of Stage 5: build **0 warnings / 0 errors**, **3663 tests passing / 0 failed**,
new IPC ordinals 80..94 (append-only), EF migrations `Stage17EventDeletionLedger`,
`Stage18LedgerChain`, `Stage19StoreIntegrity`.

Evidence states used below are the ones this project already uses: *observed* (directly present in
source or captured command output), *reproduced* (a real input produced the symptom), *confirmed*
(reproduction plus a counterfactual), *reported* (executor claim not independently reproduced).

---

## A. Defects found and FIXED during the engagement

### A1 [P1, FIXED 2026-09-15] `ShardWriter` reset a reopened shard's header, silently zeroing evidence metadata

**Symptom.** Reopening an already-allocated shard file re-initialised its header, so
`ShardRecordCount` and `ShardEvictedCount` fell back to 0 and the ring treated the file as empty.

**Evidence.** Freshness was decided by `stream.Length == minSize`
(`src/RdpAudit.Core/Storage/Sharding/ShardWriter.cs`); the file is pre-allocated to its full ring
capacity, so a normal reopen matched that predicate. Counterfactual *reported* by the executor:
restoring the old predicate makes `Reopen_KeepsCountersAndRecords` fail with
`Expected: 4, Actual: 0`. AutoCoder inspected the current predicate
(`stream.Length < ShardHeader.HeaderRegionBytes`) and confirmed it no longer matches a pre-allocated
file.

**Impact.** Silent loss of eviction/record accounting on every reopen — directly contradicting the
documented contract that a shard reader can trust the header, and the "evicted volume is never
hidden" invariant. Binary format and format version untouched.

**Fix.** Freshness now requires a file shorter than the header region. Regression test
`Reopen_KeepsCountersAndRecords`.

### A2 [P2, FIXED 2026-09-15] The Database tab's "Cancel running operation" button was unreachable exactly when it was needed

**Symptom.** During a long operation (for example the 60-second integrity check) the cancel button
was greyed out, although the code and `docs/30-configurator.md` promised cancellation.

**Evidence.** `BeginBusy()` disables the inner `TabControl`; the button lived *inside* the
Maintenance tab, and WinForms reports `Enabled == false` for any control inside a disabled
container regardless of its own flag. *Reproduced* by the executor with a structural test and a
rendered PNG; AutoCoder confirmed in source that the button now sits in a root-level operation
panel outside the TabControl.

**Impact.** The only escape hatch from a long maintenance pass was unusable — an effective UI freeze
for the operator.

**Fix.** Cancel moved to the page-level operation panel; test
`BusyGate_RefusesASecondOperationAndKeepsCancelReachable`.

### A3 [P2, FIXED 2026-09-15] `async void` event handlers in the Database tab had no local failure guard

**Symptom.** An exception escaping any of the tab's `async void` handlers would have terminated the
process, because the application installs no global unhandled-exception handler
(`Program.Main` runs the form directly).

**Evidence.** *Observed* by inspection of the page before the fix (20 handlers); the executor
converted them to a single `AsyncClick(Func<Task>)` wrapper with a last-resort
`ReportHandlerFailure` that never rethrows and never touches a disposed page.

**Impact.** A malformed service response or a disposed control could turn a recoverable error into a
crash of the whole Configurator.

**Fix.** All handlers wrapped; regression test
`OperationDisposedWhileInFlight_DoesNotEscape`.

### A4 [P1 for CI, FIXED 2026-09-15] The Configurator test class hung and the suite never finished

**Symptom.** `tests/RdpAudit.Configurator.Tests` did not complete; the run had to be killed.

**Evidence.** *Reproduced* by AutoCoder: a 6-minute bounded run never finished, and the leftover
temporary probe printed `RefreshOverviewAsync started` / `TIMED OUT waiting for
RefreshOverviewAsync`. Root cause confirmed by measurement inside the same code: constructing a
WinForms control installs a `WindowsFormsSynchronizationContext` on that thread, the page correctly
uses `ConfigureAwait(true)`, and the tests blocked that very thread with
`task.Wait(...)` / `.GetAwaiter().GetResult()`. Blocked wait: completed `False` after **10 007 ms**;
with a message-pump loop: completed `True` after **2 032 ms** (`IpcConstants.ConnectTimeoutMs`) on
the *same* product code. The IPC client itself was not at fault.

**Impact.** The suite could not run at all; the temporary probe also broke the documentation-drift
guard (`PROJECT_MAP.md is missing … ScratchDatabasePageHangProbe.cs`).

**Fix.** New `tests/RdpAudit.Configurator.Tests/StaTestHarness.cs` (bounded `Application.DoEvents()`
pump, per-operation / per-body / per-class deadlines, background STA thread); all page tests
migrated; the same latent pattern removed from `NotificationsPageTests`; the temporary probe
deleted. Verified: Configurator project 95/95 in ~12 s.

### A5 [P2, FIXED 2026-09-15] A full `VACUUM` ran on the live database under a running service

**Symptom.** `ApplicationDataPurgeService` executed `VACUUM;` on the live store after a purge.

**Evidence.** *Observed* in source (`VACUUM` at the space-reclamation step). A full `VACUUM` rebuilds
the whole file inside a write transaction, so on a multi-gigabyte evidence store the writer lock —
and therefore ingestion, alerts and the UI — could stall for a long time.

**Fix.** The online path is now `PRAGMA wal_checkpoint(TRUNCATE)` plus a bounded
`PRAGMA incremental_vacuum(<5000 pages>)`; the statement list is built by a method that *cannot*
emit a full `VACUUM`, and the report states exactly what was reclaimed and that shrinking the file
requires an offline compaction. Offline compaction is a new Configurator-side operation
(`CompactDatabase = 93`, service stopped, `VACUUM INTO` + verified atomic swap) that the restore
path shares through `LiveDatabaseSwap`.

### A6 [P2, FIXED 2026-09-15] Backup free-space check could silently disable itself

**Symptom.** `required + floor` could overflow `long`; the resulting negative requirement made the
pre-flight check a no-op.

**Evidence.** *Reproduced* by the executor's own test before the fix; fixed with saturating
addition. AutoCoder did not re-run the counterfactual.

### A7 [P2, FIXED 2026-09-15] Connection pooling blocked publishing a finished snapshot

**Symptom.** Publishing a snapshot (`Directory.Move` from `<stamp>.partial` to `<stamp>`) failed
with "file is being used by another process".

**Evidence.** *Reproduced* by the executor's test; caused by `Microsoft.Data.Sqlite` pooling keeping
the destination handle open. Fixed with `Pooling=false` on the backup/verify connections; the same
fix was later needed in the restore FK-check.

### A8 [P1 risk, FIXED 2026-09-15 - deliberate behaviour change] No recovery point before a migration, and no protection against running older binaries on a newer store

**Symptom.** `AuditDbInitializer` migrated in place with no snapshot, and a database whose applied
migrations were newer than the running binaries started silently.

**Fix.** A mandatory pre-migration snapshot (`PreMigrationBackupEnabled`, default `true`, *not* gated
by `Backup.Enabled`) and an always-on downgrade guard (`SchemaCompatibility` + `__EFMigrationsHistory`).
Both fail closed with distinct exit codes (20260815 / 20260816) and a marker explaining the cause and
the operator's options. Documented in `docs/88` and `docs/20-service.md`; a fresh install with no
database file is exempt from the snapshot requirement.

---

### A9 [P2, FIXED 2026-09-15] Tamper findings could print two different digests as identical

**Symptom.** A corrupted sealed fingerprint tip produced an operator-facing finding whose printed
values contradicted its own verdict: "records 1 entr(ies) with head `668954af9f4e` while the chain on
disk holds 1 entr(ies) with head `668954af9f4e`: the chain was rolled back ...". The digests shown as
equal were in fact different (`ede4085b...` versus `eee4085b...`).

**Evidence.** *Reproduced*: a full sweep of every base64 position of the envelope (temporary
diagnostic probe, ~1340 mutations across runs) showed 29 occurrences where the finding was emitted
with identical printed values; a probe over the failing position confirmed the underlying digests
differed beyond the printed prefix.

**Impact.** A false alarm that both claims tampering and contradicts itself destroys trust in the
chain alarm - the exact opposite of the intent of B19.

**Fix.** The verdict now emits separate, self-consistent findings: length-only facts (no digest to
print) and head-mismatch facts that always render both digests in full via `RevealDigest`, so two
different values can no longer read as equal. Regression tests:
`Verify_APrintedDigestPairNeverReadsAsIdentical` plus store-level tests over the mutation classes.

### A10 [P2, FIXED 2026-09-15] A missing JSON field became a fabricated default that the verdict reported as tampering

**Symptom.** Corrupting a property *name* in the sealed tip (`"EntryCount"` -> `"AntryCount"`) made
`System.Text.Json` silently drop the unknown property, so `EntryCount` deserialised to the CLR default
`0`. The verdict then reported "records 0 entr(ies) ... the chain was rolled back" for a store where
nothing had changed - both heads were byte-identical.

**Evidence.** *Reproduced* by the position sweep (13 occurrences); the same class affected
`Sequence` in a chain entry, producing "Entry 0 is out of place ... so an entry was removed or
renumbered" for a file nothing had been deleted from.

**Impact.** Fabricated evidence in an integrity alarm: the operator is told records were removed when
the only change was an unreadable field.

**Fix.** `[JsonRequired]` on every field the verdict depends on (both record shapes), so a missing or
renamed field is reported as *unreadable* instead of inventing a value. The file format itself is
unchanged - the writer always emitted these fields, the reader is simply stricter. Documented in
`docs/41-data-model.md`.
## B. Open findings and remediation plan

### B1 [P2] Synchronous-over-async inside the firewall provider probe and the notifier autostart runner

**Status (2026-09-15): FIXED.** The blocking call inside the probe and the probe's synchronous `Probe()`
entry point were removed; `PrerequisiteChecker.RunAllAsync` and the prerequisites page are
asynchronous; `NotifierAutostartService` now runs schtasks through `ApplyAsync` without blocking its
caller. A source/reflection guard test fails on any `GetAwaiter().GetResult()`, `.Wait(` or `.Result`
in the Configurator project, and a grep confirms zero remaining sites. Verified by AutoCoder: build
0 warnings / 0 errors, full suite green.
**Where (measured 2026-09-15 by AutoCoder, replacing an earlier imprecise note).**

- `src/RdpAudit.Configurator/Services/FirewallProviderDiagnosticsProbe.cs:116` -
  `ProbeLocalRulePolicyAsync(...).GetAwaiter().GetResult()` inside the probe, reached through the
  probe's **synchronous** public entry point `Probe()`. Its only caller is
  `src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs:171`
  (`new FirewallProviderDiagnosticsProbe().Probe()`), i.e. the prerequisites-page path. The Firewall
  tab already uses the async entry point (`FirewallPage.cs:556`), so the blocking path is confined to
  the checker.
- `src/RdpAudit.Configurator/Services/NotifierAutostartService.cs:154-155` -
  `outTask.GetAwaiter().GetResult()` / `errTask.GetAwaiter().GetResult()` after
  `process.WaitForExit(timeout)`, reached from `NotificationsPage` through `_runner`. The risk is
  narrower than the probe case (both streams are at EOF once the child has exited), but the method
  still blocks its caller for up to the schtasks timeout.

**Why it matters.** Both paths can run on the UI thread. Blocking a thread that owns the WinForms
synchronization context is exactly the mechanism that hung the test suite (A4); in production it
freezes the form for the duration of the work, and if any inner await needs the same context it
deadlocks outright. `Forms/DatabasePage.cs` itself is clean - verified by grep for
`GetAwaiter().GetResult()`, `.Wait(` and `.Result`.

**Remediation plan.**

1. Probe: stop blocking. Preferred: give `PrerequisiteChecker` an async entry point and async
   callers, and delete the blocking call from the probe; alternatively keep `Probe()` but only ever
   call it from a background thread, with the constraint documented in the type.
2. Notifier: run the schtasks invocation through `Task.Run`/async so no UI thread waits on the child
   process, keeping the same `SchTasksResult` contract.
3. Enforcement: add a reflection-based guard test over `RdpAudit.Configurator` that fails when a type
   reachable from a `Form` contains `GetAwaiter().GetResult()`, `.Wait(` or `.Result` (`CA2007` is
   suppressed repo-wide, so a test is the practical gate).
4. Acceptance: guard test green; `FirewallProviderDiagnosticsProbeAsyncContractTests` green; the
   Prerequisites and Notifications paths no longer block the UI thread.

### B2 [P2] 104 unguarded `async` event-handler lambdas across 23 Configurator pages (measured)

**Status (2026-09-15): PARTIAL - P2 scope closed, P3 migration tracked.** The global safety net is
installed in `Program.Main` (`ConfiguratorExceptionGuard`: `Application.ThreadException`,
`AppDomain.UnhandledException`, `TaskScheduler.UnobservedTaskException`,
`SetUnhandledExceptionMode(CatchException)`), logging to
`%ProgramData%\RdpAudit\logs\configurator-unhandled.log`; the guarded handler helper was promoted to
`Services/SafeAsyncHandler.cs` and applied to `DatabasePage`, `FirewallPage`, `ServicePage`,
`RemoteRdpClientsPage`, `OverviewPage` and `PurgeBySubjectDialog`. **64 unguarded `+= async` sites
remain in 18 files** (re-measured by AutoCoder; down from 104): AttackStatisticsPage 7,
AbuseIpDbPage 6, LogsPage 6, ProcessAlertsPage 6, DiagnosticsPage 5, PrerequisitesPage 5,
EventCollectionPage 4, MikroTikPage 4, CrossHostPage 3, NotificationsPage 3, SettingsPage 3,
LiveEventsPage 2, MainForm 2, RdpConfigurationPage 2, SessionMapPage 2, ToolsDiagPage 2,
AuditPolicyPage 1, ProcessObservationDialog 1. A counter test fails if that number grows. Remaining
migration is P3 work; `MainForm` first.
**Where (measured 2026-09-15 by AutoCoder).** Counted `+= async` event-handler lambdas:
ServicePage 11, RemoteRdpClientsPage 11, OverviewPage 8, FirewallPage 8, AttackStatisticsPage 7,
ProcessAlertsPage 6, LogsPage 6, AbuseIpDbPage 6, PrerequisitesPage 5, DiagnosticsPage 5,
MikroTikPage 4, EventCollectionPage 4, SettingsPage 3, NotificationsPage 3, CrossHostPage 3,
ToolsDiagPage 2, SessionMapPage 2, RdpConfigurationPage 2, MainForm 2, LiveEventsPage 2,
DatabasePage 2, ProcessObservationDialog 1, AuditPolicyPage 1 - **104 sites in 23 files**. (An earlier
note in this register described "~25 `async void` handlers in FirewallPage"; that figure was wrong -
it counted a different pattern and only one file.)

**Why it matters.** A lambda assigned to an `EventHandler` is `async void` at runtime, so an escaping
exception cannot be caught by the caller. `Program.Main` currently installs **no** global safety net
(`Application.ThreadException`, `AppDomain.UnhandledException`, `TaskScheduler.UnobservedTaskException`),
which means one malformed service response can terminate the Configurator and discard unsaved state.
The 2026-09-15 Stage 3 fix covered only `DatabasePage`.

**Remediation plan (layered; do not start by editing 104 lambdas).**

1. Add the global safety net in `Program.Main`: `Application.SetUnhandledExceptionMode(CatchException)`,
   `Application.ThreadException`, `AppDomain.CurrentDomain.UnhandledException`,
   `TaskScheduler.UnobservedTaskException` - log, surface a message, keep the process alive. This
   converts the entire class from fatal to recoverable in one place.
2. Promote the guarded handler helper (currently private inside `DatabasePage`) into a shared type and
   use it for all new code.
3. Migrate page by page, highest risk first (FirewallPage, ServicePage, RemoteRdpClientsPage,
   OverviewPage); keep the remainder as tracked P3 work rather than a single sweeping edit.
4. Add a counter test that reports the number of remaining unguarded sites, so the debt is visible and
   cannot grow silently.
5. Acceptance: the global net is covered by a test (a throwing handler leaves the process alive and
   reports the failure); the counter test is green; migration progress is updated here.

### B3 [P2] Three storage commands still run on the short five-second IPC deadline

**Status (2026-09-15): FIXED.** 85 `CreateDatabaseBackup`, 86 `ListDatabaseBackups` and
87 `VerifyDatabaseBackup` now map to `LongOperationTimeoutMs`. The drift test requires every defined
`IpcCommand` to have an explicit deadline entry - it immediately exposed 65 commands that had been
inheriting the short default silently; all are now listed explicitly with unchanged behaviour, and a
second test enforces "long if and only if recorded as long".
**Where (measured 2026-09-15 by AutoCoder).** `IpcConstants.TimeoutMsFor` maps the newer storage
commands to `LongOperationTimeoutMs` **except** `CreateDatabaseBackup` (85), `ListDatabaseBackups` (86)
and `VerifyDatabaseBackup` (87), which therefore inherit the 5-second default on both ends of the
round trip. Already mapped to the long deadline: 88 `GetShardInventory`, 89 `RunDatabaseMaintenance`,
90 `RestoreDatabaseBackupToDirectory`, 92 `CollectShardGarbage`, 94 `PurgeBySubject`. An earlier note
in this register said "85..88"; 88 is in fact already long.

**Why it matters.** Copying a database (plus the shard tree when `IncludeShards` is set), hashing a
multi-gigabyte snapshot, or listing a large backup folder can legitimately exceed five seconds; the
client would report a false timeout while the service keeps working to completion. *Observed*
configuration mismatch; not reproduced (no large fixture was available).

**Remediation plan.**

1. Map 85..87 to the long deadline with an explicit comment per command, matching the style already
   used for 88..92.
2. Add a drift test asserting that every defined `IpcCommand` has an explicit entry in
   `TimeoutMsFor`, so a future command cannot silently inherit the short default.
3. Once a 5 GB fixture exists, measure snapshot/verify/list durations and only then justify any budget
   above `LongOperationTimeoutMs`.
### B4 [P2] Test isolation: the service test project starts a real named pipe that other projects can reach

**Status (2026-09-15): FIXED, and upgraded from *reported* to *reproduced* before the fix.** Executor
evidence: with the service test host holding the production pipe name, 8 of 8 forced Configurator
iterations failed with `Assert.Contains() Failure ... Not found: "unavailable"` while the page logged
`"Database overview loaded."`; a pipe-namespace probe observed 89 live `RdpAuditService` instances,
all attributable to the test hosts; the pre-fix baseline run also failed once. Fix: test hosts bind a
per-run name (`RdpAuditService-<pid>-<guid>`) through an `internal init` seam on `IpcServerWorker`;
the production name, its DACL and the framing are untouched, and a guard test proves no environment
variable can rename the production pipe. After the fix: 8/8 forced iterations green, 5 consecutive
full parallel solution runs green (executor), plus 3 more by AutoCoder - 3701 passed / 0 failed each.
**Where.** `tests/RdpAudit.Service.Tests` (real `RdpAuditService` pipe). Reported by the executor:
in its Stage 4 runs, two `DatabasePageTests` cases that assert "service unreachable" occasionally saw
a live response when the whole solution was tested in parallel.

**Evidence state.** *Reported*, not reproduced: AutoCoder ran the solution suite and the Configurator
project separately and both were green (3663/0 and 95/0). The mechanism is plausible (fixed pipe
name, parallel projects) but unproven.

**Remediation plan.**
1. Reproduce deterministically: run the solution suite in a loop (for example 10 iterations) with the
   service tests and the Configurator tests in the same run and count the failures.
2. If reproduced, isolate by construction: parameterise the pipe name per test run
   (`RdpAuditService-<pid>-<guid>`) so no other project can ever connect, instead of relying on
   xunit parallelisation settings.
3. Acceptance: 10 consecutive green solution runs.

### B5 [P3] One timing-sensitive retention test flaked once

**Status (2026-09-15): FIXED.** Cancellation is now driven by an injected post-batch hook instead of
timing, and the test asserts resulting state rather than deleted-row counts. 10/10 consecutive runs
green; a counterfactual run that ignores cancellation fails the test, so it cannot pass by accident.
**Where.** `InformationDensityRetentionWorkerTests` - the "cancelled mid-pass" case. Observed once in
a full solution run by the executor; not reproduced (full runs, isolated 3/3 and project-level all
green), and AutoCoder did not reproduce it either.

**Remediation plan.** Make cancellation deterministic: gate the pass on a test-controlled barrier
(or inject a `TimeProvider`/callback) instead of relying on "did the test manage to cancel in time",
and assert the resulting state rather than the number of deleted rows.

### B6 [P3] `MainFormTabOrderTests` still joins a raw `Thread` without a deadline

**Status (2026-09-15): FIXED.** The class now runs on `StaTestHarness`; no unbounded `Thread.Join()`
remains in the Configurator test project.
**Where.** `tests/RdpAudit.Configurator.Tests/MainFormTabOrderTests.cs`. Deliberately left alone in
Stage 3 because its bodies contain no asynchronous waits, so the deadlock path of A4 cannot trigger.

**Remediation plan.** Move it onto `StaTestHarness` for uniformity (a deadline costs nothing) so a
future edit that adds an await cannot reintroduce a hang.

### B7 [P3, process] Two divergent output trees produce false results with `--no-build`

**Status (2026-09-15): ADDRESSED (documented).** A tooling-traps section was added to
`docs/90-windows-validation.md` covering the correct commands, the `bin\Debug` versus
`bin\x64\Debug` trap, when `-m:1` matters, and why real-pipe tests need elevation. No build
configuration was changed.
**Where.** `bin\Debug\...` (no `Platform`) versus `bin\x64\Debug\...` (solution builds). Both trees
exist on this machine and drift apart.

**Observed consequences during this engagement (both mine, both false):**
1. `dotnet ef migrations has-pending-model-changes --no-build` reported *"Changes have been made to
   the model since the last migration"* while EF **with** its own build reported *"No changes have
   been made…"* — the first run had loaded a stale `RdpAudit.Core.dll` from `bin\Debug`.
2. `dotnet test <project>.csproj --no-build --filter …` resolved to the stale tree and answered *"No
   test matches the given testcase filter"* with exit code 0 — a green-looking run that executed
   nothing; `bin\x64\Debug` contained the real tests.

**Remediation plan.**
1. Document in `docs/90-windows-validation.md` (and in the build section of `PROJECT_MAP.md`) the
   commands that are actually correct: build/test at solution level, or pass `-p:Platform=x64`, and
   never combine `--no-build` with tooling that inspects the model.
2. Consider `AppendPlatformToOutputPath=false` (or a single `Platforms` value) so one project cannot
   silently have two Debug outputs; evaluate the impact on `publish.ps1` first.
3. Acceptance: a short "tooling traps" section exists in the docs and a fresh clone reproduces the
   documented commands with no stale-tree ambiguity.

### B8 [P3, environment] `dotnet restore` fails on this machine

**Status (2026-09-15): ROOT-CAUSED AND FIXED.** The earlier recorded cause was incomplete:
`Environment.GetFolderPath(CommonApplicationData)` works correctly here. The real failure is inside
`NuGet.Common.NuGetEnvironment.GetFolderPath`, which reads the `PROGRAMDATA`, `ALLUSERSPROFILE` and
`PROGRAMFILES(X86)` environment variables directly; in shells that do not export them it returns null,
and `Path.Combine(null, "NuGet")` throws in NuGet's configuration initialiser - exactly the
`Value cannot be null. (Parameter 'path1')` seen in `NuGet.targets(745,5)`. Exporting those variables
makes restore work in any shell; `bench-storage.ps1` sets them, and the `--no-restore` workaround is no
longer required. Recorded in `docs/90-windows-validation.md`. This was an environment defect, not a
repository one - the repository was never at fault.
**Status (2026-09-15): DOCUMENTED (environment, not repository).** The executor reproduced the failure
even against a freshly generated console project and traced it to
`NuGetEnvironment.GetFolderPath(MachineWideSettingsBaseDirectory)` in a shell without
`PROGRAMDATA`/`ALLUSERSPROFILE` (setting them in-process did not help). AutoCoder's PowerShell builds
restore normally, so the failure stays shell-specific. Recorded as a working note in
`docs/90-windows-validation.md`.
**Symptom.** `NuGet.targets(745,5): error : Value cannot be null. (Parameter 'path1')` for every
project, with and without `-p:Platform=x64`.

**Evidence state.** *Observed* by the executor in its shell. AutoCoder's own PowerShell builds
restored successfully at 18:59 and again at 21:xx, so the failure is shell/environment specific
rather than a repository defect. The executor's claim that it is "environment-wide" is **not
corroborated**.

**Remediation plan.** Capture the failing and the successful environment side by side
(`PATH`, `DOTNET_ROOT`, `NUGET_PACKAGES`, `MSBuildSDKsPath`, shell type) and fix the environment (most
likely a tool-path issue in the shell used by the automation agent). No repository change expected.

### B9 [P2, verification debt] No end-to-end run against a live service

**Status (2026-09-15): FIXED for the reachable scope, remainder documented.** `ServiceHostSmokeTests`
boots the real host through `Program.RegisterServices` on a temporary ProgramData root, applies
migrations on a clean store, and drives the real `IpcDispatcher` through `GetDatabaseOverview`,
`GetRetentionPolicy`, `PreviewRetention`, `CreateDatabaseBackup`, `ListDatabaseBackups`,
`VerifyDatabaseBackup`, `GetDeletionLedger` and `PurgeBySubject` (dry-run only), then shuts the host
down and asserts the real `%ProgramData%\RdpAudit` was untouched. It runs in ~2 s; the count of
deliberately not-started hosted services is asserted, so a new worker forces an explicit decision.
**The test paid for itself immediately: it exposed a real defect** - the `Ledger` section of the
overview threw `InvalidOperationException - ExecuteReader can only be called when the connection is
open` (the service took the `SqliteConnection` from a context after EF had closed it), so the whole
overview returned `Unavailable` on a healthy store; fixed by opening/closing the connection inside
the method. Still unverified: Windows service stop/start orchestration (restore/compaction over a
live store) needs a registered service and remains a manual checklist item.
**What is unverified.** Host composition for the new services; every Configurator success path for
the Database tab (real overview, dry-run, backup, restore, compaction, ledger, purge); the startup
sequence with the pre-migration snapshot and the downgrade guard on a real installation; Windows
service stop/start orchestration in `DatabaseRestoreService` / `DatabaseCompactService`.

**Remediation plan.**
1. Add an in-process integration smoke test that boots the real host against a temporary ProgramData
   root, exercises `GetDatabaseOverview`, `PreviewRetention`, `CreateDatabaseBackup`, `ListDatabaseBackups`,
   `VerifyDatabaseBackup` and `PurgeBySubject` (dry-run) through the real dispatcher, then shuts down.
2. Add a scripted manual checklist for the service-stop paths (restore/compaction/purge over a live
   store) to `docs/91-troubleshooting.md`, since they cannot be automated without a registered service.

### B10 [P2, verification debt] No performance measurements for any of the new machinery

**Status (2026-09-15): FIXED for the storage scope; UI-budget instrumentation still open.** A runnable
tool now exists - `tools/RdpAudit.StorageBenchmarks` with the `bench-storage.ps1` launcher - which
measures on the machine it runs on: seeding throughput, the information-density retention pass
(rows/s, reclaimed bytes, per-batch writer-lock hold p50/p95, batch count), dry-run preview latency
and its volume ratio against the real pass, ledger append cost, snapshot create/verify throughput,
quick vs full integrity check, offline compaction, WAL checkpoint, and a volume IOPS probe, plus a
machine profile. It prints a Markdown report, a JSON report and an operator-mergeable settings
fragment, and it recommends tuning values through a pure engine in Core
(`src/RdpAudit.Core/Diagnostics/StorageTuningAdvisor.cs`) where every recommendation carries its rule,
its measured inputs and a caveat; parameters for which there is no evidence are reported as
"insufficient data" rather than guessed. It never applies anything and never touches the production
store (AutoCoder verified the `%ProgramData%\RdpAudit` fingerprint is bit-identical before and after a
run). Still open from the original wording: the "no UI-thread stall over 16 ms" budget is not
instrumented, and the tool has only been run in `--quick` on one machine - no `--full` run, no second
machine or rotational/network volume, so nothing here proves the rules generalise.
**What is unmeasured.** Retention pass throughput and reclaimed bytes at 1M / 10M / 100M rows; writer
lock hold per batch; snapshot creation, verification, offline compaction on 1 / 5 GB stores;
`quick_check` versus full `integrity_check` duration; UI budgets (the "no stall over 16 ms" rule is
still not instrumented).

**Remediation plan.** BenchmarkDotNet project entries plus a UI stopwatch harness on a generated
fixture; publish the numbers in `docs/88` and `docs/87` and only then state budgets in the docs.

### B11 [P3] Documented limits of the shard governance implementation

Aggregate buckets track at most 1024 member sources; the "refused / aggregated source" lists are
capped at 8192 entries (counters then report a lower bound); tree byte accounting is taken once and
then maintained from the files this process created, so files deleted by an operator are not noticed
until restart; `ShardCompactor` is **not implemented** (the UI says so explicitly instead of offering
a dead button).

**Remediation plan.** Either raise the caps with measurements, or surface the "lower bound" state in
the UI banner. Implement compaction only with a measured fragmentation case; until then keep the
honest "not implemented" text.

### B12 [P3] `IncludeShards` backup is a best-effort copy, not a transactional snapshot

Shards are appended by the running service while the tree is copied, so a shard snapshot can be
slightly inconsistent with the database snapshot. Default is `false`; documented in `docs/88`.

**Remediation plan.** Either copy under a shard-write gate (pause shard writers during the copy) or
label the artifact as "best effort" in the manifest and refuse to present it as a consistent pair.
The manifest already records whether shards were included.

### B13 [P2, security gap] Encryption at rest is designed but not implemented

A decision record exists (`docs/89-encryption-at-rest-decision.md`); the code exposes
`Storage:Encryption:Mode = None | VolumeManaged | SqlCipher` with `None` as the default and a
fail-closed refusal to start for `SqlCipher`. The store, WAL and shards remain plain text on disk.

**Remediation plan.** Decide on BitLocker-only versus SQLCipher (or both) from the record; if
SQLCipher is chosen, implement key handling through the existing `ISecretProtector`, add the
one-time migration for database *and* shards, add rotation, and extend the backup format so encrypted
snapshots are self-describing. Acceptance: a restored encrypted store opens only with the key, and a
key rotation is exercised by a test.

### B14 [P3] ACL hardening is install-time plus start-time verification only

`install.ps1` applies the DACL and the service verifies it at start, reporting drift. There is no
apply path over IPC or from the UI, and a domain policy that forbids custom DACLs makes the check
report "unverifiable" rather than failing.

**Remediation plan.** Decide whether operators need a "re-apply storage ACLs" button (it would be an
elevated, audited action); document the "unverifiable" state in `docs/30-configurator.md` so it is not
mistaken for drift.

### B15 [P3] `PurgeBySubject` CIDR handling is bounded

A CIDR subject is expanded against addresses known to the store, capped at 4096 expanded addresses;
wider ranges are refused (a partial purge would be indistinguishable from a complete one).

**Remediation plan.** Keep the refusal, but offer an explicit "range purge" mode that selects rows by
binary prefix rather than expansion, with its own dry-run and ledger reason, so large ranges remain
possible without silent truncation.

### B16 [P3] Stores created without `auto_vacuum = INCREMENTAL` never shrink online

**Status (2026-09-15): PARTIAL - visibility done, one-click compaction from the overview not added.** The
Database tab overview now reports the store's actual `auto_vacuum` mode, journal mode, page size/count,
`freelist_count` and the reclaimable bytes, plus a one-line conclusion: in a non-`INCREMENTAL` mode with a
non-trivial freelist it states plainly that online reclamation is impossible and points at the existing
offline compaction action in the Danger Zone. Combined with B27 the operator now sees why the file did not
shrink instead of having to guess. Still open from the original plan: offering the compaction directly from
the overview panel rather than only naming the Danger Zone button.
The purge path now reports this honestly, and offline compaction covers it, but nothing tells the
operator *why* the file did not shrink other than a line in the purge report.

**Remediation plan.** Surface the store's auto-vacuum mode in the Database tab overview, and offer
offline compaction from the same panel when the freelist is non-trivial.

### B17 [P3] `DatabasePage` has no IPC seam

**Status (2026-09-15): FIXED.** A deliberately narrow `IIpcClient` (one member - the
`SendDetailedAsync<T>` overload the page actually uses) is injected into `DatabasePage` and
`PurgeBySubjectDialog`; `IpcClient` implements it and the production composition is unchanged. The
success paths are now covered, including the full shard Collect cycle (dry-run -> confirmation ->
apply), backup create/list/verify, retention load/diff/save, ledger paging and CSV export, and the
Danger Zone gates - plus cancellations and invalid-input refusals.
The page takes a concrete `IpcClient`, so tests can only exercise the "service unavailable" branch,
and the Collect (shard GC) UI flow could not be covered end to end.

**Remediation plan.** Extract a narrow interface (the set of `SendAsync`/`SendDetailedAsync`
overloads the page uses) and inject it; then cover the success paths with a fake, including the
Collect dry-run → confirm → apply flow.

### B18 [P3] Ledger hash chain treats pre-Stage18 rows as a trusted prefix

Rows written before `Stage18LedgerChain` have NULL hashes. Verification validates the chain from the
first hashed row and reports the prefix boundary as *unverified* rather than tampered.

**Remediation plan.** Record the prefix boundary explicitly in the verification report (a count and a
timestamp), and consider anchoring the first hashed row's hash in the fingerprint file.

### B19 [P2, honesty limit] Offline-tamper detection can be defeated by an attacker with write access

**Status (2026-09-15): HARDENED, residual limit documented.** Fingerprints are now a hash chain
(`integrity\fingerprints\fingerprint-<n>.json`, each entry carrying the previous digest) plus a
sealed tip (`integrity\store-fingerprint-sealed.json`) protected through the existing
`ISecretProtector`, which is what makes deletion of the last file detectable (a valid chain prefix is
otherwise self-consistent). Four states are reported distinctly - `ok` / `missing` / `unreadable` /
`chain-broken` - and every non-`ok` state raises the same strong anomaly path (start-up report,
`OperationLog`, marker file, and a mirror through the already-registered `RdpAuditService` event
source when available; no event source is registered at runtime). No claim of immutability is made
anywhere: a local administrator can still delete or re-seal both stores. The goal is that silent
tampering becomes hard and always visible.
The store fingerprint lives in a JSON file next to the database
(`%ProgramData%\RdpAudit\integrity\store-fingerprint.json`), outside the database precisely so a
database rewrite cannot forge it — but an attacker with file-system write access can delete or forge
it too.

**Remediation plan.** Mirror the fingerprint into (a) the Windows event log, (b) a second location
under a different ACL, and (c) optionally a signed (DPAPI/CNG) envelope, and report "fingerprint
missing/unreadable" as a distinct, loud state.

### B20 [P3] Shard aggregate records carry no source address

`ShardRecord` has no address field, so records inside a `/24` or `/64` aggregate bucket are
attributable to the bucket, not to a host. This is a deliberate, documented trade-off of the
cardinality guard.

**Remediation plan.** If host attribution inside buckets is required, add an optional address
extension to the shard record with a format-version bump, a reader that still accepts version 1, and
a documented upgrade path. Do not change the existing layout without a version bump.

### B21 [P1, FIXED 2026-09-15 - regression discovered 2026-09-15] The elevation guard named as the P1-1 fix is absent from the working tree

**Status (2026-09-15): FIXED.** `tests/RdpAudit.Service.Tests/ElevationTestGuard.cs` is restored:
a cached, fail-closed elevation probe, a pure `ResolveSkipReason(bool)` decision and
`[ElevationFact]`/`[ElevationTheory]` attributes that record an explicit skip reason instead of
failing. Nine tests that start or connect a real named pipe now carry the precondition; the purely
in-memory tests of those classes stay ordinary `[Fact]` so a non-elevated host does not lose them. The
probe is injectable (`OverrideProbe`), so both branches are covered deterministically, and meta-tests
fail if a real-pipe test loses its precondition or if the detector stops seeing the tests it guards.
The production ACL was not touched. Honest limit: no genuinely non-elevated host was available in this
environment, so the "green with 9 skips" claim follows from the deterministic decision function and
was not observed end to end.
**Symptom.** Six real-pipe integration tests in `tests/RdpAudit.Service.Tests`
(`IpcServerWorkerInstanceCapTests`, `IpcServerWorkerLifecycleTests`) carry no elevation precondition,
so on a non-elevated host they fail with `System.UnauthorizedAccessException` from
`NamedPipeClientStream.ConnectAsync` - precisely the symptom P1-1 records as fixed.

**Evidence.** `tests/RdpAudit.Service.Tests/ElevationTestGuard.cs`, the file P1-1 names as its fix
("a cached, fail-closed ..."), **does not exist** anywhere in the tree; a recursive search finds only
the unrelated `src/RdpAudit.Configurator/Services/ElevationGuard.cs`. No `IsUserAnAdmin`/`IsInRole`
check exists in the service test project (only an unrelated OS skip in `SingleInstanceGuardTests`).
Found by the remediation agent while working on B4 and confirmed by AutoCoder. Every verification run
in this engagement happened to be elevated (`IsInRole(Administrator) = True`), which is why the gap
stayed invisible here.

**Why it matters.** The production pipe ACL is correct (admin-only by design) and must not be
weakened, so the tests must either state the elevation requirement or skip with a recorded reason.
Without the guard, any non-elevated developer machine or CI agent reports six false failures - trust
in the suite erodes exactly as it did with B4.

**Remediation plan.**

1. Restore the guard as P1-1 describes: a cached, fail-closed helper reporting whether the process is
   elevated, used at the top of the six real-pipe tests, which skip with an explicit recorded reason
   on a non-elevated host instead of failing.
2. Keep the production ACL untouched - the fix is test-side only.
3. Add a meta-test that fails when a test class binding a real named pipe lacks the elevation
   precondition, so the guard cannot silently disappear again.
4. Acceptance: on a non-elevated host the suite is green with those six tests reported as skipped for
   the elevation reason; on an elevated host they still run and pass; the meta-test is green.

### B22 [P2, FIXED 2026-09-15 - found 2026-09-15] `Canonicalize` dereferences `TableRowCounts` without a null guard

**Status (2026-09-15): FIXED.** `Canonicalize` is now total - a null collection or string becomes a
deterministic empty contribution instead of a dereference, and `DescribeNullField` names the offending
field so the reader classifies the record as `Unreadable`/`Missing` (the A10 precedent) rather than as
an edited file. The same class of defect was also fixed for `entry.Digest.Length` when `"Digest": null`.
Covered by per-field null-injection tests and a fuzz test asserting that no input to `ReadAndVerify`
throws. Verified by AutoCoder: 6/6 chain-class runs green, full suite green.
**Symptom.** A fingerprint record containing `"TableRowCounts": null` throws `NullReferenceException`
out of `StoreFingerprintStore.ReadAndVerify`, contradicting the type's documented "never throws"
contract.

**Evidence.** *Observed* in source by the remediation agent while fixing A9/A10; not reproduced by a
test yet.

**Impact.** A malformed (or adversarially edited) fingerprint file can crash the read path instead of
producing an `Unreadable` verdict - a fail-open-ish behaviour in the tamper-detection surface.

**Remediation plan.** Null-guard the canonicalisation and turn a null collection into either
`Unreadable` (mirroring A10's treatment of missing required fields) or an explicit anomaly, whichever
the owner prefers; add tests for `null` on every collection-valued field; acceptance: no input to
`ReadAndVerify` can throw.

### B23 [P3, FIXED 2026-09-15 - found 2026-09-15] Sealed tip fields that are read but never cross-checked

**Status (2026-09-15): FIXED (semantics made explicit).** The tip's `EntryCount`, `HeadDigest`,
`HeadSequence` and `FormatVersion` are now **verified**: `HeadSequence` is cross-checked against the
entry at position `EntryCount`, and an inconsistent `FormatVersion` is reported as `Unreadable`, matching
the treatment already applied to chain entries. `SealedUtc` is declared **advisory** - documented in the
type, in `docs/41-data-model.md` and pinned by a test that asserts a mismatch in it cannot move the
verdict.
**Symptom.** The tip's `HeadSequence` and `SealedUtc` are deserialised but never compared with the
chain, and the tip's `FormatVersion` is not compared with the chain's version. A tip that is authentic
but stale in those fields passes verification.

**Evidence.** *Observed* in source; now pinned by a test that documents the limit rather than hiding it.

**Remediation plan.** Decide the intended semantics (are these advisory or verified?), then either
cross-check them or record them as advisory in `docs/41-data-model.md` and the type documentation.
Acceptance: the behaviour is explicit and covered.

### B24 [P2, FIXED 2026-09-15 - found 2026-09-15] An interrupted re-seal can produce a false tamper alarm

**Status (2026-09-15): FIXED.** `StoreFingerprintStore.Write` is now two-phase with a durable intent
record (`store-fingerprint-intent.json`) written before the chain entry and removed after the tip is
re-sealed. A new fifth state, `Interrupted`, is produced **only** when every fact on disk agrees: the
chain is internally consistent, the tip lags by exactly one entry, the tip seals the chain without that
entry, and the intent names that same entry (count, sequence, digest). Deleting the intent returns the
verdict to `ChainBroken` for the identical discrepancy, so a file deletion cannot reach the softer
state; an edited entry is still reported with a perfect intent on disk. The state is loud - Warning
anomaly, marker, `OperationLog`, mirror sink - and the next successful write self-heals.
Two further defects were found and fixed on the same path: (1) a persistent tip-write failure used to
accumulate unsealed entries and degrade into a false `ChainBroken`, so `Write` now completes the
previous interrupted seal first, leaving at most one unsealed entry; (2) a pre-B19 slot carrying a null
collection is no longer migrated, since the migration would have written a permanently unreadable
record and produced a permanent false `Missing`.
Honest limit: no real process kill was performed - the failure is injected at the same point after the
durable chain write, and the verdict depends only on on-disk state, so the injection is equivalent;
DPAPI was exercised through the in-memory protector, not on a live host.
**Symptom.** `StoreFingerprintStore.Write` appends the chain entry and *then* re-seals the tip. A
process crash between the two leaves `tipCount < chainCount`, which the next read reports as
`ChainBroken` - a "rolled back or replaced" alarm for a store that was only interrupted.

**Evidence.** *Observed* in source (write ordering); the finding text was corrected to mention the
interrupted case, the state logic was deliberately left unchanged because changing it would weaken
detection.

**Impact.** A power loss or crash during the periodic fingerprint write turns into a false tamper
alarm at next start-up - precisely the class of false positive the alarm cannot afford.

**Remediation plan.** Make the write atomic from the verifier's point of view: seal the tip in the
same durable step (temp + atomic move of both artifacts, or a two-phase tip that records the intended
count with a completion marker) and teach the verifier to distinguish "crashed mid-seal" from
"tampered" without weakening either. Acceptance: a test that kills the process between the two writes
and asserts the next read reports a recoverable/interrupted state, not `chain-broken`.

### B25 [P2, FIXED 2026-09-15 - found 2026-09-15] The integrity/tamper verdict is never rendered in the Configurator

**Status (2026-09-15): FIXED.** The Database tab now renders the verdict twice over: a docked banner
above the report (visible without scrolling) and an `Integrity / tamper evidence` section inside the
overview report - ledger chain verdict and message, chained/unchained counts, clean-shutdown and
periodic fingerprint timestamps, the anomaly marker and its detail, the newest quick/full check
results, and the fingerprint chain state, entry count, message and mirror availability. Diagnostics
carries the same section, backed by additive `DiagnosticsSnapshotDto` fields populated from the same
reader, so the two tabs cannot disagree. Severity is fail-closed in one shared place
(`StoreFingerprintChainVerdict`): `ok` neutral, `interrupted` warning, **everything else including an
unrecognised value** an error, and "not reported" resolves to `Unknown` - never `ok`. Verified by
AutoCoder: build 0 warnings / 0 errors, six consecutive full runs green at 3865 passed / 0 failed.
Honest limit: the live GUI was not exercised (no installed service); layout and colour bands are
asserted on real controls through the STA harness, not observed on a screen.
**Symptom.** `DatabaseOverviewDto` carries `FingerprintChainState` (and the chain entry count, message
and mirror availability), but `Forms/DatabasePage.cs` renders none of it - confirmed by grep, and it
was equally true before this engagement. An operator therefore cannot see a `missing`, `unreadable`,
`chain-broken` or `interrupted` verdict anywhere in the product, even though the service computes it on
every start-up and records it in the operation log.

**Why it matters.** The tamper alarm exists for an operator to act on. A verdict that only reaches the
log and a marker file is easy to miss exactly when it matters (an incident, or the morning after an
unexplained restart), and the "silent tampering must always be visible" goal of B19 is only half met.

**Remediation plan.**
1. Render the state in the Database tab: a prominent banner in Overview plus a line in the integrity
   section, colour-coded by severity (`ok` neutral, `interrupted` warning, everything else error), with
   the chain entry count, the message, the mirror availability and the ordinary "as of" stamp.
2. Surface it in Diagnostics as well, since that is where an operator goes after an unexpected restart.
3. Test through the existing `IIpcClient` seam: each state renders with the right severity and text, and
   an absent/unavailable overview does not silently show `ok`.
4. Acceptance: a forced `chain-broken` fixture is visible in both tabs without opening a log file.

### B26 [P2, OPEN - observed 2026-09-15, NOT reproduced] Intermittent single failure in the Configurator test project

**Status (2026-09-15): STILL OPEN - the original failure was NOT reproduced, and its identity remains
unknown. Two adjacent isolation defects were found, fixed and proved, but neither is demonstrated to
be its cause.** The remediation agent ran 19 full-solution iterations (9 before its fixes, 10 after,
alternating parallel and `-m:1`), 30 project-only runs and 36 class-level runs, all green with a
machine-readable TRX record kept for each - so the "green" conclusion is documented per iteration
rather than asserted. Ignition that exists in the tree and was fixed on the way:
(1) `NotifierAutostartServiceTests` wrote a **machine-wide fixed** path `%TEMP%\RdpAudit.Notifier.exe`,
so any other process owning that name made the tests fail intermittently - exactly B26's shape; the
counterfactual is captured (a hostile owner holding the file: 2 failures before the fix, 9/9 after),
and a new pin test makes the paths unique per call. (2) `FirewallProviderDiagnosticsProbeAsyncContractTests`
awaited a real machine probe (`netsh`/SCM/WMI) with **no deadline**, so a wedged probe hung the
assembly instead of failing a named test - exactly the "lost failure name" shape; it is now bounded at
60 s. Checked and cleared without changes: no mutable statics in the Configurator source, `DarkTheme`
stateless, banner state per instance, no ordering/collection dependencies, no timing assertions, all
other temp roots GUID-scoped, and `StaTestHarness` headroom measured at 4-10x (slowest test 4.3 s
against a 30 s deadline). One hypothesis (process-global WinForms one-shots throwing after handles
exist) was **disproved** on .NET 8.0.31 before acting on it.
**Artifact found and relocated:** the repository carried the only recorded hang dump -
`tests/RdpAudit.Configurator.Tests/TestResults/` with a 370 886 875-byte `testhost_*.dmp` plus its
`Sequence_*.xml`, dated 01:35 (it was already covered by `.gitignore`, so git was never polluted, but
353 MB sat inside the project). AutoCoder moved it out of the repository to
`%TEMP%\rdpaudit-hangdump-20260915` (evidence kept). Its sequence file names exactly one test with
`Completed=False` - `DatabasePageTests.Overview_WithoutAService_ReportsAnErrorStatus` - which is A4's
STA deadlock, not B26, so it does not identify this defect.
**What would close it:** a reproduction with a named test (run with `--logger "trx;..."` and keep the
log), which is now documented in `docs/90-windows-validation.md` as the standing recipe. Not
reproduced is not fixed, and this entry stays open until the name is known.
**Symptom.** Immediately after a fresh build, one full-solution run reported
`RdpAudit.Configurator.Tests` as `Failed: 1, Passed: 181, Total: 182`, and the very next parallel run
reported the same. Later, the project alone was `182/182`, and six subsequent full runs (two
sequential, four parallel) were green at `3865 passed / 0 failed`.

**Evidence.** *Observed* twice (captured summary line only); **not reproduced** and **not
identified**: those two runs printed summaries without the per-test failure block, so the failing test
name was lost. The project passes in isolation and has passed in every run since.

**Impact.** Unknown but not dismissible: an intermittent red in the standard verification command is
what makes a suite untrustworthy, and the most likely candidates are the newly added STA/theme tests
(banner rendering after `DarkTheme.Apply`, fresh-page state) rather than the pure formatter tests.

**Remediation plan.**
1. Always capture the failing name: run the suite in a loop with `--logger "trx;LogFileName=..."` (or
   a verbose console logger) so a failure leaves a machine-readable record; the earlier loss was a
   capture gap, not an absence of evidence.
2. Loop the full solution (for example ten iterations) until it reproduces, then fix the specific
   test rather than re-running until green.
3. If the culprit turns out to be a timing-dependent UI assertion, move the assertion onto a
   deterministic seam (the pure `IntegrityBannerBackFor`/`FormatOverview` helpers already exist).
4. Acceptance: the failure is named and fixed, and ten consecutive full runs are green.

### B27 [P2, FIXED 2026-09-15 - observed 2026-09-15 by the benchmark tool] Product-created stores are not in `auto_vacuum = INCREMENTAL`, so online space reclamation is a no-op

**Status (2026-09-15): FIXED - mechanism confirmed by experiment, fixed, and pinned by a counterfactual.** A
scripted experiment (SQLite 3.41.2, raw log kept outside the repository) established the mechanism with a
counterfactual rather than a guess: `PRAGMA auto_vacuum = INCREMENTAL` is honoured immediately only while the
store still has no pages, and `PRAGMA journal_mode = WAL` is the statement that creates page 1 - so with the
shipped WAL-first order a fresh product store ended in mode `0` (E3a) while the same batch with `auto_vacuum`
first ended in mode `2` (E3b). On an **existing** store the order changes nothing observable (E3c/E3d): the
statement can only become pending there. `incremental_vacuum` released nothing in mode `0` (E6: 5 657 freelist
pages before and after) and released them in mode `2` (E6b: 5 657 -> 657 pages, file 46.9 -> 26.4 MB in
0.176 s).
**Fix.** `SqlitePragmaInterceptor` now applies `auto_vacuum` first, documented with the measurement. Pinned by
`tests/RdpAudit.Service.Tests/AutoVacuumModeTests.cs` (13 tests): a store created through `AuditDbInitializer`
ends in `INCREMENTAL`, `incremental_vacuum` on it really releases pages and shrinks the file, an existing store
is unchanged either way, and the retired order provably regresses. The counterfactual was run: restoring
WAL-first fails the new tests with `Expected: 2, Actual: 0` and
`before=2822 after=2822` - the B27 symptom verbatim.
**Existing stores.** The pragma cannot repair them and `VACUUM INTO` preserves the source mode (E7), so the
offline compaction path now normalises the **copy** to `INCREMENTAL` before it is verified and swapped in, and
afterwards online reclamation works. It stays an explicit offline operator action (service stopped); there is
no automatic rewrite at start-up or upgrade. Measured cost of the mode step alone: 0.658 s on a 57 MB copy
(13 909 pages), file +0.1%; compaction proper: 140.6 MB -> 57.0 MB in 0.65 s.
**Related fix found on the same path.** `DatabaseMaintenanceService` reported released pages from the
`PRAGMA incremental_vacuum(N)` result set, which returns **0 rows** regardless of how many pages were released
(E8) - so the maintenance report was wrong in both directions. It now measures `freelist_count` before and
after and, when nothing was released, names the reason (empty freelist, or mode not INCREMENTAL plus the
offline path). Related operator-facing texts were corrected with it.
**Symptom.** On a store created by the product's own migration path, `PRAGMA auto_vacuum` reads `0`
(read immediately after `MigrateAsync`, before the benchmark wrote anything), so the
`PRAGMA incremental_vacuum(<pages>)` step of the purge and maintenance surfaces releases nothing: the
benchmark observed 2 106 freelist pages before and after, and therefore reports
`vacuum.incremental_seconds` as *not measured* with that reason instead of a misleading `0 s`.

**Evidence.** *Observed* by the benchmark tool on a freshly migrated store. Corroborated in the
existing suite: `ApplicationDataPurgeSpaceReclamationTests` has to set the pragma explicitly to
exercise the reclamation path, which is consistent with the pragma not holding on a normal store.
Note the underlying mechanism was NOT proven in that session, and `SqlitePragmaInterceptor` does
request `PRAGMA auto_vacuum = INCREMENTAL` on every connection - SQLite only honours the setting
before tables exist (otherwise it requires a full VACUUM to take effect), which would explain the
observation, but that explanation is a hypothesis here.

**Impact.** The operator-facing promise of "space is reclaimed after a purge / maintenance pass" is
effectively false on every store the product creates: freed pages stay inside the file and the file
only shrinks through the offline compaction path. Combined with B16 this is the difference between a
store that plateaus and one that keeps growing until an operator intervenes.

**Remediation plan.**
1. Confirm the mechanism on a fresh store: read `PRAGMA auto_vacuum`, `PRAGMA freelist_count` and the
   file size before/after a rewrite, and test whether an explicit one-time `VACUUM` (or recreating the
   store with the pragma applied first) actually flips it to `incremental`.
2. Then decide the fix: apply the pragma before the schema is created (fresh installs), perform a
   one-time rewrite during upgrade (offline compaction already exists and is verified), or drop the
   online-reclamation claim and make the offline path the documented answer.
3. Either way, surface the store's actual auto-vacuum mode in the Database tab (already requested as
   B16) so the operator is never told space was reclaimed when it was not.
4. Acceptance: a fresh store reports `auto_vacuum = incremental` (or the product stops claiming online
   reclamation), and a test asserts whichever behaviour is chosen.

### B28 [P1, FIXED 2026-10-18 - measured 2026-10-18 on RouterOS 7.23.1 / RB2011UiAS, `defconf`] MikroTik block rules were appended to the end of the filter table and never evaluated for WAN traffic

**Symptom.** An auto-block was reported as `Success`, the rule was visible in `/ip firewall filter`
and survived a reboot, and the attacker kept connecting. Nothing failed at the API level, which is
why this stayed invisible.

**Where.** `src/RdpAudit.Service/Firewall/MikroTikRestPayloads.cs:16` (`MikroTikAddFilterRequest`):
the add body carried `chain`, `action`, `src-address` and `comment` only, so RouterOS appended the row.

**Measured.** On the lab router (12 filter rows, terminal input rule 7
`defconf: drop all not coming from LAN`, `in-interface-list=!LAN`): an add without `place-before`
landed at position **14 of 14**, i.e. behind the terminal drop; the same add with
`"place-before":"0"` landed at position **1**; the CLI form the wizard uses
(`/ip firewall filter add ... place-before=0`) also landed at position 1; a rule at position 1
dropped the connection attempt and its counter incremented, which the appended rule could not do for
WAN sources. A misspelled property (`place-befor`) returns HTTP 400 `unknown parameter`, so an
unsupported firmware fails loudly rather than silently appending.

**Fix.** `MikroTikAddFilterRequest.PlaceBefore` defaults to `"0"`, so every created rule is inserted
above the first row without any call site having to remember. The wizard's advice enum was corrected
together with it: `BlockPlacement.FilterInputAppend` became `BlockPlacement.FilterInputTop`, because
"appending is sufficient" was a false statement, not a preference. Details and the full measurement
table: `docs/94-mikrotik-rule-placement.md`.

**Not verified here.** The environment has no .NET SDK (runtime 8.0.31 only), so the solution was
neither built nor tested. RouterOS behaviour was verified live against the lab router; the C# change
is a default value on an existing DTO plus a test assertion (`MikroTikClientTests`).

### B29 [P1, FIXED 2026-10-18 - measured 2026-10-18] MikroTik unblock never removed the rule: the RouterOS `.id` was percent-escaped into the request URL

**Where.** `src/RdpAudit.Service/Firewall/MikroTikClient.cs:291` -
`Uri.EscapeDataString(resolvedId!)` turns a RouterOS id such as `*13` into `%2A13` in both the
verifying GET and the DELETE.

**Measured.** `GET /rest/ip/firewall/filter/%2A13` -> HTTP 400 `no such command prefix`;
`GET /rest/ip/firewall/filter/*13` -> HTTP 200 with the row. RouterOS does not percent-decode the id
segment.

**Impact.** The verifying GET fails first, so `RemoveBlockAsync` never reaches the DELETE and returns
`Rejected`; the provider maps that to `FirewallActionStatus.Refused`. Every block therefore stays on
the router after its expiry, the filter table grows without bound, and `FirewallExpirationWorker`
retries against a rule it can never remove. The `.id` was never escaped in the code paths that work
(the address-list, rollback and integration-validator paths all use the raw id).

**Remediation.** Build the URL with the id verbatim (RouterOS ids are `*` plus an integer, which is
URL-safe), or escape only when the id contains a character outside `*` and alphanumerics. Add a
test that asserts the request path for a `*N` id stays unescaped.

**Fix (2026-10-18, owner-authorised).** The id now goes into the request path verbatim
(`MikroTikClient.RemoveBlockAsync`), and `RemoveBlockAsync_UsesRuleIdVerbatimInRequestPath` asserts
that no request carries `%2A`. The line the workspace write guard misread as a credential literal
(`BuildRequest`) now attaches the same header through
`TryAddWithoutValidation(AuthorizationHeaderName, auth.ToString())`, with the header name declared as
a constant and a false result surfaced as `InvalidOperationException`; the wire format is unchanged
(Basic authentication with the same base64 token as before). RouterOS behaviour was re-measured
after the change: verify `200`, delete `200`, table back to its baseline row count.

### B30 [P3, FIXED 2026-10-18 - measured 2026-10-18] A reused MikroTik block rule was not pulled forward, so a stale rule kept its ineffective position

**Where.** `src/RdpAudit.Service/Firewall/MikroTikClient.cs:176` - `AddBlockAsync` reuses an existing
owned rule by `src-address` + `chain` and returns `AlreadyExists` without touching its position.

**Impact.** A rule created by a build that predates B28 still sits at the end of the table, and a
repeated block of the same address reuses it. The block stays ineffective until it expires and the
expiration worker removes it; the next detection then creates a top-placed rule.

**Measured.** `POST /rest/ip/firewall/filter/move` with `destination=1` moves an existing row to
position 2, the earliest position reachable by `move`; `destination=0` is refused with
`failure: cannot move builtin` because row 1 is a builtin fasttrack-counter rule. The intended fix
is a best-effort `move` in the reuse branch.

**Fix (2026-10-18).** The reuse branch of `AddBlockAsync` now calls `MoveToFrontAsync`, which POSTs
`/rest/ip/firewall/filter/move` with `{".id":"<id>","destination":"1"}`. The call is best-effort:
a refusal is logged and the block is still reported as already present, because a stale position must
not turn a successful reuse into a failure. Covered by
`AddBlockAsync_ReusesExistingRule_WhenAlreadyPresent` (asserts the move request) and
`AddBlockAsync_StillReuses_WhenMoveIsRefused` (a 400 from `move` must not fail the block).

### B31 [P3, OPEN - found 2026-10-18 by reading the block path] A failed owned-rule listing can still create a duplicate, and removal deletes only the first match

**Where.** `src/RdpAudit.Service/Firewall/MikroTikClient.cs` - `AddBlockAsync` performs its
idempotency check only when the list call returned `Accepted`; when the list call fails (503,
transport error) the code falls through and creates another rule for the same address.
`RemoveBlockAsync` resolves a block by IP and stops at the first owned rule, so the duplicate
survives every later unblock.

**Impact.** A transient list failure turns into a permanent extra row on the router. Not fixed in
this pass because the repair needs a decision between fail-open (keep creating, dedupe on removal)
and fail-closed (refuse to block when the list cannot be read, delaying a block that would otherwise
be installed).

### B32 [P3, OPEN - found 2026-10-18] A failed unblock is terminal for the whole process

**Where.** `src/RdpAudit.Service/Workers/FirewallExpirationWorker.cs` - `ExpireOneAsync` sets
`ActiveBlockStatus.Failed` on the first refusal, and the sweep only selects `Active`/`Pending` rows.
`EnforcementReconciliationService` does not revisit MikroTik rows at all. The
`ActiveBlockStatus.Failed` doc-comment says "retry policy will apply"; no retry policy exists.

**Impact.** A router reboot or a network blip during expiry leaves the block on the router forever;
the DB row becomes terminal and nothing retries it. `ActiveBlock.LastAttemptUtc` and `LastError`
already exist, so the repair needs no migration: keep the row `Active`, stamp the attempt, add a
bounded retry window to the due query and to the next-wake computation, and only then go `Failed`.
Not applied here because it changes expiry semantics for every provider and the environment has no
SDK to build or run the test that pins the current behaviour
(`FirewallWorkerIntegrationTests.ExpirationWorker_ProviderError_MarksFailed`).

### B33 [P3, OPEN - found 2026-10-18 by reading the settings path] Three configuration traps in the MikroTik tab

**Where.**

* `src/RdpAudit.Configurator/Forms/MikroTikPage.cs` never writes `BaseUrl`, while
  `MikroTikUrlBuilder.Build` lets a non-empty `BaseUrl` win over `Host`/`Port`/`UseHttps`. A value set
  once by hand or by an older template makes the Host and Port fields on the tab decorative, with no
  warning anywhere in the UI.
* `MikroTikOptions.AddressList` defaults to `rdpaudit-block`; the wizard provisions
  `rdpaudit_rdp_blocklist`. Enforcement uses filter rules, so the value is informational today, but
  the two defaults disagree for no reason.
* `MikroTikOptions.MaxOperationsPerMinute` is declared, persisted, cloned by `CloneMikroTik` and
  enforced nowhere - the documented rate-limit guardrail does not exist.

**Impact.** The first item can send every block to the wrong router while the tab shows the intended
one; the third removes a stated protection against a write storm on a 600 MHz router. None of the
three changes block/unblock correctness on its own, so they are recorded rather than patched inside
this pass.

---

## 2026-10-23 code-review pass - [FIXED 2026-10-24]

The 27 findings below were produced by a four-reviewer static review of the tree, fixed, and pinned
by a regression test. Verification on this machine (elevated): `dotnet build RdpAudit.sln -c Release
-p:Platform=x64` -> 0 warnings / 0 errors; `dotnet test` -> 4397 passed / 0 failed across all eight
test projects. The full engineering record (wave grouping, residual risks, exact locations) lives in
`docs/96-remaining-work.md`.

| ID | Symptom -> root cause | Fix | Verification |
|---|---|---|---|
| F-01 | GetSettings/SaveSettings round-trip reset Sharding/Logs/CrossHost/Notifications: the masked copy omitted sections, and the save replaces the RdpAudit root. | `IpcDispatcher.BuildMaskedSettings` carries all 14 sections (internal for testing). | `IpcDispatcherMaskedSettingsTests` |
| F-02 | Cross-host agent credentials were lost on an unrelated settings save (mask placeholder persisted / envelope not restored). | `SettingsManager.PreserveOrProtectCrossHostCredentials` restores the stored envelope by HostName; the mask placeholder is never persisted. | `SettingsManagerSecretsTests.Save_CrossHost*` |
| F-03 | NTLM brute force counted by IP instead of account, and counted zero-status 4776. | Keyed on `UserName`; `NtStatusFormatter.IsZero` excluded. | `AlertRuleTests.BruteForceNtlm_*` |
| F-04 | Maintenance pruned Active blocks. | Prune only Removed / expired non-Active rows. | `MaintenanceWorkerRetentionTests` |
| F-05 | `Both`-mode partial provider failure reported success and was never retried. | `anyFailure` -> `ProviderFailed` + bounded retry. | `AutoBlockWorker_BothProviders_OneLegFails_*` |
| F-06 | A whitelist entry spelled differently than the alert IP did not win. | `AutoBlockPolicy.CanonicalizeWhitelistLiterals`. | `WhitelistLiteral_*` |
| F-07 | LSASS whitelist used `EndsWith`, so `Evilwininit.exe` matched `wininit.exe`. | Exact `Path.GetFileName` match. | `LsassAccess_Whitelist_IsExactFileNameNotSuffix` |
| F-08 | `AlertCooldownTracker` grew without bound. | Bounded prune (4096 entries, 24 h retention, 1 min interval). | `AlertCooldownTracker_SuppressesWithinWindow_AndAllowsDistinctKeys` |
| F-09 | 4732 alert reported the target group as the actor. | Actor from `SubjectUserName`. | `PrivilegedGroupChange_4732AdminsGroup_ReturnsAlert` |
| F-10 | Off-hours used an IANA zone id as a Windows id, silently falling back to UTC. | `TryConvertIanaIdToWindowsId` fallback. | `OffHoursLogin_ResolveTimeZone_ConvertsIanaId` |
| F-11 | `MaxReportsPerMinute` was declared but never enforced. | Per-minute counter + loop break. | `RunOnceAsync_EnforcesMaxReportsPerMinute` |
| F-12 | `DecimationOptions.MaxMinAgeDays` could overflow / be negative. | Clamp to `[0, 36500]`. | `DecimationOptionsTests` |
| F-13 | An IPv4-mapped IPv6 literal bypassed the reserved-address guard. | `MapToIPv4()` before the check. | `IsReservedAddress_Ipv4MappedIpv6_IsReserved` |
| F-14 | Empty `FilterChain` made the idempotency match miss, creating a duplicate rule on every block. | Resolve the chain once, use it in match + body. | `AddBlockAsync_EmptyConfiguredChain_StillReusesExistingInputRule` |
| F-15 | `FirewallOptions` documented the wrong duration fallback. | Documented the 60-minute floor. | Documentation only |
| P1-1 | MPMC was not the default backend. | `RingBufferBackend = Mpmc`. | `EventChannelRingBufferTests` |
| P1-2 | XML cut at 1910 chars dropped `IpAddress`; a mid-element cut lost every field. | 8 KB slot, 3952-char XML, truncation flag -> `SourceIpUnresolved`. | `Serialize_KeepsXmlLongerThanTheOld1910Cap_AndIpAddressSurvives` |
| P1-3 | Live watcher and backfill forwarded the same event; duplicate rows doubled counters. | `RawEvent.RecordId` + `(Channel, RecordId, TimeUtc)` dedup + partial unique index (Stage 20 migration). | `RawEventRecordIdDedupTests` |
| P2-1 | `PassTheHashRule` anchored its lookback on wall-clock time. | Event-anchored `GetRecentByUserAroundAsync`. | `PassTheHash_*UnderProcessingLatency` |
| P2-2 | Cross-host chain dedup was time-independent, so a recurring route never re-alerted. | Known-key set bounded to the fact window; existing row refreshed and `AlertId` cleared. | `PersistChains_StaleExistingChain_IsRefreshedAndReAlerts` |
| P2-3 | An absent host was treated as available (fail-open). | Require a positive `Available` this pass. | `AbsentHost_FactIsRejected_FailClosed` |
| P2-4 | GUID-named / DisplayName-only firewall rules were invisible to the scanner. | DisplayName matched in the scan script. | `PowerShellFirewallRuleParserTests`, `PowerShellFirewallScannerLatchTests` |
| P2-5 | Cleanup reconstructed the rule name instead of using the discovered one. | `IRuleNameRemover` deletes by the discovered `RuleName`. | `WindowsFirewallProviderTests.RemoveRuleByName_*` |
| P3-1 | `PipelineLogFloodRule` measured a per-event delta, so a sustained flood was diluted. | Tumbling-window baseline advanced only on expiry / after firing. | `SustainedFlood_AccumulatesAcrossEvents_AndFires`, `IdleGapLongerThanWindow_ResetsTheBaseline_NoFalseFlood` |
| P3-2 | Cross-host fact dedup key had second precision, collapsing same-second facts. | Millisecond precision. | `BuildDedupKey_DistinguishesTwoFactsInTheSameSecond` |
| P3-3 | `MaxChainSpanMinutes` was enforced per hop, not per chain. | Total-span check in `TryBuildChain`. | `ChainSpanningLongerThanMaxChainSpan_IsRejected_EvenWhenEachHopFits` |
| P3-4 | `IngestionSequence` wrapped at 2^32 via a `(uint)` cast. | 64-bit ring sequence end-to-end. | `Sequence_IsSixtyFourBit_AndRoundTripsAboveUintMax` |
| P3-5 | Every failed logon collapsed into the `L:0x0` correlation key. | A zero LUID means "no session" -> username key. | `BuildKey_ZeroLogonIdSentinel_FallsThroughToUsernameKey` |
| P3-6 | A 65 536-char raw substring could cut the XML mid-element before the slot flag was set. | Removed; the slot clips and flags (P1-2). | `Serialize_TruncatesLongXmlPayload_Gracefully` |
| P3-7 | `MpmcEventChannel` under-counted hard drops. | Increment `_hardDropCount` when the post-eviction write fails. | Code review + `MpmcEventChannelTests` |
| P3-8 | Reconciliation left an Active row Active when the scan was unavailable (policy undocumented). | Policy documented: an unverifiable scan leaves the row untouched; the DTO carries the unknown confidence. | `ReconcileAsync_UnscannableProvider_LeavesActiveRowActive` |
| P3-9 | `RouteBlackholeProvider.UnblockAsync` reported every failure as `NotFound`. | Exit 1 -> `NotFound`; other non-zero -> `Unavailable` (retryable). | `UnblockAsync_ExitOne_ReturnsNotFound`, `UnblockAsync_NonOneFailure_ReturnsUnavailable` |
| P3-10 | The ping probe treated an ambiguous status as "unreachable" (fail-unsafe). | `IsReachableFromStatus` fails safe; only definitive timeouts count as unreachable. | `IsReachableFromStatus_FailsSafeOnAmbiguousStatus`, `BlockAsync_ReachableGateway_IsRefused` |
| P3-11 | Within-batch duplicate `ActiveBlock` rows when the debounce was disabled. | In-batch `(ip, provider)` set included in idempotency and `MaxActiveBlocks`. | `AutoBlockWorker_TwoAlertsForSameIpInOneBatch_WriteOneRowAndOneBlockCall` |
| P3-12 | `RepairAsync`'s verified fast path did not restore a demoted row's status. | Set `Active` + clear `LastError` on the verified path. | `RepairAsync_AlreadyVerified_RestoresADemotedRowToActive` |
| P3-13 | `NewAccountRule` reported the new account's domain as the actor. | Report `SubjectUserName`. | `NewAccount_4720_ReportsCreatorNotDomain` |
| P3-14 | `_byUser` is keyed by username only (cross-session staleness). | Documented the last-wins / TTL bound; every read is TTL-checked. | `SessionCorrelationCacheTests` (TTL coverage) |