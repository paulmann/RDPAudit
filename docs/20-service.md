# RdpAudit.Service

The Windows Worker Service that captures, persists, and analyses Windows security events.

## Workers

| Worker | Responsibility |
|--------|----------------|
| `EventCollectorWorker` | Spawns one `EventLogWatcher` per channel (`EventCatalog.AllChannels`). The XPath query is built from `EventCatalog.EventIdsForChannel`. Bookmarks are flushed every 100 events and every 30 seconds. Watcher failures trigger an exponential backoff restart capped at 5 min, max 10 retries. |
| `EventProcessorWorker` | Drains the bounded pipe in batches (via `IEventPipe.WaitToReadAsync` / `TryRead`), normalises payloads through `EventNormalizer`, upserts facts, and bulk-inserts events under a single `RawEvents` transaction. `PersistBatchAsync` enforces two independent durability boundaries: the pre-commit `try/catch` is the only path that rolls back and discards pending shard records; the post-commit shard flush runs outside it on a dedicated `SqliteConnection`, so shard-phase failures never roll back committed `RawEvents` nor discard the retained queue. |
| `AlertWorker` | Periodically loads the next 200 unprocessed `RawEvent` rows, walks every registered `IAlertRule`, persists matching `Alert` rows, and marks the events processed. |
| `IpcServerWorker` | Hosts the `RdpAuditService` named pipe with `BuiltinAdministratorsSid` + `LocalSystemSid` ACL and dispatches incoming `IpcRequest` frames to `IpcDispatcher`. v2.3.4 requests `MaxConcurrent + 1` OS instances and classifies `ERROR_PIPE_BUSY` (231) as instance-cap saturation; v2.3.5 emits per-instance lifecycle breadcrumbs (`instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting`) to `ipc-startup.log`. |
| `MaintenanceWorker` | Daily housekeeping: prunes events / alerts past retention, runs `PRAGMA incremental_vacuum`, decays `Address.ThreatScore` by 5%, prunes log files. |

## Channel<T>

`EventChannel` constructs a `Channel.CreateBounded<RawEventDto>` with `FullMode = DropOldest` so EventLogWatcher callbacks never block.

## Forensic shard commit durability

`EventProcessorWorker.PersistBatchAsync` enforces two independent durability
boundaries around the main `RawEvents` transaction:

- **Pre-commit** — normalisation, fact upserts, bookmark write and
  `tx.CommitAsync()` live inside a single `try/catch`. On failure the
transaction is rolled back and `ShardIngestionSink.DiscardPending()` drops only
the staged shard records that never reached disk.
- **Post-commit** — the shard flush (`CommitShardsAfterDatabaseCommitAsync`),
  checkpoint pruning and metrics run OUTSIDE that `try/catch`. A shard-phase
  failure can never roll back the already-committed `RawEvents` batch (the
  EventID 7013 class of defect).

Shard rows are written on a dedicated live `SqliteConnection` (the EF-owned
connection is closed together with its transaction), with bounded
`SQLITE_BUSY` / `SQLITE_LOCKED` retries. `ShardIngestionSink.CommitAsync` is a
true durability boundary for the shard batch: the pending `_touched` queue is
cleared and the writer pool trimmed only after the whole batch succeeds; a
failure inside `CommitAsync` retains the queue so the next successful flush
recovers it. Cancellation during the shard phase keeps both the committed
`RawEvents` and the pending queue.

## Adding a new alert rule

1. Implement `IAlertRule` (or extend `AlertRuleBase`). Use a unique SCREAMING_SNAKE_CASE `RuleId`.
2. Register the rule in `Alerts/AlertRuleRegistration.cs`.
3. Add at least three unit tests in `tests/RdpAudit.Service.Tests/AlertRuleTests.cs`:
   - below threshold → null
   - at threshold → alert
   - whitelisted IP / unrelated event id → null

## Single instance guard

The service enforces single-instance startup through `Infrastructure/SingleInstanceGuard.cs` around the kernel named mutex `Global\RdpAuditService`.

- Acquired in `Program.Main` immediately after `ConfigureSerilog`, before `RegisterServices` / `builder.Build()`. `WaitOne(0)` is synchronous, so no host is built inside an already-running instance.
- The mutex DACL grants `FullControl` to `BuiltinAdministratorsSid` and `LocalSystemSid` only. If the explicit descriptor is refused (`ERROR_ACCESS_DENIED`, `ERROR_INVALID_OWNER`, `ERROR_PRIVILEGE_NOT_HELD`, `ERROR_INVALID_SECURITY_DESCR`), the guard falls back to the process-default DACL so unusual host security configs still start.
- An `AbandonedMutexException` (previous process died without calling `ReleaseMutex`) is recovered as `RecoveredAbandoned` and startup continues; the recovery is logged as a warning.
- Refusal to start exits the process with the project exit code `0x1000` (`SingleInstanceExitCodePolicy.AlreadyRunningExitCode`). It is deliberately outside `0..255` (normal process error codes), distinct from Win32 code `2` (neither ERROR_FILE_NOT_FOUND nor a host-fault `1`), so SCM and operators can tell a busy mutex from a crash.
- `--console` violates the contract only by emitting a human-readable refusal line to stderr; Windows-service mode uses `Exit(int)`.

## LLM contract

- Never share a `DbContext` between workers. Always use `IDbContextFactory<AuditDbContext>` and `await using var db = await factory.CreateDbContextAsync(ct)`.
- All async methods must accept and honour the supplied `CancellationToken`.
- Logging must use named placeholders (`_logger.LogInformation("{X}", x)`) — never string interpolation in `Log.*` calls.
- `EventRecord.ToXml()` must be called synchronously inside the `EventRecordWritten` callback; the `EventRecord` is invalid after the callback returns.

## PRIVILEGED_LOGIN hardening (4672)

`PrivilegedLoginRule` flags Security 4672 (SeDebug / SeTcb assigned at logon) only when a
meaningful network context exists. Rejection paths are allocation-free: `EvaluateAsync` is
NOT an `async` method and returns a cached null-task singleton, so repeated evaluations
allocate zero managed bytes.

Gates in evaluation order:

1. **Event id** - only 4672 proceeds.
2. **Historical age gate** - events older than `Alerts.AlertEventMaxAgeMinutes` (default 5)
   are ignored; they stay persisted as `RawEvent` facts but never alert.
3. **Source IP** - a missing/empty `SourceIp` always fails (the 2026-08-24 SYSTEM storm path).
4. **User whitelist** - `Alerts.WhitelistUsers` wins.
5. **Sensitive privilege scan** - `privilegeList` must contain one of
   `SeDebug/SeTcb/SeImpersonate/SeBackup/SeRestore/SeTakeOwnership`.
6. **Well-known service SID filter** - `S-1-5-18` / `S-1-5-19` / `S-1-5-20` are rejected by
   exact SID read from the normalized `Details` JSON (`subjectUserSid`); localized account
   names are never used.
7. **Logon-type gate** - explicit `LogonType` 3 / 7 / 10 passes, everything else fails.
   A null `LogonType` (Windows 4672 has no field of its own) falls back to correlating the
   matching Security 4624 via `SubjectLogonId == TargetLogonId` through
   `IAlertContext.GetRecentByUserAsync`.

After the gates, identical triggers are suppressed per (user, source ip, logon type) inside
`Alerts.PrivilegedLoginSuppressionWindowMinutes` (default 5). One summary alert carrying the
suppressed count is emitted when the window expires. A per-minute budget
(`Alerts.PrivilegedLoginRateLimitPerMinute`, default 20) caps the total output; throttling
is logged once per minute.

`AlertWorker` additionally applies the same age ceiling to all rules, so no historical
replay can alert via any rule.

## Required tests before modifying

- `tests/RdpAudit.Service.Tests/AlertRuleTests.cs` — every alert-rule modification must update or add tests covering threshold and bypass paths.
- Run `dotnet test tests/RdpAudit.Service.Tests` before opening a PR.
