# RdpAudit.Service

The Windows Worker Service that captures, persists, and analyses Windows security events.

## Workers

| Worker | Responsibility |
|--------|----------------|
| `EventCollectorWorker` | Spawns one `EventLogWatcher` per channel (`EventCatalog.AllChannels`). The XPath query is built from `EventCatalog.EventIdsForChannel`. Bookmarks are flushed every 100 events and every 30 seconds. Watcher failures trigger an exponential backoff restart capped at 5 min, max 10 retries. |
| `EventProcessorWorker` | Drains the bounded `Channel<RawEventDto>` in batches (default 100 / 500 ms), normalises payloads through `EventNormalizer`, upserts addresses, and bulk-inserts events under a single transaction. SQLite write retries on error 5/6 with five exponential backoff steps. |
| `AlertWorker` | Periodically loads the next 200 unprocessed `RawEvent` rows, walks every registered `IAlertRule`, persists matching `Alert` rows, and marks the events processed. |
| `IpcServerWorker` | Hosts the `RdpAuditService` named pipe with `BuiltinAdministratorsSid` + `LocalSystemSid` ACL and dispatches incoming `IpcRequest` frames to `IpcDispatcher`. |
| `MaintenanceWorker` | Daily housekeeping: prunes events / alerts past retention, runs `PRAGMA incremental_vacuum`, decays `Address.ThreatScore` by 5%, prunes log files. |

## Channel<T>

`EventChannel` constructs a `Channel.CreateBounded<RawEventDto>` with `FullMode = DropOldest` so EventLogWatcher callbacks never block.

## Adding a new alert rule

1. Implement `IAlertRule` (or extend `AlertRuleBase`). Use a unique SCREAMING_SNAKE_CASE `RuleId`.
2. Register the rule in `Alerts/AlertRuleRegistration.cs`.
3. Add at least three unit tests in `tests/RdpAudit.Service.Tests/AlertRuleTests.cs`:
   - below threshold → null
   - at threshold → alert
   - whitelisted IP / unrelated event id → null

## LLM contract

- Never share a `DbContext` between workers. Always use `IDbContextFactory<AuditDbContext>` and `await using var db = await factory.CreateDbContextAsync(ct)`.
- All async methods must accept and honour the supplied `CancellationToken`.
- Logging must use named placeholders (`_logger.LogInformation("{X}", x)`) — never string interpolation in `Log.*` calls.
- `EventRecord.ToXml()` must be called synchronously inside the `EventRecordWritten` callback; the `EventRecord` is invalid after the callback returns.

## Required tests before modifying

- `tests/RdpAudit.Service.Tests/AlertRuleTests.cs` — every alert-rule modification must update or add tests covering threshold and bypass paths.
- Run `dotnet test tests/RdpAudit.Service.Tests` before opening a PR.
