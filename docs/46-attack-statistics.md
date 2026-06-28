# Attack Statistics (Stage 6)

The Attack Statistics subsystem materialises one row per attacker IP with a deterministic
`ThreatScore` and a cameyo-style green / yellow / red classification. The subsystem ships in two
sub-stages, both now complete:

* **Stage 6A** — back-end aggregation worker, threat-scoring rules, and the `GetAttackStats` IPC
  command.
* **Stage 6B** (this branch) — the Configurator **Attack Statistics** tab consuming the IPC
  contract delivered in Stage 6A. See `docs/30-configurator.md` for the operator-facing surface.

## Components

| Layer | Code | Responsibility | Stage |
|-------|------|----------------|-------|
| Schema | `Core/Models/AttackStat.cs` + `Core/Data/Configurations/AttackStatConfiguration.cs` | One row per source IP. Primary key is `Ip`. Materialised by the worker. | 2 |
| Aggregation | `Core/Models/AttackStatsAggregator.cs` | Pure projection from a bounded slice of `RawEvents` and a set of currently-blocked IPs into one `AttackStat` per distinct source IP. | 6A |
| Scoring | `Core/Models/AttackThreatScoring.cs` | Pure, deterministic `ThreatScore` in `[0..100]` and a `AttackThreatLevel` classification. | 6A |
| Worker | `Service/Workers/AttackStatsRefreshWorker.cs` | Background service. Refreshes the table once at startup and then every 60 seconds. `SemaphoreSlim` guards against concurrent re-entry. | 6A |
| IPC | `Service/Ipc/IpcDispatcher.cs::GetAttackStatsAsync` + `Core/Ipc/Contracts/AttackStatsRequest.cs` + `Core/Ipc/Contracts/AttackStatEntryDto.cs` + `Core/Ipc/Contracts/AttackStatsDto.cs` | Filtered / paged read surface. Returns controlled `IpcResponse` payloads — never raw exceptions. | 6A |
| Filter helper | `Core/Util/AttackStatsFilter.cs` | Pure predicate mirroring `AttackStatsRequest`. Used by Stage 6B UI for client-side pre-filtering while the operator types. | 6A (helper) / 6B (UI consumer) |
| Recent-range helper | `Core/Util/AttackStatsRecentRange.cs` | Pure mapping from the toolbar `Recent period` dropdown to an absolute `SinceUtc` bound. | 6B |
| Row formatter | `Core/Models/AttackStatRowFormatter.cs` | Pure clipboard formatters (multiline + TSV) and duration / top-logins UI helpers. | 6B |
| UI | `Configurator/Forms/AttackStatisticsPage.cs` | Grid + filter toolbar + right-click menu + 5-second auto-refresh with re-entry guard + status strip. See `docs/30-configurator.md`. | 6B |

## Refresh cadence

`AttackStatsRefreshWorker` runs on a fixed 60-second cadence. The worker:

1. Performs a startup refresh immediately (no initial delay) so the dashboard has data on first
   open.
2. Sleeps for `Period = 60 seconds` between passes. The sleep honours `stoppingToken`.
3. Bounds each pass:
   - `LookBackWindow = 30 days` — only `RawEvents.TimeUtc >= now - 30d` participate.
   - `MaxRawEventsPerPass = 50,000` — ceiling on rows fetched per pass to keep the SQLite
     query under the writer lock for a bounded duration.
4. Re-uses the same `IDbContextFactory<AuditDbContext>` as every other worker; one `DbContext` per
   pass with `AsNoTracking()` reads.
5. Guards against concurrent re-entry via `SemaphoreSlim(1, 1)`. A second `RefreshOnceAsync` call
   while the first is in flight returns `0` without touching the database.

### Future optimisation (not in Stage 6)

The Stage 6 worker performs a full slice scan over the look-back window every pass. The schema
already carries the indices to make this query-friendly (`RawEvents.TimeUtc`,
`RawEvents.SourceIp`), but at multi-million-row scale we will want to:

- Track a high-water `RawEvents.Id` per IP in a `Stage7Bookmarks` table and project only the delta
  per pass.
- Treat `AttackStats.LastUpdatedUtc` as the floor for the next pass so untouched rows are skipped.

Both are append-only schema changes that fit a future stage without breaking Stage 6 callers.

## Aggregation projection

`AttackStatsAggregator.Aggregate(IEnumerable<AttackEventSample>, ISet<string> blockedIps,
DateTime nowUtc)` produces one `AttackStat` per distinct, non-empty source IP. The projection is:

- `TotalAttempts` — count of input samples.
- `Successful` — count of samples where `EventId == 4624` (Security channel logon success).
- `Failed` — count of samples where `EventId == 4625` (failure) **and** any unknown event id.
- `FirstSeenUtc` — minimum `TimeUtc` observed.
- `LastSeenUtc` — maximum `TimeUtc` observed.
- `DurationSeconds` — `LastSeenUtc - FirstSeenUtc`, clamped at zero.
- `Top10AttemptedLogins` — deterministic top-10 by frequency, alphabetical tiebreak,
  serialised via `AttackStatProjection.SerializeTopLogins`.
- `LastLoginType` — `LogonType` captured on the most-recent sample.
- `IsBlocked` — `blockedIps.Contains(ip)`.
- `ThreatScore` — see below.
- `LastUpdatedUtc` — `nowUtc`.

Result ordering is deterministic: descending by `ThreatScore`, then ordinal-ascending by `Ip`.

## Threat scoring

`AttackThreatScoring.ComputeScore` assembles five additive components, then clamps to `[0..100]`:

| Component | Formula | Cap | Rationale |
|-----------|---------|-----|-----------|
| Failure pressure | `failed × 0.5` | `40` | Slow drips contribute, sustained pressure saturates. |
| Success-after-fail | `20` if `failed > 0 && successful > 0`, else `0` | `20` | Lit when an attacker eventually lands a guess. |
| Intensity | `failed / max(1, durationSeconds) × 1000` | `20` | Brute-force bursts score higher than the same total spread over hours. |
| Active block | `10` if `IsBlocked`, else `0` | `10` | Existing block is strong corroboration. |
| Recentness | `10` if `< 1h`, `5` if `< 24h`, `0` otherwise | `10` | Old chatter decays. |

Total is clamped to `[0..100]`.

### Classification

| Band | `ThreatScore` | Meaning | UI |
|------|---------------|---------|----|
| `Green` | `0 .. 29` | Legitimate or low-risk. | Soft green row. |
| `Yellow` | `30 .. 69` | Low-intensity failed connections. | Soft yellow row. |
| `Red` | `70 .. 100` | High-intensity / likely brute force. | Soft red row. |

Thresholds are public constants in `AttackThreatScoring` so the UI, IPC, and tests cannot drift.

### Worked examples

| Scenario | Inputs | Score | Band |
|----------|--------|-------|------|
| Single successful logon, 2 days ago | `f=0 s=1 dur=0 blocked=false recent=2d` | `0` | Green |
| 40 failed attempts over 1 hour, not blocked, recent | `f=40 s=0 dur=3600 blocked=false recent=now` | `~41` | Yellow |
| 200 failed attempts in 10 seconds, blocked, recent | `f=200 s=0 dur=10 blocked=true recent=now` | `80` | Red |
| 50 failed + 1 successful in 30 seconds, blocked | `f=50 s=1 dur=30 blocked=true recent=now` | `85` | Red |

These four cases are pinned in `AttackThreatScoringTests`.

## IPC

`GetAttackStats` (ordinal `18`) accepts an `AttackStatsRequest` payload:

| Field | Type | Default | Semantics |
|-------|------|---------|-----------|
| `IpQuery` | `string?` | `null` | Case-insensitive substring on `AttackStat.Ip`. |
| `MinThreatScore` | `double?` | `null` | Inclusive lower bound on `ThreatScore`. |
| `OnlyBlocked` | `bool` | `false` | Restrict to rows where `IsBlocked == true`. |
| `SinceUtc` / `UntilUtc` | `DateTime?` | last 7 days | Inclusive `LastSeenUtc` window. |
| `Limit` | `int` | `500` | Clamped server-side to `[1..2000]`. |

Response shape (`AttackStatsDto`):

- Stage 1 reservation: `Status`, `WindowStartUtc`, `WindowEndUtc`, `FailedLogons`,
  `SuccessfulLogons`, `DistinctSourceIps`, `AlertsRaised`, `AddressesAutoBlocked`, `Message` —
  preserved at the original `[Key]` indices.
- Stage 6 additions (append-only): `Entries: List<AttackStatEntryDto>`, `TotalMatching: int`,
  `AppliedLimit: int`.

The Configurator never writes to the `AttackStats` table directly; every read flows through this
IPC command.

## Validation

- **Cross-check counts.** For any non-empty `AttackStat.Ip`, the sum of `Failed + Successful` in
  the `AttackStats` row should equal the number of `RawEvents` rows with that `SourceIp` inside
  the worker's `LookBackWindow`. Verify by sampling one IP from the grid and running
  `SELECT COUNT(*) FROM RawEvents WHERE SourceIp = '…' AND TimeUtc >= datetime('now', '-30 days')`.
- **Score reproducibility.** The score is a pure function of `(failed, successful, durationSeconds,
  isBlocked, lastSeenUtc, nowUtc)`. Given the row's columns, you can reproduce the score by hand
  using the formulas above; any mismatch indicates a worker bug.
- **Block sync.** `IsBlocked` must equal `EXISTS (SELECT 1 FROM ActiveBlocks WHERE Ip = ? AND
  Status IN (Active, Pending))` at the worker's last refresh.

## Tests

| Suite | Coverage |
|-------|----------|
| `AttackThreatScoringTests` | Each scoring component, the clamp, classification boundaries, recentness buckets, clock-skew handling. |
| `AttackStatsAggregatorTests` | Empty input, blank-IP skip, group-by-IP, success vs failure counting, top-N login cap, `IsBlocked` propagation, unknown event ids, deterministic ordering. |
| `AttackStatsFilterTests` | Empty filter, null entry, IP substring, min-threat inclusive bound, only-blocked, since/until inclusive bounds, AND semantics. |
| `AttackStatRowFormatterTests` | Multiline + TSV clipboard output, top-logins formatter, duration formatter, TSV tab/newline sanitisation. (Stage 6B) |
| `AttackStatsRecentRangeTests` | Toolbar preset → `SinceUtc` mapping, display labels, append-only enum ordinals. (Stage 6B) |
| `IpcDispatcherStage6Tests` | End-to-end dispatch + filter combinations + limit clamping + invalid-JSON path + worker re-entry guard + cancellation. |
| `IpcCommandStabilityTests.Ordinal_IsStable` | Locks `GetAttackStats = 18`. |

## Roadmap

Stage 6 (back-end aggregation, scoring, IPC, and Configurator UI) is complete. Stage 7 will
introduce the **Remote RDP Clients** tab and session-control IPC. Stage 6 deliberately omits
AbuseIPDB / MikroTik integration. See `docs/80-roadmap.md`.

## Stage 6B Windows validation checklist (UI smoke before sign-off)

The Stage 6B UI must be smoked on a Windows host with the Stage 6A service running:

1. **Service health.** The Service is installed and running; `AttackStatsRefreshWorker` is
   registered; `SELECT Ip, TotalAttempts, Failed, Successful, ThreatScore, IsBlocked,
   LastUpdatedUtc FROM AttackStats ORDER BY LastUpdatedUtc DESC LIMIT 20;` returns the expected
   projection.
2. **Tab opens.** Launching the Configurator and clicking the **Attack Statistics** tab triggers a
   refresh; the status strip prints `Refresh OK. rows=…` with a UTC timestamp.
3. **Row coloring.** Rows with `ThreatLevel == Green` paint soft green, `Yellow` paint soft yellow,
   and `Red` paint soft red. The colour reflects the server-side `ThreatLevel`, not a UI re-classification.
4. **Filters.** Typing in `IP search`, raising `Min threat`, toggling `Only blocked`, and changing
   `Recent period` / `Limit` filter the grid; `Clear filters` resets every control and refreshes.
5. **Auto refresh.** Ticking `Auto refresh (5s)` starts a 5-second timer; ticks are dropped when a
   refresh is already in flight (no duplicated rows, no overlapping status lines).
6. **Context menu.** Right-click on a row enables `Copy Row Details`, `Copy IP`, `Block IP…`, and
   `Whitelist IP…`. Block / whitelist actions prompt for confirmation; the resulting IPC outcome
   is reported in the status strip.
7. **No direct DB writes.** With ProcMon / Sysmon, confirm `RdpAudit.Configurator.exe` never
   opens `rdpaudit.db` for write while the Attack Statistics tab is active.
