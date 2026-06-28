# RdpAudit data model (Stage 2)

This document describes the persistent schema added in Stage 2 of the RdpAudit roadmap. Stage 2
introduces six new tables for blocklist / whitelist / login-rule management, active firewall
blocks, AbuseIPDB report deduplication, and materialised per-IP attack statistics. It does NOT
introduce UI, Windows Firewall driver code, AutoBlockWorker, AbuseIPDB HTTP client, or MikroTik
REST client — those land in Stage 3+.

All new entities live under `RdpAudit.Core.Models` and use `IEntityTypeConfiguration<T>` mappings
under `RdpAudit.Core.Data.Configurations`. Every column documented here is **UTC** for timestamps,
ordinal-stable for enums, and indexed where the upcoming workers will scan.

## Tables

### `BlocklistEntries`

Owner: Configurator (manual ops) + future AutoBlockWorker (auto ops).
Purpose: persistent manual or automatic blocklist record for an IP, a login, or both.

| Column          | Type          | Constraints                                | Notes                                                                                       |
|-----------------|---------------|--------------------------------------------|---------------------------------------------------------------------------------------------|
| `Id`            | INTEGER PK    | autoincrement                              | Surrogate key.                                                                              |
| `Ip`            | TEXT(45)      | nullable, indexed                          | IPv4 or IPv6 textual form. At least one of `Ip` / `Login` must be populated by the writer.  |
| `Login`         | TEXT(256)     | nullable, indexed                          | sAMAccountName or UPN.                                                                      |
| `Reason`        | TEXT(1024)    | NOT NULL                                   | Operator-supplied or rule-supplied reason.                                                  |
| `AddedUtc`      | TEXT          | NOT NULL                                   | UTC timestamp.                                                                              |
| `ExpiresUtc`    | TEXT          | nullable, indexed                          | UTC timestamp; null means permanent.                                                        |
| `Source`        | INTEGER       | NOT NULL                                   | `BlocklistSource` ordinal (append-only).                                                    |
| `LinkedAlertId` | INTEGER       | nullable                                   | Optional `Alerts.Id`. No FK enforced (cross-table lifecycles are owned by the worker).      |
| `IsEnabled`     | INTEGER       | NOT NULL                                   | Soft-disable flag.                                                                          |

Indices: `Ip`, `Login`, `ExpiresUtc`, `(IsEnabled, ExpiresUtc)`.

### `WhitelistEntries`

Owner: Configurator.
Purpose: persistent IP whitelist record that bypasses automatic blocking.

| Column     | Type      | Constraints           |
|------------|-----------|-----------------------|
| `Id`       | INTEGER PK| autoincrement         |
| `Ip`       | TEXT(45)  | NOT NULL, UNIQUE      |
| `Note`     | TEXT(512) | nullable              |
| `AddedUtc` | TEXT      | NOT NULL              |
| `AddedBy`  | TEXT(256) | nullable              |

### `LoginRules`

Owner: Configurator.
Purpose: login trip-wire rules. Any attempted logon using a matching login blocks the source IP.

| Column     | Type      | Constraints           |
|------------|-----------|-----------------------|
| `Id`       | INTEGER PK| autoincrement         |
| `Login`    | TEXT(256) | NOT NULL, UNIQUE      |
| `Note`     | TEXT(512) | nullable              |
| `Enabled`  | INTEGER   | NOT NULL, indexed     |
| `AddedUtc` | TEXT      | NOT NULL              |

### `ActiveBlocks`

Owner: future AutoBlockWorker.
Purpose: currently installed firewall block. The composite `(Provider, Ip)` is unique so the
worker can reconcile DB intent with provider state via idempotent upserts.

| Column        | Type         | Constraints                          | Notes                                                              |
|---------------|--------------|--------------------------------------|--------------------------------------------------------------------|
| `Id`          | INTEGER PK   | autoincrement                        | Surrogate key.                                                     |
| `Ip`          | TEXT(45)     | NOT NULL                             |                                                                    |
| `Provider`    | INTEGER      | NOT NULL                             | Reuses `FirewallProviderKind` ordinals (None / Windows / MikroTik).|
| `RuleHandle`  | TEXT(256)    | nullable                             | Provider-specific identifier (rule name / list entry id).          |
| `CreatedUtc`  | TEXT         | NOT NULL                             |                                                                    |
| `ExpiresUtc`  | TEXT         | nullable, indexed                    | Null means permanent.                                              |
| `Reason`      | TEXT(1024)   | NOT NULL                             |                                                                    |
| `Status`      | INTEGER      | NOT NULL, indexed                    | `ActiveBlockStatus` ordinal.                                       |
| `LastError`   | TEXT(2048)   | nullable                             | Populated when `Status == Failed`.                                 |

Indices: `(Provider, Ip)` UNIQUE, `ExpiresUtc`, `Status`, `(Provider, RuleHandle)`.

### `AbuseReports`

Owner: future AbuseIPDB client.
Purpose: dedup / rate-limit reports sent to AbuseIPDB. The `(Ip, ReportedUtc)` index lets the
client cheaply enforce the public API's 15-minute window per IP.

| Column         | Type        | Constraints       |
|----------------|-------------|-------------------|
| `Id`           | INTEGER PK  | autoincrement     |
| `Ip`           | TEXT(45)    | NOT NULL          |
| `ReportedUtc`  | TEXT        | NOT NULL, indexed |
| `Categories`   | TEXT(256)   | NOT NULL          |
| `ResponseCode` | INTEGER     | NOT NULL          |
| `Error`        | TEXT(2048)  | nullable          |
| `AlertId`      | INTEGER     | nullable          |

Index: `(Ip, ReportedUtc)`.

### `AttackStats`

Owner: future projection worker.
Purpose: materialised per-IP attack statistics so the Firewall stats UI can render dashboards
without re-aggregating `RawEvents` on every refresh.

| Column                  | Type        | Constraints      | Notes                                              |
|-------------------------|-------------|------------------|----------------------------------------------------|
| `Ip`                    | TEXT(45) PK | NOT NULL         | Primary key.                                       |
| `TotalAttempts`         | INTEGER     | NOT NULL         |                                                    |
| `Successful`            | INTEGER     | NOT NULL         |                                                    |
| `Failed`                | INTEGER     | NOT NULL         |                                                    |
| `FirstSeenUtc`          | TEXT        | NOT NULL         |                                                    |
| `LastSeenUtc`           | TEXT        | NOT NULL, indexed|                                                    |
| `DurationSeconds`       | INTEGER     | NOT NULL         | Clamped at zero by `AttackStatProjection`.         |
| `Top10AttemptedLogins`  | TEXT(4096)  | NOT NULL         | JSON array; round-trip via `AttackStatProjection`. |
| `LastLoginType`         | INTEGER     | nullable         | Windows logon type, when known.                    |
| `ThreatScore`           | REAL        | NOT NULL, indexed|                                                    |
| `IsBlocked`             | INTEGER     | NOT NULL, indexed| True when an `ActiveBlocks` row exists.            |
| `LastUpdatedUtc`        | TEXT        | NOT NULL         | UTC timestamp of the last projection refresh.      |

## Enums

* `BlocklistSource` — `Unknown=0`, `Manual=1`, `Auto=2`, `Firewall=3`, `AbuseIpDb=4`, `MikroTik=5`,
  `LiveEvents=6`. Append-only; ordinals are persisted.
* `ActiveBlockStatus` — `Pending=0`, `Active=1`, `Failed=2`, `Removed=3`, `AuditOnly=4`.
  Append-only.
* `FirewallProviderKind` (Stage 1, reused by `ActiveBlocks.Provider`) — see `docs/40-options.md`.

## Migration

* Name: `Stage2FirewallStats` (full id: `20260519152135_Stage2FirewallStats`).
* Up: creates the six new tables and all indices listed above.
* Down: drops the six new tables; Stage 1 tables (`Addresses`, `Alerts`, `Bookmarks`, `DbProps`,
  `RawEvents`, `Sessions`) are untouched.
* Upgrade path: on hosts already running the Stage 1 schema, applying Stage 2 is purely additive —
  no Stage 1 rows are read, rewritten, or dropped. Verified by
  `Stage2MigrationUpgradeTests.Stage2Migration_PreservesStage1RowsOnUpgrade`.

## Future LLM extension rules

When implementing later stages on top of this data model:

1. **Append-only enums.** New `BlocklistSource` / `ActiveBlockStatus` values receive a new ordinal
   at the end. Never reorder or reuse a retired ordinal.
2. **UTC everywhere.** Every new timestamp column must be UTC and named with the `Utc` suffix.
3. **No raw SQL writes.** App-data writes go through EF Core parameterised APIs only. Bulk
   maintenance operations (purge, vacuum) belong in dedicated maintenance services, not in workers.
4. **Indexed for the worker that will scan.** Whenever a new column will be scanned by a worker on
   every tick, add an index in the same migration that introduces the column.
5. **Reuse `FirewallProviderKind`.** Never introduce a parallel enum that re-numbers the same
   providers. New providers add a new ordinal in `FirewallProviderKind`.
6. **Top-N JSON via the helper.** Anything that writes `AttackStat.Top10AttemptedLogins` must use
   `AttackStatProjection.SerializeTopLogins` so format drift cannot occur between writers.
7. **No FK to `Alerts` from blocklist / abuse-report tables.** `LinkedAlertId` and `AlertId` are
   nullable references; the lifecycle of an alert and the lifecycle of the derived block are
   independent. The worker reconciles via `LinkedAlertId.HasValue` lookups, not FK joins.
