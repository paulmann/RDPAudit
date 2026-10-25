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

### `EventDeletionLedger`

Append-only tombstone of raw-event evidence removed by information-density retention (Stage 17).
One row accounts for one deleted window segment: the exact row count, the covered UTC window, the
code, the trigger, the rule version and the initiator. Rows are never updated in place — a
correction is a new row. The rule, its triggers and its invariants are in
`docs/87-information-density-retention.md`.

| Column           | Type        | Constraints                        | Notes                                                                   |
|------------------|-------------|------------------------------------|-------------------------------------------------------------------------|
| `Id`             | INTEGER PK  | autoincrement                      | Surrogate key.                                                          |
| `EventCode`      | INTEGER     | NOT NULL, indexed with `CreatedUtc`| Windows event id the deleted rows carried.                              |
| `Scope`          | INTEGER     | NOT NULL                           | `EventDeletionScope` ordinal: `Global=0`, `PerIp=1`. Append-only.       |
| `IpBinary16`     | BLOB(16)    | nullable, indexed                  | Canonical 16-byte source address for `PerIp`; NULL for a host-wide pass. |
| `WindowStartUtc` | TEXT        | NOT NULL                           | Oldest UTC timestamp covered by the deleted window, inclusive.          |
| `WindowEndUtc`   | TEXT        | NOT NULL                           | Newest UTC timestamp covered by the deleted window, inclusive.          |
| `RowsDeleted`    | INTEGER     | NOT NULL                           | Exact number of rows this entry accounts for.                           |
| `Trigger`        | INTEGER     | NOT NULL                           | `EventDeletionTrigger` ordinal. Append-only.                            |
| `RuleVersion`    | INTEGER     | NOT NULL                           | Retention rule set that produced the deletion (`RetentionRuleVersion`).  |
| `Reason`         | TEXT(512)   | NOT NULL                           | Human-readable cause, including the channel of the affected code.       |
| `InitiatedBy`    | TEXT(256)   | NOT NULL                           | `Service` or `Operator:<identity>`.                                     |
| `CreatedUtc`     | TEXT        | NOT NULL, indexed                  | When the entry was written. Always UTC.                                 |
| `PreviousHash`   | TEXT(64)    | nullable                           | SHA-256 of the previous chained entry, or the genesis value. Stage 18.   |
| `EntryHash`      | TEXT(64)    | nullable                           | SHA-256 over `PreviousHash` and this row's content. Stage 18.            |

Indices: `IX_EventDeletionLedger_EventCode_CreatedUtc` (per-code ledger view and the timeline-gap
lookup), `IX_EventDeletionLedger_CreatedUtc` (append-order scan of the most recent passes),
`IX_EventDeletionLedger_IpBinary16` (subject-oriented review and the per-IP gap lookup).

No foreign key references this table and it references none: the ledger must outlive the rows it
describes and must never be cascaded away.

#### Hash chain (Stage 18)

Every entry appended from Stage 18 onwards carries a SHA-256 link to the entry before it, computed by
`LedgerChainHasher` (Core, pure) and written by the single writer `EventDeletionLedgerWriter` on the
caller's connection and transaction, so the tombstone and the deletion it accounts for commit or roll
back together. Both deletion paths — information-density retention and the operator's subject purge —
append through that one writer, which is why their chains verify against each other.

* The digest covers the entry's content (code, scope, address, window, count, trigger, rule version,
  reason, initiator, creation time) plus the previous entry's hash, and deliberately **not** the row id,
  so a hash can be computed before SQLite assigns the id while a deleted or reordered row still breaks
  the chain at its successor.
* Timestamps are formatted without a `Kind` suffix. SQLite stores them as wall-clock text, so a value
  written as `Utc` reads back as `Unspecified`; including the kind would make every stored row fail
  verification after a restart.
* **What it detects:** a modified value (`EntryHash` no longer matches), a row removed from the middle
  (the successor's `PreviousHash` no longer matches its actual predecessor), and reordering. **What it
  cannot detect:** truncation of the newest entries — a chain alone cannot see its own tail — which is
  what `StoreIntegrityComparer`'s ledger-length rule covers.
* **What it is not:** a keyed MAC. It is an unkeyed hash chain, so it resists anything that does not
  recompute the chain, which is the realistic threat for an offline store; it does not resist an attacker
  who can rewrite the whole chain, because the only place to keep a key on this host is the host itself.
* Rows written before Stage 18 keep `NULL` in both columns. The verifier counts them as **unverifiable**
  and never as a break: an honest "cannot verify" beats a false tamper alarm.

`LedgerChainVerifier.Verify` is a pure function over an ordered row list, so the same code serves the
start-up check, the periodic pass, the Database-tab overview and the tests.

### `DatabaseIntegrityCheckResult` (Stage 19)

Durable journal of executed integrity checks: one row per `PRAGMA quick_check`, full `integrity_check`,
`foreign_key_check` and ledger-chain verification. It records an **observation**; no code path repairs,
truncates or rebuilds the store from a result.

| Column        | Type        | Constraints                     | Notes                                                                 |
|---------------|-------------|---------------------------------|-----------------------------------------------------------------------|
| `Id`          | INTEGER PK  | autoincrement                   | Surrogate key.                                                        |
| `Kind`        | INTEGER     | NOT NULL, indexed with `CompletedUtc` | `DatabaseIntegrityCheckKind`: `QuickCheck=1`, `FullIntegrityCheck=2`, `ForeignKeyCheck=3`, `LedgerChainVerify=4`. Append-only ABI. |
| `StartedUtc`  | TEXT        | NOT NULL                        | When the check started. Always UTC.                                   |
| `CompletedUtc`| TEXT        | NOT NULL, indexed               | When it finished. Always UTC.                                         |
| `Outcome`     | INTEGER     | NOT NULL                        | `Ok=0` (the check ran and reported nothing), `Warning=1` (reported something, or could not run at all), `Failed=2` (corruption). A check that could not run is never `Ok`. |
| `Detail`      | TEXT(4096)  | NOT NULL                        | What the check returned, bounded at 200 report lines.                 |
| `DurationMs`  | INTEGER     | NOT NULL                        | Wall-clock duration.                                                  |
| `InitiatedBy` | TEXT(256)   | NOT NULL                        | `Schedule` or `Operator:<identity>`.                                  |

Index: `IX_DatabaseIntegrityCheckResult_Kind_CompletedUtc` — one index seek per kind for the overview and
for the full-check cadence.

### Store fingerprint (a file chain, not a table)

The offline-modification detector's durable state lives **outside** the database on purpose: a fingerprint
stored in the file it describes could be rewritten together with the tampering it exists to reveal. Since
B19 it is a **chain**, not one rewritten document:

| Path | What it is |
|---|---|
| `integrity\fingerprints\fingerprint-0000000001.json`, `...0002.json`, … | One immutable record per capture. Each record carries its own SHA-256 digest over every other field **and** the digest of its predecessor, so an edited record, a re-ordered chain or a record removed from the middle breaks the linkage and is reported. |
| `integrity\store-fingerprint-sealed.json` | The **sealed tip**: how many records the chain should hold and what its head digest is, written through `ISecretProtector` (DPAPI `LocalMachine` on Windows). It is the second, independent store, and it exists because a *prefix of a valid chain is a valid chain*: removing the newest record cannot be noticed from the chain alone. |
| `integrity\store-fingerprint-intent.json` | The **durable write intent** (B24): a marker written *before* a record is appended and removed *after* the tip has been re-sealed, naming the record the capture was about to write (position, sequence, digest). It exists only while a capture is in flight — finding it after a restart is what an interrupted capture leaves behind, and it is the only input that can turn the "tip exactly one record short" shape from `ChainBroken` into `Interrupted`. Written through the same protector as the tip. |
| `integrity\store-fingerprint.json` | The pre-B19 single document. Read **once** to migrate an existing installation into the chain and then left on disk as history; never written again. |

Records are appended under two labels, and they are what the comparer's authority rests on:

* `Shutdown` — captured by `StoreIntegrityWorker.StopAsync`, which runs *last* in the stop sequence because
  that worker is registered *first*. It is the only baseline that proves no writer remained, and therefore
  the only one that can support a conclusion about rows that disappeared.
* `Schedule` — captured by the maintenance worker (and once at start-up) while the service runs. Today's row
  counts plus a growth baseline for the case where the service was killed rather than stopped.

#### Chain states

`StoreFingerprintChain.Verify` reports exactly one of five states, and the difference between them is the
point: "nothing has been recorded yet", "something that was recorded is gone" and "we were cut short while
writing" must never render the same way. The states reach the operator through the start-up report, an
`OperationLog` row, the anomaly marker and, when the service's event-log source exists, a mirror record
outside `%ProgramData%`.

| State | Meaning | What an operator does |
|---|---|---|
| `Ok` | The chain verifies and matches the sealed tip. An empty chain with no tip is `Ok` as well — that is a first run, and nothing is wrong. | Nothing. |
| `Missing` | The sealed tip accounts for records that are not on disk: the newest fingerprint(s) were deleted, or the whole `fingerprints` folder is gone while the tip remains. | A deletion happened. Treat the remaining records as a superseded baseline. |
| `Unreadable` | A record exists but cannot be read or parsed, or the sealed tip exists but cannot be unsealed (not an envelope, damaged bytes). "We could not look" is **never** reported as "we looked and it was fine". A record that is missing one of the fields every writer of this layout emits belongs here too — and so does one that carries an explicit `null` in such a field, which is the same situation one step further: the property is present and holds nothing, so there is nothing to read. The record's digest, its sequence, its predecessor's digest, its table row counts, its payload and the tip's record count are read as *required*, because a reader that quietly substituted a default for a removed or renamed property would report a length or a position nobody ever recorded — an entry accused of being "removed or renumbered", or a tip accused of a rollback over a head that was never touched. A tip written in a layout version this build does not read is reported here as well, instead of being interpreted field by field under this layout's rules. | Investigate permissions, DPAPI scope and disk damage before trusting anything in the folder. |
| `ChainBroken` | The records contradict each other (digest mismatch, broken linkage, sequence gap) or the chain contradicts the tip in the rollback direction (fewer entries or a different head than the tip records, or a tip whose head sequence is not the sequence of the record it names). | The chain was edited or replaced. Fingerprints recorded before the break cannot be trusted as evidence. |
| `Interrupted` | The chain holds exactly one record more than the tip accounts for, the tip is the seal of the chain *without* that record, and the durable write intent on disk names that very record by position, sequence and digest. The capture was cut short between appending the record and re-sealing the tip — a crash or a power loss, not a rollback. Nothing already recorded is missing and no digest fails. | Nothing: the next capture re-seals the tip over the full chain and clears the intent, and the next write completes an interrupted seal before appending anything. **If this host did not lose power and the service did not crash, treat it as an intrusion attempt instead** — the same shape is what a re-sealed tip over an appended forged record would leave. |

Every non-`Ok` state is appended to the start-up report, so it shares the log, `OperationLog` row and marker
with every other store-integrity observation instead of getting a channel of its own.

All of them are `Strong` anomalies except `Interrupted`, which is a `Warning`: it is reported through exactly
the same channels and with a message that names the state, but its meaning is "a capture was cut short"
rather than "the store was changed". Keeping it `Strong` would restore the false tamper alarm on every power
loss; treating it as silence would hide a real interruption. The evidence for interference is the *same*
shape **without** a matching intent, which is still `ChainBroken` and still `Strong`.

#### Why `Interrupted` cannot be earned by deleting a file

The recoverable reading is granted strictly on agreement, never on absence:

* Every field of the intent is compared with what is on disk — the position, the sequence and the digest of
  the appended record — and the tip must seal exactly the chain without that record (its record count, its
  head sequence and its head digest are cross-checked against the record at the position it names).
* It is refused whenever anything else is wrong: an edited record, a broken linkage, a sequence gap or an
  unreadable file keeps the strict verdict, because those findings are checked first.
* A missing, unreadable, unprotected-on-a-protecting-host or other-version intent is treated as *no* intent,
  so the strict verdict stands. Deleting the file therefore removes the soft reading instead of earning it,
  and a forged intent requires write access to `integrity\` — from which the documented, already-accepted
  step to a plain `Ok` is to re-seal the tip itself.

#### The sealed tip's fields: verified or advisory (B23)

| Field | Status | What a divergence means |
|---|---|---|
| `EntryCount` | **Verified** | Fewer records on disk than this is `Missing`; more is a contradiction, reported as `ChainBroken` unless the write intent explains exactly that one appended record. |
| `HeadDigest` | **Verified** | It must be the digest of the record at position `EntryCount`. |
| `HeadSequence` | **Verified** | It must be the sequence of the record at position `EntryCount`. Both values were written by the same writer from the same record, so a tip whose own two fields disagree with the chain was not written for this chain — `ChainBroken`, with both numbers printed. It cannot be cross-checked when the position it names is off the end of the chain (a deleted tail), and `Missing` stands on its own there. |
| `FormatVersion` | **Verified** | A tip from a layout this build does not read is `Unreadable`, exactly as a chain record of an unknown version is: reading it under this layout's rules would produce a confirmation nobody issued. |
| `SealedUtc` | **Advisory** | Reported, never compared, so a divergence in it alone does **not** change the verdict. It is a wall-clock observation: a clock that moved backwards is not tampering, and a record's own `CapturedUtc` is already covered by that record's digest. |

#### What this does and does not achieve

Stated plainly, because the honesty limit is the whole point: a **local administrator can delete the chain,
delete the tip, or — because DPAPI `LocalMachine` is by design usable by any process on that machine —
re-seal a forged tip.** Nothing here makes tampering impossible. What it makes impossible is tampering being
*invisible* while the process still reports `ok`: deleting a record, editing one, breaking the linkage or
rolling the chain back all produce a named state, an audit row and a marker. Removing **both** stores still
leaves a shorter but self-consistent chain — which is why the key facts are also mirrored to the Windows
Application log (`IStoreFingerprintAlarmSink`, source registered by the installation, never created at
runtime) when that source exists, and why the overview reports whether the mirror is available rather than
implying it is.

The one state that is deliberately soft (`Interrupted`) does not widen that surface: it is still a named,
logged, audited and mirrored non-`Ok` verdict, and reaching it costs an attacker more than the `Ok` they
already get by re-sealing the tip with the machine's own DPAPI key. What it buys is the removal of a false
tamper alarm on every power loss, which is the only way the loud states stay worth reading.

The mirror is deliberately bounded: a non-`Ok` verdict and the clean-shutdown tip are published (the latter
bounded by service restarts), while every periodic capture is not — the sealed tip already covers those, and
mirroring them would grow the Application log without adding information.

A capture writes in this order, and the order is the mechanism: the write intent first, then the chain
record, then the re-sealed tip, then the removal of the intent. A crash anywhere in the middle leaves the
marker next to the discrepancy it explains, and any successful capture first completes a previous interrupted
seal (re-sealing the tip over what is on disk) before appending anything — so at most one record is ever
unsealed, even when the tip cannot be written at all, and the store never drifts from `Interrupted` into a
rollback accusation because of a full disk.

Each fingerprint records: capture time, whether it came from a clean shutdown, the main/WAL file sizes and
the database file's last write time, the highest durable `IngestionSequence`, per-table row counts for the
fourteen evidence tables, the applied migration list, and the ledger's chain length, head and verdict.

`StoreIntegrityComparer.Compare` (Core, pure) applies these rules, each with the false positive it avoids:

| Observation | Verdict | Why this is not a false alarm |
|---|---|---|
| Row count fell, baseline from a clean shutdown | **Strong** anomaly | Nothing in the product removes evidence while the service is stopped. A restore of an older snapshot produces the same observation, and the message says so. |
| Row count fell, baseline periodic | *withheld* | Retention legitimately deletes rows while the service runs, so a crash after a pass would otherwise look like tampering on every restart — the alarm nobody reads. |
| Migration list is not an extension of the baseline | **Strong** | An upgrade appends; nothing supported removes, reorders or replaces. A prefix test accepts every legitimate upgrade. |
| `IngestionSequence` advanced past a clean baseline | **Strong** | Recorded after every writer stopped, so the value is final; a higher one means rows were written offline. |
| Database file written after a clean baseline | **Strong** | No supported offline operation writes the file on its own. A restore or compaction does, and again the detail says so. |
| Ledger chain broken, or fewer chained entries | **Strong** | The ledger is append-only; a shorter one is never a retention effect. Evaluated against either baseline. |
| Database file smaller | *Information* | Shrinking the file is what an offline compaction is for. |

An anomaly is an operator signal, never a refusal to start: it is written to the structured log, to an
`OperationLog` row (`Source=Storage`, `Operation=StoreIntegrityAnomaly`) and to
`integrity\store-integrity-anomaly.json`, which the Database tab's overview reads. A verified clean
shutdown clears the marker. Refusing to start on a suspected tampering would turn evidence of it into an
outage.

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
