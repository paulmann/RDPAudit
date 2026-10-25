# Information-density retention

Status: implemented (Stage 17, schema `EventDeletionLedger`). Policy default: **disabled**.

Information-density retention is a *pressure* rule. It runs only when the store crosses a
configured ceiling, and it reduces the store by deleting the rows that carry the least unique
information: the interior of the densest event codes. It never deletes the first record of a
code, never deletes the newest records of a code, never touches an event class that carries
attack signal, and it records every removed window so that "no activity" and "evidence removed"
are never the same thing.

Owner's rule, verbatim: *"Самое старое событие с уникальным кодом никогда не удаляется.
При достижении лимита объёма или числа регистрируемых событий удаляются предпоследние события,
имеющие наибольшее число регистраций по своему уникальному коду."*

## 1. Vocabulary

| Term | Definition |
|---|---|
| **Code** | The unit that owns one anchor and one tail. `(EventId, Channel)` with `AnchorScope = PerCode`; `(EventId, Channel, sourceIp)` with `PerCodeAndIp`. |
| **Anchor** | The **oldest** persisted row of a code (`TimeUtc`, tie-break `Id`). Never deleted by any pressure rule. |
| **Tail** | The newest `TailKeepPerCode` rows of a code. Never deleted by any pressure rule: they carry live detection and the current investigation window. |
| **Interior** | Rows that are neither anchor nor tail. The only deletion candidates. |
| **Density `d(c)`** | Number of eligible interior rows of code `c` inside the deletion window (older than `MinAgeDays`). Codes are processed densest first. |
| **Deletion window** | `(-∞, now - MinAgeDays)`. Rows newer than the floor are never candidates, whatever the pressure. |
| **Protected class** | An event code listed in `ProtectedEventIds`. Never a pressure candidate, at any density. |

## 2. Triggers

Exactly one trigger is evaluated per tick, in this fixed order. The first ceiling that is breached
wins and is recorded in every ledger row of the pass, so the cause is never ambiguous.

| # | Trigger | Condition | `Enabled` |
|---|---|---|---|
| 1 | `DatabaseBytes` | `database + WAL + SHM` size > `MaxDatabaseBytes` | `MaxDatabaseBytes > 0` |
| 2 | `FreeDiskBytes` | lowest free space on the database and shard-tree volumes < `MinFreeDiskBytes` | `MinFreeDiskBytes > 0` |
| 3 | `RawEventRows` | `COUNT(*) FROM RawEvents` > `MaxRawEventRows` | `MaxRawEventRows > 0` |

A ceiling of `0` disables its trigger. If no trigger fires, the worker writes **nothing** — no
rows are deleted, no ledger entry and no operation-log entry is produced.

Age windows are *not* a pressure trigger of this worker: `RetentionWorker` owns age-based pruning
of `RawEvents`, and it runs first. Information-density retention only ever sees what the age
windows left behind.

## 3. Deletion rule

1. Eligible codes are those with `d(c) >= CandidateMinRows`, not in `ProtectedEventIds`, and not
   under legal hold.
2. Codes are ordered by `d(c)` **descending** — the densest registration stream is the most
   redundant, so it is compressed first.
3. Inside a code, rows are deleted **oldest first**, i.e. immediately after the anchor and before
   the tail.
4. The per-pass budget `MaxRowsPerPass` is distributed across codes in that order.
5. Deletion runs in batches of `DeleteBatchRows` rows. Each batch is one transaction containing
   the `DELETE` and the matching `EventDeletionLedger` insert. After each batch the worker checks
   `MaxWriterLockMs`; if the batch exceeded the budget the pass yields and defers the remainder to
   the next tick.
6. A pass never runs a full `VACUUM`, and it does not issue an `incremental_vacuum` either. When rows
   were removed it issues `PRAGMA wal_checkpoint(PASSIVE)` only. Deleted rows return their pages to the
   file's own freelist; those pages leave the file through the bounded `incremental_vacuum` of the purge
   and the maintenance surface — which needs the store's auto-vacuum mode to be `INCREMENTAL`; the
   Database tab's Overview reports the mode and says plainly when online release is impossible on the
   store — or through the offline compaction, which also shrinks the file.

### Tie-breaks (deterministic)

Same state + same trigger ⇒ same plan, always. Ordering is a total order:

1. `d(c)` descending,
2. `EventId` ascending,
3. `Channel` ordinal ascending,
4. IP hex ascending (only meaningful for `PerCodeAndIp`),
5. then total rows descending and anchor id descending as a backstop for a duplicated key.

### Invariants

| Invariant | Enforced by |
|---|---|
| The anchor of every code survives, byte-identically. | `InformationDensityRetentionPlanner` drops any row at or before the anchor; the executor re-applies `(TimeUtc, Id) > (anchorTime, anchorId)` in SQL. |
| The newest `TailKeepPerCode` rows of every code survive. | Planner drops every row at or after the tail boundary and caps the interior at `TotalRows - 1 - TailKeepPerCode`; the executor re-applies `(TimeUtc, Id) < (tailTime, tailId)` in SQL. |
| Rows newer than `MinAgeDays` survive. | Planner age floor plus `TimeUtc < $minAgeCutoff` in both the candidate query and the delete statement. |
| Protected classes are never touched. | Planner eligibility filter plus a `NOT IN` filter in the statistics scan. |
| Rows referenced by alert evidence are never touched. | SQL guard; see §6. |
| `IpEventSummary` / `IpEventTypeCounter` counters never regress. | Structural: the pass only writes to `RawEvents` and `EventDeletionLedger`. The counters are durable aggregates in their own tables and no trigger or foreign key couples them to `RawEvents`. |
| Every deletion is accounted for exactly once. | Each batch commits its `DELETE` and its ledger row inside one transaction, so a batch either commits both or neither; a pass interrupted at any boundary leaves the ledger exact and the anchor/tail intact. |
| `LegalHold` stops pressure deletion entirely. | Checked before trigger evaluation and again inside the planner, which returns an empty plan. |

## 4. Configuration

`RdpAudit:Storage:RetentionPolicy`. Field-by-field defaults are in `docs/40-options.md`.
Disabled by default: with `Enabled: false` the service behaves exactly as it did before this
policy existed, and the worker performs no query beyond reading the effective options.

Minimum viable configuration:

```json
"RetentionPolicy": {
  "Enabled": true,
  "AnchorScope": "PerCode",
  "TailKeepPerCode": 512,
  "CandidateMinRows": 1000,
  "MinAgeDays": 7,
  "MaxRowsPerPass": 50000,
  "MaxWriterLockMs": 250,
  "DeleteBatchRows": 2000,
  "MaxDatabaseBytes": 0,
  "MaxRawEventRows": 0,
  "MinFreeDiskBytes": 0
}
```

`Enabled: true` with every ceiling at `0` is a valid configuration and an honest no-op: the
worker evaluates nothing, fires no trigger and reports a skip counter.

## 5. Ledger and operator signals

`EventDeletionLedger` is append-only. One row per deleted window segment accounts for the exact
row count, the covered `WindowStartUtc..WindowEndUtc`, the code, the scope, the trigger, the rule
version, the reason text and the initiator.

- A pass that completes a code in a single batch produces exactly one ledger row for that code.
- A pass that needs several batches produces one ledger row per batch. All rows written by one pass
  share the same `Trigger` and `RuleVersion` (and are written within the same pass), so the pass is
  reconstructable by grouping. This is a deliberate refinement of the "one row per pass and code"
  sketch: pairing the ledger insert with the delete inside one transaction is what makes the ledger
  exact under a crash. Splitting it into one row per code would leave a window where rows are gone
  and nothing accounts for them.

Operator-visible signals:

| Signal | Where |
|---|---|
| Pass summary — trigger, rows removed, codes completed, codes skipped, state | `OperationLog` (source `Retention`, operation `InformationDensityRetention`) and the structured service log |
| Cumulative rows removed, pass count, skip count, last trigger, last error | `ServiceMetrics` (`InformationDensity*`) |
| Per-code, per-window tombstone with the rule and the actor | `EventDeletionLedger` |

A forced pass is never silent. Even a pass that deletes nothing writes a summary naming the state.

## 6. Linked-evidence protection and its limits

The pass must not delete a raw event that an alert or a correlation record still points at.
Audit of the schema at HEAD found exactly two real row-level references to `RawEvents.Id`:

| Table | Column | Strength |
|---|---|---|
| `AuthAttemptFacts` | `EvidenceRawEventId` | real reference, indexed (`IX_AuthAttemptFacts_EvidenceRawEventId`) |
| `ProcessObservations` | `RawEventId` | real reference, `0` reserved for operator-forced rows, not indexed |

Both are honoured with an `EXISTS` guard bounded by the code's surrogate-key span, so the
subquery can only see rows that could point into the code being processed. Rows referenced by
either table are excluded from the candidate fetch *and* from the delete statement, so the plan
and the execution agree.

The following tables hold **no** row-level reference to `RawEvents.Id`, so they cannot be
consulted row by row: `Alerts`, `ActiveBlocks`, `CrossHostChains`, `CrossHostFacts`,
`CrossHostLinks`, `ProcessAlertResponses`, `AbuseReports`, `AttackStats`. Where an alert or a
block is relevant to a code, its coverage is instead expressed by:

1. the **protected class** rule — the codes an alert would be raised from (logon anomalies,
   account changes, service install, Kerberos signals) are in `ProtectedEventIds` by default; and
2. the **age floor** — `MinAgeDays` keeps the window in which alerts are still live.

Limitations to state plainly:

- An alert raised from a *non-protected, high-volume* code (for example a `4625` burst alert)
  does not by itself protect individual `4625` rows from pressure deletion. Only the anchor, the
  tail and the age floor protect those.
- `ProcessObservations.RawEventId` is not indexed. The guard bounds its scan with a `BETWEEN` on
  the code's id span, so the cost is bounded by the number of observations inside that span; the
  table is additionally bounded by `ProcessMonitoring.MaxObservations` and its own retention.

## 7. What counts as an honest skip

A skip is honest when the trigger fired, the store was examined, and nothing could be deleted
without violating an invariant. The pass then reports which of these applies:

| State | Meaning |
|---|---|
| `no code reached the eligibility threshold` | No code has at least `CandidateMinRows` rows inside the window. |
| `every eligible code is fully protected by its anchor, tail or age floor` | Codes are dense enough, but everything they hold is anchor, tail, fresh, protected or referenced by alert evidence. |
| `writer-lock budget reached; remainder deferred to the next tick` | Work was done and remains: the pass stopped to keep the writer lock short. |
| `cancelled mid-pass; anchors, tails and the ledger remain consistent` | Shutdown or cancellation stopped the pass between batches. |

The planner additionally reports a per-code reason for every code it considered and rejected:
`LegalHold`, `ProtectedEventCode`, `BelowCandidateMinRows`, `NoInteriorRows`, `BudgetExhausted`.
That list is what the dry-run preview renders (see §7.1); it is also available to tests and to the
structured log.

## 7.1 Dry run (`PreviewRetention`)

`PreviewRetention` (IPC ordinal 83) answers "what would the next pass delete?" without deleting
anything: no row, no ledger entry, no operation-log row, no configuration change.

**The preview is the pass, not a model of it.** Both drive one component,
`RdpAudit.Service.Services.InformationDensityRetentionEngine`:

| Step | Shared by |
|---|---|
| Trigger enumeration (`DatabaseBytes` → `FreeDiskBytes` → `RawEventRows`, first breach wins) | `InformationDensityRetentionWorker` and `RetentionPreviewService` |
| Statistics snapshot (bounded `GROUP BY`, anchor lookup, tail-boundary lookup, exact density count, bounded candidate fetch) | same engine method, same SQL |
| Plan (`InformationDensityRetentionPlanner.Plan`) | same call |
| Delete predicate (`BuildCandidatePredicate`: code, age floor, exclusive anchor bound, exclusive tail bound, linked-evidence guard) | the plan's executor and the preview's step list come from the same plan |

There is no second implementation to drift. The worker is only scheduling, metrics and the operator
summary; the rules live in the engine.

Consequences that follow, and the tests that hold them:

* A code's predicted `PlannedRows` equals the rows the real pass deletes for that code on the same
  state, and the predicted window equals the window the ledger records -
  `InformationDensityRetentionPreviewTests.Preview_ReportsExactlyTheRowsAndWindowTheRealPassDeletes`.
* Budget distribution matches too: with `MaxRowsPerPass` smaller than the total, the same densest-first
  split happens in both -
  `Preview_MatchesThePass_AcrossCodesAndABudgetSplit`.
* A preview is read-only -
  `Preview_IsReadOnly_AndDeletesNothing`.

Differences between the two, by design:

* The preview reports the **latent** plan even when no ceiling is breached (`TriggerWouldFire = false`,
  `Trigger = Unknown`), because that is what an operator needs in order to choose a ceiling. The pass,
  by contract, reads nothing beyond the cheap ceiling probes when no trigger fires.
* The preview lists the **protected** codes that currently hold rows, with the reason, so the operator
  can see what is out of scope. The eligibility scan deliberately excludes protected codes to keep its
  bounded code budget on streams that could actually be compressed, so the pass never needs that
  inventory.
* Under a legal hold the preview still names the ceiling the hold is covering (`Trigger`), but reports
  `TriggerWouldFire = false` and skips every code with `LegalHold`. The pass stops before any probe.
* `EstimatedReclaimedBytes` is always null and the DTO says why: a SQLite delete returns pages to the
  file's own freelist, so the file only shrinks after an incremental vacuum or a VACUUM, and the
  page-granular yield depends on occupancy. Quoting a byte figure would be a guess. The exact figure
  that is known is `WouldDeleteRows`.

## 8. Danger to state openly

A pressure-driven deletion policy is a remotely triggerable evidence-destruction primitive: an
attacker who can generate enough noise can push the store over a ceiling and force deletion of
the middle of a real attack burst. The mitigations are part of this change, not a follow-up:

- anchors are never deleted, so first contact from every address survives under `PerCodeAndIp`;
- the tail keeps the live investigation window intact;
- `MinAgeDays` keeps fresh evidence verbatim;
- `CandidateMinRows` keeps rare, high-signal streams out of scope;
- `ProtectedEventIds` removes the codes an attacker would most like compressed;
- `MaxRowsPerPass` bounds how much one incident can force;
- every forced pass is recorded in `EventDeletionLedger` and `OperationLog`;
- `LegalHold` disables pressure deletion entirely.

Operate it with `MinAgeDays` at or above the incident-response window you actually commit to.

## 9. Verification

`tests/RdpAudit.Core.Tests/InformationDensityRetentionPlannerTests.cs` locks the planner
invariants: anchor and tail survival for hostile inputs, budget distribution, priority ordering,
protected classes, legal hold, determinism and idempotency.

`tests/RdpAudit.Core.Tests/RetentionPolicyOptionsTests.cs` locks the defaults and every clamp.

`tests/RdpAudit.Core.Tests/Stage17EventDeletionLedgerSchemaTests.cs` proves the migration chain
reproduces the model exactly and that the ledger table, columns and indexes exist.

`tests/RdpAudit.Service.Tests/InformationDensityRetentionWorkerTests.cs` drives the worker against
a real SQLite database and covers anchor byte-identity after overfill, interior-only deletion,
counter preservation, ledger accuracy, protection of rare and protected codes, repeated passes,
legal hold and cancellation mid-pass.

`tests/RdpAudit.Service.Tests/InformationDensityRetentionPreviewTests.cs` drives the dry run and the
pass over the same store and asserts that they agree: identical per-code row counts, identical
covered windows, identical trigger, identical budget split; that the preview is read-only; and that
protected, below-threshold, legal-hold and no-trigger cases are reported honestly.

`tests/RdpAudit.Service.Tests/IpcDispatcherDatabaseTests.cs` drives the Database-tab IPC surface
(ordinals 80-84) end to end through the real dispatcher: overview sections and the partial snapshot,
the retention read/write round trip with clamping and refusal-without-partial-write, the ledger page
and filters, and the read-only guarantee.

`tests/RdpAudit.Core.Tests/DatabaseGovernanceDtoTests.cs` locks the JSON wire shape of the Stage 2a
DTOs, including the honest null for the reclaimed-bytes estimate.

`tests/RdpAudit.Core.Tests/IpcCommandStabilityTests.cs` proves the Stage 2a commands were appended
(80-84) and that no earlier ordinal moved.

## 10. Rollback

- **Behavioural rollback:** set `RetentionPolicy.Enabled: false`. The policy is inert and the
  service behaves as before; no schema change is needed.
- **Schema rollback:** `EventDeletionLedger` is additive and unreferenced by any other table, so
  `Down` drops it and nothing else. Dropping the table destroys the deletion audit trail — export
  it first if a pass has ever run.
- **Data rollback:** deletions performed by the pass are not reversible. The ledger records what
  was removed and when, not the removed rows themselves. Keep the database backup that preceded
  enabling the policy.
