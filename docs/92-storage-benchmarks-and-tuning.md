# 92 - Storage benchmarking and tuning

Status: implemented (the `B10` remediation from `BUGS.md`). The runner is
`tools/RdpAudit.StorageBenchmarks`; the pure half is `src/RdpAudit.Core/Diagnostics`.

Related: `docs/87-information-density-retention.md` (the retention machinery this measures),
`docs/88-database-backup-and-restore.md` (snapshots and verification),
`docs/40-options.md` (every setting a recommendation can name), `docs/90-windows-validation.md`
(how the test suite and the shells are set up), `docs/91-troubleshooting.md`.

---

## 1. What this tool is for

`BUGS.md` recorded `B10` as verification debt: retention throughput, writer-lock holds, snapshot and
compaction costs, integrity-check durations and volume behaviour had **no measurements at all**, so
every budget the documents stated was a guess. This tool replaces the guesses on a specific machine
with numbers measured on that machine, and turns those numbers into parameter recommendations the
owner can apply by hand.

It answers one question: *on this host, with this volume, what does the store machinery actually
cost, and what does that imply for the settings?*

It does **not** answer "how is my production service doing" - see section 7.

## 2. Running it

```powershell
# Fast profile: ~200 000 rows, 2 samples. A few tens of seconds.
./bench-storage.ps1 -Quick

# Full profile (default): 1 000 000 rows, 5 warm-up +3 samples. Minutes.
./bench-storage.ps1

# Point the temporary store at the volume you want to characterise, and say where the report goes.
./bench-storage.ps1 -Store 'D:\bench-store' -Out 'D:\bench-report'
```

Or run the tool directly, which is what the script does:

```
dotnet run --project tools/RdpAudit.StorageBenchmarks -c Release -p:Platform=x64 -- --quick
```

Options (`--help` prints the same list):

| Option | Meaning |
| --- | --- |
| `--quick` / `--full` | Profile: rows, codes and sample count. Default is `--full`. |
| `--rows <n>` | Synthetic rows to seed. Range 5 000 .. 5 000 000. |
| `--codes <n>` | Distinct (event id, channel) codes. Range 1 .. 256. |
| `--samples <n>` | Timed samples per repeated measurement. Range 1 .. 25. |
| `--warmup <n>` | Warm-up runs per repeated measurement, discarded. |
| `--store <dir>` | Directory to build the temporary store in. |
| `--allow-existing-store` | Accept a `--store` directory that already holds a database (see section 3). |
| `--out <dir>` | Report directory. Default: `<work-root>\reports\<utc timestamp>`. |
| `--work-root <dir>` | Parent for temporary working directories. |
| `--no-shards` | Skip the shard-inclusive snapshot probe. |

Exit codes: `0` the report was written, `1` the command line was rejected, `2` the run **refused to
start** (nothing was measured), `3` the run finished but at least one probe failed - the report says
which, and those metrics read `failed`, never `0`.

## 3. What it touches, and what it refuses to touch

This tool is designed to be safe to run on a production host. It needs **no administrator rights**
and **no installed Windows service**, and it never reads or writes a live installation:

* Everything it creates lives under one directory it owns (`--work-root`, default
  `%TEMP%\RdpAudit.StorageBenchmarks`) and is removed when the run ends. Reports are written outside
  that directory so they survive.
* **`%ProgramData%\RdpAudit` is never read and never written.** A `--store` or `--out` path inside it
  is refused unconditionally, and there is no override. The refusal happens before any file is opened.
* If `--store` names a directory that already contains `rdpaudit.db`, the run **refuses to start** and
  says so. `--allow-existing-store` is the explicit override, and even then the run works on a **copy**
  of that database and never opens the original for writing.
* The offline compaction runs the **real** `DatabaseCompactService` with a service name that cannot
  exist (`RdpAuditStorageBenchmarkProbe`), so no service is stopped and no service is started. That
  result type separates `Compacted` from `Success` for exactly this case, and the report says which one
  it observed.

The tool applies nothing it recommends. There is no code path from this tool to `appsettings.json`,
the registry or any running configuration; `recommended-settings.json` is a file for a human to read.

## 4. What is measured, and how

Every repeated measurement runs `--warmup` warm-up passes (discarded) and then `--samples` timed
passes. The value column is the **median** of the timed samples; p95 (nearest rank:
`ceil(0.95 * n) - 1`), mean, min and max are in `report.json`. Sample counts are in the report, per
metric.

| Group | Metrics |
| --- | --- |
| Store fill | rows/s, seconds per 100 000-row chunk, seconds per million rows (only when a million rows were actually written - it is never extrapolated), database and database-family bytes |
| Retention | pass duration, rows/s, reclaimed freelist bytes and bytes/s, committed batches, per-batch writer-lock hold, main-file bytes before and after |
| Retention dry run | preview latency, rows the preview predicted, and the ratio of actually-removed rows to predicted rows |
| Ledger | chained entries/s, per-append latency |
| Snapshot | snapshot duration, bytes, MiB/s, verification duration; separately the shard-inclusive snapshot with the shard file count and bytes |
| Integrity | `quick_check`, full `integrity_check`, `foreign_key_check` durations |
| Reclaim | `wal_checkpoint(TRUNCATE)` duration, bounded `incremental_vacuum(N)` duration |
| Offline compaction | duration, bytes before and after, bytes reclaimed |
| Volume | free and total bytes, flushed 4 KiB write latency and derived IOPS, media type |

Conventions worth knowing when reading the numbers:

* **Retention runs through the real engine** (`InformationDensityRetentionEngine`), and the per-batch
  writer-lock hold comes from that engine's own observation hook - the span of the delete-plus-ledger
  transaction the budget governs. Batches from every timed pass are pooled into one sample set; the
  warm-up pass's batches are counted as warm-up.
* **Each retention sample gets its own copy of the seeded store.** A pass removes rows, so a second
  pass over the same store would face less work; copying gives every sample identical starting state.
* **The dry run is timed before the pass, against the same instant and the same store**, so comparing
  them compares two answers to one question.
* **The retention probe runs with the writer-lock budget at its supported maximum.** The budget decides
  only *when the engine yields*, never what a batch costs, so raising it lets a pass run to completion
  and makes "rows/s" describe the whole plan instead of its first slice.
* **Deleting rows does not shrink the file.** `retention.reclaimed_bytes` is freelist bytes - pages
  returned to SQLite's freelist, not to the operating system. Only the offline compaction returns them,
  which is why the compaction numbers exist in the same report.
* **The seed is a bulk load** through one transaction, not the service's per-event ingestion path. It
  measures how fast the volume absorbs rows, which is a volume fact, not an ingestion fact.
* **The volume write probe flushes to the device** after every 4 KiB write. A buffered write would
  measure the page cache and every machine would win.
* **The snapshot duration is the backup service's own reported duration.** The verification duration is
  a stopwatch around the call, because that result type carries no duration of its own. The report says
  both.

### 4.1 The `auto_vacuum` observation

The report prints the store's `PRAGMA auto_vacuum` as read **immediately after the product's own EF
migrations and before this tool writes anything**. This is where B27 was found: on the machine this was
developed on it read `0`, not incremental mode, and `PRAGMA incremental_vacuum(N)` is a documented no-op
unless the store is in incremental mode. That reading was the bug, not a property of the volume — the
product's connection-time pragma batch applied `journal_mode = WAL` before `auto_vacuum`, and SQLite
honours an auto-vacuum change only while a store still has no pages. The batch now applies `auto_vacuum`
first, so a store created by this build reports `2` here; `AutoVacuumModeTests` in
`tests/RdpAudit.Service.Tests` pins both the mode of a fresh store and the fact that the retired order
leaves it in `0`.

The tool still reports `vacuum.incremental_seconds` as **not measured** rather than as a near-zero
duration whenever the store it was pointed at is not in incremental mode, because a near-zero duration
would look like a result. That now applies to stores created before the fix, which keep mode `0`: the
library refuses to change the mode of a store that already has pages, and the offline compaction is what
rewrites one (`docs/88-database-backup-and-restore.md`; the Database tab's Overview shows the mode). The
product's own purge test (`ApplicationDataPurgeSpaceReclamationTests`) sets the pragma explicitly before
the schema exists, which is consistent with this observation. Treat it as a finding to confirm on your
host, not as a conclusion: the probe states what it read and when.

## 5. How the recommendations are computed

`StorageTuningAdvisor` in `src/RdpAudit.Core/Diagnostics` is a pure function:
`(MachineProfile, measurements) -> recommendations`. It performs no I/O, reads no clock and is
deterministic - the test suite checks both.

Three state values, and they are not interchangeable:

* **Recommended** - the rule had every input and proposes a value.
* **Declined** - the rule had every input and the measured evidence says the parameter should *not* be
  set that way. This is a real outcome: a store whose full integrity check takes twenty minutes gets
  "do not put it on a schedule", not a number.
* **InsufficientData** - the rule was missing an input and proposes **nothing**, naming the metric it
  needed. A plausible default dressed up as a measurement is the one failure mode this feature exists
  to prevent.

Each recommendation carries the rule, the rule with this run's numbers substituted into it (so the
arithmetic can be redone by hand from the measurement table), the measured inputs it consumed, and the
caveat that bounds it. The goals the rules optimize for (`StorageTuningTargets`: a 30-second target
pass against the worker's 60-second tick, a 3x writer-lock headroom, 1 GiB of free-space headroom, and
so on) are data, not constants buried in the rules.

| Parameter | Rule, in one line |
| --- | --- |
| `RdpAudit:Storage:RetentionPolicy:MaxWriterLockMs` | `ceil(p95 batch hold x headroom)`, clamped to the supported range |
| `RdpAudit:Storage:RetentionPolicy:DeleteBatchRows` | `floor((recommended budget x budget share) / measured ms per row)`, rounded to the batch step, clamped |
| `RdpAudit:Storage:RetentionPolicy:MaxRowsPerPass` | `measured rows/s x target pass seconds`, rounded, clamped |
| `RdpAudit:Storage:RetentionPolicy:MinFreeDiskBytes` | `store bytes + snapshot bytes + headroom`, refused when it would claim more than a quarter of the volume |
| `RdpAudit:Storage:Backup:MinFreeDiskBytesBeforeBackup` | `snapshot bytes + headroom`, same refusal |
| `RdpAudit:Storage:Backup:RetentionCopies` | `floor((volume free - backup floor) / snapshot bytes)`, clamped |
| `RdpAudit:Sharding:MinFreeDiskBytes` | `shard tree bytes + headroom`, same refusal |
| `Operations:FullIntegrityCheckSchedule` | measured full-check duration mapped to weekly / monthly / not-on-a-schedule (operational advice, never written to the settings fragment) |

Supported bounds are taken from the options types themselves
(`RetentionPolicyOptions.MinMaxWriterLockMs` and friends), never restated, so a change to a supported
range moves the recommendations with it.

### 5.1 Parameters this tool deliberately does not advise on

`TailKeepPerCode`, `CandidateMinRows`, `MinAgeDays`, `ProtectedEventIds` and the shard caps are
decisions about **evidence value**, not about performance. No measurement available here can decide
them, so the tool emits nothing for them and says so in the report's limitations section. Silence
about a parameter is not approval of its current value.

## 6. How to read the numbers

1. Check section 1 of `report.md` first. A number measured on a rotational volume, a network share or
   a machine with 8 GiB of RAM describes *that* machine.
2. Check the sample counts in section 3. A profile that took two samples of a metric that is noisy
   under load carries more fixed-cost noise than one that took twenty-five.
3. Read a `not measured` row as "this run does not know", never as zero. The note says why.
4. Read the retention table together: `retention.rows_per_second` with
   `retention.batch_lock_ms` and `retention.batches` describes a pass; the raw row rate alone does not.
5. `retention.preview_volume_ratio` near 1.0 is the tool's own correctness check - it says the dry run
   and the pass agreed about how much work existed. Far below 1.0 means a pass stopped early (the note
   says if the writer-lock budget fired).
6. Read the caveat on every recommendation. It names what the number was measured on and when to
   re-measure.

## 7. What this tool does not do

* **It applies nothing.** It cannot write `appsettings.json`, the registry or any live configuration.
  `recommended-settings.json` is a fragment for you to merge by hand, and its `_`-prefixed keys are
  provenance notes you delete while merging.
* **It does not touch the production store.** `%ProgramData%\RdpAudit` is neither read nor written, by
  construction and with a refusal instead of an override.
* **It does not replace production observation.** The numbers are quiet-store numbers measured on a
  synthetic store on an otherwise idle machine. They bound what the hardware can do. Only production
  telemetry - the retention worker's own pass summary, the snapshot and compaction receipts, the
  operation log - says what the store actually does under real ingestion, real alert volume and real
  backup concurrency.
* **It does not measure the service's ingestion path.** The ring buffer, ETW collection and the
  per-event write path have their own benchmarks (`benchmarks.ps1`,
  `tests/RdpAudit.Benchmarks`).
* **It does not measure the UI.** The "no stall over 16 ms" rule is not instrumented here.
* **It does not decide safety.** A recommendation to *lower* a limit is not a claim that the current
  value is unsafe; the supported bounds in the product remain the authority.

## 8. Tests

`tests/RdpAudit.StorageBenchmarks.Tests` runs the whole tool in process against a 50 000-row temporary
store on the `--quick` profile and checks that the three artifacts exist with the sections an operator
reads, that the exit codes are the documented ones, that the refusals fire, and - the reason the test
exists - that `%ProgramData%\RdpAudit` is **bit-for-bit unchanged** afterwards, compared by a digest
over every path, length and last-write time in the tree.

The pure half is covered by `tests/RdpAudit.Core.Tests`: the sample arithmetic
(`BenchmarkSampleSetTests`), the recommendation rules at their boundaries and their `InsufficientData`
behaviour (`StorageTuningAdvisorTests`), and the report round trip
(`StorageBenchmarkReportWriterTests`).
