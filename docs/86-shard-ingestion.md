# Shard ingestion

## Scope

The optional shard ingestion sink writes a bounded, per-source-IP forensic record stream beside
the SQLite event store. It is enabled only with `RdpAudit:Sharding:Enabled=true`; the default is
`false`. The default keeps the sink out of the write path until an operator has reviewed the capacity
policy, the shard-file budget and the available disk - not because the sink cannot protect itself:
since this stage it enforces per-shard, whole-tree and free-disk ceilings, refuses new files with an
operator-visible banner instead of failing, and can route a distributed source-IP spray into IPv4
`/24` or IPv6 `/64` buckets when the cardinality guard is switched on.

Enable it only where the source address population is bounded and monitored, the service account
can write the selected root, and the shard-file budget is appropriate for the available disk. The
`Sharding` section of the Configurator's `Database` tab (see `docs/30-configurator.md`) is the single
place to configure all of it; every value is written to `appsettings.json` through the same settings
writer the retention policy uses and is live without a service restart.

## Paths and contents

`ShardPath` creates a portable relative name such as
`actions/cb/00/cb00710a.rdpshard`. The actions root defaults to
`%ProgramData%\RdpAudit\actions`; a configured `ActionsRoot` replaces that root. The sink checks
that the completed absolute path remains beneath the root before opening it.

Each fixed-size record contains the actual ingestion sequence, event UTC ticks, event ID, compact
channel code, event layer, source-IP confidence, logon type, parsed status fragments, session ID,
parsed logon ID, and success/failure flags. It has a CRC32C over its first 124 bytes.

The current writer has no string heap. Consequently the username, workstation, process name,
domain, and activity ID offsets are all `-1`; no string value is claimed to be stored in a shard.

## Commit order and failure semantics

The processor assigns `IngestionSequence` first and appends records to mapped writer state while
its SQLite transaction is active. `RawEvents` then commits first. Only after that success does the
sink commit shard headers and update `IpEventSummary` in a short, separate SQLite transaction.
Readers use committed headers, so a database rollback cannot publish a staged shard record; rollback
discards those writer instances without committing their headers.

A process crash between the SQLite commit and the shard-header commit can leave the shard absent or
its `Shard*` columns stale. This is intentional: `RawEvents` is the system of record, while shards
are derived forensic artifacts. The next successful batch refreshes metadata from the actual shard
header and file size. A shard I/O failure never rolls back a committed event batch.

## Configuration

| Option | Default | Meaning |
|---|---:|---|
| `Enabled` | `false` | Enables per-IP shard writing only after capacity and disk review. |
| `ActionsRoot` | empty | Empty uses `%ProgramData%\RdpAudit\actions`. |
| `ShardCapacityRecords` | `1024` | Ring capacity per shard; the oldest record is evicted when full. |
| `MaxOpenWriters` | `128` | Maximum cached open writers after a batch; least-recently-used writers are committed and closed. |
| `MaxShardFiles` | `4096` | File-creation budget. Existing open shards continue after the limit; new ones are refused and counted. |
| `MaxShardBytes` | `0` | Per-shard byte ceiling; `0` disables it. Selects the ring capacity of NEW shards only. |
| `MaxTotalShardBytes` | `0` | Whole-tree byte budget for `actions\`; `0` disables it. |
| `MinFreeDiskBytes` | `0` | Free-space floor of the shard volume; `0` disables it. |
| `OrphanGraceDays` | `14` | How long a shard must have been untouched before orphan collection may remove it (clamped to 1..3650). |

### `SubnetAggregationOptions` (cardinality guard)

| Option | Default | Meaning |
|---|---:|---|
| `Enabled` | `false` | With it off, new sources always get a per-IP file and every ceiling behaves as before. |
| `TotalFileThreshold` | `4096` | The guard engages once the tree holds MORE files than this (clamped to ≥1). |
| `NewFilesPerIntervalLimit` | `64` | The guard engages once this process has created this many files in the current interval (clamped to ≥1). |
| `IntervalSeconds` | `60` | Length of the rate window (clamped to 1..86 400). |
| `MinSourceRowsPerInterval` | `8` | A source with fewer rows than this in the window counts as low volume (clamped to ≥0; `0` means every new source is low volume). |

Clamped resolution helpers: `ResolveShardCapacityRecords`, `ResolveRingCapacityRecords`,
`ResolveMaxOpenWriters`, `ResolveMaxShardFiles`, `ResolveMaxShardBytes`, `ResolveMaxTotalShardBytes`,
`ResolveMinFreeDiskBytes`, `ResolveOrphanGraceDays`, and on the guard `ResolveTotalFileThreshold`,
`ResolveNewFilesPerIntervalLimit`, `ResolveIntervalSeconds`, `ResolveMinSourceRowsPerInterval`.
`ShardingPolicyValuesDto.FromOptions` is the only producer of the IPC projection, so a client cannot
display a value the service would not enforce.

## `IpEventSummary` shard metadata

The sink is the sole writer of `Shard*` columns. It writes only values observed from the shard
writer/header or filesystem: relative path, live record count, format version, total evictions, and
actual on-disk file length. `ShardOldestRetainedUtc` is set only when the sink knows the minimum
record tick from records it wrote since opening an empty shard; otherwise it remains `NULL`.

`ShardBytes` is the real length of the file on disk. A shard is pre-allocated to its full ring
capacity when it is created, so this value is close to constant for a given capacity and must not
be read as the volume of retained evidence. `ShardRecordCount` is the field that answers that.

`NULL` in any shard metadata column means the corresponding fact is unavailable. In particular, a
null path means no confirmed shard file is recorded for that IP, and a null oldest timestamp does
not mean zero or the current time.


## Byte ceilings against a fixed-size format (honest limitations)

A shard file is **pre-allocated to its full ring capacity**: its length is
`128 + capacity * 128` bytes (`ShardHeader.HeaderRegionBytes` plus `capacity * ShardRecord.SizeBytes`),
and that length is written once when the file is created. `MaxShardBytes` therefore cannot be a soft
cap that grows with the evidence; it can only select the **ring capacity of files created after the
ceiling is set**:

```
effectiveRingCapacity = min(ShardCapacityRecords, MaxShardBytes / 128)   // integer division, floor 1
```

Three consequences are deliberate and documented rather than hidden:

1. **A new shard may be up to 128 bytes longer than `MaxShardBytes`** - the header region is not part
   of the division. The ceiling bounds the record ring; it is not a byte-exact file size.
2. **An existing shard is never re-shaped.** `ShardWriter.OpenOrCreate` adopts the ring capacity the
   file's own header declares, so lowering `ShardCapacityRecords` or `MaxShardBytes` changes only
   files created afterwards. Rewriting a pre-allocated shard would move evidence, which this stage
   does not do.
3. **A small ceiling shortens retention, not the format.** The ring still evicts its oldest record by
   advancing the head in O(1); `ShardEvictedCount` and `ShardRecordCount` stay exact.

The whole-tree budget `MaxTotalShardBytes` and the disk floor `MinFreeDiskBytes` are checked **before a
new file is created**. Reaching either refuses new files only:

* an already-open shard keeps being written, so no event is lost from `RawEvents` and no shard is
  corrupted or truncated;
* every refusal increments its own metric (`ShardByteBudgetRefusals`, `ShardDiskFloorRefusals`, or the
  pre-existing `ShardBudgetRefusals` for the file budget), so the three ceilings stay distinguishable;
* the refusal is recorded once per reason in the service log, once as an `OperationLog` row, and
  continuously in the live capacity state (`ShardCapacityStatusDto`) that the Database tab's Shards
  section renders as a banner;
* the byte total is a lazily cached walk plus the real length of every file this process created since
  that walk, exactly like the pre-existing file count. A file an operator adds or removes out of band
  is not re-counted until the service restarts - a stated limitation, not a silent one.

When the volume's free space cannot be read at all, the disk floor **cannot** be evaluated; the sink
says so in the capacity state and does not refuse on a guessed number.

## Cardinality guard (subnet aggregation)

Wiring `ShardPath.TryComposeSubnetShardPath` (previously without a caller) so a distributed spray can
no longer stop sharding entirely:

* the guard engages once the tree holds more than `TotalFileThreshold` files **or** this process has
  created `NewFilesPerIntervalLimit` files in the current `IntervalSeconds` window;
* when it is engaged, a **new** source whose row count inside the window is below
  `MinSourceRowsPerInterval` is written into an IPv4 `/24` (or IPv6 `/64`) aggregate bucket whose file
  name carries the `-agg` suffix (`actions/cb/00/cb007100-agg.rdpshard`);
* a source that reaches `MinSourceRowsPerInterval` leaves the bucket and gets its own file: its
  `IpEventSummary` row is re-pointed at the per-IP path and the aggregate keeps the records it already
  holds. Evidence is never moved between files;
* every `IpEventSummary` row that names an aggregate shard is flagged `IsSubnetAggregate = true`
  truthfully, and the shard **records** written into an aggregate carry `ShardRecord.Flags` bit 2. A
  shard record has no address field, so an aggregate's records are attributable to the bucket, not to
  one host - that is the information trade the guard makes, and it is registered here rather than
  implied;
* activation is an event, not a state change: it raises one `OperationLog` row, one warning log line
  and the `ShardAggregations` metric on the transition, plus a continuously visible "guard engaged"
  state in the capacity report;
* with `SubnetAggregation.Enabled = false` the sink behaves exactly as it did before the guard existed:
  one file per source, and a reached `MaxShardFiles` still refuses new files with a visible banner.

## Orphan shard collection

`CollectShardGarbage` reclaims `.rdpshard` files that **no `IpEventSummary` row references** and that
have not been written for at least `OrphanGraceDays`. Before this stage such files were never deleted
and `actions\` grew monotonically.

A pass is deliberately two-step: `DryRun=true` (the default when the payload omits the flag) returns
the candidate list and deletes nothing; only an explicit `DryRun=false` applies. Every candidate is
re-validated immediately before its deletion:

| Guard | Reason code | Effect |
|---|---|---|
| An `IpEventSummary` row names the file | `BecameReferenced`, `ReferencedBySummary` | kept |
| The sink holds an open writer for it | `OpenInWriter` | kept |
| Last write is inside the grace period | `YoungerThanGracePeriod` | kept |
| Last-write time cannot be read | `LastActivityUnknown` | kept - nothing is deleted on a guess |
| The path resolves outside the actions root | `OutsideActionsRoot` | kept |
| The per-run deletion budget is spent | `DeletionBudgetSpent` | kept, reported |
| The delete itself failed | `DeletionFailed` | nothing removed, reported with the exception type |

The pass is bounded by `MaxDeletionsPerRun = 200` files, so one command can never mass-delete a tree.
Each removed file gets its own `OperationLog` row naming the path, the bytes, the retained records and
the age; a failed audit downgrades the report instead of claiming a clean pass.

**`EventDeletionLedger` is deliberately not used for shard-file collection.** That ledger accounts for
deleted event *rows* by `(EventCode, Scope, IpBinary16, WindowStartUtc, WindowEndUtc)` and a
`RowsDeleted` count. A shard file removal has no event code and no per-row window; filling those fields
would make the ledger state facts that are not true. Shard-file removals are audited through
`OperationLog`, and per-shard eviction accounting stays in `IpEventSummary`'s `Shard*` columns and the
shard header's `TotalEvicted`, exactly as the evidence model already defines it.

## What is NOT implemented

* **Compaction.** No `.rdpshard` file is ever rewritten in place, and no `ShardCompactor` exists. Ring
  eviction is the only intra-shard retention mechanism the format provides. The Configurator's Shards
  section states this instead of offering a button that cannot work.
* **A legacy-to-shard migrator.** Enabling sharding does not shrink an existing `RawEvents` table.
* **Byte-exact file sizing.** See the limitations above: `MaxShardBytes` selects a record capacity.
* **Encryption at rest for shards.** Shard files are plain files, like the database, in this stage.
