# Shard ingestion

## Scope

The optional shard ingestion sink writes a bounded, per-source-IP forensic record stream beside
the SQLite event store. It is enabled only with `RdpAudit:Sharding:Enabled=true`; the default is
`false`. The default avoids uncontrolled file creation until a cardinality guard can aggregate a
distributed source-IP spray into IPv4 `/24` or IPv6 `/64` buckets.

Enable it only where the source address population is bounded and monitored, the service account
can write the selected root, and the shard-file budget is appropriate for the available disk.

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
