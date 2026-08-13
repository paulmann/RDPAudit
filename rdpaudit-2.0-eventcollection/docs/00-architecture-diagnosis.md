# RDPAudit 2.0 — Event Collection Subsystem: Architecture Diagnosis

Repository state used for this diagnosis: `paulmann/RDPAudit@main`, tree read 2026-08-13.
Files inspected verbatim: `Events/EventCatalog.cs`, `Events/EventDescriptor.cs`,
`Events/BookmarkStore.cs`, `Events/EventXmlParser.cs`, `Events/RawEventDto.cs`,
`Config/MonitoringOptions.cs`, `Config/StorageOptions.cs`,
`Service/Workers/EventCollectorWorker.cs`, `Service/Workers/EventProcessorWorker.cs`,
`Service/Workers/MaintenanceWorker.cs`, `Service/EventChannel.cs`
(SPSC ring buffer `RingBufferEventChannel` in `Service/Infrastructure`).

Everything below is grounded in what is actually on `main`, not on the prior
spec-v1.0 wording. Where the spec and the code diverge, the code wins and the
divergence is called out.

---

## 1. Data-flow trace (per-hop failure modes)

Producer → durable persistence path currently on `main`:

    (a) EventLogWatcher.EventRecordWritten (BCL callback, unmanaged thread)
      →
    (b) EventCollectorWorker.OnEventRecordWritten
      → EventRecord.ToXml()  <-- allocation + string materialisation on callback
      → RawEventDto (heap alloc per event)
      → EventChannel.Channel.TryWrite(dto) (RingBufferEventChannel, drop-oldest)
      →
    (c) EventProcessorWorker (single consumer)
      → EventXmlParser (XmlReader over XmlPayload string)
      → PerEventIpResolver
      → EventNormalizer → AuthAttemptFactUpserter / RdpConnectionFactUpserter
      → raw SqliteCommand batch (1000 rows, single transaction)
      →
    (d) BookmarkStore.SaveBookmarkAsync (separate EF Core SaveChanges,
        SEPARATE transaction from the batch above — DUAL WRITE)
      →
    (e) IPC push / DB indexes / attack-stats refresh worker.

Findings, per hop:

| Hop | Defect | Consequence |
|-----|--------|-------------|
| (a) | Windows internal event delivery buffer is fixed. On overflow the BCL raises `EventRecordWritten` with `EventException` and a **null** `EventRecord`. `EventCollectorWorker` treats this as a stall and calls `QueueRestart`, but does **not** emit a distinct "buffer overflowed → events lost" alert to the operator. | Silent gap window that looks identical to a channel restart. Forensically indistinguishable from "quiet period" during an attack. |
| (b) | `EventRecord.ToXml()` allocates a string per event, `RawEventDto` allocates twice more, XML holds the entire payload as a managed string. Under 100k+ EPS this alone dominates Gen0 pressure. | Ingestion ceiling is roughly the string-alloc / GC-collect rate, well below the 100k+ EPS target. |
| (b) | Watcher callback runs on the caller thread; a slow `TryWrite` or a stall in normalisation reflects back to Windows and can cause the internal Windows buffer to fill (see (a)). | Watcher-buffer overflow becomes reachable under attacker load. |
| (b) | XML payload has no `MaxCharactersInDocument`, `DtdProcessing`, `MaxCharactersInEntities` guard. `EventRecord.ToXml()` itself is safe, but downstream `XmlReader` in `EventXmlParser` uses defaults. | Adversarial (or badly-authored) event provider can inflate memory in the parser. |
| (c) | `RingBufferEventChannel` is SPSC and drop-oldest — good for latency, but *drop-oldest silently drops the newest history if the reader stalls, and drops the oldest if new events keep coming*. `_metrics.IncrementRingBufferOverflow()` counts total drops but does **not** classify them by event id / channel / source. | Impossible to answer "were any 4625s dropped in the last 5 minutes?" |
| (c) → (d) | Batch and bookmark are in **separate transactions**. Kill between step (c) commit and step (d) `SaveBookmarkAsync` and the next start reprocesses; kill in the reverse order and events are lost. This is called out in `MonitoringOptions.BatchTimeoutMilliseconds` documentation nowhere. | Duplicate rows on crash today; loss window if bookmark commits first. |
| (c) | Every event ends up in a single wide `RawEvents` table with `EventId + TimeUtc + Channel + SourceIp + Xml` and multiple indexes. Write amplification is high; Configurator queries that filter by IP need to scan the fat XML column. | GUI cold-open latency grows with total row count. On a 10M-event DB, opening the Connections tab is dominated by the SQLite index seek + page fetches through the fat table. |
| (e) | Retention runs as a periodic bulk `DELETE` inside `MaintenanceWorker`. On a hot DB this holds the writer lock long enough to be visible in `wal-index`/`journal_mode=WAL` checkpoint spikes. | GUI freeze during retention windows; ingestion backpressure via SQLite busy timeout. |
| UI  | Several Configurator pages read SQLite directly on the UI thread (`OverviewPage`, `LiveEventsPage`, `AttackStatisticsPage`) via `ReadOnlyDb` helpers. | Any query slower than 16 ms freezes the window; unmeasured today. |

---

## 2. Concrete DoS vectors against the collector

1. **Log flood.** Adversary produces high-rate benign events (e.g. login attempts
   to a monitored account) faster than the ring buffer drains. The current
   drop-oldest policy loses forensic detail exactly when it matters most.
   Nothing today distinguishes *"attacker flood"* from *"noisy provider"*.
2. **Oversized field payload.** No enforced per-field max on `UserName`,
   `WorkstationName`, `IpString`. The parser doesn't blow up (defaults save us)
   but the SQLite row size grows unbounded and the fat table's page count with
   it.
3. **Adversarial XML.** `XmlReader` defaults: DTD prohibited on modern .NET, but
   `MaxCharactersInDocument`/`MaxCharactersInEntities` are unset. A 500 KB
   payload is not rejected today; it just costs 500 KB per event.
4. **Shard-cardinality attack (post-2.0).** Once we shard per IP, an attacker
   who sprays from a `/24` can trivially create 256 shard files a second and
   inflate the NTFS MFT / handle count. Mitigated by the **shard-cardinality
   guard** (Section 3-G below) that promotes low-volume sources to `/24` (v4)
   or `/64` (v6) aggregate shards once cardinality crosses a per-window cap.
5. **Filename injection.** Deriving shard file names from raw event text would
   let a crafted `IpAddress` string like `..\..\config` or `CON` or `\\?\`
   escape the actions directory. Mitigated by canonicalising to
   `IPAddress.GetAddressBytes()` and encoding as hex under a two-level fan-out.
6. **Disk exhaustion.** Ring-eviction on individual shards caps per-shard bytes,
   but *total* actions-folder bytes are unbounded without a **global shard
   budget** and a **disk-free floor**.

---

## 3. Cost model — fat single-events table vs IP-sharded cold storage

Assumptions: SQLite WAL, page size 4 KiB, `RawEvents` row width ≈ 620 B
(including XML), one B-tree index on `(EventId, TimeUtc)`, one on `SourceIp`,
one on `Channel`. NVMe-class disk, warm OS cache.

| Row count | Fat-table GUI cold-open  | Sharded (main = `IpEventSummary`) |
|-----------|---------------------------|-----------------------------------|
| 1 M       | ~180 ms (index seek + 4-5k page reads for filter+aggregate) | ~15 ms (single scan over `IpEventSummary`, ~50 K rows for typical distribution) |
| 10 M      | 1.5–3.0 s (SQLite optimiser occasionally picks nested loop; index-only paths not always chosen) | ~40 ms (still one small table) |
| 100 M     | 15–45 s and highly variable, dominated by page cache misses; VACUUM effectively impossible without downtime | ~120 ms; shards touched **only** on drill-down |

Single-IP timeline query at 10 M rows:

- Fat table: index seek on `SourceIp` → row fetch of every event for that IP →
  parse XML at read time. 60–400 ms warm, seconds cold, and O(events-for-that-IP).
- Sharded: read summary row (O(1)) → open one memory-mapped shard file →
  `MemoryMarshal.Cast<byte, ShardRecord>` → iterate a contiguous
  `ReadOnlySpan<ShardRecord>`. 2–15 ms warm; bounded by shard cap.

Write amplification during ingestion:

- Fat table: 4-5 index updates per row + XML column material. At 100 K EPS the
  WAL grows ~60 MB/s and `wal_autocheckpoint` runs continuously.
- Sharded: main table gets **one** upsert per (IP, EventId) counter, plus one
  update of `IpEventSummary` per IP; the shard is an append into a fixed-size
  ring on disk (one 128-B write + header double-buffer flip). WAL growth drops
  ~15–20× because the fat XML column and its indexes no longer exist for
  IP-attributed events.

Retention amplification:

- Fat table + periodic bulk `DELETE`: WAL spike, checkpoint stall, GUI freeze.
- Sharded + incremental prune + O(1) ring eviction: no bulk `DELETE` in the
  shard path at all — the head pointer moves. Main-table prune is bounded per
  tick and yields to the writer.

---

## 4. Non-code deliverables produced by this design

- **File plan** — `docs/01-file-plan.md`
- **EF Core migration** — `migrations/20260814000000_Stage10IpShardsRetention.cs`
- **`appsettings.json` additions** — `appsettings/appsettings.additions.json`
- **Operator-visible behaviour changes** — `docs/02-operator-behavior.md`
- **Residual risks + roadmap** — `docs/03-residual-risks.md`

---

## 5. Bottom line

The current pipeline is well-engineered for correctness at low-to-moderate
volume but has three structural ceilings: string-allocation on the watcher
callback, dual-transaction bookmark drift, and a single fat events table that
degrades UI responsiveness linearly with row count. The 2.0 redesign attacks
all three, and adds the IP-sharded cold store, the retention governor, and the
operator control surface without breaking the existing `IEventSource` /
`EventCatalog` abstractions — it *extends* them.
