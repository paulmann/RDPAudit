# Residual Risks + Roadmap — RDPAudit 2.0 Event Collection

## Known residual risks after this iteration

1. **`EventLogWatcher` is still the primary event source.** It remains a
   BCL-owned, single-threaded, XML-materialising API. The new `IEventPipe`
   abstraction is the first half of the migration away from it, but until we
   switch to `OpenTrace`/`ProcessTrace` we cannot claim the 100k+ EPS ceiling
   is architectural rather than empirical. **Mitigation:** `IEventSource` +
   `IEventPipe` keep the swap point isolated.
2. **SQLite writer is single-threaded by design.** Even with WAL and batching,
   heavy concurrent writes force serialisation. The IP-sharded design removes
   the fat-table pressure but does not remove the summary/counter pressure.
   **Mitigation:** the durability boundary batches summary + counter + shard
   append per commit, minimising write-tx count.
3. **NTFS directory entry count.** Two-level fan-out (65 536 leaves) keeps any
   single directory small in the median case, but a pathological /8 spray
   still ends up in one leaf directory. **Mitigation:** the shard-cardinality
   guard promotes low-volume sources to subnet-aggregate shards.
4. **Memory-mapped file cache pressure.** Under sustained heavy read load the
   OS keeps shard file pages in the standby list; on memory-starved hosts this
   can compete with SQL Server-class workloads sharing the box. **Mitigation:**
   the shard-handle pool bounds mapped view count via LRU eviction; readers
   release mappings under memory pressure.
5. **First-incident forever-retention is a policy invariant, not a filesystem
   one.** A hostile administrator with SYSTEM privileges can still tamper with
   `IpEventSummary`. **Mitigation:** `EventCollectionAudit` records every
   config change with SID and account; SACL on the actions directory is
   restricted to SYSTEM + Administrators with inheritance blocked.

## Roadmap to full RDPAudit 2.0 (post-this-iteration)

- **ETW-first ingestion.** Replace `EventLogWatcher` behind `IEventSource` with
  `OpenTrace`/`ProcessTrace`. Consume `Microsoft-Windows-TerminalServices-*`
  and `Microsoft-Windows-Security-Auditing` providers directly.
- **Raw EVTX binary parse.** Bypass XML entirely via `wevtapi.dll`
  `EvtReadNextEvent` + `Span<byte>` walkers, and extract SID / TSID from
  `EVENT_HEADER.ExtendedData` without marshaling.
- **Custom lock-free ring buffer.** Replace the current SPSC
  `RingBufferEventChannel` with an MPMC cache-line-padded ring using
  `Interlocked.CompareExchange` + `[StructLayout(LayoutKind.Explicit)]` so
  multiple ETW consumer threads can produce without serialising on a channel
  writer.
- **Shard format v2.** Add `TargetUserNameHeapOffset`, `RuleFlags`, and a
  compact per-record `Sha256Digest` prefix of the raw EVTX bytes so incident
  reports can prove a record was never altered post-ingestion. Loader stays
  backward-compatible with v1 by branching on `HeaderPayload.FormatVersion`.
- **Timeline distribution.** `IncidentTimelineBuilder` streams merged
  main-table + shard rows over IPC as a `IAsyncEnumerable<TimelineEvent>` so
  the Configurator UI can paginate very long timelines without buffering.
- **Optional Parquet cold-cold tier.** Shard files older than N days may be
  swept out to a compressed Parquet columnar store for long-term SIEM export.
  `IpEventSummary` remains authoritative for first/last/count regardless.

## Non-goals for this iteration

- Cross-host correlation (multi-machine SIEM aggregation). RDPAudit 2.0 stays
  single-host; the shard format is per-host by design.
- Full VACUUM automation. Deliberately not scheduled: the space reclamation
  cost is not worth the lock hold on a 100M+ event DB.
