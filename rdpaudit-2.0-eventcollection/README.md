# RDPAudit 2.0 — Event Collection Redesign (Foundation Drop)

This directory is the **foundation drop** for the RDPAudit 2.0 event-collection
redesign. It contains the architecture diagnosis, the target file plan, the EF
Core migration for the new tables and columns, and the first tranche of new
source files. It is designed to be dropped into the existing
[paulmann/RDPAudit](https://github.com/paulmann/RDPAudit) repository as a
branch, or reviewed directly here in the Perplexity Project file repo.

## What is finished in this drop

- **Diagnosis** — full data-flow audit of the 1.0 pipeline and every DoS /
  correctness risk identified. See `docs/00-architecture-diagnosis.md`.
- **File plan** — complete Add/Modify list across Core, Service, Configurator,
  and tests. See `docs/01-file-plan.md`.
- **EF Core migration** — new tables (`IpEventSummary`, `IpEventTypeCounter`,
  `IngestionSequence`, `EventCollectionAudit`, `EventRetention`,
  `EventEnablement`) and new columns on `RawEvents`. See
  `migrations/20260814000000_Stage10IpShardsRetention.cs`.
- **Shard subsystem** — `ShardRecord` (128-byte packed struct),
  `ShardHeader` (double-buffered, CRC-guarded), `ShardPath` (safe canonical
  hex paths under `actions/`), `ShardWriter` (memory-mapped append with O(1)
  ring eviction), `ShardReader` (read-only iterator with generation-change
  detection and CRC verification).
- **Flood guard** — `EventFloodGuard`: fixed-slot sliding-window rate limiter
  with three decision levels (Accept / Sample / AggregateOnly).
- **Summary upserter** — `IpEventSummaryUpserter`: zero-alloc, prepared, raw
  SQL upsert into `IpEventSummary` + `IpEventTypeCounter` inside the caller's
  transaction; preserves the sacred *"first event per IP is never
  overwritten"* invariant.
- **Retention worker** — `RetentionWorker`: incremental, cancellable,
  I/O-throttled pruner honouring per-event overrides (`0 = forever`) and the
  global default, with WAL-checkpoint hint.
- **Configurator page** — `EventCollectionPage`: virtualised
  `DataGridView`, presets (Minimal / Essential / Full), per-event retention,
  and bulk retention apply, all routed through cached snapshots and IPC — no
  UI-thread SQLite or IPC calls.
- **Config additions** — `appsettings/appsettings.additions.json`: expanded
  `EnabledEventIds` list, `FloodGuard`, `Sharding`, and per-event
  `Retention.PerEventDays` blocks.
- **Operator behaviour** — `docs/02-operator-behavior.md`: exactly which
  screens change, what new columns and counters appear, and how sampled /
  aggregate-only events render.
- **Residual risks + roadmap** — `docs/03-residual-risks.md`: what remains,
  and the path to full ETW-first ingestion, custom MPMC ring, and shard
  format v2.
- **Test skeletons** — `tests/RdpAudit.Core.Tests/Sharding/ShardWriterTests.cs`
  and `tests/RdpAudit.Service.Tests/Alerts/FloodGuardTests.cs`: the intended
  test shape, including the allocation-count assertion pattern.

## What is intentionally left for follow-up

- Full rewrite of `EventCollectorWorker` and `EventProcessorWorker` around
  the new `IEventPipe` and `IEventSource` abstractions. The current 1.0
  implementations still work with the new schema; the migration is planned
  in `docs/01-file-plan.md` and is a multi-week rewrite.
- `EventCatalog` extension with `Preset`, `Criticality`, `RequiredEventIds`,
  `DefaultRetentionDays` fields (mechanical addition per plan).
- ETW-first ingestion, custom MPMC ring, and shard format v2 — see
  `docs/03-residual-risks.md`.

## Layout

```
rdpaudit-2.0-eventcollection/
├── docs/
│   ├── 00-architecture-diagnosis.md
│   ├── 01-file-plan.md
│   ├── 02-operator-behavior.md
│   └── 03-residual-risks.md
├── migrations/
│   └── 20260814000000_Stage10IpShardsRetention.cs
├── src/
│   ├── RdpAudit.Core/
│   │   ├── Events/
│   │   │   └── EventFloodGuard.cs
│   │   └── Storage/Sharding/
│   │       ├── ShardHeader.cs
│   │       ├── ShardPath.cs
│   │       ├── ShardReader.cs
│   │       ├── ShardRecord.cs
│   │       └── ShardWriter.cs
│   ├── RdpAudit.Service/
│   │   ├── Storage/
│   │   │   └── IpEventSummaryUpserter.cs
│   │   └── Workers/
│   │       └── RetentionWorker.cs
│   └── RdpAudit.Configurator/
│       └── Forms/
│           └── EventCollectionPage.cs
├── tests/
│   ├── RdpAudit.Core.Tests/Sharding/ShardWriterTests.cs
│   └── RdpAudit.Service.Tests/Alerts/FloodGuardTests.cs
├── appsettings/
│   └── appsettings.additions.json
└── README.md
```
