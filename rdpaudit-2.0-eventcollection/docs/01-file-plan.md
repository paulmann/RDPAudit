# RDPAudit 2.0 — Event Collection Subsystem: Exact File Plan

Every path is relative to the repo root of `paulmann/RDPAudit`.
Each row is **A**dd, **M**odify, or **R**efactor-in-place.

## src/RdpAudit.Core

| Op | Path | One-line reason |
|----|------|----------------|
| M  | `Events/EventDescriptor.cs` | ✅ Done (iter 2): `Preset`, `Criticality`, `RequiredEventIds`, `DefaultRetentionDays`, `Purpose` added as init-only properties with defaults; positional signature preserved. `ExpectedVolumeClass`/`AuditSubcategory` deferred — not blocking. |
| M  | `Events/EventCatalog.cs` | ✅ Done (iter 2): every entry annotated with preset masks (Minimal ⊂ Essential ⊂ Full), criticality, retention defaults, required-event links; added events 22, 1150, 1158; added `TryGet`, `ByPreset`, `EventIdsByPreset`, `DefaultRetentionFor`, `CriticalityOf`, `RequiredClosure`, `ExpandPreset`, `ClassifyActiveSet`. |
| A  | `Events/EventPreset.cs` | ✅ Done (iter 2): `[Flags]` enum with `None`, `Minimal`, `Essential`, `Full`, `Custom`. |
| A  | `Events/EventCriticality.cs` | ✅ Done (iter 2): ordered enum `Informational` (0) → `Critical` (4); values numerically comparable. |
| M  | `Events/RawEventDto.cs` | ✅ Done (iter 3): added `ActivityId`, `LogonId`, `SessionId`, `IngestionSequence`, `EventLayer`, `SourceIpBinary` (16 bytes, IPv6-mapped), `SourceIpAddressFamily`, `SourceIpConfidence`. All new fields default to safe "not set" values; the v1.0 object-initialiser used by `EventCollectorWorker.TryCaptureDto` still compiles unchanged. |
| A  | `Events/EventLayer.cs` | ✅ Done (iter 3): `byte`-backed enum with 15 stable numeric values (`Unknown=0` … `System=15`) + `EventLayers.Parse`/`ToLabel` for round-trip. `EventDescriptor.LayerKind` derives from the legacy string `Layer` so the two can never drift. Added `EventCatalog.LayerOf` / `LayerKindOf` (O(1)). Reclassified 4778/4779 from `Logoff` to `Reconnect` (window-station reconnect ≠ logoff). |
| M  | `Events/EventXmlParser.cs` | ✅ Done (iter 4, v2.0.1): hardened `XmlReaderSettings` (`MaxCharactersInDocument = 1 MiB`, `MaxCharactersFromEntities = 4 KiB`, depth cap `MaxDepth = 64` inclusive with strict-greater comparison and boundary tests pinning both 64 (accepted) and 65 (refused), XPath-safe field-name whitelist, per-field 4 KiB cap, expanded catch-all of `IOException`/`InvalidOperationException`/`NotSupportedException`/`ArgumentException`). Legacy `ParseSafe`/`GetData`/`GetInt`/`GetDataAt` public API preserved bit-for-bit — `EventNormalizer`, `PerEventIpResolver`, `SecurityAuthProbeService`, and their tests continue to work unchanged. Added 2.0 correlation API: `ExtractSourceIp(doc, eventId)` (with per-event switches for 22, 39, 40, 1149, 1150, 1158, 261, 4778, 4779, 4625, 4648, 4624, 4634, 4647, 4768–4771), `ExtractLogonId`, `ExtractSessionId`, `ExtractActivityId`, and `PopulateFrom(doc, dto)` — non-clobbering idempotent filler for `RawEventDto` correlation fields. |
| M  | `Events/BookmarkStore.cs` | ✅ Done (iter 5, v2.0.0): unified-commit API added — `SaveInSameTransactionAsync(conn, tx, channel, xml)` and batched `SaveBatchInSameTransactionAsync(conn, tx, IReadOnlyDictionary<string,string>)` UPSERT through the caller's `SqliteConnection`+`SqliteTransaction` (single-statement `INSERT ... ON CONFLICT DO UPDATE`, ISO 8601 round-trip `UpdatedUtc` byte-identical to EF SQLite emit). Cache ordering API: `UpdateCache(channel, xml)` returns previous value; `RollbackCache(channel, previous)` restores it; `MarkCommitted` reserved for future observability. Legacy `SaveBookmarkAsync`/`DeleteBookmarkAsync`/`LoadAllAsync`/`GetBookmarkXml` preserved bit-for-bit — `SecurityBackfillWorker` and the current `EventCollectorWorker` bookmark-flush loop continue working unchanged. Guarded against caller mistakes: throws `InvalidOperationException` if connection not open, `ArgumentException` if transaction bound to a different connection. |
| A  | `Events/EventFloodGuard.cs` | Sliding per-channel + per-source rate counters, alert emission on sustained flood. |
| A  | `Storage/Sharding/ShardHeader.cs` | Struct-of-arrays double-buffered header layout + CRC32C. |
| A  | `Storage/Sharding/ShardRecord.cs` | 128-B fixed record layout, `[StructLayout(LayoutKind.Sequential, Pack=1)]`. |
| A  | `Storage/Sharding/ShardPath.cs` | Filesystem canonicaliser: two-level fan-out, filename derived from binary IP, path-traversal validator, reparse-point rejection. |
| A  | `Storage/Sharding/ShardWriter.cs` | Append + ring eviction + generation counter + torn-write repair, hot-path zero-alloc. |
| A  | `Storage/Sharding/ShardReader.cs` | Memory-mapped, `ReadOnlySpan<ShardRecord>` scan, CRC verify, generation-change retry. |
| A  | `Storage/Sharding/ShardStringHeap.cs` | Per-shard append-only string heap with offset dictionary. |
| A  | `Storage/Sharding/ShardCompactor.cs` | Off-hot-path, cancellable, incremental compaction. |
| A  | `Storage/Sharding/ShardOptions.cs` | Options: `MaxShardBytes`, `MaxRecordsPerShard`, `GlobalBudgetBytes`, `DiskFreeFloorBytes`, `FanOutDepth`, `SubnetAggregationV4`, `SubnetAggregationV6`. |
| A  | `Storage/Retention/RetentionOptions.cs` | Per-event-id retention map + global default + apply-to-all bulk key. |
| A  | `Storage/Retention/RetentionPolicyResolver.cs` | Resolves per-event retention with precedence: per-id > preset default > global. |
| A  | `Incidents/IncidentTimelineBuilder.cs` | Merges main-table rows + shard records under one abstraction; explicit gap annotation. |
| A  | `Ipc/EventCollectionMessages.cs` | IPC contracts for toggle/preset/retention/shard settings. |
| A  | `Config/ShardStorageOptions.cs` | Nested options block, referenced from `RdpAuditOptions`. |
| A  | `Config/EventCollectionOptions.cs` | Preset name, per-id enable/disable map, per-id retention map. |
| M  | `Config/RdpAuditOptions.cs` | Wire the two new option blocks. |
| M  | `Config/MonitoringOptions.cs` | Add `PipelineHighWatermark`, `PipelineLowWatermark`, `DegradeStrategy` enum, `MaxFieldLength`, `MaxXmlPayloadBytes`. |
| A  | `Data/Configurations/IpEventSummaryConfiguration.cs` | EF Core config for the summary table. |
| A  | `Data/Configurations/IpEventTypeCounterConfiguration.cs` | EF Core config for per-type counters. |
| A  | `Data/Configurations/EventCollectionAuditConfiguration.cs` | EF Core config for the SOC2 change-log rows. |
| A  | `Data/Migrations/20260814000000_Stage10IpShardsRetention.cs` | Adds all three tables + `IngestionSequence` PK on `RawEvents` + indexes. |

## src/RdpAudit.Service

| Op | Path | One-line reason |
|----|------|----------------|
| A  | `Infrastructure/IEventPipe.cs` | Abstraction over `RingBufferEventChannel` + backpressure. |
| A  | `Infrastructure/BoundedEventPipe.cs` | Implementation using existing SPSC ring + watermark + degrade strategy. |
| A  | `Infrastructure/PipelineDegradeStrategy.cs` | `PriorityDrop`, `Sampling`, `BackpressureBounded`. |
| M  | `EventChannel.cs` | Return `IEventPipe`, keep existing shape for callers. |
| A  | `Workers/RetentionWorker.cs` | Incremental, cancellable, I/O-throttled pruner. Coexists with `MaintenanceWorker`. |
| M  | `Workers/EventCollectorWorker.cs` | Overflow-detection alert; watcher rearm w/ exponential backoff; single durability boundary. |
| M  | `Workers/EventProcessorWorker.cs` | Single-transaction bookmark + batch + shard append; sequence-number monotonic assignment. |
| A  | `Storage/DurabilityBoundary.cs` | Coordinates SQLite transaction + shard append + bookmark under one commit protocol; crash-recovery reconciler. |
| A  | `Storage/IpEventSummaryUpserter.cs` | Zero-alloc raw-SQL upsert for `IpEventSummary` + `IpEventTypeCounter`. |
| A  | `Storage/LegacyToShardMigrator.cs` | Resumable one-time migration of existing `RawEvents` rows into shards. |
| M  | `Workers/IpcServerWorker.cs` | Route new `EventCollection*` IPC messages. |
| M  | `AppSettingsTemplate.cs` | Defaults for new blocks. |

## src/RdpAudit.Configurator

| Op | Path | One-line reason |
|----|------|----------------|
| A  | `Forms/EventCollectionPage.cs` | New tab: per-event enable/disable, presets, retention, shard settings. |
| A  | `Services/EventCatalogViewModel.cs` | Immutable snapshot per refresh; cache with generation stamp. |
| A  | `Services/CachedQueryService.cs` | Async, cancellable, request-coalescing read-through cache. |
| M  | `Forms/MainForm.cs` | Register the new tab; wire generation-stamp invalidation. |
| M  | `Forms/LiveEventsPage.cs`, `AttackStatisticsPage.cs`, `OverviewPage.cs` | Route reads through `CachedQueryService`; virtualise grids. |

## tests

| Op | Path | Reason |
|----|------|--------|
| A  | `tests/RdpAudit.Core.Tests/Storage/Sharding/ShardWriterTests.cs` | Round-trip, ring eviction, CRC quarantine, torn-write repair. |
| A  | `tests/RdpAudit.Core.Tests/Storage/Sharding/ShardPathTests.cs` | Filename safety fuzz. |
| A  | `tests/RdpAudit.Core.Tests/Storage/Retention/RetentionPolicyResolverTests.cs` | Precedence + `0 = forever`. |
| A  | `tests/RdpAudit.Core.Tests/Events/EventFloodGuardTests.cs` | Boundary + hover-then-burst. |
| A  | `tests/RdpAudit.Core.Tests/Events/EventXmlParserHardeningTests.cs` | Oversized field, entity expansion, malformed encoding. |
| A  | `tests/RdpAudit.Service.Tests/Workers/DurabilityBoundaryTests.cs` | Crash mid-batch, mid-shard-append, mid-bookmark. |
| A  | `tests/RdpAudit.Service.Tests/Workers/RetentionWorkerTests.cs` | Counter-preserving, incremental, cancellable. |
| A  | `tests/RdpAudit.Service.Tests/Storage/LegacyToShardMigratorTests.cs` | Resume + idempotence + parity. |
| A  | `tests/RdpAudit.Benchmarks/PipelineBenchmarks.cs` | 100k EPS, zero-alloc assertions. |
| A  | `tests/RdpAudit.Benchmarks/ShardBenchmarks.cs` | Append/scan ns/op, timeline latency at 1M/10M/100M. |
