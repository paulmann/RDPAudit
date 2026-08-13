# RDPAudit 2.0 — Event Collection Subsystem: Exact File Plan

Every path is relative to the repo root of `paulmann/RDPAudit`.
Each row is **A**dd, **M**odify, or **R**efactor-in-place.

## src/RdpAudit.Core

| Op | Path | One-line reason |
|----|------|----------------|
| M  | `Events/EventDescriptor.cs` | Add `Preset`, `Criticality`, `RequiredEventIds`, `DefaultRetentionDays`, `ExpectedVolumeClass`, `AuditSubcategory` fields. |
| M  | `Events/EventCatalog.cs` | Encode preset masks (Minimal / Essential / Full), criticality, retention defaults, required-event links. |
| A  | `Events/EventPreset.cs` | Flags enum: `Minimal`, `Essential`, `Full`, `Custom`. |
| A  | `Events/EventCriticality.cs` | Enum: `Informational`, `Security`, `Critical`. |
| M  | `Events/RawEventDto.cs` | Add `ActivityId`, `LogonId`, `SessionId`, `IngestionSequence`, `EventLayer`, `SourceIpBinary` (16 bytes), `SourceIpConfidence`. |
| A  | `Events/EventLayer.cs` | Enum: `AuthLayer`, `SessionLayer`, `ReconnectLayer`, `TransportAnomalyLayer`, `PostLogonLayer`, `AccountLayer`, `TamperingLayer`. |
| M  | `Events/EventXmlParser.cs` | Enforce field length caps; add hardened `XmlReaderSettings` (`MaxCharactersInDocument`, `MaxCharactersInEntities`, `DtdProcessing = Prohibit`, no resolver); parsers for **22, 4778, 4779, 39, 40, 1150, 1158**. |
| M  | `Events/BookmarkStore.cs` | Expose `SaveInSameTransactionAsync(SqliteConnection conn, SqliteTransaction tx, string channel, string xml)` for unified commit. |
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
