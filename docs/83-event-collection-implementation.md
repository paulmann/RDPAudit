# Event Collection Implementation Map

## Delivered components

| Area | Current implementation | Notes |
|---|---|---|
| Event metadata | `RdpAudit.Core/Events/EventCatalog.cs`, `EventDescriptor.cs`, `EventPreset.cs`, `EventCriticality.cs`, `EventLayer.cs` | Catalog entries carry preset, criticality, layer, required-event, and default-retention metadata. |
| Event DTO and parsing | `RawEventDto.cs`, `EventXmlParser.cs` | Correlation fields, source-IP extraction, and hardened legacy XML parsing are available. |
| Bookmark durability | `BookmarkStore.cs`, `BookmarkCheckpointLedger.cs`, `EventProcessorWorker.cs` | Event rows and committable bookmarks use one SQLite transaction. |
| Ingestion abstraction | `IEventSource.cs`, `IEventPipe.cs`, `EventLogWatcherEventSource.cs`, `RingBufferEventPipe.cs`, `FloodGuardEventPipe.cs` | Watcher capture remains the active source behind explicit abstractions. |
| Summary storage | `IpEventSummaryUpserter.cs`, Stage 10 model/configuration/migration files | Summary and event-type counters are updated in the caller transaction for resolved IPs. |
| Retention | `RetentionWorker.cs`, `EventRetention.cs` | A minute-based worker performs bounded deletes and a passive WAL checkpoint. A retention value of zero means retain forever. |
| Configurator | `EventCollectionPage.cs`, IPC event-collection contracts | Operators select presets, change enabled flags, edit per-event retention, save, and refresh through service IPC. |
| Shard format | `Storage/Sharding/` | Fixed 128-byte records, double-buffered headers, CRC-32C, safe paths, read/write APIs, and ring eviction are implemented. |

## Intentionally not claimed

The prototype described a completed shard-backed drill-down UI, shard budget,
subnet aggregation, a cached Configurator configuration layer, and a full
ETW-first pipeline. They are not implemented by the current source tree and
must not be described as production behavior.

## Verification inventory

The Core test project contains:

- `BookmarkStoreUnifiedCommitTests` for commit/rollback atomicity.
- `EventLayerTests`, `RawEventDtoTests`, and expanded `EventCatalogTests` for
  event contracts and serializer sequence stamping.
- `EventXmlParserHardeningTests` together with the pre-existing basic and
  positional parser tests; duplicated basic DTD and positional cases were not
  copied.
- `ShardWriterTests` for record round trip, eviction, one-copy header damage,
  append allocation measurement, and Castagnoli CRC-32C vectors.

Tests target `net8.0-windows`. Build validation is supported on a Linux host
with Windows targeting enabled; runtime test execution requires Windows.
