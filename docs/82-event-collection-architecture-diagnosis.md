# Event Collection Architecture Diagnosis

## Scope

This document records the implemented event-collection architecture after the
prototype merge. It replaces the prototype diagnosis with the current code
contracts and separates delivered behavior from work that remains planned.

## Current data path

1. `EventLogWatcherEventSource` captures a Windows event and creates a
   `RawEventDto`.
2. `RawEventSerializer` assigns a monotonic `IngestionSequence` before the DTO
   enters the `IEventPipe` implementation.
3. `FloodGuardEventPipe` applies the configured flood policy, then delegates to
   the ring-buffer pipe.
4. `EventProcessorWorker` drains batches, normalizes event XML, persists raw
   events and derived facts, and updates IP summaries where the configured
   summary upserter is available.
5. `BookmarkCheckpointLedger` only releases per-channel bookmarks whose
   sequences are covered by the current batch. The worker writes those
   bookmarks through `BookmarkStore.SaveBatchInSameTransactionAsync` using the
   same SQLite connection and transaction as the event batch.
6. A successful commit makes both the event rows and their covered bookmarks
   durable. Failure restores the optimistic bookmark cache before the exception
   escapes the batch path.

The bookmark and raw-event write boundary is covered by
`BookmarkStoreUnifiedCommitTests`: a commit makes both visible, while a
rollback leaves neither durable and restores the previous cache value.

## Defensive boundaries

- `EventXmlParser` rejects DTD input, documents above 1 MiB, documents deeper
  than 64 XML-reader levels, unsafe XPath field names, and individual field
  values above 4 KiB.
- `RawEventDto` keeps correlation data optional so legacy capture initializers
  remain valid. The serializer is responsible for setting
  `IngestionSequence`; callers must not invent a sequence value.
- `IEventPipe` and `IEventSource` isolate capture transport from processing.
  The current production transport is still Event Log watcher plus ring-buffer
  infrastructure.
- `ShardHeader` stores two CRC-32C protected header copies. `ShardReader`
  selects the valid copy with the highest generation and skips individual shard
  records whose CRC does not verify.

## Storage shape

`RawEvents` remains the forensic event store. `IpEventSummary` and
`IpEventTypeCounter` provide smaller aggregate surfaces for IP-oriented views.
Per-event retention data is stored in `EventRetention`; configuration changes
are audited through the event-collection data model and IPC contracts.

`ShardWriter`, `ShardReader`, `ShardHeader`, `ShardRecord`, and `ShardPath` are
implemented as a standalone, fixed-record shard format. The writer uses a
bounded ring with O(1) eviction, and the reader verifies CRC-32C before
returning a record. The shard subsystem is not yet wired into the live
processor's summary path; that is a residual risk, not an operator guarantee.
