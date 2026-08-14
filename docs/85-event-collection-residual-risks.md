# Event Collection Residual Risks

## Explicitly unimplemented work

The following items are not implemented and remain planned work:

1. **`IncidentTimelineBuilder`.** There is no merged, streaming timeline
   builder that combines detail rows and shard records for long investigations.
2. **Shard-cardinality guard.** The system has no per-window guard that promotes
   source-IP fan-out to `/24` IPv4 or `/64` IPv6 aggregate shards under a spray
   attack.
3. **Resumable install migration.** The installation and upgrade process does
   not yet persist and resume a partially completed event-collection data
   migration after interruption.
4. **Configurator caching layer.** The Event Collection page refreshes through
   IPC; it has no independent cached snapshot layer or freshness policy.

## Additional material risks

- `EventLogWatcher` and XML materialization remain the active capture path.
  `IEventSource` and `IEventPipe` provide swap points, but ETW-first ingestion
  and raw EVTX parsing are not implemented.
- SQLite writes remain serialized by SQLite's writer model. Batching and WAL
  reduce contention but do not remove it.
- The shard format is implemented and tested in isolation, but live shard
  writing, shard capacity policy, global shard budget, disk-free floor, handle
  cache, and operator drill-down are not integrated into the active processor
  path.
- The summary upserter currently records shard metadata placeholders rather
  than a live shard writer result. Operators must treat `IpEventSummary` as an
  aggregate store, not proof that a usable shard exists.
- No complete MPMC ring, ETW provider consumer, or per-event lost-event
  classification is present. High-rate behavior must be measured on the target
  Windows host before relying on it for an incident response SLA.

## Planned direction

Future work should first connect the shard writer and cardinality guard to the
same transaction-oriented ingestion design, then add a bounded reader cache and
an IPC timeline surface. ETW-first capture and an MPMC transport should follow
only with benchmark and failure-injection coverage that preserves current
bookmark durability guarantees.
