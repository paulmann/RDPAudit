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
- Live shard writing is integrated but disabled by default. The current writer has
  no string heap, so shard records retain only fixed-width event metadata and not
  usernames, workstation names, process names, domains, or activity IDs.
- There is no cardinality guard. `MaxShardFiles` is only a coarse creation budget:
  it stops new per-IP files after the limit and leaves existing writers active.
  There is also no disk-free floor, reader cache, or operator timeline drill-down.
- Shard headers and `Shard*` metadata are committed only after the source SQLite
  transaction succeeds. A crash in that interval can lose a derived shard record
  or leave metadata stale, but cannot make a shard record authoritative over a
  missing `RawEvents` row. Metadata is refreshed from real headers and file size
  on the next successful batch; unknown values remain `NULL`.
- No complete MPMC ring, ETW provider consumer, or per-event lost-event
  classification is present. High-rate behavior must be measured on the target
  Windows host before relying on it for an incident response SLA.

## Planned direction

Future work should add a cardinality guard, disk-free floor, bounded reader cache,
and an IPC timeline surface to the active shard path. ETW-first capture and an MPMC transport should follow
only with benchmark and failure-injection coverage that preserves current
bookmark durability guarantees.
