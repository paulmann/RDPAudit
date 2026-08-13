# Operator-Visible Behaviour Changes — RDPAudit 2.0

## Diagnostics tab

- New counter block: **Pipeline** — depth / high-watermark / degrade strategy
  currently engaged. Reads directly from `IEventPipe.SnapshotHot`.
- New counter block: **FloodGuard** — hot bucket count, top 3 (channel, keyHash,
  hits) with first/last seen, running for a full `WindowSeconds`.
- New counter block: **Shards** — total shards, total bytes, evicted total,
  subnet-aggregate count, disk-free.
- Cache-freshness stamp on every derived value ("as of 22:14:07 UTC"). If a
  value is stale beyond the configured TTL, the stamp turns amber.

## Live Events tab

- Grid switches to virtualised paged mode. Column widths persist per user.
- New column **Layer** (`AuthLayer` / `SessionLayer` / etc.).
- New column **Confidence** (SourceIp confidence 0–100 %).
- Events that were **sampled** by the flood guard are rendered with a subtle
  `~` prefix on the timestamp and a hover tooltip explaining the sample rate.
- Events that were **aggregate-only** (per-event detail dropped, count kept)
  are represented as a single row with `Count: N` and a hover explaining the
  window.

## Connections tab

- Loads from `IpEventSummary` alone — no fat-table scan.
- Each row shows `TotalEventCount`, `ShardRecordCount`, and
  `ShardEvictedCount` distinctly. Evicted count is never hidden.
- Drill-down opens the shard reader for that IP; if the shard is empty (all
  records evicted, first/last preserved in summary), the UI shows the frozen
  first- and last-event snapshots plus an explicit *"records evicted from
  local cache — aggregate counts retained"* banner.
- Subnet-aggregate rows carry a `/24` or `/64` badge and expand to list the
  contributing sources by count.

## Attack Statistics tab

- Percentages and totals now derive from `IpEventTypeCounter` for O(1) roll-up
  over unlimited history.
- A dedicated column shows *"pruned range"* — the earliest date for which
  detail records still exist, per event id. When retention has evicted detail,
  the operator sees exactly what remains.

## New "Event Collection" tab (Configurator)

- One row per event id: id, channel, purpose, criticality, current 24 h / 7 d
  volume, prerequisites-satisfied indicator, per-event retention, and enable
  checkbox.
- **Presets**: Minimal / Essential / Full. Selecting a preset shows a diff
  before apply. Deviations flip to **Custom** automatically.
- **Retention**: per-event editable inline, plus **Apply to all events**.
  Separate knobs for main-table rows, shard records, alerts, and
  `IpEventSummary` (with a warning if the operator opts into first-incident
  deletion).
- **Shard settings**: `MaxShardBytes`, `MaxRecordsPerShard`, global budget,
  disk-free floor, fan-out depth, subnet-aggregation prefixes. Each field
  shows the forensic cost of reducing it inline.
- Apply is atomic over IPC; the service hot-reloads without restart. Every
  change lands in `EventCollectionAudit` with old value, new value, and the
  invoking Windows identity.
- Disabling an event that a rule requires shows a hard-confirmation dialog
  listing the specific rules that will stop working.

## Retention pass

- No more periodic bulk `DELETE` spike. Retention runs incrementally every
  minute, up to `IncrementalBatchSize` rows per table per tick.
- WAL checkpoint is nudged with `wal_checkpoint(PASSIVE)` after each pass;
  full `VACUUM` remains a manual operator action available from the Tools
  tab and is documented as blocking.

## Failure modes now surfaced (previously silent)

- `EventLogWatcher` internal buffer overflow raises a distinct **critical**
  alert *"Windows event delivery buffer overflowed on `<channel>` at `<time>`;
  events between `<t0>` and `<t1>` may be lost"*. Previously indistinguishable
  from a routine channel restart.
- Ring-buffer drops are classified by (channel, event id class) so the
  operator can see *what* was dropped, not just *how many*.
- Shard CRC failures quarantine the offending record and increment a
  quarantine counter; they never crash the reader.
