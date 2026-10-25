# Session Map - Session Timeline (Backlog #6)

Read-only per-session timeline over the existing `RdpConnectionFacts` and
`RawEvents` tables. No new tables, no migrations. Implemented as IPC ordinal 72
`GetSessionTimeline` plus the Configurator's **Session Map** tab.

## 1. What it does

For one connection fact the service returns a chronologically ordered timeline:

- **Lifecycle phases** derived from `RdpConnectionFact`: logon start
  (`AuthenticatedUtc`, 4624/TS-RCM 1149), connected (`ConnectedUtc`, TS-LSM 21),
  reconnected (`ReconnectedUtc`, 4778 / TS-LSM 25), disconnected
  (`DisconnectedUtc`, 4779 / TS-LSM 24), logoff (`LoggedOffUtc`, 4634 / TS-LSM
  23 / 4647). Missing phases are simply not drawn (graceful degradation, never an
  exception).
- **Process / file activity** from `RawEvents` inside the fact's observation
  window `[FirstSeenUtc, max(LastSeenUtc, LoggedOffUtc)]`, classified by event
  id: 4688/4689 → Process; 4656/4657/4658/4663/5140/5145 → File; everything
  else → Other.
- **Correlation metadata** per activity node:

| Priority | Correlation | Method label in DTO |
|---|---|---|
| 1 | `RawEvent.LogonId == fact.LogonId` (exact, index-backed) | `LogonId` |
| 2 | `RawEvent.SessionId == fact.WtsSessionId` (both non-null) | `SessionId` |
| 3 | `UserName`+`Domain` equal AND event inside the session window | `UserWindow` |

Lifecycle nodes carry `Lifecycle`. The builder never guesses silently: a
`UserWindow` fallback is always visible in the UI (amber in the event grid, shown
in the Gantt tooltip), protecting against false forensic conclusions.

## 2. Bounds (always enforced)

- Activity node cap: request `ActivityCap`; default 500, clamped server-side to
  **50..2000** (`SessionTimelineBuilder.MinActivityCap/MaxActivityCap`,
  `SessionTimelineQueryService.ResolveCap`).
- When candidates exceed the cap the service returns the chronologically FIRST
  nodes (session onset matters most) plus `Truncated=true` and the pre-cap
  `TotalMatching`. No pagination.
- `Other` nodes are suppressed unless `IncludeOtherEvents=true` (default false),
  so a flood of correlated security noise cannot starve the map.
- Raw `Details` of an event node are populated only when the service DEBUG mode
  is on (same rule as `QueryOperationLogs`).
- Unknown `SessionId` → `IpcResultStatus.NotFound` (append-only ordinal 5). An
  empty event window is a normal, valid timeline - not an error.

## 3. Transport and ABI

- `IpcCommand.GetSessionTimeline = 72` (append-only, pinned by
  `IpcCommandStabilityTests`).
- MessagePack DTOs with append-only keys:
  `GetSessionTimelineRequest` (0..2), `SessionTimelineEventDto` (0..10),
  `SessionTimelineDto` (0..16). See `docs/50-ipc.md`, Stage 16.
- Read-only command over the admin-only named pipe; timeout is the default
  short operation deadline (`IpcConstants.TimeoutMsFor`).
- SQLite access: `SessionTimelineQueryService` over
  `IDbContextFactory<AuditDbContext>`, `AsNoTracking()`; the correlation
  pre-filter uses exact equality so the existing `(LogonId, TimeUtc)` /
  `(SessionId, TimeUtc)` indexes apply.

## 4. Threat model

1. **Trust boundary.** The timeline is a read-only projection of local data over
   the admin-only named pipe (same ACL as every other IPC command). No new
   network surface appears; the optional REST API does not expose this command.
2. **Confidentiality.** The response carries usernames, processes, command
   lines and file-object names - sensitive forensic material. It is available
   only over the existing authorized transport, on the same rights as the other
   commands. Raw `Details` are DEBUG-gated.
3. **Load.** Bounded by the 50..2000 cap and the index-backed correlation
   pre-filter; a request can never scan the whole table. No pagination surface,
   no unbounded serialization.
4. **False correlation.** The `UserWindow` fallback is explicitly labelled in
   every node and surfaced amber in the UI; the operator is never shown a
   silently-guessed correlation.
5. **Availability.** Unknown fact → typed `NotFound`; DB read failures are
   caught by the standard dispatch boundary and surfaced as a curated error;
   the Session Map tab never blocks the other tabs.

## 5. UI (Configurator → Session Map tab)

- Session list reuses `ListConnectionFacts` (40) with IP / User filters and the
  same dark theme as the other tabs.
- Selecting a row calls `GetSessionTimeline` and shows the event table (time,
  kind, event id, process/object, correlation) plus the GDI+ Gantt
  (`SessionGanttPanel`): horizontal UTC axis, colour-coded lanes (lifecycle /
  process / file), marker tooltips, legend, an open blue "now" beam for active
  sessions, and a `TRUNCATED` badge when the cap fired.
- No third-party chart libraries.

## 6. Rollback

- The change is additive: one new ordinal, new DTOs, new files. An older
  Configurator does not know the tab; an older Service answers `GetSessionTimeline`
  with "unknown command", preserving version-skew compatibility.
- The feature can be rolled back by hiding the tab (rebuild of the previous
  Configurator) without touching data or schema.

## 7. Tests

- `SessionTimelineCoreTests` - classifier table and pure builder (lifecycle
  degradation, correlation priority, window gate, Other filtering, truncation,
  stable ordering).
- `SessionTimelineQueryServiceTests` - in-memory SQLite: fact lookup, index-
  friendly pre-filter, cap clamping, DEBUG-gated details.
- `IpcDispatcherSessionTimelineTests` - command shape, typed NotFound, cap
  clamping, MessagePack round-trip.
- `SessionTimelineScenarioTests` (Tier 3) - real dispatcher end-to-end: full
  cycle, adversarial noise, truncation, NotFound.
