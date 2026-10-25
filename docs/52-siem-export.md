# SIEM export (Backlog #4)

The Configurator exports the bounded raw-event window plus the bounded
correlated-alert window for one selected IP into three SIEM formats:

- **CEF** (Common Event Format, ArcSight)
- **LEEF 2.0** (Log Event Extended Format, IBM QRadar)
- **NDJSON** (newline-delimited JSON)

All three renderers consume the same neutral Core model (`RdpAudit.Core.Siem.SiemEvent`),
so field shapes stay consistent across formats: one model, three renders.

## Where the feature lives

- UI: context menu **Export SIEM Events + Alerts...** on the **Live Events** and
  **Attack Statistics** pages; the entry is enabled only for a valid IP.
- Flow: `src/RdpAudit.Configurator/Services/SiemExportRunner.cs` (pure
  `BuildText` composition + threaded `RunAsync` with dialog and file write).
- Serializers: `src/RdpAudit.Core/Siem/` (`CefSerializer`, `LeefSerializer`,
  `SiemJsonSerializer`, `SiemEventMapper`, `SiemEscape`, `SiemSerializerFactory`).
- IPC: `GetStatus` (device version), `GetEventsForIp` (39), `GetAlertsForIp` (70).

## Export flow

1. **IPC `GetStatus`** supplies `ServiceStatus.Version` - the value carried in the
   CEF / LEEF header device-version field. It is never hardcoded.
2. **IPC `GetEventsForIp` (39)** with `Limit = 0` returns the bounded
   newest-first raw-event window for the IP (server default cap).
3. **IPC `GetAlertsForIp` (70)** with `Limit = 0` returns the bounded
   newest-first correlated-alert window for the IP (server default 200).
4. Both projections are mapped into neutral `SiemEvent` records:
   events first, then alerts - each section ordered by the server (newest first).
5. The Core serializer for the selected format renders the stream.
6. The operator picks the target path in the standard **SaveFileDialog**
   (file extension, filter and default name come from `SiemSerializerFactory`).
7. The file is written as **UTF-8 without BOM** - a leading U+FEFF breaks
   CEF / LEEF / NDJSON consumers.

Every failure mode reports a concrete status string: empty IP, invalid IP,
service version unavailable, `GetEventsForIp` / `GetAlertsForIp` error status,
no data for the IP, user-cancelled dialog, or a file-write error.

## Record shapes

### Event records

| Field | Value |
|---|---|
| signature id | `event:<EventId>` (e.g. `event:4625`) |
| name | EventCatalog description, fallback `Windows event <id>` |
| severity | `5` for failed auth ids (4625 / 4771 / 4776), `1` otherwise |
| time | event `TimeUtc` (see date formats below) |
| source | `src=<ip>`, `suser=<domain>\<user>` |
| extra | channel, logon type, auth package, process name, NTSTATUS status, attack classification, external id (raw-event row id) |

### Alert records

| Field | Value |
|---|---|
| signature id | `RuleId` (e.g. `BruteForce`) |
| name | alert `Message` |
| severity | mapping: Info=1, Low=3, Medium=5, High=8, Critical=10 |
| time | alert `TimeUtc` |
| source | `src=<source ip>`, `suser=<username>` |
| extra | acknowledged flag, triggering event id, external id (alert id) |

### Date formats

- CEF: `MMM dd yyyy HH:mm:ss +00:00` computed in UTC
  (e.g. `Sep 10 2026 12:34:56 +00:00`) in `deviceCustomDate1`.
- LEEF: `devTime` in ISO-8601 UTC (`yyyy-MM-ddTHH:mm:ss.fffZ`).
- NDJSON: `timeUtc` in ISO-8601 UTC with a trailing `Z`.

No local time-zone shift is ever applied; values that arrive Kind=Unspecified
from the SQLite round-trip are re-marked as UTC before rendering.

## Format examples (condensed)

**CEF**

```text
CEF:0|RdpAudit|RdpAudit|2.0.2|event:4625|...|5|rt=... deviceCustomDate1Label=eventTime deviceCustomDate1=Sep 10 2026 12:34:56 +00:00 src=203.0.113.17 ... cs8Label=recordType cs8=event
CEF:0|RdpAudit|RdpAudit|2.0.2|BruteForce|...|8|... cs8Label=recordType cs8=alert
```

**LEEF 2.0**

```text
LEEF:2.0|RdpAudit|RdpAudit|2.0.2|event:4625|devTime=2026-09-10T12:34:56.000Z	sev=5	src=203.0.113.17	...	recordType=event
```

**NDJSON**

```json
{"type":"event","severity":5,"signatureId":"event:4625","timeUtc":"2026-09-10T12:34:56Z","sourceIp":"203.0.113.17","deviceVersion":"2.0.2"}
```

NDJSON properties are camelCase; enum values render as `"event"` / `"alert"`;
null properties are omitted; the last record has no trailing newline.

## Injection safety

All external field values are treated as untrusted data and neutralised before
rendering:

- embedded CR / LF / TAB become spaces in every format;
- CEF header escapes `\` and `|`; CEF extension key/value escapes `\`, `=` and `|`;
- LEEF values escape `\`, `^` and `|`;
- NDJSON uses the strict `JavaScriptEncoder.Default`, so control characters
  render as JSON escapes and a hostile value cannot inject a record boundary.

## IPC notes

- `GetAlertsForIp` is ordinal **70**, append-only, pinned by
  `IpcCommandStabilityTests.Ordinal_IsStable`; full contract in `docs/50-ipc.md`.
- `AlertEntryDto` carries keys 0..8 (`Id`, `RuleId`, `Severity`, `TimeUtc`,
  `SourceIp`, `UserName`, `Message`, `Acknowledged`, `TriggerEventId`);
  `Details` is deliberately not projected.

## Tests

- Unit: `RdpAudit.Core.Tests` (Siem folder: serializers, escaping, mapper, factory).
- Runner: `tests/RdpAudit.Configurator.Tests/SiemExportRunnerTests.cs`
  (CEF/LEEF/NDJSON goldens, ordering, status-skip, no-BOM write).
- Dispatcher: `tests/RdpAudit.Service.Tests/IpcDispatcherAlertsForIpTests.cs`
  (filtering, newest-first ordering, caps, validation).
- Scenario: `tests/RdpAudit.ScenarioTests/SiemExportScenarioTests.cs`
  (seeded SQLite → real `IpcDispatcher` GetStatus/39/70 → `BuildText` →
  golden CEF/LEEF/NDJSON shapes, strict per-IP filtering).
