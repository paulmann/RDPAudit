# Named-pipe IPC

The Service hosts a Windows named pipe (`\\.\pipe\RdpAuditService`) restricted to the BUILTIN\Administrators SID and LocalSystem.

## Wire format

```
[ uint32 LE  body length ]
[ MessagePack body — IpcRequest / IpcResponse ]
```

`IpcRequest.Payload` and `IpcResponse.Payload` carry a JSON string serialized with `JsonOptions.Default`. This two-tier scheme keeps the MessagePack frame small and lets the service dispatch on `IpcCommand` without having to know every payload type at compile time.

## Commands

Existing commands (Stage 0):

| Command | Ordinal | Direction | Payload (JSON) | Returns |
|---------|---------|-----------|----------------|---------|
| `Ping` | 0 | C→S | – | `"pong"` |
| `GetStatus` | 1 | C→S | – | `ServiceStatus` |
| `GetRecentEvents` | 2 | C→S | – | `RawEvent[]` |
| `GetRecentAlerts` | 3 | C→S | – | `Alert[]` |
| `GetAddresses` | 4 | C→S | – | `Address[]` |
| `GetSessions` | 5 | C→S | – | `Session[]` |
| `AcknowledgeAlert` | 6 | C→S | `long` (Alert id) | `true` |
| `BlockAddress` | 7 | C→S | `string` (IP) | `true` |
| `UnblockAddress` | 8 | C→S | `string` (IP) | `true` |
| `GetSettings` | 9 | C→S | – | `RdpAuditOptions` |
| `SaveSettings` | 10 | C→S | JSON document | `{ saved: true }` |

Stage 3 implemented commands (backend-only — Configurator UI lands in a later stage):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetFirewallStatus` | 11 | C→S | – | `FirewallStatusDto` |
| `ListBlocklist` | 12 | C→S | – | `AddressListEntryDto[]` |
| `ListWhitelist` | 13 | C→S | – | `AddressListEntryDto[]` |
| `AddToBlocklist` | 14 | C→S | `AddressListMutationRequest` | `{ status, address }` |
| `RemoveFromBlocklist` | 15 | C→S | `AddressListMutationRequest` | `{ status, address, removed }` |
| `AddToWhitelist` | 16 | C→S | `AddressListMutationRequest` | `{ status, address }` |
| `RemoveFromWhitelist` | 17 | C→S | `AddressListMutationRequest` | `{ status, address, removed }` |
| `ListActiveBlocks` | 31 | C→S | – | `AddressListEntryDto[]` |

Stage 5 implemented commands (Firewall tab in the Configurator drives these):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `ListLoginRules` | 32 | C→S | – | `LoginRuleDto[]` |
| `AddLoginRule` | 33 | C→S | `LoginRuleMutationRequest` | `{ status, login }` |
| `RemoveLoginRule` | 34 | C→S | `LoginRuleMutationRequest` | `{ status, id, login }` |
| `SetLoginRuleEnabled` | 35 | C→S | `LoginRuleMutationRequest` | `{ status, id, enabled }` |
| `ListActiveBlocksDetailed` | 36 | C→S | – | `ActiveBlockDto[]` |
| `UnblockActiveBlock` | 37 | C→S | `long` (ActiveBlock id) | `{ status, id, address, providerOk, providerError, blocklistDisabled }` |

Stage 5 IPC semantics:

* `AddLoginRule` normalises the supplied login (trim + lower-case invariant) and rejects empty / control-character input. Adding an already-present login re-enables it (`Enabled = true`) and updates the operator note when supplied; this keeps re-adds idempotent.
* `RemoveLoginRule` prefers the supplied `Id` and falls back to a normalised `Login` lookup. Removing a missing rule returns a controlled `IpcException` ("Login rule not found.").
* `SetLoginRuleEnabled` requires a positive `Id` and writes the `Enabled` flag verbatim; it never creates a row.
* `ListActiveBlocksDetailed` returns the full `ActiveBlocks` row shape (`Id`, `Ip`, `Provider`, `RuleHandle`, `CreatedUtc`, `ExpiresUtc`, `Reason`, `Status`, `LastError`). Use this when the UI needs the structured fields; the legacy `ListActiveBlocks` keeps returning the flat `AddressListEntryDto[]` for backward compatibility.
* `UnblockActiveBlock` accepts the `ActiveBlock.Id` as the payload, calls `FirewallManager.UnblockAsync` for Windows-provider rows on Windows hosts, soft-disables any matching `BlocklistEntries` rows, and flips the row to `Removed` (or `Failed` with `LastError` on provider error). Rows whose provider is `None` (audit-only) skip the provider call. The handler returns `IpcResultStatus.Unavailable` when the provider call failed but the bookkeeping is still recorded.
* All Stage 5 writes flow through the service's `AuditDbContext` via EF Core; the Configurator never opens the SQLite database for writes.

Stage 3 IPC semantics:

* Every mutation handler validates the supplied address with `IPAddress.TryParse` and refuses non-IP input with a controlled `IpcException` message (no raw exceptions surface to the client).
* `AddToBlocklist` refuses an address that already has a `WhitelistEntries` row. Whitelist precedence is enforced server-side, not by the Configurator.
* `AddToWhitelist` soft-disables any conflicting `BlocklistEntries` rows (`IsEnabled = false`) so the whitelist always wins.
* `RemoveFromBlocklist` is a soft-disable that sets `IsEnabled = false` and retains the row for audit. `RemoveFromWhitelist` is a hard delete.
* `ListActiveBlocks` returns `AddressListEntryDto` records whose `Source` field encodes `Provider:Status` (e.g. `Windows:Active`). `Note` carries the audit reason and any provider error.
* All writes go through the service's `AuditDbContext` via EF Core parameterised APIs; the Configurator never opens the SQLite database for writes.

Stage 6A implemented commands (backend aggregation + IPC; the Configurator Attack Statistics tab is delivered in Stage 6B and is the consumer of this command):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetAttackStats` | 18 | C→S | `AttackStatsRequest` (optional) | `AttackStatsDto` (includes `Entries`, `TotalMatching`, `AppliedLimit`; see `docs/46-attack-statistics.md`) |

Stage 7 implemented commands (Remote RDP Clients tab in the Configurator drives these):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `ListRdpSessions` | 19 | C→S | – | `RdpSessionListDto` (`{ Status, Sessions[], Message, QueriedUtc }`) |
| `DisconnectSession` | 20 | C→S | `SessionActionRequest` | `SessionActionResult` |
| `LogoffSession` | 21 | C→S | `SessionActionRequest` | `SessionActionResult` |
| `ShadowSession` | 22 | C→S | `SessionActionRequest` (carries `ShadowMode`: 0=ViewOnly, 1=Control, 2=ControlNoConsent) | `SessionActionResult` (policy approval only — Configurator launches mstsc itself) |
| `GetShadowPolicyStatus` | 23 | C→S | – | `ShadowPolicyStatusDto` |
| `ApplyShadowPolicy` | 24 | C→S | `ShadowPolicyApplyRequest` | `ShadowPolicyStatusDto` |
| `BackupShadowPolicy` | 25 | C→S | – | `ShadowPolicyStatusDto` |
| `RestoreShadowPolicy` | 26 | C→S | `string` (optional snapshot id; null = use latest) | `ShadowPolicyStatusDto` |

Stage 7 IPC semantics:

* `ListRdpSessions` runs `qwinsta.exe` via `ProcessStartInfo.ArgumentList` and parses the output with the pure `Core/Util/QwinstaParser`. Each row carries `IsActive`, `IsDisconnected` and `IsCurrent` so the UI can pick a colour and glyph without re-parsing the state string. The handler best-effort backfills `ClientAddress` from recent `RawEvents` rows when qwinsta does not surface it.
* `DisconnectSession` / `LogoffSession` validate the session id (`>= 0`, `<= 65535`) and refuse the request when `SessionControlOptions.AllowDisconnect` / `AllowLogoff` is false. Output is captured (stdout/stderr/exit code) and the resulting `SessionActionResult` always carries a stable `IpcResultStatus` enum value.
* `ShadowSession` is approval-only: the service refuses when `AllowShadow` is false, when the session id is invalid, or when `RequireShadowPolicy = true` and the current `Shadow` value does not permit the requested mode (`ShadowPolicyModel.AllowsMode`). On approval the Configurator spawns `mstsc.exe /shadow:<id> [/control] [/noConsentPrompt]` through `Configurator/Services/ShadowLauncher`, because the service runs under LocalSystem and cannot launch UI in the operator's desktop.
* `GetShadowPolicyStatus` reads the tracked registry values (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow` and per-machine fallback) without writing anything and reports `HasBackup` + `LatestSnapshotId`.
* `ApplyShadowPolicy` accepts a desired `ShadowMode` (0..4) or the `EnableAllPermissions` preset (full control with no consent prompt = value 2). It writes the value under the group-policy key only; the per-machine value is left intact so group-policy refresh continues to work normally. `TakeBackupFirst = true` (default) captures the current state into a fresh snapshot directory before mutating the registry.
* `BackupShadowPolicy` captures every tracked registry value into `%ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\shadow-policy.json`. The snapshot directory layout matches `BackupRunner` so the global backup workflow can include the shadow policy in the same folder hierarchy.
* `RestoreShadowPolicy` accepts an optional snapshot id (or null = latest). Missing values in the snapshot are deleted from the registry on restore, exactly mirroring the captured pre-change state.

Stage 8 implemented commands (AbuseIPDB integration — Configurator AbuseIPDB tab drives these):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetAbuseIpDbStatus` | 27 | C→S | – | `AbuseIpDbStatusDto` |
| `TestAbuseIpDbKey` | 28 | C→S | – | `AbuseIpDbTestResult` |

Stage 8 IPC semantics:

* `GetAbuseIpDbStatus` returns `AbuseIpDbStatusDto` carrying `CredentialPresent`, `ReportingEnabled`, `EndpointUrl`, total / hourly / daily report counters, the last response code / timestamp / IP / error, the `RateLimited` flag and the configured dedup window / hourly cap / daily cap. It also returns `ReportDedupeEnabled` and `ReportCooldownHours` (clamped 1..8760) so the Configurator's "1 report per 1 IP" toggle and cooldown-hours input re-display after a restart. The API key is NEVER returned over IPC. `GetSettings` masks any non-empty secret envelope to the literal string `***configured***` so the encrypted payload also never leaves the service host.
* `TestAbuseIpDbKey` performs a structural check (40..128 hex characters, canonical 80) against the unprotected key. On a passing format check the dispatcher issues a read-only `GET /api/v2/check?ipAddress=127.0.0.1` request to the configured BaseUrl; a 2xx response means AbuseIPDB accepted the credential, 401/403 means it was rejected, 429 means rate-limited. The handler NEVER submits an abuse report.
* `SaveSettings` continues to handle AbuseIPDB persistence: a plaintext key supplied by the Configurator is wrapped by `ISecretProtector` (DPAPI on Windows, `InMemorySecretProtector` for non-Windows CI) before atomic-write replacement of `appsettings.json`. Already-protected envelopes are passed through unchanged. The literal placeholder `***configured***` submitted for the AbuseIPDB `ApiKey` is a do-not-overwrite sentinel: `SettingsManager` preserves the existing on-disk envelope rather than DPAPI-wrapping the sentinel, so saving unrelated AbuseIPDB settings can never destroy a stored key. An explicit empty string (the **Clear key** button) still clears the credential.

Stage 9 implemented commands (MikroTik RouterOS v7 integration — Configurator MikroTik tab drives these):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetMikroTikStatus` | 29 | C→S | – | `MikroTikStatusDto` |
| `TestMikroTik` | 30 | C→S | – | `MikroTikTestResult` |

Stage 9 IPC semantics:

* `GetMikroTikStatus` returns `MikroTikStatusDto` carrying `Configured`, `CredentialPresent`, `Enabled`, `AddAttackerRules`, the sanitised `Endpoint` / `Scheme` / `Host` / `Port`, the `ProviderStatus` resolved from the registered `IFirewallProvider` (`Available`, `Unreachable`, `Disabled`, `NotConfigured`, `NotImplemented`), the count of active MikroTik rows in `ActiveBlocks`, the configured filter chain / action / comment prefix, the composed `BlockDurationSeconds`, the TLS-validation flag and the last sanitised error. The DTO NEVER contains the password or the protected envelope payload.
* `TestMikroTik` performs a controlled read-only probe (`GET /rest/system/resource`) and returns a `MikroTikTestResult` with `CredentialFormatValid`, `RemoteVerified`, the HTTP `ResponseCode`, the sanitised `Endpoint` and a controlled `Message`. The handler NEVER writes any firewall rule and NEVER echoes the password.
* `SaveSettings` continues to handle MikroTik persistence: a plaintext password supplied by the Configurator is wrapped by `ISecretProtector` before atomic-write replacement of `appsettings.json`. Already-protected envelopes are passed through unchanged. The Configurator MUST submit the literal string `***configured***` as a placeholder when the operator does not want to change the existing envelope.

## DTO contracts

All Stage 1 DTOs live under `RdpAudit.Core.Ipc.Contracts.*` with explicit `[MessagePackObject]` and integer `[Key]` annotations. `Key` indices are append-only — never reuse a retired index. The `IpcResultStatus` discriminator is also append-only.

## LLM contract

* The IPC client (`Configurator/Ipc/IpcClient.cs`) **must** swallow `TimeoutException` / `IOException` and return `default`. Never propagate to the UI thread.
* `IpcCommand` enum values are an append-only ABI. Never reuse a retired value.
* Every new command must be:
  1. added to `IpcCommand` at the next free ordinal,
  2. documented here with a payload + return shape,
  3. handled in `IpcDispatcher.DispatchAsync` (Service) — even if the initial handler is a `NotImplemented` stub,
  4. consumed by the Configurator through `IpcClient.SendAsync<T>`.
* DTO `[Key]` indices are append-only. To remove a field, mark it `[Obsolete]` but keep the slot reserved.
* IPC responses MUST NOT contain secret material (API keys, passwords, envelope payloads).
* IPC handlers MUST honour the supplied `CancellationToken` — no `.Result` / `.Wait()`.

## Required tests before modifying

* Manual: restart service, point Configurator at it, walk every tab, confirm round-trip.
* Automated: `IpcCommandStabilityTests` (Core.Tests) — fails if any ordinal is reused or renumbered. Add a fakes-based dispatcher test if you change `IpcDispatcher`.

## Stage 6A — Attack Statistics IPC (this branch)

`GetAttackStats` (ordinal `18`) was a Stage 1 reservation and is implemented in Stage 6A. The
Configurator UI tab that consumes it lands in Stage 6B; until then, the command is exercised by
the Service unit tests and any future operator tooling that speaks the IPC ABI directly. The
payload is optional `AttackStatsRequest` JSON:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `IpQuery` | `string?` | `null` | Case-insensitive substring match against `AttackStat.Ip`. |
| `MinThreatScore` | `double?` | `null` | Inclusive lower bound on `ThreatScore`. |
| `OnlyBlocked` | `bool` | `false` | When `true`, only rows where `IsBlocked == true` are returned. |
| `SinceUtc` / `UntilUtc` | `DateTime?` | last 7 days / now | Inclusive `LastSeenUtc` window. |
| `Limit` | `int` | `500` | Clamped server-side to `[1..2000]`. Zero falls back to the default. |

The response is the existing `AttackStatsDto` extended with append-only fields:

| Key | Field | Stage |
|-----|-------|-------|
| 0..8 | `Status`, `WindowStartUtc`, `WindowEndUtc`, `FailedLogons`, `SuccessfulLogons`, `DistinctSourceIps`, `AlertsRaised`, `AddressesAutoBlocked`, `Message` | Stage 1 reservation. |
| 9 | `Entries: List<AttackStatEntryDto>` | Stage 6A. |
| 10 | `TotalMatching: int` | Stage 6A. Total rows matching the filter before the limit. |
| 11 | `AppliedLimit: int` | Stage 6A. The clamped limit the server actually used. |

`AttackStatEntryDto` is a new contract under `RdpAudit.Core.Ipc.Contracts` with explicit
`[MessagePackObject]` + integer `[Key]` indices (`0..12`). All new MessagePack keys land at the end
of the existing schema — Stage 6A introduces zero ordinal renumbering.

Rows are returned ordered by descending `LastSeenUtc`, descending `ThreatScore`, ascending `Ip`.
Threat scoring / classification semantics are defined in `docs/46-attack-statistics.md`. Error
paths (malformed JSON payload, internal exceptions) surface as a controlled `IpcResponse` with
`Success = false` and a sanitised `Error` string — never a raw exception message or stack trace.

## Stage A — Overview dashboard + IP events export (this branch)

Two new IPC commands are introduced. Both land at the next free ordinals; ABI stability is locked
by `IpcCommandStabilityTests.Ordinal_IsStable`.

### `GetOverviewSummary` (ordinal `38`)

No request payload. Returns `OverviewSummaryDto`:

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status. `Unavailable` carries `Message` describing the failure. |
| 1 | `AttacksToday: long` | `Alerts.Count where TimeUtc >= utc-day-start`. |
| 2 | `BlockedIps: long` | Distinct IPs in `ActiveBlocks` with `Status in (Active, Pending)`. |
| 3 | `ActiveSessions: long` | Sessions in `Active` state reported by the service-side `RdpSessionManager` (0 on non-Windows hosts). |
| 4 | `FailedLogins24h: long` | `RawEvents.Count where EventId = 4625 and TimeUtc >= now - 24h`. |
| 5 | `ServiceHealth: string` | Operator-facing health string (`"Running"` when the IPC handler responds). Never contains secrets. |
| 6 | `DatabaseSizeBytes: long` | Current SQLite file length, or `-1` when unmeasurable. |
| 7 | `DatabaseGrowthBytesDay: long?` | Growth vs the snapshot closest to `now - 1 day`; `null` until snapshots accrue. |
| 8 | `DatabaseGrowthBytesWeek: long?` | Growth vs the snapshot closest to `now - 7 days`; `null` until snapshots accrue. |
| 9 | `DatabaseGrowthBytesMonth: long?` | Growth vs the snapshot closest to `now - 30 days`; `null` until snapshots accrue. |
| 10 | `Message: string?` | Operator-facing summary; never carries secrets. |
| 11 | `QueriedUtc: DateTime` | UTC timestamp of the query. |

Snapshots are written daily by `MaintenanceWorker.CaptureDbSizeSnapshotAsync` into the existing
`DbProps` table under the key prefix `OverviewDbSize:`. No new schema or migration is required.
Snapshots older than `DbSizeGrowthCalculator.MonthLookbackMaxDays` (45 days) are pruned in the same
pass, so `DbProps` stays bounded.

### `GetEventsForIp` (ordinal `39`)

Request payload `EventsForIpRequest`:

| Key | Field | Default | Meaning |
|-----|-------|---------|---------|
| 0 | `Ip: string` | (required) | Target IP literal; validated server-side via `IPAddress.TryParse`. |
| 1 | `Limit: int` | `0 → 1000` (default) | Maximum RawEvents returned. Server clamps to `[1..5000]`. |

Response `EventsForIpDto`:

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status. |
| 1 | `Ip: string` | Canonical IP literal echoed from the request. |
| 2 | `FirstSeenUtc: DateTime?` | First RawEvent for this IP; `null` when no events exist. |
| 3 | `LastSeenUtc: DateTime?` | Most recent RawEvent for this IP. |
| 4 | `FailedCount: long` | RawEvents with `EventId = 4625` for this IP. |
| 5 | `SuccessCount: long` | RawEvents with `EventId = 4624` for this IP. |
| 6 | `TotalEvents: long` | All RawEvents for this IP. |
| 7 | `DurationSeconds: long` | `LastSeenUtc − FirstSeenUtc` in whole seconds. |
| 8 | `AttemptedUserNames: List<string>` | Up to 20 distinct user names, most-recent first. |
| 9 | `AttackType: string` | Projected from `AttackStats` (`BruteForce` / `BruteForceWithSuccess` / `LogonActivity`); empty when not classified. |
| 10 | `ThreatLevel: string` | Projected from `AttackStats` (`Green` / `Yellow` / `Red`); empty when not classified. |
| 11 | `IsBlocked: bool` | True when at least one Active / Pending row in `ActiveBlocks` targets this IP. |
| 12 | `Events: List<IpEventEntryDto>` | Bounded RawEvents window, newest first. |
| 13 | `Message: string?` | Operator-facing summary; never carries secrets. |
| 14 | `QueriedUtc: DateTime` | UTC timestamp of the query. |

`IpEventEntryDto` (keys `0..9`) projects `RawEvent` fields used by the export formatter: `Id`,
`TimeUtc`, `EventId`, `Channel`, `UserName`, `Domain`, `LogonType`, `AuthPackage`, `ProcessName`,
`Status`. No raw exception detail, command-line content, or password material ever leaves the
server through this command.

Error paths (empty payload, malformed JSON, invalid IP) surface as a controlled `IpcResponse` with
`Success = false` and a sanitised `Error` string.
