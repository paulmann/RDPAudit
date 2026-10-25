# Named-pipe IPC

The Service hosts a Windows named pipe (`\\.\pipe\RdpAuditService`) restricted to the BUILTIN\Administrators SID and LocalSystem.

## Wire format

```
[ uint32 LE  body length ]
[ MessagePack body — IpcRequest / IpcResponse ]
```

`IpcRequest.Payload` and `IpcResponse.Payload` carry a JSON string serialized with `JsonOptions.Default`. This two-tier scheme keeps the MessagePack frame small and lets the service dispatch on `IpcCommand` without having to know every payload type at compile time.

Both ends deserialize with `IpcConstants.SerializerOptions`, which is
`MessagePackSerializerOptions.Standard` plus `MessagePackSecurity.UntrustedData`: the nesting
limit and the string-key hash randomisation are on. The pipe DACL already limits senders to
`BUILTIN\Administrators` and `LocalSystem`, so this is defence in depth, not a live exposure -
but the receiver does not trust a frame's shape merely because the sender held a privileged
token. The wire format is unchanged: this is a decoding policy, not an ABI change.

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
* Lifecycle coverage: `IpcServerWorkerLifecycleTests` / `IpcServerWorkerInstanceCapTests` (Service.Tests) — must stay green when `IpcServerWorker`, `Program.RegisterServices`, or `TimedHostedService` change.

## IpcServerWorker lifecycle observability (v2.3.5)

Each `IpcServerWorker` instance carries a stable `Guid instanceId` and writes append-only, file-size-capped (512 KiB) lines to `%ProgramData%\RdpAudit\logs\ipc-startup.log`:

- constructor — `instance constructed (pid=…, instanceId=…)`;
- `ExecuteAsync` start — `ExecuteAsync entered (pid=…, instanceId=…, entry=N)`;
- `ExecuteAsync` exit — `ExecuteAsync exiting (…, entryCount, exitCount, iteration, activeHandlers, livePipes, stoppingTokenCancelled, hostApplicationStoppingCancelled, exitReason, lifetimeMs)`.

`exitReason` is `HostStop` (host stopping), `ServiceStop` (stopping token cancelled but host still running), `Faulted:<type>` (accept loop fault), or `LoopExited` otherwise.

Interpretation: repeated `entered` lines with the same `instanceId` (entry=2/3) mean one worker instance was started more than once; multiple distinct `instanceId` values mean more than one worker or host instance was created. The same facts are also emitted through `ILogger` as structured log events.

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
## Stage IP-E - Connection Facts IPC (this branch)

Two IPC commands expose the normalised historical connection model
(`RdpConnectionFact`) to the Configurator: a filtered recent-facts list and a per-IP
detail summary. Both land at the next free ordinals after `GetEventsForIp`; ABI
stability is locked by `IpcCommandStabilityTests.Ordinal_IsStable`.

### `ListConnectionFacts` (ordinal `40`)

Request payload `ConnectionFactsRequest`:

| Key | Field | Default | Meaning |
|-----|-------|---------|---------|
| 0 | `IpQuery: string?` | `null` | Optional case-insensitive IP substring filter. |
| 1 | `UserQuery: string?` | `null` | Optional case-insensitive `UserName` substring filter. |
| 2 | `SinceUtc: DateTime?` | `null` | Optional inclusive lower bound on `LastSeenUtc`. |
| 3 | `UntilUtc: DateTime?` | `null` | Optional inclusive upper bound on `LastSeenUtc`. |
| 4 | `OnlyActive: bool` | `false` | Restrict to currently-active facts only. |
| 5 | `Limit: int` | `0 -> server default` | Requested row cap; server hard-caps at 1000. |

Response `ConnectionFactsDto`:

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status. |
| 1 | `QueriedUtc: DateTime` | UTC timestamp of the snapshot. |
| 2 | `TotalMatching: int` | Matching facts before the limit was applied. |
| 3 | `AppliedLimit: int` | Limit the server clamped the response to (equals `Facts.Count`). |
| 4 | `Facts: List<ConnectionFactDto>` | Bounded facts, ordered `LastSeenUtc` descending. |
| 5 | `Message: string?` | Operator-facing; never carries secret material. |

### `GetConnectionFactsForIp` (ordinal `41`)

Request payload `ConnectionFactsForIpRequest`:

| Key | Field | Default | Meaning |
|-----|-------|---------|---------|
| 0 | `Ip: string` | (required) | Canonical IPv4 / IPv6 literal. |
| 1 | `Limit: int` | `0 -> server default` | Requested row cap; server hard-caps at 1000. |

Response `ConnectionFactsForIpDto`:

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status. |
| 1 | `Ip: string` | Canonical IP literal echoed from the request. |
| 2 | `QueriedUtc: DateTime` | UTC timestamp of the snapshot. |
| 3 | `TotalMatching: int` | Total facts for the IP before the limit was applied. |
| 4 | `AppliedLimit: int` | Limit the server clamped the response to (equals `Facts.Count`). |
| 5 | `FirstSeenUtc: DateTime?` | Earliest `FirstSeenUtc` across the IP's facts; `null` when none exist. |
| 6 | `LastSeenUtc: DateTime?` | Latest `LastSeenUtc` across the IP's facts. |
| 7 | `FailedLogons: long` | Sum of `FailedLogons` counters across the IP's facts. |
| 8 | `SuccessfulLogons: long` | Sum of `SuccessfulLogons` counters across the IP's facts. |
| 9 | `HasActiveFact: bool` | True when any fact for this IP is currently active. |
| 10 | `Facts: List<ConnectionFactDto>` | Bounded facts, `LastSeenUtc` descending; excludes raw XML. |
| 11 | `Message: string?` | Operator-facing; never carries secret material. |

`ConnectionFactDto` (keys `0..22`) projects one `RdpConnectionFact` row: `Id`, `Ip`,
`UserName`, `Domain`, `WtsSessionId`, `LogonId`, lifecycle timestamps
(`FirstSeenUtc`..`LoggedOffUtc`), `FailedLogons` / `SuccessfulLogons`,
`ObservedEventIds`, `UserNamesAttempted`, `IsActive`, plus the Stage RDP-Diag
reportability fields (`Classification`, `IsPublic`, `IsWhitelisted`,
`IsReportableToAbuseIPDB`, `IsEligibleForAutoBlock`). Raw XML payloads are
deliberately omitted so a fact-list response cannot leak event bodies.

Errors and malformed requests surface as a controlled `IpcResponse` with
`Success = false` and a sanitised error string - never a raw exception.

## Stage RDP-Config, Diag, Reconciliation, Report-log, Tools, Cleanup, Logs, Rebuild, MikroTik mTLS, Auth-success, Event-collection commands (ordinals 42-65)

These commands were added after the Stage IP-E branch but never documented
before the 2026-09-09 documentation sync. Ordinals are append-only and pinned
by `IpcCommandStabilityTests.Ordinal_IsStable`.

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetRdpConfiguration` | 42 | C→S | - | `RdpConfigurationDto` |
| `GetDiagnostics` | 43 | C→S | - | `DiagnosticsSnapshotDto` |
| `RunSecurityAuthProbe` | 44 | C→S | - | `SecurityAuthProbeDto` |
| `GetFirewallDiagnostics` | 45 | C→S | - | `FirewallDiagnosticsDto` |
| `ReconcileEnforcement` | 46 | C→S | - | `ReconciliationDto` |
| `RepairActiveBlock` | 47 | C→S | `long` (ActiveBlock id) | `ReconciliationDto` |
| `RemoveAllEnforcement` | 48 | C→S | - | `ReconciliationDto` |
| `RepairBlocklistEnforcement` | 49 | C→S | `long` (BlocklistEntry id) | `ReconciliationDto` |
| `RepairAllEnabledBlocklistEnforcement` | 50 | C→S | - | `ReconciliationDto` |
| `ListAbuseIpDbReportLog` | 51 | C→S | - | `AbuseIpDbReportLogDto[]` |
| `RunToolsDiagnostics` | 52 | C→S | - | `ToolsDiagnosticsDto` |
| `RunTemporaryFirewallRuleProbe` | 53 | C→S | `string` (test IP) | `ToolsDiagnosticsDto` |
| `DedupeBlocklistEntries` | 54 | C→S | - | `BlocklistDedupeResultDto` |
| `ClearAllBlocklist` | 55 | C→S | - | `BlocklistClearResultDto` |
| `ClearAllFirewallRules` | 56 | C→S | - | `FirewallClearResultDto` |
| `ClearAllApplicationData` | 57 | C→S | `string` (typed confirmation phrase) | `AppDataPurgeResultDto` |
| `QueryOperationLogs` | 58 | C→S | `OperationLogQueryRequest` | `OperationLogDto` page |
| `GetOverviewProgress` | 59 | C→S | - | `OverviewProgressDto` |
| `RebuildAttackStats` | 60 | C→S | - | `AttackStatsRebuildResultDto` |
| `PushMikroTikConfig` | 61 | C→S | `MikrotikConfigPushMessage` (`Config` + `SchemaVersion` + `Note`) - DPAPI envelope + certificate thumbprints, never plaintext | `{ status, ... }` |
| `GetMikroTikMtlsStatus` | 62 | C→S | - | `MikrotikMtlsStatusReply` |
| `GetAuthSuccessSummaryForIp` | 63 | C→S | `AuthSuccessSummaryRequest` | `AuthSuccessSummaryDto` |
| `GetEventCollectionSettings` | 64 | C→S | - | `EventCollectionSettingsDto` |
| `SaveEventCollectionSettings` | 65 | C→S | `EventCollectionMutationRequest` | `EventCollectionSettingsDto` |

Semantics:

* `GetFirewallDiagnostics` (45) returns the pre-rendered firewall enforcement
  report (provider/backend/scope, resolved RDP port, RdpAudit-group rules,
  per-provider availability, third-party interference note, enforcement
  reconciliation). Never contains secret material.
* `ReconcileEnforcement` (46) runs a live pass: scans the real firewall, compares
  against DB-intended ActiveBlocks, and returns per-block status
  (`Active / MissingRule / ParameterMismatch / Expired / Orphaned /
  ProviderUnavailable / EffectiveUnknown / Failed`) plus confidence. RdpAudit
  never reports an IP as blocked unless a matching backend object is discovered.
* `RepairActiveBlock` (47) / `RepairBlocklistEnforcement` (49) /
  `RepairAllEnabledBlocklistEnforcement` (50) re-install missing/mismatched rules via
  the owning backend and return post-repair reconciled rows.
* `RemoveAllEnforcement` (48) is the emergency cleanup: removes only
  RdpAudit-created enforcement objects and marks the affected rows Removed.
  `ClearAllFirewallRules` (56) does the same for firewall rules only (DEBUG-gated),
  while `ClearAllBlocklist` (55) soft-disables every enabled blocklist entry and
  synchronises enforcement.
* `ClearAllApplicationData` (57) is DEBUG-gated and requires the exact typed
  confirmation phrase in the payload; it transactionally clears operational
  tables while preserving schema, migrations, bookmarks and configuration.
* Long-running commands in this range (`RepairActiveBlock`, `ReconcileEnforcement`,
  `Clear*`, `RebuildAttackStats`, `RunToolsDiagnostics`, `RunTemporaryFirewallRuleProbe`)
  use the 60 s deadline from `IpcConstants.LongOperationTimeoutMs`.
* `PushMikroTikConfig` (61) never carries plaintext secrets: the password travels
  as a DPAPI envelope and certificates are referenced by thumbprint only.
* `GetAuthSuccessSummaryForIp` (63) is summary-only: one row per login, never one
  row per attempt, sourced entirely from `AuthAttemptFacts`.

## Stage P4-18 implemented commands (Cross-host RDP attack correlation, ordinals 66-69)

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetCrossHostFacts` | 66 | C→S (agent-side) | `CrossHostFactsRequest` | `CrossHostFactsDto` |
| `ListCrossHostChains` | 67 | C→S | `CrossHostChainsRequest` | `CrossHostChainListDto` |
| `GetCrossHostChainDetails` | 68 | C→S | `long` (chain Id) | `CrossHostChainDetailsDto` |
| `AcknowledgeCrossHostChain` | 69 | C→S | `CrossHostChainAckRequest` | `CrossHostChainAckResultDto` |

Stage P4-18 IPC semantics:

* `GetCrossHostFacts` (66) is the agent-side export command: the central service's
  `CrossHostCorrelationWorker` connects to each configured agent host over the
  same admin-only named pipe and pulls `AuthAttemptFact`-derived projections
  (`CrossHostFactDto` summaries: host-qualified time, normalized user, kind,
  event id, source IP - never XML event bodies). Non-default `SinceUtc` runs an
  incremental export; `LedgerHashUtc` watermarks the caller's last applied
  position. Unavailable / malformed agents surface as
  `IpcResultStatus.Unavailable`.
* `ListCrossHostChains` (67) returns the persisted attack-chain list window
  ordered `DetectedUtc` descending. `MaxRows` is clamped server-side to
  `[1..1000]` (default 200) and the response reports `TotalMatching` +
  `AppliedLimit`. Each `CrossHostChainDto` row carries the stable `ChainKey`,
  ack state (`IsAcknowledged`), score and the ordered `HostPath` so the
  Configurator grid renders host-to-host hops without per-row detail calls.
* `GetCrossHostChainDetails` (68) returns the full ordered-hop breakdown
  (`CrossHostChainLinkDto[]`) of one chain by Id; unknown Ids return a
  controlled `IpcResultStatus` error with a sanitized `Message`.
* `AcknowledgeCrossHostChain` (69) marks the chain and its linked
  `CROSS_HOST_CHAIN` alert as acknowledged; nothing is deleted, so the audit
  trail stays intact.
* Ordinals 66-69 are append-only and pinned by
  `IpcCommandStabilityTests.Ordinal_IsStable`. Commands 67/68 use the
  `IpcConstants` long-operation timeout; DTO `Key` indices are append-only.

## Stage SIEM - correlated alerts for one IP (Backlog #4, ordinal 70)

### `GetAlertsForIp` (ordinal `70`)

Request payload `AlertsForIpRequest`:

| Key | Field | Default | Meaning |
|-----|-------|---------|---------|
| 0 | `Ip: string` | (required) | Target IP literal; validated server-side via `IPAddress.TryParse`. |
| 1 | `Limit: int` | `0 → 200` (default) | Maximum Alert rows returned. Server clamps to `[1..2000]`. |

Response `AlertsForIpDto`:

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status. |
| 1 | `Ip: string` | Canonical IP literal echoed from the request. |
| 2 | `QueriedUtc: DateTime` | UTC timestamp of the query that produced this snapshot. |
| 3 | `TotalAlerts: long` | Total correlated alerts stored for this IP across the full history. |
| 4 | `Alerts: List<AlertEntryDto>` | Bounded alert window, newest first (`TimeUtc` desc, then `Id` desc). |
| 5 | `Message: string?` | Operator-facing; never carries secret material. |

`AlertEntryDto` (keys `0..8`) projects one `Alert` row: `Id`, `RuleId`, `Severity`,
`TimeUtc`, `SourceIp`, `UserName`, `Message`, `Acknowledged`, `TriggerEventId`.
`Details` is deliberately omitted from the IPC projection.

Ordinal 70 pairs with `GetEventsForIp` (39) for the Configurator "Export SIEM Events
+ Alerts" flow (`SiemExportRunner`, see `docs/52-siem-export.md`). Errors surface as a
controlled `IpcResponse` with `Success = false` and a sanitised `Error` string - never
a raw exception. The ordinal is append-only and pinned by
`IpcCommandStabilityTests.Ordinal_IsStable`.

## Stage 15 - Threat-intel reputation check (Backlog #5, ordinal 71)

### `GetThreatIntelStatus` (ordinal `71`)

No request payload. Returns `ThreatIntelStatusDto` - a cache-only status snapshot of
the threat-intel enrichment subsystem. The handler never performs a network call and
never returns the AbuseIPDB API key or provider payloads.

| Key | Field | Meaning |
|-----|-------|---------|
| 0 | `Status: IpcResultStatus` | Controlled status; `Unavailable` carries `Message` when the store is not composed. |
| 1 | `CheckEnabled: bool` | True when the /api/v2/check enrichment feature is enabled in configuration. |
| 2 | `TotalCacheRows: int` | Total rows in the `ThreatIntelLookups` cache table. |
| 3 | `SuccessCacheRows: int` | Cache rows whose persisted outcome is Success (may include stale snapshots). |
| 4 | `FreshSuccessRows: int` | Success rows younger than the configured freshness window - the only rows able to stamp High-risk flags. |
| 5 | `DailyUsage: int` | Persisted lookups performed today (UTC). |
| 6 | `DailyBudget: int` | Configured daily lookup budget (clamped). |
| 7 | `HighRiskThreshold: int` | Clamped abuse-confidence score threshold used by the High-risk classifier. |
| 8 | `LastPassStartedUtc: DateTime?` | UTC start of the most recent enrichment pass; null when no pass has run. |
| 9 | `LastPassFinishedUtc: DateTime?` | UTC finish of the most recent enrichment pass; null when no pass has run. |
| 10 | `LastPassLookups: int` | Lookups performed by the most recent pass (0 when none or failed). |
| 11 | `LastPassError: string?` | Sanitised error of the most recent failed pass; null when the pass succeeded. |
| 12 | `OutcomeCounts: List<ThreatIntelOutcomeCountDto>` | Cache row counts grouped by persisted outcome ordinal, ascending (`Outcome`, `Count`). |
| 13 | `Message: string?` | Operator-facing summary; never carries secrets. |

### Stage 15 High-risk stamping on read commands

`GetAttackStats`, `ListConnectionFacts` and `GetRecentEvents` are stamped from the
persistent threat-intel cache only - never from a live HTTP call, so the IPC path has
no network dependency and cannot be delayed by the provider:

* `AttackStatEntryDto` gains append-only keys `21` (`IsHighRisk: bool`) and `22`
  (`ThreatIntelConfidenceScore: int`).
* `ConnectionFactDto` gains append-only keys `23` (`IsHighRisk: bool`) and `24`
  (`ThreatIntelConfidenceScore: int`).
* `GetRecentEvents` now returns typed `RecentEventDto` rows (MessagePack keys `0..14`)
  carrying `IsHighRisk` / `ThreatIntelConfidenceScore` at keys `13` / `14`; the JSON
  serialisation keeps the Configurator's camelCase field names (`isHighRisk`,
  `threatIntelConfidenceScore`) unchanged.

Fail-closed semantics: a row is marked High-risk only when a FRESH Success cache row
(within the configured `CheckMaxAgeInDays`) exists for the IP and its clamped score is
at or above `ReportThreshold`. Stale, failed, missing or whitelisted snapshots leave the
default `false` / `0`. The flag is informational only and never feeds auto-block
enforcement. Ordinal 71 and the DTO key indices are append-only and pinned by
`IpcCommandStabilityTests.Ordinal_IsStable`.

## Stage 16 - Session Map timeline (Backlog #6, ordinal 72)

### `GetSessionTimeline` (ordinal `72`)

Request payload `GetSessionTimelineRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | `SessionId: long` | Surrogate row id of the `RdpConnectionFact` session to load. Required. |
| 1 | `ActivityCap: int` | Requested cap on activity event nodes; 0 means the service default (500). Clamped to 50..2000 server-side. |
| 2 | `IncludeOtherEvents: bool` | True to include events classified as Other (not process/file); hidden by default. |

Response `SessionTimelineDto`:

| Key | Field | Meaning |
|---|---|---|
| 0 | `Status: IpcResultStatus` | Controlled status. `NotFound` when the session id is unknown. |
| 1 | `QueriedUtc: DateTime` | UTC timestamp of the snapshot. |
| 2 | `SessionId: long` | Surrogate row id of the session fact. |
| 3 | `Ip: string` | Source IP observed for this connection, always a parseable IPv4/IPv6. |
| 4 | `UserName: string?` | User name observed on the fact. |
| 5 | `Domain: string?` | Domain observed on the fact. |
| 6 | `WtsSessionId: int?` | Windows Terminal Services session id, when known. |
| 7 | `LogonId: string?` | Windows TargetLogonId/SubjectLogonId, when known. |
| 8 | `StartUtc: DateTime` | Start of the session (first observed logon phase), used as the Gantt axis origin. |
| 9 | `EndUtc: DateTime?` | End of the session; null while the fact is still active. |
| 10 | `IsActive: bool` | True when the underlying fact is still active (no logoff observed). |
| 11 | `DurationSeconds: long` | Duration of the session in seconds (to EndUtc or to now when active). |
| 12 | `Events: List<SessionTimelineEventDto>` | Ordered event nodes (chronological, stable). |
| 13 | `TotalMatching: int` | Total activity rows that matched the correlation filter before the cap. |
| 14 | `Truncated: bool` | True when more rows matched than the applied cap, so the timeline is truncated. |
| 15 | `AppliedCap: int` | The activity cap the service actually applied (50..2000). |
| 16 | `Message: string?` | Operator-facing message; never carries secret material. |

`SessionTimelineEventDto` (keys `0..10`) carries one ordered timeline node:
`TimeUtc`, `Kind` (enum: LogonStart / Connected / Reconnected / Disconnected /
Logoff / Process / File / Other), `EventId` (0 for lifecycle nodes), `Channel`,
`CorrelationMethod` (enum: Lifecycle / LogonId / SessionId / UserWindow),
`ProcessName?`, `CommandLine?`, `ObjectName?`, `AccessMask?`, `Status?`, and
DEBUG-gated `Details?`.

Correlation rules (Backlog #6 D3): lifecycle nodes derive from the fact and are
labelled `Lifecycle`; activity rows correlate by exact `LogonId` (strongest),
`WtsSessionId`, or UserName+Domain inside the fact's observation window
(`[FirstSeenUtc, max(LastSeenUtc, LoggedOffUtc)]`, labelled `UserWindow`).
Rows that correlate only by window are always marked so the UI can show the
lower forensic confidence. Event-id classification: 4688/4689 → Process;
4656/4657/4658/4663/5140/5145 → File; everything else → Other. `Other` nodes
are suppressed unless `IncludeOtherEvents = true`. The ordinal is append-only
and pinned by `IpcCommandStabilityTests.Ordinal_IsStable`.
## Stage PM - Process Monitoring (ordinals 73-77)

The process-monitoring subsystem watches Security 4688 (process creation), keeps a
DB-backed baseline of known process identities (KnownProcesses), raises a High
PROCESS_NEW alert the first time an identity appears inside the configured alert
window, and can automatically log off the session that ran the new process through
the existing RdpSessionManager logoff pipeline.

### ReportProcessObservation (ordinal 73)

Forces one process identity through the same baseline evaluation NewProcessRule uses,
records a bounded ProcessObservations row and optionally arms the automated session
close. Request payload ProcessObservationRequest:

| Key | Field | Meaning |
|---|---|---|
| 0 | ProcessName: string | Process image name or path; any path segments are discarded server-side. Required. |
| 1 | UserName: string? | Process owner account (optionally Domain\User); blank means a system process. |
| 2 | Domain: string? | Domain of the owner account; blank means no domain prefix. |
| 3 | SessionId: int | Windows Terminal Services session id, when known; -1 means unknown. |
| 4 | AutoClose: bool | When true the response carries a queued automated session-close request (respects SessionControl gates and the auto-close rate limit). |

Response ProcessObservationResult:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | InvalidRequest for unusable input; Refused when the requested auto-close is disallowed by policy. |
| 1 | IsAlreadyKnown: bool | True when the identity already existed in the baseline before this observation. |
| 2 | IsNew: bool | True when the identity is newer than the configured alert window. |
| 3 | RecordingId: long | Id of the persisted ProcessObservations journal row. |
| 4 | Alert: ProcessAlertDto? | The PROCESS_NEW alert raised by this observation, when one was raised. |
| 5 | AutoCloseQueued: bool | True when an automated session-close response was queued for the alert. |
| 6 | Message: string? | Operator-facing message. |

### ListProcessAlerts (ordinal 74)

Request ListProcessAlertsRequest: key 0 Limit: int - maximum rows to return;
0 means the service default (200). Clamped to 1..500 server-side.

Response ProcessAlertListDto:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | Success even when the result is empty. |
| 1 | Total: int | Total PROCESS_NEW alert rows that matched, before the limit. |
| 2 | Items: List<ProcessAlertDto> | Newest-first alert projections, bounded by the applied limit. |
| 3 | Message: string? | Operator-facing message. |

### GetProcessAlertDetails (ordinal 75)

Request GetProcessAlertDetailsRequest: key 0 AlertId: long - alert row id of the
PROCESS_NEW alert to load. Required.

Response ProcessAlertDetailsDto:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | NotFound when the alert id is unknown or not PROCESS_NEW. |
| 1 | Alert: ProcessAlertDto? | Base alert projection; null when Status != Success. |
| 2 | DetailsJson: string? | Raw forensic Details JSON stored on the alert row (sanitised on creation). |
| 3 | Response: ProcessAlertResponseDto? | Persisted automated-response state, when one exists. |
| 4 | Message: string? | Operator-facing message. |

ProcessAlertResponseDto carries the persistent state of the automated session-close
response attached to the alert:

| Key | Field | Meaning |
|---|---|---|
| 0 | HasResponse: bool | False when no response row exists for the alert. |
| 1 | SessionId: int | Windows Terminal Services session id the response targets; -1 when absent. |
| 2 | Status: int | ProcessAutoCloseStatus ordinal (0 = Queued, 1 = Completed, 2 = Failed); 0 while queued. |
| 3 | ResultText: string? | Operator-facing outcome text, when the attempt has finished. |
| 4 | RequestedAtUtc: DateTime? | UTC instant the response was queued. |
| 5 | CompletedAtUtc: DateTime? | UTC instant the attempt finished; null while queued. |

### SetProcessAutoClose (ordinal 76)

Request SetProcessAutoCloseRequest:

| Key | Field | Meaning |
|---|---|---|
| 0 | AlertId: long | Alert row id of the PROCESS_NEW alert. |
| 1 | Enabled: bool | True arms the automated session close; false cancels a still-queued request. A response already in a final state cannot be re-queued or cancelled. |
| 2 | Reason: string? | Optional operator-provided reason text recorded in the audit log. |

Response ProcessAutoCloseActionResult:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | NotFound when the alert id is unknown / not PROCESS_NEW; Refused when the requested state is disallowed (terminal state reached, no target session, or SessionControl.AllowLogoff off); InvalidRequest for malformed input. |
| 1 | Alert: ProcessAlertDto? | The affected alert projection (with AutoCloseEnabled updated). |
| 2 | Response: ProcessAlertResponseDto? | Persisted automated-response state after the change. |
| 3 | Message: string? | Operator-facing message. |
### GetProcessMonitoringStatus (ordinal 77)

Response ProcessMonitoringStatusDto - informational only, never performs a session
operation:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | Success even when the feature is disabled. |
| 1 | Enabled: bool | True when the process-monitoring feature master switch is on. |
| 2 | BaselineWindowsDays: List<int> | Effective baseline look-back windows in days (sorted, distinct, 1..365). |
| 3 | AlertWindowDays: int | Effective alert window (days) used for the "new process" decision. |
| 4 | AutoCloseSessionDefault: bool | Global default for arming automated session close on new alerts. |
| 5 | EnableAlertOnSystemProcesses: bool | True when system-account processes may raise PROCESS_NEW alerts. |
| 6 | KnownProcessCount: long | Total rows in the KnownProcesses baseline table. |
| 7 | AlertsSinceStart: long | PROCESS_NEW alerts raised since the service started. |
| 8 | AutoCloseLogoffPending: int | Automated session-close requests currently waiting in the queue. |
| 9 | AutoCloseLogoffCompleted: int | Automated session-close requests that completed successfully. |
| 10 | AutoCloseLogoffFailed: int | Automated session-close requests that failed or were refused. |
| 11 | LastAutoCloseUtc: DateTime? | UTC instant of the most recent completed automated close; null when none. |
| 12 | ObservationCount: long | Rows currently retained in the ProcessObservations journal. |
| 13 | Message: string? | Operator-facing message. |

## Stage Notifications - tray notifier settings (ordinals 78/79)

The Notifications tab and the RdpAudit.Notifier tray app read/write the effective
notification settings through two commands. `NotificationSettingsDto` fields:
`EnableTrayNotifier` (bool, master switch), `StartWithWindows` (bool, logon
autostart), `PollIntervalSeconds` (int, clamped 1..60), `MinimumSeverity`
(string; invalid values fall back to "High"), `MaxToastsPerMinute` (int,
clamped 1..60), `UseNativeToasts` (bool, prefer WinRT toasts over balloon tips),
`ShowAlerts` (Dictionary<string,bool>; absent key means shown), `ShowEvents`
(Dictionary<string,bool>; absent key means shown).

### GetNotificationSettings (ordinal 78)

No request payload. Returns the effective notification settings resolved to
safe clamped values.

### SaveNotificationSettings (ordinal 79)

Request payload `NotificationSettingsDto` (partial documents allowed). The
handler clamps values server-side, falls back the severity to High, merges
ONLY the `RdpAudit.Notifications` section into the existing appsettings.json
document and persists it through SettingsManager. Returns the normalized DTO.

## Stage 2a - Database tab, server side (ordinals 80-84)

The Database tab's server surface. Four read-only commands and one mutation. No
handler in this family opens SQLite or the shard tree itself: every query is
bounded and owned by a data service, so a slow or degraded store reports a
section failure instead of stalling the dispatcher. `SaveRetentionPolicy` is the
only command here that writes, and the only one that produces an `OperationLog`
row.

### GetDatabaseOverview (ordinal 80)

No request payload. Returns `DatabaseOverviewDto`, a sectioned snapshot of the
evidence store:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | Unavailable when nothing at all could be read; Success even when the snapshot is partial. |
| 1 | QueriedUtc: DateTime | The instant every field describes ("as of"). |
| 2 | DatabasePath: string | Absolute path of the SQLite database file. |
| 3 | DatabaseBytes: long | Database file size; 0 when the file does not exist yet, -1 when unreadable. |
| 4 | WalBytes: long | Write-ahead log size, same 0 / -1 convention. |
| 5 | ShmBytes: long | Shared-memory file size, same 0 / -1 convention. |
| 6 | TotalDatabaseFamilyBytes: long | Database + WAL + SHM; the figure the `MaxDatabaseBytes` trigger compares against. -1 when any part is unreadable. |
| 7-9 | DatabaseVolumeRoot / DatabaseVolumeFreeBytes / DatabaseVolumeTotalBytes | Volume hosting the database. |
| 10-12 | ActionsVolumeRoot / ActionsVolumeFreeBytes / ActionsVolumeTotalBytes | Volume hosting the shard tree. |
| 13 | ActionsRoot: string | Absolute shard-tree root. |
| 14 | ActionsBytes: long | Total size of every file under the shard tree; -1 when the tree could not be walked. |
| 15 | ActionsFileCount: long | Number of files under the shard tree; -1 when the walk failed. |
| 16 | ActionsScanTruncated: bool | True when the bounded walk stopped early, making 14/15 lower bounds. |
| 17 | TableRowCounts: List&lt;DatabaseTableRowCountDto&gt; | `{ Table, RowCount, Error? }` per key table; RowCount -1 with an Error when that one table failed. |
| 18-20 | GrowthBytesDay / Week / Month: long? | Growth from `DbSizeGrowthCalculator` snapshots; null when no usable snapshot exists. |
| 21 | ProjectedDaysToCap: long? | Whole days until the database family reaches `MaxDatabaseBytes` at the monthly rate; null when no honest projection exists. |
| 22 | GrowthNote: string? | How the projection was derived, or why it is null. |
| 23 | AppliedMigrations: List&lt;string&gt; | Migrations applied to the live database. |
| 24 | PendingMigrations: List&lt;string&gt; | Migrations known to the binaries but not yet applied. |
| 25 | MigrationFailureMarkerPresent: bool | True when the migration-failure marker file exists. |
| 26-28 | MigrationFailureUtc / MigrationFailureMessage / MigrationFailurePendingMigrations | Marker contents; never secrets. |
| 29 | RetentionPolicyEnabled: bool | Effective information-density master switch. |
| 30 | LegalHold: bool | True when a legal hold is in force. |
| 31-33 | MaxDatabaseBytes / MaxRawEventRows / MinFreeDiskBytes: long | Effective ceilings; 0 means the trigger is disabled. |
| 34 | LedgerEntryCount: long | `EventDeletionLedger` row count; -1 when the aggregate failed. |
| 35 | LedgerRowsDeleted: long | Sum of `RowsDeleted` across the ledger: how many evidence rows an audited rule removed. |
| 36 | LedgerLastCreatedUtc: DateTime? | Newest ledger entry; null when the ledger is empty. |
| 37 | ShardingEnabled: bool | Effective sharding switch. |
| 38 | ShardCount: long | Number of `.rdpshard` files under the shard tree; -1 when the walk failed. |
| 39 | MaxShardFiles: int | Configured shard-file cap. |
| 40 | IsPartial: bool | True when at least one section timed out or failed. |
| 41 | Sections: List&lt;DatabaseOverviewSectionDto&gt; | `{ Section, DurationMs, Status, Error? }`, Status = Completed / TimedOut / Failed. |
| 42 | Warnings: List&lt;string&gt; | One line per degraded section. |
| 43 | Message: string? | Operator-facing summary. |
| 74 | AutoVacuumMode: int? | The store's `PRAGMA auto_vacuum` mode - `0` NONE, `1` FULL, `2` INCREMENTAL; null when it could not be read. Only `2` lets the online path release free pages at all (B27), so this belongs next to any "reclaimed nothing" report. |
| 75 | JournalMode: string? | `PRAGMA journal_mode` (normally `wal`); null when unreadable. |
| 76-77 | PageSize: int? / PageCount: long? | Page size in bytes and how many pages the store occupies; null when unreadable. |
| 78 | FreeListPages: long? | Pages inside the file that hold no row: the depth the online reclamation path tries to release. |
| 79 | ReclaimableBytes: long? | `PageSize × FreeListPages` - a LOWER BOUND on what an offline compaction could return, not a promise. Null when either factor is unknown. |
| 80 | SpaceReclamationNote: string? | One sentence for this store: whether online release is possible, and - when the mode is not INCREMENTAL and free pages are waiting - that only the offline compaction returns them. Null when the mode could not be read, because a sentence derived from an unknown mode would be a guess. |

Keys 74-80 come from the `StorePages` section, which reads the five PRAGMAs on one connection.

Sections run in a fixed order - `DbFiles`, `ShardTree`, `DbCounts`, `Growth`, `StorePages`,
`Schema`, `Ledger`, `Integrity`, `StorageAcl`, `Fingerprint`, `MigrationMarker`, `Backups` - each with
its own 8 s budget. A failing section marks the snapshot partial and names itself; it never fails the
command.

### GetRetentionPolicy (ordinal 81)

No request payload. Returns `RetentionPolicyDto`:

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | Unavailable when the per-event overrides could not be read. |
| 1 | Policy: RetentionPolicyValuesDto | The information-density policy. |
| 2 | GlobalWindows: RetentionWindowsDto | The global `StorageOptions` windows. |
| 3 | EventWindows: List&lt;EventRetentionWindowDto&gt; | Persisted per-event overrides, ordered by event id. |
| 4 | ConfigPath: string | Settings document these values come from. |
| 5 | QueriedUtc: DateTime | "As of" stamp. |
| 6 | EventWindowsUnavailable: bool | True when key 3 is empty because the read failed, not because no override exists. |
| 7 | Message: string? | Operator-facing message. |

`RetentionPolicyValuesDto` reports every `RetentionPolicyOptions` field twice:
the configured value and the clamped-effective value (`Effective*`), plus
`EffectiveProtectedEventIds`, `EffectiveAnchorScope`, `HasAnyPressureTrigger`,
`PressureDeletionAllowed` and a `Bounds` object carrying every supported
min/max. A hand-edited out-of-range `appsettings.json` is therefore visible as
configured ≠ effective instead of being silently normalised in the UI.

`RetentionWindowsDto` carries the eight global windows (events, alerts, abuse
reports, active blocks, attack stats, session/IP correlations, connection facts,
logs). `EventRetentionWindowDto` carries `{ EventId, Channel, DisplayName,
RetentionDays, DefaultRetentionDays, UpdatedUtc? }`, enriched from the event
catalog; `RetentionDays = 0` means "retain this code forever".

### SaveRetentionPolicy (ordinal 82)

Request payload `RetentionPolicyMutationRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | Policy: RetentionPolicyValuesDto? | Policy values to persist; null leaves the section untouched. |
| 1 | GlobalWindows: RetentionWindowsDto? | Global windows to persist; null leaves them untouched. |
| 2 | EventWindows: List&lt;EventRetentionWindowDto&gt; | Per-event overrides to upsert. |
| 3 | EventWindowsReplaceAll: bool | True makes key 2 the complete set; other overrides are removed. |

The handler validates and clamps the whole request before touching anything.
Refused (as a controlled failure, with nothing written): an unknown anchor
scope, an event id that is not catalogued, a duplicated event id, a window
outside 0..36500 days, a non-positive protected event id, an inverted per-event
list, or a request that carries nothing to save. Clamped through the
`RetentionPolicyOptions.Resolve*` helpers: `TailKeepPerCode`,
`CandidateMinRows`, `MinAgeDays`, `MaxRowsPerPass`, `MaxWriterLockMs`,
`DeleteBatchRows`, and the three byte ceilings (floored at zero).

On success the per-event rows are staged inside a transaction, the settings
document is written through `SettingsManager` (validated bind, secret handling,
atomic replace; only the retention keys change), and the transaction is
committed only afterwards - so an unwritable file leaves no override behind.
`IOptionsMonitor` picks the new document up through its change token, so the
policy is live without a restart. One `OperationLog` row is written with the old
value, the new value and the invoker (`Operator:<identity>` when the pipe could
report the peer, otherwise `Service:<process account>`); if that row cannot be
written the response is marked `Unavailable` rather than reporting a clean
success. Returns the resulting `RetentionPolicyDto` (same shape as ordinal 81).

### PreviewRetention (ordinal 83)

No request payload. Returns `RetentionPreviewDto` - a dry run with no side
effects whatsoever. The preview and the background pass share one component
(`InformationDensityRetentionEngine`): the same trigger enumeration, the same
statistics snapshot, the same planner and the same delete predicate. The
predicted per-code counts and step order are therefore what a subsequent real
pass deletes on the same state, not an estimate; this is asserted by
`InformationDensityRetentionPreviewTests`.

| Key | Field | Meaning |
|---|---|---|
| 0 | Status: IpcResultStatus | Unavailable when the store could not be examined at all. |
| 1 | PolicyEnabled: bool | Master switch state at the time of the preview. |
| 2 | LegalHold: bool | True when a hold makes every pressure rule inert. |
| 3 | Trigger: EventDeletionTrigger | The first ceiling that is breached, or Unknown. Reported even under a legal hold, so the operator can see which ceiling the hold covers. |
| 4 | TriggerWouldFire: bool | True when a real pass would act on key 3: a ceiling is breached and no legal hold is in force. |
| 5 | WouldDeleteRows: long | Rows a real pass would delete; equals the sum of `Steps.Rows`. |
| 6 | EstimatedReclaimedBytes: long? | Always null - see key 7. |
| 7 | ReclaimedBytesNote: string | Why no byte figure is offered: a SQLite delete returns pages to the file's own freelist, so the file only shrinks after an incremental vacuum or a VACUUM, and the page-granular yield depends on occupancy. The exact figure that is known is key 5. |
| 8 | RuleVersion: int | Retention rule-set version that produced the preview. |
| 9 | MinAgeCutoffUtc: DateTime | Age floor applied; rows newer than this are never candidates. |
| 10-11 | TailKeepPerCode / MaxRowsPerPass: int | Effective policy values the preview applied. |
| 12 | Codes: List&lt;RetentionPreviewCodeDto&gt; | Every code considered, densest first. |
| 13 | Steps: List&lt;RetentionPreviewStepDto&gt; | The planned steps in execution order. |
| 14 | SkippedCodeCount: int | Codes reported as left alone; equals `Codes.Count - Steps.Count`. |
| 15 | QueriedUtc: DateTime | "As of" stamp. |
| 16 | Message: string? | Operator-facing summary naming the trigger and the counts. |

`RetentionPreviewCodeDto` carries `{ EventId, Channel, IpHex, PerIp, Count,
EligibleInteriorRows, PlannedRows, SkipReason?, Explanation, OldestRetainedUtc?,
OldestDeletedUtc?, NewestDeletedUtc? }`. `SkipReason` is one of `LegalHold`,
`ProtectedEventCode`, `BelowCandidateMinRows`, `NoInteriorRows`,
`BudgetExhausted`, with a plain-language `Explanation` beside it. Protected
codes are listed explicitly even though the eligibility scan excludes them,
because "which codes are protected and why" is part of what a dry run owes the
operator; for those codes `EligibleInteriorRows` is 0 and `OldestRetainedUtc` is
null, because their interior was deliberately not measured. A preview taken when
no ceiling is breached still reports the latent plan - that is the one thing the
real pass does not compute, and the information an operator needs when choosing
a ceiling.

### GetDeletionLedger (ordinal 84)

Request payload `DeletionLedgerQueryRequest` (optional; an absent payload means
"first page, no filters"):

| Key | Field | Meaning |
|---|---|---|
| 0 | EventCode: int? | Exact event-code filter. |
| 1 | FromUtc: DateTime? | Inclusive lower bound on `CreatedUtc` (when the deletion happened). |
| 2 | ToUtc: DateTime? | Inclusive upper bound on `CreatedUtc`. |
| 3 | Scope: EventDeletionScope? | Global / PerIp filter. |
| 4 | IpHex: string? | Exact hexadecimal address filter against `IpBinary16`. |
| 5 | Page: int | Zero-based page index; negatives clamp to 0. |
| 6 | PageSize: int | Rows per page; 0/negative means 100, clamped to 1000. |

Returns `DeletionLedgerPageDto`: `{ Status, Items, TotalMatching, Page,
PageSize, HasMore, QueriedUtc, Message? }`, ordered `CreatedUtc` then `Id`
descending, so the newest deletion is always first. Each
`DeletionLedgerEntryDto` carries `{ Id, EventCode, Scope, IpHex, WindowStartUtc,
WindowEndUtc, RowsDeleted, Trigger, RuleVersion, Reason, InitiatedBy,
CreatedUtc }` - the covered evidence window is reported per row, while the
filter operates on when the deletion happened. A non-hexadecimal `IpHex` is
refused rather than silently ignored, because a dropped filter reads as "nothing
was deleted for that address".

### Stage 2a IPC semantics

* The four read commands mutate nothing: no row is deleted, no ledger entry and
  no `OperationLog` row is written. Asserted by
  `IpcDispatcherDatabaseTests.ReadOnlyCommands_LeaveTheStoreAndTheAuditLogUntouched`.
* `SaveRetentionPolicy` is the only writer in this family and the only one that
  writes `OperationLog`.
* All five commands are additive: no existing ordinal moved and no existing
  contract changed. `IpcCommandStabilityTests` locks this.
* The asynchronous `DispatchAsync(request, ct, callerIdentity)` overload carries
  the pipe peer's Windows account (`NamedPipeServerStream.GetImpersonationUserName`)
  into the mutating handler. The parameter is optional, so in-process callers
  (the REST surface, tests) are unaffected.

## Stage 2b - Database backup and restore (ordinals 85-87)

Three commands over the snapshot engine documented in `docs/88-database-backup-and-restore.md`.
`CreateDatabaseBackup` is the only one that mutates; the other two are strictly read-only and write
neither a snapshot nor an `OperationLog` row.

All three run on the long round-trip deadline (`IpcConstants.LongOperationTimeoutMs`, 60 s) in
`IpcConstants.TimeoutMsFor`: `CreateDatabaseBackup` copies the live store — plus the whole shard tree
when `IncludeShards` is set — `ListDatabaseBackups` walks the backup folder, stats every snapshot and
reads each manifest, and `VerifyDatabaseBackup` hashes an entire snapshot to compare it with the
manifest digest. On a multi-gigabyte store each of them routinely exceeds the 5-second default, and a
client that abandoned the request would report a false timeout while the service kept working to
completion (`IpcConstantsTimeoutTests` locks the mapping, including the drift guard that requires an
explicit deadline for every defined command).

### CreateDatabaseBackup (ordinal 85)

Request payload `CreateDatabaseBackupRequest` (optional; an absent payload means "use the configured
scope"):

| Key | Field | Meaning |
|---|---|---|
| 0 | IncludeShards: bool? | true also copies the shard tree into the snapshot; false copies the database only; null uses `Storage:Backup:IncludeShards`. |

Returns `DatabaseBackupCreationDto`: `{ Status, QueriedUtc, SnapshotName, SnapshotDirectory,
DatabasePath, DatabaseBytes, DatabaseSha256, Kind, DurationMs, SnapshotCountBefore,
SnapshotCountAfter, RetentionDeleted[], RetentionSkipped[], ShardsIncluded, ShardFileCount,
ShardBytes, Message? }`.

The artifact is `Backups\<yyyyMMdd-HHmmss>\dbdpaudit.db` plus `manifest.json`; see
`docs/88-database-backup-and-restore.md` for the layout and the consistency guarantee. The status is
`Success` when the snapshot was written and passed its own `quick_check`, and `Refused` with the
reason when it was not taken - including when `Storage:Backup:Enabled` is false, which is reported
(naming the setting) instead of publishing nothing silently.

Mutating and audited: one `OperationLog` row with `Source=Database`, `Operation=CreateDatabaseBackup`,
`Actor` set from `callerIdentity` (`Operator:<account>` on a resolved pipe peer, otherwise
`Service:<process account>`), and a message carrying the snapshot count before and after, the
absolute snapshot path, its size, its SHA-256 and how many older snapshots retention removed. A
refused snapshot writes no audit row, because it changed nothing. If the snapshot is written but the
audit row cannot be, the result is downgraded to `Unavailable` rather than reported as a clean
success.

### ListDatabaseBackups (ordinal 86)

No request payload. Returns `DatabaseBackupListDto`: `{ Status, QueriedUtc, BackupDirectory, Enabled,
PreMigrationBackupEnabled, RetentionCopies, Entries[], TotalCount, SkippedDirectoryCount, Truncated,
Message? }`, newest first, each `DatabaseBackupEntryDto` carrying `{ Name, Directory, CreatedUtc,
DatabaseBytes, SnapshotBytes, ManifestValid, ManifestError, DatabaseSha256, LastAppliedMigration,
AppliedMigrationCount, Kind, ShardsIncluded, ShardFileCount, ShardBytes, RowCounts, ProductVersion }`.

`ManifestValid` is false with the reason in `ManifestError` for a directory whose manifest cannot be
used, so a damaged snapshot is visible as damaged instead of missing. Directories in the backup root
that belong to another scope (settings, shadow policy) are counted in `SkippedDirectoryCount` and not
listed: they are not database snapshots and database retention never removes them. An absent backup
root is an honest empty inventory, not an error. Read-only: the command does not create the backup
root, let alone a snapshot.

### VerifyDatabaseBackup (ordinal 87)

Request payload `VerifyDatabaseBackupRequest` (optional; an absent payload verifies the newest
snapshot):

| Key | Field | Meaning |
|---|---|---|
| 0 | Name: string? | Snapshot directory name to verify. Server-validated against the snapshot timestamp format and combined through `PathSafety`, so it can never address a directory outside the backup root. |

Returns `DatabaseBackupVerificationDto`: `{ Status, QueriedUtc, SnapshotName, SnapshotDirectory,
Verdict, VerdictName, IsUsable, ExpectedSha256, ActualSha256, QuickCheckResult, SchemaVerdict,
SchemaMessage, Message? }`.

`Verdict` is `Ok`, `SnapshotMissing`, `ManifestUnreadable`, `DatabaseMissing`, `HashMismatch`,
`QuickCheckFailed`, `SchemaIncompatible` or `Unreadable`; each names a different operator action, so a
damaged file is never conflated with an unreadable manifest or a schema from a newer build. The
verification always completes (status `Success`) even when the snapshot fails its checks; status
`NotFound` means there is no such snapshot to verify, and `Unavailable` means the host did not
register the service.

Read-only: the snapshot database is opened read-only and nothing under the snapshot is written, moved
or deleted.

### Stage 2b IPC semantics

* `ListDatabaseBackups` and `VerifyDatabaseBackup` mutate nothing: no file under the backup root is
  created, moved or deleted and no `OperationLog` row is written.
* `CreateDatabaseBackup` is the only writer in this family and the only command that produces an
  `OperationLog` row.
* All three commands are additive: no existing ordinal moved and no existing contract changed.
  `IpcCommandStabilityTests` locks this.
* `Storage:Backup` is deliberately **not** part of `GetRetentionPolicy` / `SaveRetentionPolicy`: those
  two govern retention windows only. The snapshot state the Overview needs (whether the surface is
  enabled, whether a pre-migration snapshot is required, where snapshots live, how many exist and
  which is newest) is reported by `GetDatabaseOverview` in its `Backups` section, and editing
  `BackupOptions` over IPC is a later stage.

---

## Stage 3 - Database tab UI support (ordinals 88-90)

Three commands that complete the Database tab's server surface. `GetShardInventory` and
`RunDatabaseMaintenance` are read-safe (neither deletes an evidence row, neither writes an
`OperationLog` row); `RestoreDatabaseBackupToDirectory` writes files, but only inside the directory
the operator named, and is audited.

### GetShardInventory (ordinal 88)

No request payload. Returns `ShardInventoryDto`:

`{ Status, QueriedUtc, ActionsRoot, ShardingEnabled, Entries[], Summary{...}, Warnings[], Message? }`

Each `ShardInventoryEntryDto` carries `{ RelativePath, IpText, IpHex, Records, Bytes, FormatVersion,
Evicted, OldestRetainedUtc, IsOrphan, IsSubnetAggregate, Note? }`. Entries whose
`IpEventSummary.ShardRelativePath` is set come from that row (the sink is its sole writer, so a
non-null path is a confirmed artifact); every `.rdpshard` file on disk that no summary row references
is reported with `IsOrphan = true`, its address decoded from the file name and - within the bounded
header-read budget - its header read for records, format version, evicted count and oldest retained
timestamp. `ShardInventorySummaryDto` carries `{ ShardFiles, OrphanFiles, OrphanBytes,
TotalShardBytes, TotalRecords, TotalEvicted, ScannedFileCount, Truncated, EntriesReturned }`.

Read-only by construction: the command never writes, moves, quarantines or deletes a shard file -
capacity governance and orphan GC are later stages - and the walk is bounded
(`MaxShardTreeFilesScanned`, `MaxEntriesReturned`) and skips reparse points, so a pathological tree
degrades to a stated lower bound (`Truncated`, a `Warnings` entry) instead of an unbounded
enumeration. A tree that does not exist yet is an honest zero, not an error.

### RunDatabaseMaintenance (ordinal 89)

Request payload `DatabaseMaintenanceRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | Kind: `DatabaseMaintenanceKind` | The single action to run. |
| 1 | IncrementalVacuumPages: int? | Free-page budget for `IncrementalVacuum`; clamped to `[1, 5000]`, default 5000. |

`DatabaseMaintenanceKind` is `QuickCheck` (1), `FullIntegrityCheck` (2), `ForeignKeyCheck` (3),
`WalCheckpointPassive` (4), `WalCheckpointTruncate` (5), `IncrementalVacuum` (6), `Optimize` (7).
`Unknown` (0) and any value outside the defined set are refused with
`IpcResultStatus.InvalidRequest`, and the refusal names the supported kinds.

**There is no full-VACUUM member.** A full `VACUUM` rewrites the entire database file and can hold the
SQLite writer lock for minutes on a multi-gigabyte evidence store, which the no-freeze rule forbids on
a live database; `docs/88-database-backup-and-restore.md` states the policy, and space already freed
by deletions is reclaimed through the bounded `incremental_vacuum` instead — but only when the store's
auto-vacuum mode is `INCREMENTAL` (B27; the Database tab's Overview reports the mode, and on a store
where it is not, only the offline compaction returns that space). Because the validator refuses
anything outside the enum, a hand-crafted numeric payload cannot smuggle one in.

Returns `DatabaseMaintenanceReportDto`:
`{ Status, QueriedUtc, Kind, KindName, DurationMs, Steps[], ResultText, Message? }`, each
`DatabaseMaintenanceStepDto` carrying `{ Name, Outcome, Detail, DurationMs }`. `Outcome` is
`Completed`, `TimedOut` (the step exceeded its 30 s budget) or `Failed`; `ResultText` is the
monospace report the Configurator displays verbatim. A check answers `ok`/a bounded list of problem
lines (the result list is capped, so a badly corrupted store cannot produce an unbounded response); a
checkpoint answers `busy`/`walFrames`/`checkpointedFrames`; the vacuum answers the pages it actually
released — `freedPages=N (freelist X -> Y, budget B)` — measured from the freelist depth before and
after, because `PRAGMA incremental_vacuum(N)` itself returns no rows whether it released nothing or
thousands of pages, and when it released nothing the detail names the cause (an empty freelist, or a
store whose mode is not `INCREMENTAL` together with the offline route); `optimize` reports that it ran.
Any step that did not complete downgrades the report to `IpcResultStatus.Unavailable`, so a partial
run is never presented as clean.

Read-safe: no action deletes evidence rows, no action rewrites the database file wholesale, the shard
tree is untouched, and no `OperationLog` row is written (`ResultText`/`Message` say so explicitly).

### RestoreDatabaseBackupToDirectory (ordinal 90)

Request payload `RestoreDatabaseBackupToDirectoryRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | Name: string? | Snapshot directory name to restore; null/empty means the newest snapshot. |
| 1 | TargetDirectory: string | Absolute directory the copy is written into. Created when missing. |

Returns the existing `DatabaseBackupRestoreReportDto` (the same contract as the service-layer scratch
restore): `{ Status, QueriedUtc, SnapshotName, TargetDirectory, TargetDatabasePath, DatabaseBytesCopied,
ShardsRestored, ShardFilesRestored, ShardBytesRestored, Verification?, Message? }`.

The snapshot is verified first (`DatabaseSnapshotVerifier`: manifest, SHA-256, `quick_check`, schema
compatibility against the running binaries) and **a snapshot that does not verify writes nothing**.
On success the database (and the shard tree the snapshot carries) is copied through a staging file that
is moved into place, so a half-written target is never visible under the final name. The live store and
the backup root are never modified by this command: replacing the live database while the service is
stopped is the Configurator's `DatabaseRestoreService` flow and stays out of IPC, which is what keeps
this command safe to call from a non-elevated Configurator.

The target is validated before any filesystem work: it must resolve to an absolute path that is not a
drive root, otherwise the response is `IpcResultStatus.InvalidRequest`. A successful restore writes one
`OperationLog` row (`Source=Database`, `Operation=RestoreDatabaseBackupToDirectory`, `Actor` from the
pipe-resolved identity, details carrying the snapshot, the target and the bytes copied); a refused
restore writes no audit row, because it changed nothing - the same rule `CreateDatabaseBackup` follows.

### Stage 3 IPC semantics

* `GetShardInventory` and `RunDatabaseMaintenance` mutate nothing: no evidence row changes, no file
  under the shard tree is created, moved or deleted, and no `OperationLog` row is written.
  `IpcDispatcherDatabaseStage3Tests` locks this with counterfactual assertions.
* `RestoreDatabaseBackupToDirectory` writes only inside the requested directory and is the only
  Stage 3 command that produces an `OperationLog` row.
* All three commands are additive: no existing ordinal moved and no existing contract changed.
  `IpcCommandStabilityTests` locks ordinals 88-90 and the enum length.
* All three get the long round-trip deadline (`IpcConstants.TimeoutMsFor`), because a bounded tree
  walk, an integrity check on a large store and a multi-gigabyte copy all routinely exceed the short
  default. No existing command's timeout changed.

### SaveShardingPolicy (ordinal 91)

Request payload `ShardingPolicyMutationRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | Enabled: bool | Whether per-IP shard writing is enabled. |
| 1 | ActionsRoot: string | Absolute actions root, or empty for the ProgramData default. |
| 2 | ShardCapacityRecords: int | Ring capacity per shard, in records. |
| 3 | MaxOpenWriters: int | Maximum cached open shard writers. |
| 4 | MaxShardFiles: int | File-creation budget; `0` refuses every new file. |
| 5 | MaxShardBytes: long | Per-shard byte ceiling; `0` disables it. |
| 6 | MaxTotalShardBytes: long | Whole-tree byte budget for `actions\`; `0` disables it. |
| 7 | MinFreeDiskBytes: long | Free-space floor of the shard volume; `0` disables it. |
| 8 | OrphanGraceDays: int | Orphan-collection grace period in days. |
| 9 | SubnetAggregation: object | `{ Enabled, TotalFileThreshold, NewFilesPerIntervalLimit, IntervalSeconds, MinSourceRowsPerInterval }`. |

Returns `ShardingPolicyDto`: `{ Status, QueriedUtc, Policy, Bounds, SettingsPath, HotReloaded, Message? }`,
where `ShardingPolicyValuesDto` carries every field both as configured and as clamped-effective plus
the two derived values a client needs to explain the byte ceiling -
`EffectiveRingCapacityRecords` (what a NEW shard is allocated with) and `EffectiveShardFileBytes`
(`128 + capacity * 128`).

The **whole request is validated and clamped before anything is written**:

* a negative value or an unusable `ActionsRoot` (relative, or a drive root) is refused with an
  `IpcException`, and **nothing** is written - not the settings file, not an `OperationLog` row;
* a value above a supported maximum is clamped through the option's own `Resolve*` helper, and the
  clamped value is what gets written and what the response reports back.

On success the `Sharding` section is merged into `appsettings.json` through `SettingsManager`
(atomic replace, secret handling, schema validation), every other section is carried over verbatim,
and `IOptionsMonitor` re-reads the file through its change token - so the new policy is in force
without a service restart. One `OperationLog` row is written with `Source=Sharding`,
`Operation=SaveShardingPolicy`, the invoking identity in `Actor`, and the old and new policy in the
message. A save that changes nothing is still audited and says so. The command governs shard writing
only: it never moves, rewrites or deletes a shard file.

### CollectShardGarbage (ordinal 92)

Request payload `CollectShardGarbageRequest`:

| Key | Field | Meaning |
|---|---|---|
| 0 | DryRun: bool | `true` returns the candidate list and deletes nothing. |

**An omitted payload is a dry run.** `true` is the default in the contract, and the dispatcher builds
that default when no payload is supplied, so a malformed or absent request can never delete a file.
The command gets the long round-trip deadline (`IpcConstants.TimeoutMsFor`).

Returns `ShardGarbageCollectionReportDto`:
`{ Status, QueriedUtc, DryRun, ActionsRoot, OrphanGraceDays, Candidates[], DeletedPaths[],
DeletedFileCount, DeletedBytes, DeletedRecords, DeletionBudgetReached, CandidateListTruncated,
Warnings[], Message? }`, each `ShardGarbageCandidateDto` carrying
`{ RelativePath, AbsolutePath, IpText, IsSubnetAggregate, Bytes, Records, Evicted, LastWriteUtc,
AgeDays, Disposition, Note? }`.

Only files that **no `IpEventSummary` row references** and that have not been written for at least
`OrphanGraceDays` are candidates. An apply pass re-validates each one immediately before deleting it -
unreferenced (re-read from `IpEventSummary` with the inventory's own path normalization), not open in
any live shard writer, still older than the grace period, and contained under the configured actions
root - and names the outcome in `Disposition` (`Eligible`, `ReferencedBySummary`, `OpenInWriter`,
`YoungerThanGracePeriod`, `OutsideActionsRoot`, `DeletionBudgetSpent`, `DeletionFailed`,
`VanishedBeforeDeletion`, `LastActivityUnknown`, `BecameReferenced`). A candidate whose last-write
time cannot be read is never eligible: nothing is deleted on a guess.

The pass is bounded by `MaxDeletionsPerRun = 200` files per call, so one command cannot mass-delete a
tree; when the budget is spent the remaining candidates are reported as `DeletionBudgetSpent` rather
than skipped silently. Every removed file produces its own `OperationLog` row
(`Source=Sharding`, `Operation=CollectShardGarbage`, the invoking identity in `Actor`, and the path,
bytes, retained records, last write and age in the message/details). If an audit row cannot be
written the report is downgraded to `IpcResultStatus.Unavailable` instead of claiming a clean pass.
The command writes nothing outside `actions\`.

`EventDeletionLedger` is deliberately not used: that ledger accounts for deleted event **rows** by
`EventCode`/`Scope`/time window, and a shard-file removal has neither an event code nor a per-row
window, so filling those fields would make the ledger state facts that are not true. See
`docs/86-shard-ingestion.md`.

### Stage 4 IPC semantics

* `GetShardInventory` (88) gained two additive fields - `Policy` and `CapacityStatus` - so the shard
  policy and the live refusal state are read through the existing read-only command instead of a new
  one. A field the host cannot know is null: `CapacityStatus` is null when the host has no shard sink,
  and `TotalShardBytes` is `-1` when the byte budget is disabled and the sink therefore never walks
  the tree.
* `SaveShardingPolicy` (91) is mutating and audits; `CollectShardGarbage` (92) is destructive, defaults
  to a dry run and audits per file.
* `GetShardInventory` and `SaveShardingPolicy` keep the short round-trip deadline (both answer from a
  bounded walk); only `CollectShardGarbage` gets the long one, because it may walk the tree, re-read
  orphan headers and delete up to its budget one file at a time with an audit row each.
* Both commands are additive: no ordinal at or below 90 moved and no existing contract changed.
  `IpcCommandStabilityTests` locks ordinals 91-92 and the enum length.

## Stage 5 storage-hardening commands (93–94)

Both are appended after the Stage 4 maximum (`CollectShardGarbage = 92`); no earlier ordinal moved.
`IpcCommandStabilityTests` locks ordinals 93–94 and the enum length, and
`IpcConstantsTimeoutTests` locks their round-trip deadlines.

| Command | Ordinal | Deadline | Mutating | Payload | Returns |
|---------|---------|----------|----------|---------|---------|
| `CompactDatabase` | 93 | short | no (refuses) | `DatabaseCompactionRequest` (optional) | `DatabaseCompactionDto` |
| `PurgeBySubject` | 94 | long | only with `Apply=true` and the phrase | `PurgeBySubjectRequest` | `PurgeBySubjectReportDto` |
| `GetMikroTikSecurityAudit` | 95 | long | no (read-only) | - | `MikroTikSecurityAuditDto` |

### `CompactDatabase` (93) — the refusal is the contract

A full `VACUUM` rewrites the whole database file inside one write transaction: on a multi-gigabyte
evidence store it can hold the single SQLite writer for minutes and stall ingestion, which the
no-freeze rule forbids (`docs/88-database-backup-and-restore.md`). A service that answers an IPC
call is by definition running, so the online path can never be the process that performs the rewrite.
This command therefore always answers `IpcResultStatus.Refused`, and that is a documented contract
rather than a stub:

* `Message` explains the refusal and names the offline procedure below it.
* `Procedure` lists the exact offline steps, one per entry, for display verbatim.
* `ServiceRunning` and `Refused` are both true; `PolicyNote` states what the online path does instead
  (WAL checkpoint plus a bounded `incremental_vacuum`) and points at the policy document.
* The store's read-only page accounting is still reported - `PageSize`, `PageCount`, `FreeListPages`
  and `ReclaimableBytes` (`page_size × freelist_count`) - so the operator can judge whether an offline
  compaction is worth stopping the service for. It is a lower bound, not a promise.
* `AutoVacuumMode` (key 15) carries the store's `PRAGMA auto_vacuum` value: `2` INCREMENTAL, `0` NONE,
  `1` FULL, `-1` unreadable. It decides whether an offline pass is merely worth stopping the service for
  or the only way this store will ever release free pages - in any mode but INCREMENTAL the bounded
  online `incremental_vacuum` is a documented no-op (B27), and the Configurator's compaction also
  rewrites the store into INCREMENTAL mode.
* The refusal is audited as an `OperationLog` row with `Severity=Warning`, `Source=Database`,
  `Operation=CompactDatabase` and the invoking identity in `Actor`: an operator asked for a destructive
  operation, and the answer belongs in the trail next to the actions that ran.

The compaction itself is the Configurator's `DatabaseCompactService`: stop the service, checkpoint the
WAL, `VACUUM INTO` a copy, verify it (`quick_check`, per-table row counts, the migration history and
`foreign_key_check`), then swap it in atomically through the same `LiveDatabaseSwap` mechanics the
restore path uses. The pre-compaction file is kept as a timestamped `.bak` plus a `.compact.json`
receipt. Before the verification, the copy's auto-vacuum mode is normalised to INCREMENTAL - `VACUUM
INTO` carries the source's mode over, so a legacy store would otherwise be compacted back into the mode
whose online reclamation is a no-op. That costs one further `VACUUM` over the already compacted copy
(measured: 0.66 s on a 57 MB store) and needs twice the copy's size free on the volume, refusing below
that with both numbers in the message. The report and the receipt name the mode before and after
(`docs/88-database-backup-and-restore.md`).

### `PurgeBySubject` (94) — dry run first, ledger always

Deletes every evidence row about one subject: a single IP, a CIDR range, a login, or a UTC window.

* **An omitted payload is an invalid request**, never a full wipe. `Apply=false` (the default) is a
  pure dry run returning per-table matched counts; the preview and the apply pass compose their
  `WHERE` clause with the same code, so the dry run is a prediction rather than an estimate.
* **`Apply=true` requires the exact typed phrase** (`PURGE SUBJECT DATA`), re-validated on the server,
  and is **refused outright while `Storage:RetentionPolicy:LegalHold` is true**. Both refusals still
  report the counts, so the operator sees the size of what is protected.
* **Every table that loses rows gains an `EventDeletionLedger` entry**, appended inside the transaction
  of the batch that finished that table, through the same hash-chain writer the retention engine uses
  (`docs/41-data-model.md`). `Trigger=OperatorRequest`, `RuleVersion` is the current rule-set version,
  `Reason` names the table, the subject kind, the subject and the actor, and `WindowStartUtc`/
  `WindowEndUtc` are the observed timestamps of the rows actually deleted.
* **Deletes are bounded** to `ResolveDeleteBatchRows()` per transaction, one transaction per batch, with
  a whole-run ceiling of `MaxTotalRowsPerRun = 5_000_000`. A run that hits the ceiling stops cleanly and
  says so.
* **Deliberately untouched, and reported as such in `Preserved`**: the schema and
  `__EFMigrationsHistory`, `DbProps`, `Bookmarks`, `OperationLogs`, `DatabaseIntegrityCheckResult`, the
  append-only ledger itself, and the operator's own configuration and enforcement state
  (`BlocklistEntries`, `WhitelistEntries`, `LoginRules`, `ActiveBlocks`). Removing an operator's
  blocklist entry as a side effect of a subject purge would silently change enforcement, which is a
  different act than removing evidence.
* **CIDR scope** is resolved against the binary key of `IpEventSummary`/`IpEventTypeCounter` and the
  text IPs already known to the store (capped at `MaxCidrAddressExpansion = 4096`); a range covering
  more known addresses than that is refused rather than half-purged, because a partial CIDR purge is
  indistinguishable from a complete one in the report.
* **Login scope is case-insensitive** (`COLLATE NOCASE`), because Windows logins are: matching
  case-sensitively would leave rows behind that the operator believes they purged.
* An applied pass writes one `OperationLog` row (`Source=Database`, `Operation=PurgeBySubject`) with the
  invoking identity, the subject, the window, the per-table counts, the ledger entry count and the
  resulting chain head.

The Configurator's Database ▸ Danger Zone ▸ `Purge by subject…` opens a dialog that enforces the
sequence in the UI as well: the Purge button stays disabled until a preview has succeeded *and* the
exact phrase has been typed.
### `GetMikroTikSecurityAudit` (95) — the audit reads and never writes

Runs the RouterOS v7 security catalogue (rules `S-00` … `S-35` plus `S-27b`) against the router the
`MikroTik` options point at and returns the finished report: pasport, risk index `0..100` (critical 40,
high 15, medium 5, low 1, info 0, capped at 100), verdict, per-severity counts, one row per finding
with `menu :: value` evidence, the reason, the recommendation and ready RouterOS commands, the menus
the device does not have, and the Markdown rendering.

* **Read-only by construction.** The path issues `GET` calls only: no rule, no address-list entry and
  no setting is written, and there is no `apply` variant of this command.
* **Coverage is stated, not implied.** `system/resource` is read first as the probe; if it fails the
  reply is `IpcResultStatus.Unavailable` with the transport reason and **no findings**, so an empty
  report can never be mistaken for a clean device. A menu that exists but cannot be read becomes an
  `S-00` finding; a menu the device does not have (package absent) is reported in `unavailableMenus`
  and is not a finding.
* **No credentials leave the router.** The SNMP community string, the `/system/note` text and every
  script secret are redacted before the report is built: the finding names the object and the kind of
  secret, never the value.
* **Bounded.** The menu walk has a 45-second budget; menus it did not reach are reported as unread
  (`S-00`), which is how the report stays honest about its own coverage. The command timeout is
  `LongOperationTimeoutMs` (60 s) for the same reason.

## Zabbix integration (ordinals 96-101)

The integration pushes RDP incidents to a Zabbix server over the native sender protocol (TCP 10051,
item type "Zabbix trapper") and uses the JSON-RPC API only for provisioning and the connection test.
Both call shapes were verified against a live Zabbix 8.0.0 on 2026-10-25.

| Ordinal | Command | Deadline | What it does |
|---|---|---|---|
| 96 | `GetZabbixSettings` | short | Returns the settings with both credentials masked. |
| 97 | `SaveZabbixSettings` | short | Clamps the payload and merges only `RdpAudit.Zabbix` into the live settings document. An unchanged credential arrives as the mask placeholder and the stored envelope is written back verbatim; a blank value clears it. |
| 98 | `TestZabbixConnection` | long | Probes the trapper port and the API separately and reports which of them answered. |
| 99 | `PushZabbixNow` | long | Runs one push cycle immediately and returns the server's own accounting of it. |
| 100 | `ProvisionZabbix` | long | Ensures the host group, the host, its items, its triggers and the dashboard exist. Idempotent, additive, never deletes. |
| 101 | `GetZabbixStatus` | short | Reads the push position and counters. Touches no network. |

* **A success envelope is not a delivery.** The server answers
  `{"response":"success","info":"processed: 0; failed: 1; total: 1; ..."}` when it rejected every
  value. The position advances only when `failed == 0` and `total > 0`; anything else is recorded as
  a failure and retried on the next cycle.
* **A fresh host is not immediately known to the trapper.** Measured: the first push after
  `ProvisionZabbix` fails for about ten seconds while Zabbix syncs its configuration cache, and the
  answer still says `success`. The operator sees "0 of 7 accepted" and the next cycle succeeds.
* **No credential crosses IPC or a log.** Both the API token and the password are stored as DPAPI
  envelopes through `SettingsManager`, which is why the tab only ever reads back `***configured***`.
* **Bounded backlog.** Incidents above `MaxBacklogIncidents` are skipped from the tail and the skip
  count is reported in the payload (`skipped`), in the status and in the log. Zabbix is a notification
  channel; the local database remains the evidence store.

## Editions (ordinal 102)

| Ordinal | Command | Deadline | What it does |
|---|---|---|---|
| 102 | `GetEditionInfo` | short | Reports the edition, ordinal, product version, licence, cross-host host budget and one row per capability with the lowest edition that contains it and whether this build has it. |

* **The answer is a property of the binary, not of configuration.** It is derived from the
  `RDPAUDIT_EDITION_*` compilation constant, so a Community service reports `RestApi`,
  `CrossHostCorrelation`, `ZabbixIntegration`, `SiemExport` and `ResponseDryRun` as unavailable
  regardless of what `appsettings.json` asks for.
* **No dependency is touched.** The handler reads compile-time constants only, so it still answers
  when the database, the firewall provider and the network are all degraded — which is exactly when
  an operator needs to know which package is installed.
* **A missing capability is not a missing command.** The command exists in every edition so the
  Configurator of any edition can talk to any service; the payload, not the ABI, carries the
  difference.
