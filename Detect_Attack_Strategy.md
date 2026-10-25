# RdpAudit Attack Detection Strategy

This document describes the unified data-collection, normalization, correlation, and enrichment strategy for detecting RDP attacks and reconstructing RDP activity on a Windows host. The goal is to make every UI surface and alert rule work from the same reliable telemetry model instead of treating raw Windows events as independent facts.

The strategy combines direct Windows Security log evidence, Terminal Services operational events, active WTS session state, TCP connection snapshots, and persisted historical facts. Each data point must carry its origin and confidence so the product can explain why a field is populated, why it is missing, and what the administrator should fix when Windows does not emit the required audit events.

## Objectives

- **Detect brute-force attacks**: capture failed RDP logon attempts with source IP, attempted username, timestamp, failure reason, and logon type.
- **Track successful logons**: capture successful RDP logons with source IP, username, session ID, logon ID, authentication package, and process details where Windows provides them.
- **Reconstruct sessions**: connect successful logon events, Terminal Services session events, WTS active state, and process activity into a coherent session timeline.
- **Enrich weak events**: attach IP, username, session ID, and outcome to RDP events that do not carry all fields directly.
- **Keep diagnostics actionable**: if Windows emits RDP transport events but not Security logon events, show a clear health warning instead of blank IP/user fields.
- **Stay lightweight**: avoid full log scans, use bounded lookback windows, batch persistence, and indexed queries.

## Data Sources

### Windows Security Log

The Security log is the primary source for authentication outcome and attempted credentials. RdpAudit must collect these events continuously and also run a bounded backfill path to recover from missed watcher callbacks, service downtime, bookmark issues, or log rotation.

| Event ID | Meaning | Primary Use |
|---:|---|---|
| 4625 | Failed logon | Failed RDP attempt, brute-force counter, attempted username, source IP, failure status/substatus |
| 4624 | Successful logon | Successful RDP login, success counter, user/session/logon correlation |
| 4648 | Explicit credentials | Explicit credential usage, useful success/credential correlation and fallback evidence |
| 4634 | Logoff | Session closure and logon ID correlation |
| 4778 | RDP session reconnect | Reconnect timeline and client/source correlation |
| 4779 | RDP session disconnect | Disconnect timeline and active session status |

For Security events, named XML fields must be the primary parser. Positional `EventRecord.Properties` indexes may be used only as a compatibility fallback when named fields are missing or when Windows returns a legacy template.

Required named fields include:

| Field | Purpose |
|---|---|
| TargetUserName | Attempted or authenticated username |
| SubjectUserName | Actor username for explicit credential and process-related events |
| IpAddress | Source IP when Windows records it |
| WorkstationName | Client workstation name or fallback correlation key |
| LogonType | Distinguishes remote interactive RDP from other logon types |
| LogonProcessName | Authentication process context |
| AuthenticationPackageName | NTLM/Kerberos/package context |
| ProcessName | Process involved in logon or explicit credentials |
| Status | Failure reason code |
| SubStatus | More specific failure reason |
| TargetLogonId | Correlation key between logon, logoff, and session activity |

Compatibility fallback rules:

| Event ID | Field | Fallback Index | Notes |
|---:|---|---:|---|
| 4625 | Username | 5 | Use only if named username fields are empty |
| 4625 | Source IP | 19 | Use only if named `IpAddress` is empty |
| 4648 | Username | 5 | Use only if named username fields are empty |
| 4648 | Source IP | 12 | Use only if named network address fields are empty |

### Terminal Services LocalSessionManager

The LocalSessionManager operational channel provides session lifecycle events and often includes the session address that is not present in weak transport events.

| Event ID | Meaning | Primary Use |
|---:|---|---|
| 21 | Session logon | Session ID, user, address, successful session start |
| 22 | Shell start | Confirms interactive session readiness |
| 23 | Session logoff | Historical session closure |
| 24 | Session disconnected | Disconnected state |
| 25 | Session reconnected | Reconnect timeline |
| 39 | Session disconnected by reason | State enrichment |
| 40 | Session disconnected/reconnected reason | State enrichment |

Event 21 is especially important because it can contain:

| XML Field | Purpose |
|---|---|
| SessionID | WTS session identifier |
| User | Username attached to the session |
| Address | Client IP address |

When a session logon is observed, RdpAudit should query the LocalSessionManager channel for a short bounded window around the event time and match by `SessionID`. This enriches the session table and gives RDP Clients a reliable IP even when the active WTS API does not expose it.

### Terminal Services RemoteConnectionManager

RemoteConnectionManager events are useful for pre-authentication and connection-level visibility, but they are not sufficient alone for brute-force attribution.

| Event ID | Meaning | Primary Use |
|---:|---|---|
| 1149 | User authentication succeeded | Pre-session user/IP evidence when available |
| 261 | Listener or transport-related RDP event | Weak signal that may need correlation |

Event 1149 should be normalized for username, domain, client address, and timestamp. Event 261 should be stored as a raw/weak signal and correlated with stronger events rather than treated as a complete attack record.

### RdpCoreTS Operational Log

RdpCoreTS events provide transport and protocol state. They are useful for timing and health, but many records do not carry attempted username or source IP.

| Event ID | Meaning | Primary Use |
|---:|---|---|
| 131 | RDP transport/protocol event | Weak signal, timing marker, diagnostic trigger |
| 140 | RDP listener or protocol state | Listener health and port/state context |

If events 131 or 261 are present but no Security 4625/4624/4648 events appear in the same window, RdpAudit must show a diagnostic explaining that authentication audit events are missing or unreadable.

### WTS Active Session State

WTS APIs provide the current server-side session list and are required for the RDP Clients tab to work even when the service IPC path is temporarily unavailable.

RdpAudit should collect:

| WTS Field | Purpose |
|---|---|
| Session ID | Stable runtime session key |
| Username | Current logged-on user |
| Domain | Account domain where available |
| State | Active, disconnected, listen, idle, reset, down |
| LogonTime | Session start correlation |
| DisconnectTime | Disconnected duration |
| LastInputTime | Activity signal |
| ClientAddress | Best-effort active client IP if available |
| ClientName | Fallback correlation key |
| Display | Optional UI metadata |

WTS state is a snapshot, not an audit log. It should update current session status and fill missing fields, but historical facts must remain based on persisted events.

### TCP Connection Snapshot

The RDP listener port is configurable and must be read from:

`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`

If the registry value is missing, use 3389 only as a fallback. All collectors and firewall rules must use the resolved RDP port.

TCP snapshots can provide current remote endpoints for active RDP transport connections. They should be used as a low-confidence enrichment source when Security or Terminal Services events do not contain an IP.

Required fields:

| Field | Purpose |
|---|---|
| LocalAddress | Bound listener address |
| LocalPort | Actual RDP port |
| RemoteAddress | Candidate client IP |
| RemotePort | Client source port |
| State | Established, TimeWait, etc. |
| OwningProcess | Process-level diagnostic |

TCP snapshots must not be used to invent usernames. They can only enrich IP/time context.

## Unified Event Model

Every collected event should be normalized into one internal shape before persistence and UI projection.

| Property | Description |
|---|---|
| TimeUtc | UTC timestamp |
| Channel | Windows event channel |
| Provider | Windows provider name |
| EventId | Windows Event ID |
| RecordId | Event record ID where available |
| SourceIp | Source IP, if directly known or enriched |
| SourcePort | Source port, if known |
| UserName | Attempted or authenticated user |
| Domain | Account domain |
| WorkstationName | Client workstation name |
| LogonType | Windows logon type |
| LogonId | Logon correlation key |
| SessionId | WTS/Terminal Services session ID |
| ProcessName | Related process |
| AuthPackage | Authentication package |
| Status | Failure status |
| SubStatus | Failure substatus |
| Outcome | Failed, Successful, Informational, Unknown |
| EventRole | Authentication, Session, Transport, Process, Firewall, Diagnostic |
| EnrichmentSource | DirectXml, SecurityFallbackIndex, Lsm21, WtsSnapshot, TcpSnapshot, Correlation, None |
| EnrichmentConfidence | High, Medium, Low, None |
| DetailsJson | Capped structured event details |

Normalization must be deterministic and testable. Raw XML should be captured before `EventRecord` disposal, capped before persistence, and parsed with XXE-safe XML settings.

## Collection Pipeline

### Watcher Path

The watcher path handles near-real-time updates:

1. Start `EventLogWatcher` per enabled channel with an Event ID XPath filter.
2. In the callback, synchronously copy `EventId`, `Channel`, `Provider`, `TimeCreated`, `RecordId`, and `ToXml()`.
3. Push the raw event into a bounded channel.
4. Never block the Windows Event Log callback on database writes.
5. Restart watchers with exponential backoff on errors.

### Backfill Path

The backfill path guarantees that important authentication records are not missed:

1. Keep a per-channel durable cursor using record ID, timestamp, or bookmark where available.
2. On service start, read a bounded lookback window for critical events.
3. Periodically read only critical channels and event IDs since the last cursor.
4. Deduplicate by channel, record ID, event ID, and timestamp.
5. Never scan the entire Security log during normal operation.

Critical backfill targets:

| Channel | Event IDs |
|---|---|
| Security | 4625, 4624, 4648, 4634, 4778, 4779 |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 21, 22, 23, 24, 25, 39, 40 |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | 1149, 261 |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational | 131, 140 |

### Snapshot Path

The snapshot path provides current state:

1. Read WTS sessions on interval and on UI request.
2. Read TCP established connections for the resolved RDP port.
3. Merge snapshots into current-state tables, not raw audit history.
4. Use snapshots for low-confidence enrichment only when stronger sources are absent.

## Correlation Strategy

Correlation must enrich weak records without fabricating facts.

### Correlation Keys

Use keys in this priority order:

| Priority | Key | Confidence |
|---:|---|---|
| 1 | LogonId | High |
| 2 | SessionId | High |
| 3 | SourceIp + UserName + tight time window | High |
| 4 | SourceIp + tight time window | Medium |
| 5 | UserName + WorkstationName + tight time window | Medium |
| 6 | TCP remote IP + RDP event time window | Low |

### Time Windows

Recommended defaults:

| Event Relationship | Window |
|---|---:|
| 131/261 to 4625 | ±30 seconds |
| 131/261 to 1149 | ±30 seconds |
| 1149 to 21 | 0 to +90 seconds |
| 4624 to 21 | 0 to +120 seconds |
| WTS session snapshot to 21 | ±120 seconds |
| TCP snapshot to transport event | ±10 seconds |

The windows should be configurable only if operational data proves a need. Wider windows increase false correlation risk.

### Enrichment Rules

- **Direct evidence wins**: fields extracted from the same event XML override correlated fields.
- **Security authentication evidence beats transport evidence**: 4625/4624/4648 should define authentication outcome.
- **Session event address beats TCP snapshot**: LocalSessionManager 21 `Address` is stronger than a generic TCP connection.
- **WTS username can enrich session state**: use WTS username for active sessions, but do not use it to label a failed login attempt unless correlated by session/logon evidence.
- **TCP snapshot can enrich IP only**: never use TCP state to infer username or success/failure.
- **Weak events stay visible**: keep 131/261 in Live Events, but mark missing IP/user with diagnostics when not enrichable.

## Persisted Facts

Raw events are not enough for UI and alerting. RdpAudit should maintain fact tables that are safe to update incrementally.

### IP Facts

One row per source IP:

| Field | Purpose |
|---|---|
| SourceIp | IP address |
| FirstSeenUtc | First known event |
| LastSeenUtc | Last known event |
| FailedLogons | Count from 4625 and correlated failed records |
| SuccessfulLogons | Count from 4624/4648/session success evidence |
| AttemptedUserNames | Distinct attempted usernames, capped in display |
| LastFailureStatus | Last failure status/substatus |
| IsBlocked | Windows firewall/blocklist state |
| IsWhitelisted | Whitelist state |
| LastEnrichmentSource | Most recent source used |
| LastConfidence | Most recent confidence |

### User/IP Facts

One row per source IP and username:

| Field | Purpose |
|---|---|
| SourceIp | IP address |
| UserName | Attempted or authenticated username |
| FailedCount | Failed attempts for this pair |
| SuccessCount | Successful logons for this pair |
| FirstSeenUtc | First pair occurrence |
| LastSeenUtc | Last pair occurrence |
| LastStatus | Last failure reason |

### Session Facts

One row per RDP session identity:

| Field | Purpose |
|---|---|
| SessionKey | Stable key derived from WTS session ID and logon time where possible |
| WtsSessionId | Runtime WTS session ID |
| UserName | Session user |
| SourceIp | Client IP |
| State | Active, disconnected, ended |
| StartedUtc | Session start |
| EndedUtc | Session end |
| LastSeenUtc | Last refresh or event |
| LogonId | Security logon correlation key |
| ClientName | Client workstation |
| EnrichmentSource | Source of IP/user |
| EnrichmentConfidence | Confidence level |

### Diagnostic Facts

Diagnostics must be first-class data:

| Diagnostic | Trigger |
|---|---|
| SecurityLogMissing | RDP 131/261 exists but no 4625/4624/4648 in window |
| AuditPolicyMissing | Audit logon success/failure disabled |
| SecurityReadDenied | Service cannot read Security channel |
| BookmarkStale | Stored cursor points beyond retained events or cannot resume |
| ChannelDisabled | Required operational channel disabled |
| ParserFallbackUsed | Named XML parse failed and positional fallback was used |
| CorrelationLowConfidence | UI field filled from low-confidence source |

## Attack Classification

### Brute Force

An IP is suspicious when it produces repeated failed logons within a time window.

Signals:

- Multiple Security 4625 events from the same IP.
- Multiple usernames from the same IP.
- Failure statuses indicating bad username or bad password.
- RDP transport events near failures.
- No successful logon from the same IP in the same period.

Default classification:

| Condition | Classification |
|---|---|
| FailedLogons >= threshold and IP not whitelisted | Attack |
| FailedLogons > 0 and below threshold | Suspicious |
| SuccessfulLogons > 0 and FailedLogons below high threshold | Legitimate or mixed |
| Only weak transport events and no Security data | Unknown with diagnostic |

### Password Spray

An IP is suspicious when it attempts many usernames with low per-user frequency.

Signals:

- High distinct username count.
- Low attempts per username.
- Similar time spacing.
- Mostly 4625 outcomes.

### Targeted Account Attack

An IP is suspicious when it repeatedly targets one account.

Signals:

- High failed count for one `SourceIp + UserName`.
- Repeated status/substatus pattern.
- Optional eventual success after repeated failure.

### Successful Compromise Indicator

A successful logon is high risk when it follows repeated failures from the same IP or username.

Signals:

- 4624/4648/1149/21 success after failed attempts from same IP.
- Same username targeted during failures.
- Session starts from same IP shortly after final failure.

## UI Projection Rules

### Live Events

Live Events should show raw event timing plus normalized/enriched fields:

- Event ID and channel.
- Outcome.
- UserName.
- SourceIp.
- LogonType.
- ProcessName.
- SessionId.
- EnrichmentSource and confidence.
- Diagnostic message when key fields are missing.

If an event cannot be enriched, the row must not silently show empty cells. It should show `Unknown` plus the reason, for example: `Security logon audit event not found in correlation window`.

### Attack Statistics

Attack Statistics must be built from IP facts and User/IP facts, not by recounting visible UI rows.

Required columns:

- Source IP.
- Failed logons.
- Successful logons.
- Active failed count in current window.
- First seen.
- Last seen.
- Duration.
- Attempted usernames.
- Last status/substatus.
- Blocked/whitelisted state.
- Enrichment confidence.

### Remote RDP Clients

Remote RDP Clients must combine:

- Current WTS sessions.
- Persisted session facts.
- LocalSessionManager 21 addresses.
- Security success events.
- TCP snapshot only as fallback.

It must work when service IPC is unavailable by using a local WTS/qwinsta-compatible fallback in the Configurator, but persisted service facts should provide richer history when available.

### Overview

Overview cards must read from facts:

- Attacks today.
- Blocked IPs.
- Active sessions.
- Failed logins.
- Service health.
- Database size and growth.

## Health Checks

RdpAudit should continuously verify that the telemetry pipeline is usable.

Required checks:

| Check | Expected Result |
|---|---|
| Security channel readable | Service can query Security event IDs |
| Audit logon success enabled | 4624 can be emitted |
| Audit logon failure enabled | 4625 can be emitted |
| LocalSessionManager channel enabled | Event 21 can be read |
| RemoteConnectionManager channel enabled | 1149/261 can be read |
| RdpCoreTS channel enabled | 131/140 can be read |
| RDP port resolved | Registry port or fallback is known |
| WTS query works | Current sessions can be listed |
| Bookmark/backfill healthy | Cursor advances and no stale bookmark errors |

When a check fails, show:

- What failed.
- Why it matters.
- The likely Windows setting or permission.
- The exact action button or PowerShell command to fix it.

## Performance Rules

- Use `EventLogWatcher` for real-time capture.
- Use bounded backfill for critical event IDs only.
- Deduplicate persisted events.
- Batch database writes.
- Keep correlation buffer bounded by time and count.
- Store only capped XML/details.
- Index fact tables by `SourceIp`, `UserName`, `SessionId`, `LogonId`, `EventId`, and `TimeUtc`.
- Never query the full Security log during UI refresh.
- Never run expensive PowerShell commands on the UI thread.

## Failure Modes and Expected Behavior

### Only Events 131 and 261 Appear

Expected behavior:

- Store the events as weak transport signals.
- Attempt bounded correlation against Security, RemoteConnectionManager, LocalSessionManager, WTS, and TCP snapshots.
- If no stronger event exists, show SourceIp/UserName as `Unknown`.
- Add a diagnostic that Security logon events are missing or unreadable.
- Do not increment failed or successful login counters from 131/261 alone.

### Security 4625 Exists Without IP

Expected behavior:

- Store username and failure details.
- Try workstation/client correlation.
- Try TCP snapshot only for low-confidence IP enrichment.
- Mark enrichment confidence as Low if TCP is used.

### Session Exists Without Address

Expected behavior:

- Query LocalSessionManager 21 by SessionID and time window.
- Query WTS active state.
- Try matching Security 4624/1149 by user/time.
- Leave IP unknown with diagnostic if no reliable source exists.

### Service Was Down

Expected behavior:

- On restart, run bounded backfill for Security and Terminal Services channels.
- Rebuild facts from newly found events.
- Refresh active WTS sessions and merge with persisted history.

## Acceptance Criteria

- Failed RDP logins with wrong password or nonexistent username appear in Live Events with attempted username and source IP when Security 4625 is emitted.
- Failed counts increment only from failed authentication evidence.
- Successful counts increment only from successful authentication/session evidence.
- Events 131 and 261 remain visible but do not create false failed/success counters by themselves.
- Attack Statistics shows brute-force IPs even if the UI Live Events tab was not open during the attack.
- Remote RDP Clients shows active sessions from WTS and enriches them with persisted IP/session facts.
- Missing audit policy, Security read permission, disabled channels, and stale bookmarks are visible as actionable diagnostics.
- The pipeline remains low-overhead on busy RDP servers.
