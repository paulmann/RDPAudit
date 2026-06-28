# RdpAudit.Configurator

WinForms front-end for setup, monitoring, and configuration.

## Tabs

| Tab | Implementation | Purpose |
|-----|----------------|---------|
| Overview | `Forms/OverviewPage.cs` + `Services/OverviewProbe` + `Services/InstallationService` | First-run "home" tab. Shows product info, version, project/author links, and an aggregate snapshot of ProgramData/DB/service state, surfaces detected errors/warnings, and exposes a single "Install / Repair" button that creates the ProgramData layout (with admin/SYSTEM ACLs), copies the sibling Service distribution into Program Files, and registers/starts the Windows service. |
| Prerequisites | `Forms/PrerequisitesPage.cs` + `Services/PrerequisiteChecker.cs` | Runs the 15 prerequisite probes (OS, .NET, PowerShell, TermService, RDP port, firewall rule, four event channels, privilege, ProgramData write probe, DB existence, audit policy, RunAsPPL). |
| Audit Policy | `Forms/AuditPolicyPage.cs` + `Core.Events.AuditPolicyManager` | Lists the canonical `auditpol` rows; offers elevated buttons for "Apply audit policy" and "Configure SACL". Below the buttons a read-only help block explains each action, defines SACL, and documents the `S=Y/N F=Y/N` column shorthand. Current state is read via the locale-stable `AuditQuerySystemPolicy` advapi32 API with `auditpol /r` CSV as a fallback. |
| Service | `Forms/ServicePage.cs` | sc.exe lifecycle controls + 5-second IPC status refresh + recent-alerts grid with severity coloring. A dedicated "Process:" row shows the running service's PID, executable path, and start time (or `Not running` / `Not installed`), refreshed every 5 s. Start / Stop / Restart / Uninstall / Install each surface a `ServiceOperationResult` dialog containing the action name, per-step OK/FAIL, final service state, PID, executable, and a UTC timestamp. A read-only panel shows install destination, configured database path, and the sibling-distribution discovery result (Configurator → parent → `Service`). The "Install service" button calls `Services/InstallationService` so it shares logic with the Overview tab. |
| Settings | `Forms/SettingsPage.cs` | Loads `RdpAuditOptions` via IPC (falls back to disk). Saves to `%ProgramData%\RdpAudit\appsettings.json`; the service hot-reloads via `IOptionsMonitor<T>`. |
| Live Events | `Forms/LiveEventsPage.cs` + `Core/Events/LiveEventFilter.cs` + `Core/Events/LiveEventRowFormatter.cs` | Live tail of the most recent `RawEvent` rows fetched over `IPC.GetRecentEvents` (currently 200 rows). A filter bar above the grid combines IP / user / event-id / channel / free-text / time-range filters with AND semantics and a 350 ms debounce on text input. A per-cell right-click context menu offers `Copy Event Details` (multiline + TSV), `Copy Cell Value`, `Filter by This Value`, `Block IP in Windows Firewall and Add to Blocklist`, `Add IP to Whitelist and Unblock`, and `Add Login to Blocklist and Block IP`. Every operator action is recorded in a status strip with a UTC timestamp and per-step success/failure detail. All mutations go through IPC handlers — the page never writes to SQLite directly. |
| Firewall | `Forms/FirewallPage.cs` + `Core/Util/AddressListFilter.cs` | Stage 5 of the roadmap. Surfaces provider status / availability (Windows / None for Stage 5; MikroTik and Both are reserved for Stage 6 and shown disabled), the auto-block policy knobs from `FirewallOptions` (auto-block toggle, threshold, default block duration as days/hours/minutes, blacklisted-login auto-block, private-address refusal), and four inner tabs (Blocklist, Whitelist, Login trip-wires, Active blocks) each with a search/filter box, validated Add / Remove buttons, and a 5-second refresh timer. Whitelisting offers a follow-up prompt to remove an installed Windows Firewall rule via `UnblockAddress`. Removing a whitelist entry never installs a new block. Login trip-wires are explicitly separate from blocklist IPs and the UI makes clear they do **not** disable local Windows accounts. Active blocks expose the full `ActiveBlocks` row shape (IP, provider, rule handle, created / expires UTC, status, reason, last error) and a confirmation-gated `Unblock selected` button that drives `UnblockActiveBlock`. Settings persistence reuses the existing `GetSettings` / `SaveSettings` IPC round-trip; the JSON document is fetched, the `Firewall` sub-tree is mutated in place, and the wrapped `{ "RdpAudit": ... }` envelope is sent back through `SaveSettings`. A status strip timestamps every action with `[HH:mm:ss Z]` and reports per-step OK / FAIL detail. |
| Attack Statistics | `Forms/AttackStatisticsPage.cs` + `Core/Util/AttackStatsFilter.cs` + `Core/Util/AttackStatsRecentRange.cs` + `Core/Models/AttackStatRowFormatter.cs` | Stage 6B of the roadmap. Renders one row per attacker IP fetched via `GetAttackStats` IPC (ordinal 18). Twelve grid columns (IP, Threat score / band, Total, Failed, Successful, First Seen, Last Seen, Duration, Top 10 Attempted Logins, Last LogonType, Blocked) with cameyo-style green / yellow / red row coloring driven directly by the Stage 6A `ThreatLevel` returned over the wire (no UI re-classification). A toolbar combines IP-search, min-threat score, only-blocked, recent-period preset (`Last hour` / `Last 24 hours` / `Last 7 days` / `Last 30 days` / `All time`), row-limit selector (100 / 250 / 500 / 1000 / 2000), an `Auto refresh (5s)` checkbox with a re-entry guard that drops overlapping ticks, a `Refresh` button, and a `Clear filters` button. A right-click context menu offers `Copy Row Details`, `Copy IP`, `Block IP…`, and `Whitelist IP…`; mutations are confirmation-gated and reuse the existing Stage 5 `AddToBlocklist` / `AddToWhitelist` IPC commands. A status strip timestamps every refresh and action with `[yyyy-MM-dd HH:mm:ss Z]`. The Configurator never writes to the `AttackStats` table directly — every read flows through `GetAttackStats`. Cross-tab "filter Live Events by this IP" is deferred (the existing Live Events page does not expose a public filter API). |
| AbuseIPDB | `Forms/AbuseIpDbPage.cs` + service-side `Workers/AbuseIpDbReportWorker.cs` + `AbuseIpDb/AbuseIpDbClient.cs` + `Core/AbuseIpDb/AbuseIpDbCommentBuilder.cs` + `Core/AbuseIpDb/AbuseIpDbReportDecision.cs` | Stage 8 of the roadmap. Read-only intro panel describing AbuseIPDB, privacy properties of the report payload, and the steps to obtain a key. Password-style API key input with a `Show key` toggle. `Report attacks to AbuseIPDB` checkbox enabled only after a key is configured. Buttons: `Save settings`, `Test key`, `Refresh status`. Status read-out: credential present / not configured, endpoint URL, hourly / daily counters, last report result, rate-limit state. A red warning line states that reports are sent to a third-party service and include source IP + attack metadata. The UI never displays the API key plaintext; `GetSettings` returns the masked literal `***configured***` for non-empty secret envelopes, and the page treats that placeholder as a do-not-overwrite sentinel. The service-side `SettingsManager` wraps incoming plaintext keys with `ISecretProtector` before persistence; on Windows the protector is DPAPI with `SecretScope.LocalMachine`. See `docs/48-abuseipdb.md`. |
| MikroTik | `Forms/MikroTikPage.cs` + service-side `Firewall/MikroTikClient.cs` + `Core/MikroTik/MikroTikUrlBuilder.cs` + `Firewall/MikroTikFirewallProvider.cs` | Stage 9 of the roadmap. Read-only intro panel with the RouterOS v7 REST setup checklist (enable `www-ssl`, restrict allowed-address, install TLS certificate, create least-privilege user/group). Input form: Host/IP, Port (0 = scheme default), Use HTTPS toggle, Validate TLS toggle, Username, Password (password-style input with `Show password` toggle), Filter chain (default `input`), Filter action (default `drop`), Comment prefix (default `RdpAudit`), Block duration (days/hours/minutes), `Add attacker IP block rules to MikroTik Firewall` checkbox, `Enable MikroTik integration` checkbox. Buttons: `Save settings`, `Test connection`, `Refresh status`. Status panel: configuration / credential / enabled / AddRules flags, resolved endpoint, provider status, active MikroTik block count, last probe result. The page never displays the plaintext password — `GetSettings` masks any non-empty secret envelope to the literal `***configured***` and the page treats it as a do-not-overwrite sentinel. The service-side `SettingsManager` wraps incoming plaintext passwords with `ISecretProtector` before persistence; on Windows the protector is DPAPI with `SecretScope.LocalMachine`. See `docs/49-mikrotik.md`. |
| Remote RDP Clients | `Forms/RemoteRdpClientsPage.cs` + `Services/ShadowLauncher.cs` + `Core/Util/QwinstaParser.cs` + `Core/Util/SessionCommandBuilder.cs` + `Core/Util/ShadowPolicyModel.cs` | Stage 7 of the roadmap. Lists current RDP sessions fetched via `ListRdpSessions` IPC (ordinal 19) — service-side runs `qwinsta.exe` and parses it with the pure `QwinstaParser`, then opportunistically correlates Source IP from `RawEvents` rows. A toolbar combines free-text search (user / client / IP / session name / id), a state filter (`All states` / `Active` / `Disconnected` / `Inactive (other)`), `Auto refresh (5s)` with a re-entry guard, a `Refresh` button and a `Clear filters` button. Rows are colour-coded — green for active, orange for disconnected, grey for inactive — and the first column shows ●/◐/○ glyphs so the state is visible at a glance. A right-click context menu offers `Disconnect session…`, `Log off (kill) session…`, `Shadow — view only…`, `Shadow — view + control…`, and `Shadow — view + control (NO CONSENT)…`. Every destructive / high-impact action is confirmation-gated with a modal that names the session, the user, and (for logoff) the irreversible nature of the change. A horizontal splitter at the bottom hosts the shadow-policy panel: a summary label of the current policy (raw value + canonical description + latest backup id), a grid of every tracked registry value, and four buttons — `Enable all permissions…` (sets HKLM `Shadow=2` after taking a backup), `Backup`, `Restore latest…` and `Refresh policy`. Session control IPCs (`DisconnectSession`/`LogoffSession`/`ShadowSession`, ordinals 20–22) flow through service-side handlers that enforce the `SessionControl` options gate and validate session ids. `ShadowSession` is approval-only — the actual `mstsc.exe /shadow:<id> [/control] [/noConsentPrompt]` spawn happens in the Configurator's interactive desktop via `ShadowLauncher`, and only after the service has approved the request against the live policy. Shadow policy management uses `GetShadowPolicyStatus`/`ApplyShadowPolicy`/`BackupShadowPolicy`/`RestoreShadowPolicy` (ordinals 23–26). Backups are serialised JSON snapshots stored alongside the existing `BackupLayout` snapshot directories so the unified restore workflow can recover the pre-change state. |

## Service distribution discovery

`Core.Util.ServiceLayout.Discover` resolves the published Service distribution relative to the running
Configurator's `AppContext.BaseDirectory`:

- Sibling rule: `…\publish\Configurator` → `…\publish\Service`
- Install destination: `%ProgramFiles%\RdpAudit\Service` (override with the `RDPAUDIT_INSTALL_DIR` env var)
- DB path: read from `RdpAudit.Storage.DatabasePath` in `appsettings.json`, falling back to
  `%ProgramData%\RdpAudit\rdpaudit.db`

The Overview and Service tabs both call `ServiceLayout.Discover` so the install workflow works on any
machine, regardless of where the user puts the publish output (`C:\1st_RdpMON\Service\publish\…`,
`D:\builds\…`, etc.).

## IPC client contract

`IpcClient.SendAsync<T>` enforces a hard 5-second total timeout and a 2-second connect timeout. On `OperationCanceledException`, `TimeoutException`, or `IOException` it returns `default(T)`. **It must never throw to the UI thread.**

## Threading rules

- Async event handlers (`Click`) are `async void`; everything else returns `Task`.
- Background callbacks always check `InvokeRequired` and marshal back to the UI thread before touching controls.

## LLM contract

- Never call SQLite write paths from the Configurator. Reads through `ReadOnlyDb.Open()` are fine; writes go through the IPC server.
- Any new tab must be added to `MainForm` constructor and follow the existing pattern (5-second refresh timer, `Invoke` dispatch).
- Elevated operations must launch a child process with `Verb = "runas"` and handle UAC cancel (`Win32Exception.NativeErrorCode == 1223`).

## Live Events page (Stage 4)

### Filter bar

The filter bar above the grid exposes six controls:

| Control | Semantics |
|---------|-----------|
| `IP` | Case-insensitive substring match against `SourceIp`. |
| `User / login` | Case-insensitive substring match against `UserName`. |
| `Event id` | Exact integer match against `EventId`. Non-numeric text is ignored. |
| `Channel` | Case-insensitive substring match against `Channel`. |
| `Text` | Case-insensitive substring match across `SourceIp`, `UserName`, `Channel`, `Domain`, `ProcessName`, `AuthPackage`, and the stringified `EventId`. |
| `Time range` | Drop-down: `All time`, `Last 5 minutes`, `Last 15 minutes`, `Last 60 minutes`, `Last 24 hours`. Bound is `DateTime.UtcNow - delta`, inclusive. |

Filters combine with AND semantics. Text inputs are debounced by 350 ms so a typing burst triggers a single refresh. The `Clear filters` button resets every control and re-applies. Filtering is currently performed client-side over the bounded recent-event window returned by the existing `GetRecentEvents` IPC (capped at 200 rows server-side). The predicate (`Core/Events/LiveEventFilter.cs`) is intentionally UI-agnostic so it can be reused once `GetRecentEvents` grows a server-side query.

### Context menu (per-cell)

Right-click on a grid cell opens a menu whose items target the row under the cursor (not the previously-selected row):

| Item | Enable condition | Effect |
|------|------------------|--------|
| `Copy Event Details` | A row exists under the cursor. | Copies both a labelled multiline block and a TSV row (header + data) to the clipboard, joined by a `--- TSV ---` separator. |
| `Copy Cell Value` | Clicked cell has a non-empty, non-placeholder value. | Copies the normalised cell text. Null / blank cells never copy. |
| `Filter by This Value` | Same as `Copy Cell Value`. | Pushes the cell value into the matching filter input (IP, User, Event id, Channel) or into the free-text filter for other columns and applies. |
| `Block IP in Windows Firewall and Add to Blocklist` | Row has a value that parses via `IPAddress.TryParse`. | Confirmation dialog → `AddToBlocklist` IPC + legacy `BlockAddress` IPC (which applies the live firewall rule). Per-step result is shown in the status strip. |
| `Add IP to Whitelist and Unblock` | Same as Block IP. | Confirmation dialog → `AddToWhitelist` IPC (server-side whitelist precedence soft-disables conflicting blocklist rows) + `UnblockAddress` IPC. |
| `Add Login to Blocklist and Block IP` | Row has a non-empty `UserName`. | Confirmation dialog → `AddToBlocklist` IPC with the login; if the row also has a valid IP, also `AddToBlocklist` + `BlockAddress` for the IP. |

### Status strip

A `StatusStrip` along the bottom of the page reports every action and refresh outcome:

```
[12:34:56Z] Copied event details (Id=1234) to clipboard.
[12:35:02Z] Block 203.0.113.5 (OK). blocklist=OK, firewall=OK. Detail: [AddToBlocklist: ok] [BlockAddress: ok]
[12:35:50Z] Whitelist 203.0.113.5 (OK). whitelist=OK, unblock=OK. Detail: [AddToWhitelist: ok] [UnblockAddress: ok]
```

All status updates are pre-stamped with the UTC HH:mm:ss when the action ran and are marshalled to the UI thread when invoked from a continuation.

### IPC commands consumed

- `GetRecentEvents` (2) — populates the grid.
- `AddToBlocklist` (14), `AddToWhitelist` (16) — Stage 3 mutation handlers.
- `BlockAddress` (7), `UnblockAddress` (8) — legacy address-state toggles that also drive the live `netsh advfirewall` rule via `FirewallManager`.

No new IPC ordinals are introduced in Stage 4.

## Required tests before modifying

- WinForms-specific unit tests are not feasible in CI. Document manual verification steps in the PR description.
- The Service-side IPC tests in `RdpAudit.Service.Tests` must continue to pass after any IPC contract change.

## Attack Statistics page (Stage 6B)

The Configurator **Attack Statistics** tab consumes the Stage 6A `GetAttackStats` IPC command
(ordinal `18`) only — every read flows through IPC, and the Configurator never opens the SQLite
file directly. The tab is registered on `MainForm` immediately after the Firewall tab.

### Grid columns

| Column | Source |
|--------|--------|
| `IP` | `AttackStatEntryDto.Ip` |
| `Threat` | `ThreatScore` (one decimal) followed by `ThreatLevel` band in parentheses. |
| `Total` | `TotalAttempts` |
| `Failed` | `Failed` |
| `Successful` | `Successful` |
| `First Seen (UTC)` | `FirstSeenUtc` formatted `yyyy-MM-dd HH:mm:ss` |
| `Last Seen (UTC)` | `LastSeenUtc` formatted `yyyy-MM-dd HH:mm:ss` |
| `Duration` | `DurationSeconds` formatted `[d ]hh:mm:ss` via `AttackStatRowFormatter.FormatDuration`. |
| `Top 10 Attempted Logins` | `Top10AttemptedLogins` JSON deserialised and joined with `, `. |
| `Last LogonType` | `LastLoginType` (blank when null). |
| `Blocked` | `IsBlocked` rendered `yes` / `no`. |

### Row coloring

The row background color is driven directly by the Stage 6A `ThreatLevel` value returned over the
wire — the UI does NOT re-classify the numeric score. Bands match `AttackThreatScoring`:

| Band | Server `ThreatScore` | Row background |
|------|----------------------|----------------|
| `Green` | `0..29` | Soft green (`#DCF5DC`). |
| `Yellow` | `30..69` | Soft yellow (`#FFF8C8`). |
| `Red` | `70..100` | Soft red (`#FFDCDC`). |

### Filter toolbar

| Control | Behaviour |
|---------|-----------|
| `IP search` | Case-insensitive substring on `Ip`. Forwarded to the request and also re-applied client-side via `AttackStatsFilter` while the operator types. |
| `Min threat` | Inclusive lower bound on `ThreatScore` (0..100, step 5). |
| `Recent period` | Maps to `AttackStatsRequest.SinceUtc` via `AttackStatsRecentRanges.ToSinceUtc`. Choices: `Last hour`, `Last 24 hours`, `Last 7 days` (default — matches the server default), `Last 30 days`, `All time`. |
| `Limit` | Row limit (`100`, `250`, `500`, `1000`, `2000`). Server clamps to `1..2000`. |
| `Only blocked` | When checked, restricts to rows where `IsBlocked == true`. |
| `Auto refresh (5s)` | Optional 5-second refresh timer. Re-entry guarded — overlapping ticks are dropped, not queued. |
| `Refresh` | Manual refresh button. |
| `Clear filters` | Resets every control to its default and triggers a refresh. |

### Context menu

Right-click on a grid row opens a bounded menu whose items target the right-clicked row:

| Item | Effect |
|------|--------|
| `Copy Row Details` | Copies a multiline labelled block produced by `AttackStatRowFormatter.FormatMultiline` to the clipboard. |
| `Copy IP` | Copies the row's IP to the clipboard. |
| `Block IP…` | Confirmation dialog → `AddToBlocklist` IPC. Disabled when the row is already blocked. |
| `Whitelist IP…` | Confirmation dialog → `AddToWhitelist` IPC. Active blocks are not auto-removed; use the Firewall tab if required. |

Both mutation actions reuse the existing Stage 5 IPC commands; no new ordinals are introduced.

Cross-tab "Filter Live Events by this IP" is deferred — the existing `LiveEventsPage` does not
expose a public filter API, and adding one would be out of scope for Stage 6B. SOC operators can
copy the IP from Attack Statistics and paste it into the Live Events IP filter manually.

### Status strip

A `StatusStrip` along the bottom of the page reports every refresh outcome and operator action,
pre-stamped with the UTC timestamp:

```
[2026-05-19 12:34:56Z] Refresh OK. rows=42 (matching=42, server limit=500, window=[2026-05-12 12:34:56Z..2026-05-19 12:34:56Z]).
[2026-05-19 12:35:02Z] AddToBlocklist 203.0.113.5: OK
[2026-05-19 12:35:50Z] Copy row details: OK.
```

### IPC commands consumed

- `GetAttackStats` (18) — populates the grid (read).
- `AddToBlocklist` (14) — context-menu "Block IP…".
- `AddToWhitelist` (16) — context-menu "Whitelist IP…".

No new IPC ordinals are introduced in Stage 6B.

### Threading rules

- `RefreshAsync` is guarded by a `_refreshing` flag so the auto-refresh timer and the manual
  `Refresh` button cannot interleave.
- All IPC calls are awaited with `ConfigureAwait(true)` so continuations land on the UI thread.
- `_statusLabel.Text` updates honour `InvokeRequired` and marshal via `BeginInvoke`.
- The UI never calls `.Result` / `.Wait()`.

## Stage A — Overview dashboard, Firewall layout, MikroTik instructions, Export All IP Events

### Overview dashboard cards

The Overview tab now hosts a row of six summary cards above the existing status report:

| Card | Source | Notes |
|------|--------|-------|
| Attacks today | `Alerts.Count where TimeUtc >= utc-day-start` via `GetOverviewSummary`. | Alerts of any severity / rule count; the Overview tab reports incident pressure, not classification. |
| Blocked IPs | `ActiveBlocks` rows in `Active` or `Pending` state, distinct by IP. | Reflects what the firewall provider has installed right now, not historical totals. |
| Active sessions | `RdpSessionListDto` filtered by `state == Active`. | Returns `0` on non-Windows hosts (no session manager wired up). |
| Failed logins (24h) | `RawEvents.Count where EventId = 4625 and TimeUtc >= now - 24h`. | Matches the Attack Statistics page's failure tally for the same window. |
| Service health | Service IPC status (`"Running"` when the IPC handler responds) combined with the existing `ServiceController` probe. | Highlights `Stopped` / `not installed` paths transparently. |
| DB size | Current SQLite file length (`Storage.DatabasePath`). | Sub-title reports growth versus the closest snapshots in the day / week / month windows (`+1.2 MB d:+512 KB w:+8.5 MB`). |

The card row refreshes on tab load and whenever `Refresh status` / `Install` / `Backup Settings`
finish. Errors are actionable — a service-unreachable refresh swaps the values for `—` and the card
sub-title for `service unreachable`, while the existing status report remains the source of truth for
the detailed install / backup workflow.

DB-size snapshots are written by `Service/Workers/MaintenanceWorker.CaptureDbSizeSnapshotAsync` on
each daily maintenance pass into the existing `DbProps` table under the `OverviewDbSize:<yyyymmdd>`
key. Growth windows use `Core/Util/DbSizeGrowthCalculator.Compute` to pick the snapshot closest to
each target lookback (1 / 7 / 30 days) within documented caps (2 / 10 / 45 days). Until snapshots
accrue, growth lines render `snapshot pending (24h required)` — the current size is still shown so
operators can sanity-check the file at any time.

### Firewall layout (Stage A2 fix)

The Firewall tab uses a `TableLayoutPanel` root with two auto-sized rows (Provider / Status,
Auto-block policy), a fill row for the inner tabs (Blocklist / Whitelist / Login trip-wires /
Active blocks), and an auto-sized status-strip row. `AutoScroll` on the root grid is a safety net
for pathologically small host windows.

Within the Auto-block policy group, the layout was rebuilt as a **2-column** `TableLayoutPanel`
(`AutoSize` label column, percent-100 value column) with `AutoSize` rows:

* Row 0 — full-width brute-force trigger checkbox.
* Row 1 — `Threshold (failed attempts):` label + compact `NumericUpDown` (90 px).
* Row 2 — `Default block duration:` label + a compact `FlowLayoutPanel` carrying the three
  numeric inputs and their unit labels: `[N] days [N] hours [N] min`. The flow panel auto-sizes
  to ~260 px so the group stays visually compact regardless of how wide the parent column gets.
* Row 3 — full-width blacklisted-login trigger checkbox.
* Row 4 — full-width refuse-private-address checkbox.
* Row 5 — Save / Reload button row.

The inner `TabControl` carries a `MinimumSize` of `(0, 220)` so the grids remain usable when the
host shrinks, while the policy row's `AutoSize` height still takes precedence over the fill row.
The combination guarantees that the Auto-block policy controls are never overlapped by the inner
tabs at the original screenshot size (793 × 570) and at 150 % DPI.

### MikroTik tab — Copy commands

The MikroTik tab carries a read-only monospace block with the full RouterOS v7 shell setup bundle:
least-privilege group + user, REST endpoint enable (`www-ssl` / `www`), allowed-address restriction
to the RdpAudit host, optional TLS certificate notes, and verification queries
(`/ip/service/print where name~"www"`, `/user/print where name=rdpaudit`,
`/ip/firewall/filter/print where comment~"^RdpAudit"`). A `Copy commands` button copies the bundle
verbatim to the clipboard and reports the result in the status label (`Copied RouterOS setup
commands to clipboard (N chars).`). Operators substitute `<RDPAUDIT-HOST-IP>` and
`<STRONG-PASSWORD>` before pasting into the RouterOS console.

The command string is produced by `Core/MikroTik/MikroTikSetupCommands.BuildAll()` and locked by
`Core.Tests/MikroTikSetupCommandsTests` — every required section header is present, every
placeholder token (`HostPlaceholder`, `PasswordPlaceholder`, `CertificatePlaceholder`) appears
verbatim, no plaintext credential or common weak default is embedded anywhere in the bundle, and
every uncommented `password=` assignment must resolve to the placeholder token. The Configurator
itself only references `MikroTikSetupCommands.BuildAll()`, so the bundle cannot drift between the
UI and the tests.

### Export All IP Events

Both Live Events and Attack Statistics context menus now expose an `Export All IP Events` submenu
with `JSON…`, `TXT…`, `Markdown…`, and `CSV…` items. The submenu enables when the right-clicked
row carries a value that parses via `IPAddress.TryParse`.

Selecting a format triggers:

1. `GetEventsForIp` IPC (ordinal 39) — service-side bounded query returning recent / full-for-IP
   RawEvents (default cap 1000, ceiling 5000) plus summary metadata (IP, attack type, first / last
   UTC, failed / success counts, attempted usernames, duration, threat level, block status).
2. `Core/Events/IpEventsExportFormatter.Format` — renders JSON / TXT / Markdown / CSV.
   - JSON / TXT / Markdown include the summary header.
   - CSV is a clean tabular event stream (no summary) with a stable column order ready for Excel.
   - Embedded tabs / CR / LF are sanitised inside TXT and CSV so a pasted row never breaks the structure.
3. `SaveFileDialog` with a sensible default filename
   (`rdpaudit-events-<ip>-<yyyymmdd-hhmmss>.<ext>`) and the matching filter / extension.
4. UTF-8 write (CSV uses UTF-8 BOM so Excel auto-detects the encoding; other formats are
   plain UTF-8).
5. Status line: `Export OK (JSON): wrote N chars to <path>.` or a controlled failure message.

The Configurator never writes to an arbitrary path — exports only happen after the operator confirms
a path in `SaveFileDialog`. The runner lives in `Configurator/Services/IpEventsExportRunner.cs`.
