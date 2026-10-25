# RdpAudit.Configurator

WinForms front-end for setup, monitoring, and configuration.

## Tabs

| Tab | Implementation | Purpose |
|-----|----------------|---------|
| Overview | `Forms/OverviewPage.cs` + `Services/OverviewProbe` + `Services/InstallationService` | First-run "home" tab. Shows product info, version, project/author links, and an aggregate snapshot of ProgramData/DB/service state, surfaces detected errors/warnings, and exposes a single "Install / Repair" button that creates the ProgramData layout (with admin/SYSTEM ACLs), copies the sibling Service distribution into Program Files, and registers/starts the Windows service. |
| Prerequisites | `Forms/PrerequisitesPage.cs` + `Services/PrerequisiteChecker.cs` | Runs the 19 prerequisite probes (OS, .NET, PowerShell, TermService, RDP port, firewall rule, seven monitored event channels, privilege, ProgramData write probe, DB existence, object-access audit, audit baseline, RunAsPPL). Channel probes report disabled-vs-missing separately: a disabled channel offers a `wevtutil sl /enabled:true` fix, while a channel absent on this Windows build/SKU (e.g. TerminalServices-Gateway on a host without the role) reports "no automatic fix available" and shows no Fix button. |
| Audit Policy | `Forms/AuditPolicyPage.cs` + `Core.Events.AuditPolicyManager` | Lists the canonical `auditpol` rows; offers elevated buttons for "Apply audit policy" and "Configure SACL". Below the buttons a read-only help block explains each action, defines SACL, and documents the `S=Y/N F=Y/N` column shorthand. Current state is read via the locale-stable `AuditQuerySystemPolicy` advapi32 API with `auditpol /r` CSV as a fallback. |
| Service | `Forms/ServicePage.cs` | sc.exe lifecycle controls + 5-second IPC status refresh + recent-alerts grid with severity coloring. A dedicated "Process:" row shows the running service's PID, executable path, and start time (or `Not running` / `Not installed`), refreshed every 5 s. Start / Stop / Restart / Uninstall / Install each surface a `ServiceOperationResult` dialog containing the action name, per-step OK/FAIL, final service state, PID, executable, and a UTC timestamp. A read-only panel shows install destination, configured database path, and the sibling-distribution discovery result (Configurator → parent → `Service`). The "Install service" button calls `Services/InstallationService` so it shares logic with the Overview tab. |
| Settings | `Forms/SettingsPage.cs` | Loads `RdpAuditOptions` via IPC (falls back to disk). Saves to `%ProgramData%\RdpAudit\appsettings.json`; the service hot-reloads via `IOptionsMonitor<T>`. |
| Live Events | `Forms/LiveEventsPage.cs` + `Core/Events/LiveEventFilter.cs` + `Core/Events/LiveEventRowFormatter.cs` | Live tail of the most recent `RawEvent` rows fetched over `IPC.GetRecentEvents` (currently 200 rows). A filter bar above the grid combines IP / user / event-id / channel / free-text / time-range filters with AND semantics and a 350 ms debounce on text input. A per-cell right-click context menu offers `Copy Event Details` (multiline + TSV), `Copy Cell Value`, `Filter by This Value`, `Block IP in Windows Firewall and Add to Blocklist`, `Add IP to Whitelist and Unblock`, and `Add Login to Blocklist and Block IP`. Every operator action is recorded in a status strip with a UTC timestamp and per-step success/failure detail. All mutations go through IPC handlers — the page never writes to SQLite directly. |
| Firewall | `Forms/FirewallPage.cs` + `Core/Util/AddressListFilter.cs` | Stage 5 of the roadmap. Surfaces provider status / availability (Windows / None for Stage 5; MikroTik and Both are reserved for Stage 6 and shown disabled), the auto-block policy knobs from `FirewallOptions` (auto-block toggle, threshold, default block duration as days/hours/minutes, blacklisted-login auto-block, private-address refusal), and four inner tabs (Blocklist, Whitelist, Login trip-wires, Active blocks) each with a search/filter box, validated Add / Remove buttons, and a 5-second refresh timer. Whitelisting offers a follow-up prompt to remove an installed Windows Firewall rule via `UnblockAddress`. Removing a whitelist entry never installs a new block. Login trip-wires are explicitly separate from blocklist IPs and the UI makes clear they do **not** disable local Windows accounts. Active blocks expose the full `ActiveBlocks` row shape (IP, provider, rule handle, created / expires UTC, status, reason, last error) and a confirmation-gated `Unblock selected` button that drives `UnblockActiveBlock`. Settings persistence reuses the existing `GetSettings` / `SaveSettings` IPC round-trip; the JSON document is fetched, the `Firewall` sub-tree is mutated in place, and the wrapped `{ "RdpAudit": ... }` envelope is sent back through `SaveSettings`. A status strip timestamps every action with `[HH:mm:ss Z]` and reports per-step OK / FAIL detail. |
| Attack Statistics | `Forms/AttackStatisticsPage.cs` + `Core/Util/AttackStatsFilter.cs` + `Core/Util/AttackStatsRecentRange.cs` + `Core/Models/AttackStatRowFormatter.cs` | Stage 6B of the roadmap. Renders one row per attacker IP fetched via `GetAttackStats` IPC (ordinal 18). Twelve grid columns (IP, Threat score / band, Total, Failed, Successful, First Seen, Last Seen, Duration, Top 10 Attempted Logins, Last LogonType, Blocked) with cameyo-style green / yellow / red row coloring driven directly by the Stage 6A `ThreatLevel` returned over the wire (no UI re-classification). A toolbar combines IP-search, min-threat score, only-blocked, recent-period preset (`Last hour` / `Last 24 hours` / `Last 7 days` / `Last 30 days` / `All time`), row-limit selector (100 / 250 / 500 / 1000 / 2000), an `Auto refresh (5s)` checkbox with a re-entry guard that drops overlapping ticks, a `Refresh` button, and a `Clear filters` button. A right-click context menu offers `Copy Row Details`, `Copy IP`, `Block IP…`, and `Whitelist IP…`; mutations are confirmation-gated and reuse the existing Stage 5 `AddToBlocklist` / `AddToWhitelist` IPC commands. A status strip timestamps every refresh and action with `[yyyy-MM-dd HH:mm:ss Z]`. The Configurator never writes to the `AttackStats` table directly — every read flows through `GetAttackStats`. Cross-tab "filter Live Events by this IP" is deferred (the existing Live Events page does not expose a public filter API). |
| AbuseIPDB | `Forms/AbuseIpDbPage.cs` + service-side `Workers/AbuseIpDbReportWorker.cs` + `AbuseIpDb/AbuseIpDbClient.cs` + `Core/AbuseIpDb/AbuseIpDbCommentBuilder.cs` + `Core/AbuseIpDb/AbuseIpDbReportDecision.cs` | Stage 8 of the roadmap. Read-only intro panel describing AbuseIPDB, privacy properties of the report payload, and the steps to obtain a key. Password-style API key input with a `Show key` toggle. `Report attacks to AbuseIPDB` checkbox enabled only after a key is configured. Buttons: `Save settings`, `Test key`, `Refresh status`. Status read-out: credential present / not configured, endpoint URL, hourly / daily counters, last report result, rate-limit state. A red warning line states that reports are sent to a third-party service and include source IP + attack metadata. The UI never displays the API key plaintext; `GetSettings` returns the masked literal `***configured***` for non-empty secret envelopes, and the page treats that placeholder as a do-not-overwrite sentinel. The service-side `SettingsManager` wraps incoming plaintext keys with `ISecretProtector` before persistence; on Windows the protector is DPAPI with `SecretScope.LocalMachine`. See `docs/48-abuseipdb.md`. |
| MikroTik | `Forms/MikroTikPage.cs` + service-side `Firewall/MikroTikClient.cs` + `Core/MikroTik/MikroTikUrlBuilder.cs` + `Firewall/MikroTikFirewallProvider.cs` | Stage 9 of the roadmap. Read-only intro panel with the RouterOS v7 REST setup checklist (enable `www-ssl`, restrict allowed-address, install TLS certificate, create least-privilege user/group). Input form: Host/IP, Port (0 = scheme default), Use HTTPS toggle, Validate TLS toggle, Username, Password (password-style input with `Show password` toggle), Filter chain (default `input`), Filter action (default `drop`), Comment prefix (default `RdpAudit`), Block duration (days/hours/minutes), `Add attacker IP block rules to MikroTik Firewall` checkbox, `Enable MikroTik integration` checkbox. Buttons: `Save settings`, `Test connection`, `Refresh status`. Status panel: configuration / credential / enabled / AddRules flags, resolved endpoint, provider status, active MikroTik block count, last probe result. The page never displays the plaintext password — `GetSettings` masks any non-empty secret envelope to the literal `***configured***` and the page treats it as a do-not-overwrite sentinel. The service-side `SettingsManager` wraps incoming plaintext passwords with `ISecretProtector` before persistence; on Windows the protector is DPAPI with `SecretScope.LocalMachine`. See `docs/49-mikrotik.md`. |
| Zabbix | `Forms/ZabbixPage.cs` + `Services/ZabbixGateway.cs` | Connection settings for the Zabbix integration (server and trapper port, technical host name, host group, frontend URL, masked API token or user/password, certificate validation, cadence, severity floor, batch and backlog caps). Buttons: Save, Refresh, Test connection (probes the trapper port and the API separately and names the port on failure), Provision in Zabbix (idempotent: host group, host, seven trapper items, six triggers and the shared dashboard), Push now, and Open all incidents (the tag-filtered Problems view that lists the whole fleet). A grid shows the incidents carried by the last accepted batch. Every action is an IPC round-trip through SafeAsyncHandler. See `docs/53-zabbix.md`. |
| Remote RDP Clients | `Forms/RemoteRdpClientsPage.cs` + `Services/ShadowLauncher.cs` + `Core/Util/QwinstaParser.cs` + `Core/Util/SessionCommandBuilder.cs` + `Core/Util/ShadowPolicyModel.cs` | Stage 7 of the roadmap. Lists current RDP sessions fetched via `ListRdpSessions` IPC (ordinal 19) — service-side runs `qwinsta.exe` and parses it with the pure `QwinstaParser`, then opportunistically correlates Source IP from `RawEvents` rows. A toolbar combines free-text search (user / client / IP / session name / id), a state filter (`All states` / `Active` / `Disconnected` / `Inactive (other)`), `Auto refresh (5s)` with a re-entry guard, a `Refresh` button and a `Clear filters` button. Rows are colour-coded — green for active, orange for disconnected, grey for inactive — and the first column shows ●/◐/○ glyphs so the state is visible at a glance. A right-click context menu offers `Disconnect session…`, `Log off (kill) session…`, `Shadow — view only…`, `Shadow — view + control…`, and `Shadow — view + control (NO CONSENT)…`. Every destructive / high-impact action is confirmation-gated with a modal that names the session, the user, and (for logoff) the irreversible nature of the change. A horizontal splitter at the bottom hosts the shadow-policy panel: a summary label of the current policy (raw value + canonical description + latest backup id), a grid of every tracked registry value, and four buttons — `Enable all permissions…` (sets HKLM `Shadow=2` after taking a backup), `Backup`, `Restore latest…` and `Refresh policy`. Session control IPCs (`DisconnectSession`/`LogoffSession`/`ShadowSession`, ordinals 20–22) flow through service-side handlers that enforce the `SessionControl` options gate and validate session ids. `ShadowSession` is approval-only — the actual `mstsc.exe /shadow:<id> [/control] [/noConsentPrompt]` spawn happens in the Configurator's interactive desktop via `ShadowLauncher`, and only after the service has approved the request against the live policy. Shadow policy management uses `GetShadowPolicyStatus`/`ApplyShadowPolicy`/`BackupShadowPolicy`/`RestoreShadowPolicy` (ordinals 23–26). Backups are serialised JSON snapshots stored alongside the existing `BackupLayout` snapshot directories so the unified restore workflow can recover the pre-change state. |
| Database | `Forms/DatabasePage.cs` + `Core/Ipc/Contracts` (80-90) + `Services/DatabaseRestoreService.cs` + `Services/DatabaseResetService.cs` + `Services/ElevationGuard.cs` | Stage 3 of the roadmap. Seven inner tabs. **Overview** renders the sectioned `GetDatabaseOverview` snapshot as a monospace report (file sizes, volume free space, shard-tree footprint, per-table row counts, growth and projected time-to-cap, applied/pending migrations, migration-failure marker, retention switches, ledger aggregate, snapshot state, and the store's `auto_vacuum` mode with its page accounting - page size, page count, free pages and `page_size × freelist_count` reclaimable bytes - plus one sentence saying whether online space reclamation is possible on that store and, when it is not, that only the offline compaction returns the space (B27), plus the ingest-persistence line: how many batches the writer had to keep in memory for retry since the service started, how many of them passed the ten-minute stall threshold, or that the service reported no such counter at all - a retained batch means ingest paused instead of discarding evidence, and "unknown" never renders as a clean bill) with an `as of HH:mm:ss UTC` stamp and an explicit error line per degraded section - a partial snapshot never reads as an empty store. The `Integrity / tamper evidence` section and the docked banner above the report carry the store-integrity verdict (B25): the fingerprint-chain state with its entry count, the fingerprint timestamps, the anomaly marker with its detail, the ledger-chain verdict and the newest quick / full integrity check outcomes, colour-coded `ok` neutral, `interrupted` a warning and every other reported state an error, while a verdict that was NOT obtained renders UNKNOWN - never `ok` (see *Database ▸ Overview - store integrity / tamper evidence*). **Retention** edits the global `StorageOptions` windows, every `RetentionPolicyOptions` field (through the server-reported `RetentionPolicyBoundsDto` clamps) and the per-event `EventRetention` windows (inline edit plus bulk apply to selection or all rows); **Preview (dry-run)** renders the per-code result grid and the ordered plan, and states honestly that reclaimed bytes are unknown until a checkpoint/vacuum instead of inventing a number; **Save policy…** shows the computed old to new diff in a confirmation dialog, then re-reads the service state and displays the effective (clamped) values. **Maintenance** exposes `Rebuild attack stats` (ordinal 60) and every read-safe `RunDatabaseMaintenance` action (quick check, full integrity check, foreign key check, WAL checkpoint PASSIVE/TRUNCATE, incremental vacuum, `PRAGMA optimize`) with a cancellable wait and a monospace report; full VACUUM is deliberately absent and the tooltip says why (docs/88), and the incremental-vacuum step reports the pages it actually released - measured from the freelist depth before and after, because the statement itself returns no rows either way - or names the mode when it released nothing (B27). **Backup & Restore** creates snapshots (with an optional best-effort shard-tree copy), lists them (created, size, manifest validity, kind, shard scope, product version, last applied migration), verifies the selected one, restores into a scratch folder chosen in a `FolderBrowserDialog` (ordinal 90, safe: the live store is never touched), and restores **over** the live database through `DatabaseRestoreService` (elevation + double confirmation + the typed phrase, then an offered verification). **Shards** carries the whole shard-capacity policy editor over the `GetShardInventory` inventory: enable, actions root, ring capacity, writer pool, file budget, the per-shard, whole-tree and free-disk byte ceilings, the orphan grace period and the four cardinality-guard thresholds, all bounded by the server-reported `ShardingPolicyBoundsDto`; **Save policy…** shows the computed old to new diff in a confirmation dialog, writes through `SaveShardingPolicy` (91) and re-reads the effective (clamped) values; **Collect orphans…** runs `CollectShardGarbage` (92) as the required two-step flow - a dry run whose candidate list (path, IP, bytes, records, age) is shown in full and capped with a stated remainder, and only then, on confirmation, an apply pass - and reports how many files, bytes and records were removed. A banner above the grid renders the live capacity state (refusal reason and since when, refused-source count, byte budget, disk floor, guard engaged) in the danger face only for a real refusal, and the compaction line states plainly that no shard is ever rewritten in place. The grid adds last-write and shared-by-class columns on top of relative path, IP, records, bytes, format version, evicted, oldest retained and `referenced`/`orphan`/`subnet aggregate (shared by N)`. Both mutating actions stay disabled until an inventory has actually been read, so the editor never offers a save it has no baseline for. **Danger Zone** requires DEBUG mode (`Diagnostics.DebugMode`) **and** elevation; it hosts `Back up and reset database…` (the marker-driven `DatabaseResetService` flow, which says explicitly when no marker exists), `Clear all application data…` (ordinal 57 with the same `CLEAR ALL RDP AUDIT DATA` phrase the Firewall tab uses, which the service re-validates server-side) and the same restore-over-live action; each requires a dialog plus a typed phrase and reports into a monospace pane. `Purge by subject` is a stated stub for a later stage, with no button. **Ledger** pages and filters `GetDeletionLedger` (event id, deletion-date range, page size), newest first, with an `as of` stamp and a client-side CSV export that pages the whole filtered ledger (bounded, and it says so when the bound is hit). Every read flows through IPC - the Configurator never opens the SQLite file or a shard file - every long action runs behind a re-entrancy guard with a client-side cancellation token, and every failure is rendered from `IpcCallResult.Headline()` instead of a bare FAILED. |
| Notifications | `Forms/NotificationsPage.cs` + `Services/NotificationSettingsGateway.cs` + `Services/NotifierAutostartService.cs` | Configures the elevated `RdpAudit.Notifier` tray app: enable, autostart (`schtasks` logon task), poll interval, minimum severity, toast budget, native-toast preference, and per-rule / per-event visibility maps (Alerts / Events sub-tabs). Save / Refresh round-trip over IPC `GetNotificationSettings` (78) / `SaveNotificationSettings` (79); saving also registers or removes the logon autostart task. |

## Database tab (Stage 3)

`Forms/DatabasePage.cs` sits between Tools Diag and Notifications. It is the operator surface for the
evidence store; the IPC commands it drives are documented in `docs/50-ipc.md` (ordinals 80-90) and the
snapshot mechanics in `docs/88-database-backup-and-restore.md`.

### Safety model

| Action | Gate |
|---|---|
| Every read (overview, retention policy, preview, ledger, snapshot list, verification, shard inventory) | none - read-only commands |
| `Save policy…` (retention) | confirmation dialog showing the computed old to new diff |
| `Save policy…` (Shards) | confirmation dialog showing the computed old to new diff; the service validates and clamps the whole request before writing, and refuses an invalid one with no write at all |
| `Collect orphans…` (Shards) | dry run first (the candidate list is shown in full); the apply pass needs a second confirmation, and the service re-validates every candidate (unreferenced, not open in a writer, past the grace period) and audits each deletion |
| `RunDatabaseMaintenance`, `Rebuild attack stats` | none - read-safe actions only; full VACUUM is not in the surface |
| `Create snapshot` | none; the shard-tree copy is labelled best-effort in a tooltip |
| `Restore to folder…` | confirmation; the service verifies the snapshot and refuses to write a byte when it fails |
| `Restore over live database…` | elevation + confirmation dialog + typed phrase `RESTORE OVER LIVE DATABASE`; the service is stopped, the pre-state is renamed aside and the path is reported |
| Danger Zone: `Back up and reset database…` | DEBUG mode + elevation + confirmation + typed phrase `RESET RDP AUDIT DATABASE` (and an explicit message when no migration-failure marker exists) |
| Danger Zone: `Clear all application data…` | DEBUG mode + elevation + confirmation + typed phrase `CLEAR ALL RDP AUDIT DATA`, re-validated server-side by ordinal 57 |
| Danger Zone: `Restore over live database…` | the Backup & Restore gates plus the DEBUG gate |

The Danger Zone tab is always visible so the actions are discoverable, but its buttons stay disabled
until both gates are satisfied - the same pattern the Firewall tab uses. The gate re-reads
`Diagnostics.DebugMode` over `GetSettings` before every destructive action and fails closed when the
service cannot be asked.

### Non-freeze rules

Nothing on the UI thread touches SQLite, the shard tree or IPC. Every call is awaited with
`ConfigureAwait(true)` behind `BeginBusy`/`EndBusy`, which disables the inner tab control (so a double
click cannot start a second overlapping operation) while leaving the cancel button reachable: that
button sits in an operation bar between the tab control and the status strip. The placement is
load-bearing, not cosmetic - WinForms reports a control inside a disabled container as
`Enabled == false` even when its own flag is set, so a cancel button living on a tab page would be dead
for exactly as long as a long maintenance action or snapshot copy is running. Grids
are read-only and bounded by the service, and each view carries its `as of HH:mm:ss UTC` stamp. The
maintenance and backup actions accept a client-side cancellation token; cancelling abandons the wait,
which the status line states explicitly because the service may still be completing the operation.

### Required tests before modifying

`tests/RdpAudit.Configurator.Tests/DatabasePageTests.cs` (tab structure and order, the Danger Zone
gate and its fail-closed refresh, the typed phrases, the purge stub, the retention control to contract
mapping, the old to new diff, the busy gate that refuses a second overlapping operation while keeping
cancel reachable, and the pure renderers) plus `MainFormTabOrderTests` for the tab's
position. On the service side, `IpcDispatcherDatabaseStage3Tests` covers ordinals 88-90 including their
read-only guarantees.

Every asynchronous page call in that class must run through
`tests/RdpAudit.Configurator.Tests/StaTestHarness.cs`, which pumps the STA thread's Win32 message queue
(`Application.DoEvents()` in a bounded loop) instead of blocking it. Constructing a WinForms control
installs a `WindowsFormsSynchronizationContext` on the constructing thread, so the continuation of a
page's `await ... ConfigureAwait(true)` - the correct choice for a UI page - is posted back to that
thread; a test that blocks it with `Wait()` or `GetAwaiter().GetResult()` deadlocks the page against
itself. Measured on this page: with the owning thread blocked, `RefreshOverviewAsync` never completed
(10 s wait, status still `Ready.`); with the queue pumped, the same call completed in 2.03 s and
reported its degraded-service status. The harness also gives every wait a deadline (30 s per test body,
20 s per awaited operation, 2 minutes per test class) on a background STA thread, so a regression fails
a test in bounded time instead of hanging the run.

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

`IpcClient.SendAsync<T>` enforces a per-command round-trip deadline (5 s by default, 60 s for the long-running commands listed in `IpcConstants.TimeoutMsFor` — see `docs/50-ipc.md`) and a 2-second connect timeout. On `OperationCanceledException`, `TimeoutException`, or `IOException` it returns `default(T)`. **It must never throw to the UI thread.**

### The Database tab talks to an interface, not to `IpcClient` (B17)

`Forms/DatabasePage.cs` and `Forms/PurgeBySubjectDialog.cs` take `IIpcClient` (`Ipc/IIpcClient.cs`), a
one-member seam that exposes exactly the overload they use —
`SendDetailedAsync<T>(IpcCommand, object?, CancellationToken)`. Production composition is unchanged
(`MainForm` constructs the real `IpcClient`, which implements it), but a test can now answer each command
and assert what the page renders and what it refuses, instead of being limited to the "service
unreachable" branch. `tests/RdpAudit.Configurator.Tests/DatabasePageIpcTests.cs` does exactly that.

**Do not widen `IIpcClient`.** A page that needs `SendAsync`, `SendRawAsync` or `PingAsync` should inject
`IpcClient` directly; growing this interface back into a copy of the client re-creates the coupling it
exists to remove.

Two page seams exist for the same reason and default to the real dialogs:

| Seam | Replaces | Why |
|---|---|---|
| `DatabasePage.ConfirmPrompt` | the modal `MessageBox` confirmation | every irreversible operation on the page (retention save, both restore paths, reset, cleanup, purge, offline compaction, shard policy save, orphan collection) is gated by it, and a test must be able to assert **both** answers — including that a cancelled confirmation sends nothing. |
| `DatabasePage.ChooseLedgerExportPath` | `SaveFileDialog` | the ledger CSV export pages through the dispatcher and then writes a file; the cancelled path must write nothing, and neither is reachable through a modal picker. |

Both default to the production implementation in the constructor, so replacing them changes nothing unless
a test does it.

## Threading rules

- Async event handlers (`Click`) are `async void`; everything else returns `Task`.
- Background callbacks always check `InvokeRequired` and marshal back to the UI thread before touching controls.
- **No blocking task waits in this assembly.** `GetAwaiter().GetResult()`, `.Wait(...)` and a `.Result` read on a task are forbidden: the page that owns a control owns the WinForms synchronization context, and blocking that thread is what deadlocks an inner `await ... ConfigureAwait(true)` (and what hung this test suite before `StaTestHarness` existed). If an API is genuinely synchronous, call it from a thread-pool task (`Task.Run`) instead. `tests/RdpAudit.Configurator.Tests/ConfiguratorSyncOverAsyncGuardTests.cs` enforces this over the whole project and carries an explicit allow-list that must state a reason.

## Global unhandled-exception safety net

`Program.Main` installs `ConfiguratorExceptionGuard.Default` before the first window exists. The guard is the Configurator's counterpart of the service's `CrashGuard` and attaches all four hooks:

| Hook | Behaviour |
|------|-----------|
| `Application.SetUnhandledExceptionMode(CatchException)` | Routes a UI-thread fault to `Application.ThreadException` instead of the WinForms dialog. |
| `Application.ThreadException` | Journal + operator dialog; the message loop and the unsaved state survive. |
| `AppDomain.CurrentDomain.UnhandledException` | Journal, written synchronously because the process is on its way down. No dialog: the fault is not recoverable, so the guard records it and lets the runtime terminate. |
| `TaskScheduler.UnobservedTaskException` | `SetObserved()` + journal. A stray faulted task can no longer escalate to process termination. |

The journal is `%ProgramData%\RdpAudit\logs\configurator-unhandled.log`, written through the shared `DiagnosticLogRotation` helper (same folder and rotation policy as `ipc-startup.log`). The Configurator owns no `OperationLog` writer and no Event Log source, so unlike `CrashGuard` it records a fault only to the journal, the `Debug` mirror and — for recoverable faults — the operator. Repeated faults are throttled: one dialog at a time and at most one every 30 seconds, so a fault that fires on every timer tick cannot bury the window behind modal dialogs.

### Rule: new handlers only through the shared helper

An `async` lambda attached to an event (`X.Click += async (_, _) => ...`) is `async void` at runtime: an exception that escapes it has no caller left to catch it. Every new handler is therefore attached as

```csharp
_button.Click += SafeAsyncHandler.Wrap(() => DoWorkAsync(), ReportHandlerFailure);
_keyInput.KeyDown += SafeAsyncHandler.KeyDown(async e => await OnKeyAsync(e), ReportHandlerFailure);
```

`SafeAsyncHandler` (`Services/SafeAsyncHandler.cs`) journals the fault under the declaring page's name and then calls the page's own `ReportHandlerFailure`, which renders it on the surface the operator is looking at and never touches a disposed control. `DatabasePage`'s former private `AsyncClick` helper is this type; the Firewall, Service, Remote RDP Clients and Overview pages — plus `PurgeBySubjectDialog`, which the Database tab opens — were migrated onto it, and `tests/RdpAudit.Configurator.Tests/ConfiguratorAsyncHandlerHygieneTests.cs` pins the remaining `+= async` sites per file so the debt cannot grow silently.

## LLM contract

- Never call SQLite write paths from the Configurator. Reads through `ReadOnlyDb.Open()` are fine; writes go through the IPC server.
- Any new tab must be added to `MainForm` constructor and follow the existing pattern (5-second refresh timer, `Invoke` dispatch).
- Attach every async event handler with `SafeAsyncHandler` (never a raw `+= async` lambda) and report its failure on the page's own status surface.
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
    - A CSV cell that starts with `=`, `+`, `-` or `@` is prefixed with an apostrophe, because
      Excel, LibreOffice and Google Sheets evaluate such a cell as a formula and the values
      here include a user name the attacker typed at the RDP prompt. A leading `-` followed by
      a digit stays untouched so numeric columns keep their values. The rule lives in
      `Core/Models/TabularExportWriter.AppendCsvCell` and therefore applies to every grid export.
3. `SaveFileDialog` with a sensible default filename
   (`rdpaudit-events-<ip>-<yyyymmdd-hhmmss>.<ext>`) and the matching filter / extension.
4. UTF-8 write (CSV uses UTF-8 BOM so Excel auto-detects the encoding; other formats are
   plain UTF-8).
5. Status line: `Export OK (JSON): wrote N chars to <path>.` or a controlled failure message.

The Configurator never writes to an arbitrary path — exports only happen after the operator confirms
a path in `SaveFileDialog`. The runner lives in `Configurator/Services/IpEventsExportRunner.cs`.

### Export Selected / Red / Yellow / All Rows (RDP Activity)

The RDP Activity (Attack Statistics) grid is multi-select: `Ctrl`-click toggles single rows, `Shift`-click
takes a range. Selection is mirrored by source IP rather than by row index, because a refresh, a filter
change and a column sort all rebuild or reorder the bound list — an index-based selection would silently
move to a different IP at the first sort, and `Export Selected Rows` would then write rows the operator
never picked. The mirrored IPs are re-applied after every rebuild, rows that disappeared from the view
lose their selection by definition, and the status strip reports `N row(s) selected (of M displayed)`.
Right-clicking inside an existing multi-row selection keeps it (the selection only moves when the click
lands outside it), and the grid's current cell is moved with it so a later data-source reset cannot drop
the highlight.

The context menu hosts a three-level `Export` submenu placed immediately before `Export All IP Events`:
`Export` → one scope item per slice → one item per format. Both the rows and the encoding are therefore
explicit choices in the menu, and the save dialog is only asked for a path.

| Scope item | Covers |
|------|--------|
| `Export Selected Rows` | Exactly the highlighted rows. |
| `Export Red Rows` | Displayed rows whose authoritative `ThreatLevel` is `Red`, minus the unresolved-IP sentinel. |
| `Export Yellow Rows` | Displayed rows whose `ThreatLevel` is `Yellow`. |
| `Export All Rows` | Every displayed row, i.e. the current filter result (IP search, min threat score, only blocked). |

Each scope item opens `JSON` / `TXT` / `Markdown` / `CSV`. The confirmed file extension must agree with
the format the menu item fixed, otherwise the export is refused rather than written into a
mis-named file; the save dialog's own filter is already narrowed to that one format.

**The unresolved-IP sentinel row (`0.0.0.0`, shown as `(unresolved)`) is not an attacker.** It renders
  with the red band when it carries red pressure, but it represents logon events with no resolvable
  source address. It is therefore excluded from `Export Red Rows` and `Export Yellow Rows` — and the
  exclusion is **counted and printed**, on the status line and in the file header, so it can never happen
  invisibly. It is kept in `Export All Rows` and in `Export Selected Rows` when the operator selects it.

Each produced file states its own scope: scope label, row count, number of excluded unresolved rows,
the visible grid row count, the active filter description and the UTC generation timestamp. CSV carries
that provenance as leading `#` comment lines before the header row, so a file found later on disk still
says where it came from. Every format writes UTF-8; CSV gets the BOM so Excel detects the encoding.
Timestamps in the files are UTC while the grid displays local time, and the header says so.

Classification uses the `ThreatLevel` returned by the service, never a re-derived band, and the export is
a pure read: it writes only the rows already received via `GetAttackStats`, adds no IPC command and never
touches the database. The formatter lives in `Core/Models/AttackStatRowsExportFormatter.cs`
(unit-testable without WinForms) and the runner in
`Configurator/Services/AttackStatRowsExportRunner.cs`.

### Export in every other table and list

Every `DataGridView` (24) and details-view `ListView` (3) in the Configurator exposes a two-level
`Export → Export Selected Rows → JSON / TXT / Markdown / CSV` submenu:

| Surface | Helper |
|---------|--------|
| Grids already using the shared clipboard helper | `Theming/DataGridClipboardMenu.AttachWithExport` |
| Grids that build their own menu (Firewall ×4, Live Events, Service alerts, Remote RDP clients) | `DataGridClipboardMenu.AppendExportSubmenu` |
| Lists (`Audit Policy`, `Prerequisites`, `IIS install progress`) | `Theming/ListViewClipboardMenu.AttachWithExport` |

Three rules apply to all of them:

* **Empty selection means no export.** `Export Selected Rows` is disabled (and stays disabled per menu
  open) when nothing is highlighted, and the format items refuse with a hint instead of writing an empty
  file that would look like success while carrying no evidence.
* **One writer.** Cell sanitising, CSV quoting, Markdown escaping, the extension→format mapping and the
  JSON envelope all live in `Core/Models/TabularExportWriter.cs`; `Configurator/Services/TabularExportRunner.cs`
  is the only save path. A value containing a comma, a quote or a line break is therefore encoded
  identically no matter which tab produced the file, and the file's contents always match its extension.
* **Multi-select only where it is inert.** Rows can be highlighted in multiple only where the selection
  does not drive an action or a detail pane. The grids where `SelectedRows[0]` / `CurrentRow` feeds
  buttons or detail panes (Firewall blocklist / whitelist / active blocks, Database backups, Database
  event retention, Logs, Process Alerts, Session Map facts, AbuseIPDB report log, Cross-host chains)
  stay single-select and export the one highlighted row.

Every produced file states its own provenance: table name, scope, row and column counts, the visible row
count, the active filters and the UTC generation timestamp. CSV carries that provenance as leading `#`
comment lines before the header row. All formats write UTF-8, CSV with the BOM so Excel detects the
encoding, and no export adds an IPC command or touches the database.

## Database ▸ Danger Zone (Stage 5 additions)

The Danger Zone keeps its single gate — DEBUG mode (`Diagnostics:DebugMode`) **and** elevation, re-checked
at click time — and its rule that every action needs a typed confirmation phrase that the server validates
again. Two actions were added:

* **`Purge by subject…`** (`PurgeSubjectPhrase = "PURGE SUBJECT DATA"`, IPC `PurgeBySubject = 94`). Opens
  `PurgeBySubjectDialog`, which enforces the order of operations in the UI as well as on the server: choose
  the subject (IP address, CIDR range, login, or UTC window) → **Preview (dry run)** → read the per-table
  counts, the totals and the list of what is deliberately *not* touched → type the phrase → **Purge**. The
  Purge button stays disabled until a preview has succeeded *and* the typed phrase matches, and the phrase
  is re-read at click time. A legal hold (`Storage:RetentionPolicy:LegalHold`) makes the server refuse the
  apply outright; the dialog still shows the frozen counts, so the operator can see the size of what is
  held. The outcome is rendered verbatim — counts, ledger entries, chain head, preserved list — into the
  shared Danger Zone report.
* **`Compact database (offline)…`** (`CompactOfflinePhrase = "COMPACT RDP AUDIT DATABASE"`). Stops the
  service, runs `DatabaseCompactService` (`VACUUM INTO` a verified copy, that copy's auto-vacuum mode
  normalised to `INCREMENTAL`, then an atomic swap through the same `LiveDatabaseSwap` mechanics the
  restore path uses) and restarts it. This is the only action in the product that shrinks the database
  file; the online purge never runs a full VACUUM (docs/88). The mode step is what lets a store created by
  an older build reclaim space online again: `VACUUM INTO` carries the source's mode over, so without it a
  legacy store would be compacted back into mode NONE, where the bounded online `incremental_vacuum`
  releases nothing (B27) — the Overview states which mode the store is in. The step costs one further
  `VACUUM` over the compacted copy (measured: 0.66 s on a 57 MB store) and needs twice the copy's size
  free beside the store, refusing below that with both numbers. The report
  names the bytes before, after and reclaimed, the auto-vacuum mode before and after, the pre-compaction
  `.bak` and the `.compact.json` receipt,
  and says explicitly when the compaction completed but the service could not be restarted.

The Danger Zone's explanatory text states what the subject purge deliberately leaves alone — the schema,
the migration history, `DbProps`, the bookmarks, the append-only ledger, the audit records, and the
operator's own configuration and enforcement state (blocklist, whitelist, login rules, active blocks) —
because a silent omission from a destructive action is indistinguishable from a bug.

`IPC CompactDatabase = 93` is the counterpart that never runs: a client asking the *running* service to
compact the store gets a documented refusal carrying the offline procedure and the reclaim forecast. The
Configurator does not need it to perform the compaction; it exists so the online request has an honest
answer rather than a silent one.

## Database ▸ Overview — store integrity / tamper evidence (B25)

The service computes a store-integrity verdict on every start-up (B19/B24): a hash chain over the store
fingerprints, sealed by a tip that no longer lives in the folder it describes, plus the deletion-ledger
hash chain and the anomaly marker a failed comparison leaves behind. Before B25 that verdict reached the
operation log and a marker file and **nothing else** — the one alarm whose whole purpose is to be acted on
was the one an operator could not see while looking at the store.

Two surfaces now carry it, and both read their severity and their wording from one place
(`RdpAudit.Core/Integrity/StoreFingerprintChainVerdict.cs`), so the same state can never be coloured or
phrased differently on two tabs.

### The banner (Overview tab)

A fixed band sits between the button bar and the monospace report. It is docked, not part of the report,
so the verdict is readable **without scrolling** — a verdict 90 lines down a monospace dump is a verdict
nobody reads. It states the verdict in words, then one line of facts: the chain state with its entry
count, whether the key facts are mirrored outside the integrity folder, whether the anomaly marker is
present, and the same `as of` stamp the rest of the overview uses.

Colour follows the escalation band and nothing else:

| Band | Banner face | When |
| --- | --- | --- |
| `Ok` | neutral | the chain verifies against its sealed tip |
| `Warning` | amber | `interrupted` — a capture was cut short by a crash or power loss |
| `Error` | red | `missing`, `unreadable`, `chain-broken`, `unverified`, or any state this build does not recognise |
| `Unknown` | red | no verdict was obtained at all |

### The section (Overview report)

`Integrity / tamper evidence` renders the whole verdict, stamped like every other section: the band, the
chain state and entry count, the chain message (the findings behind a non-`ok` state), the mirror
availability, the last clean-shutdown and periodic fingerprint times, the anomaly marker with its detail,
the ledger-chain verdict with its chained/unchained row counts, and the newest journaled quick, full and
ledger-chain check outcomes.

### Reading the five chain states

| State | What it means | What to do |
| --- | --- | --- |
| `ok` | The chain verifies and matches its sealed tip. A first run (no chain, no tip) is also `ok`. | Nothing. |
| `missing` | The sealed tip accounts for fingerprints that are not on disk: a chain tail or the whole `fingerprints` folder was removed while the tip survived. | Treat the remaining fingerprints as a superseded baseline. Read `WARNING`-level evidence around the affected window; the marker file (also shown here) records what the last comparison found. |
| `unreadable` | An entry or the tip exists but could not be read, parsed or unsealed (a broken DPAPI envelope, a truncated file, an unknown layout version). | Inspect `%ProgramData%\RdpAudit\integrity` before touching anything. "We could not look" is never an intact store. |
| `chain-broken` | The records are internally inconsistent (digest mismatch, broken linkage, sequence gap) or contradict the tip in the "replaced / rolled back" direction. | The strongest reading available: assume the baseline was replaced. Escalate. |
| `interrupted` | Exactly one entry more than the tip accounts for, corroborated by the durable write intent B24 writes before appending — a crash or power loss between appending an entry and re-sealing the tip. | Nothing was lost and nothing was altered: the next capture re-seals the tip. Reported as a **warning**, deliberately not as tampering. |
| `unverified` | This host could only read the pre-B19 fingerprint document, so the chain itself was never verified. | Treat the fingerprint timestamps as unverified. It is shown as an error, not as a pass. |

### Why an absent verdict is never `ok`

The banner and the report show `UNKNOWN` — in the error face, never the neutral one — whenever **no
verdict was obtained**, which is any of:

* the overview could not be read at all (service unreachable, command rejected, read threw);
* the service answered but marked the snapshot `Unavailable`;
* the snapshot carries **no completed `Fingerprint` section** (the read that produces the verdict timed
  out, failed, or never ran — the usual shape of a partial snapshot);
* the state field is `null`, i.e. a host that does not carry the fingerprint store.

"We did not read it" and "it is broken" are different sentences, and neither of them is "it is fine".

The one case that is deliberately **not** downgraded to `UNKNOWN` is a partial snapshot whose
`Fingerprint` section did complete: that verdict is a real reading, and rendering a `chain-broken` alarm
as "unknown" because an unrelated section (the shard-tree walk, say) timed out would hide exactly the
alarm this exists to raise. The banner and the report both state `(snapshot partial)` in that case, so
the reading is never presented as an unqualified pass.

### Diagnostic tab

`DiagnosticsSnapshotDto` now carries the same fields (appended, so existing consumers are untouched) and
the Diagnostic report renders them as its own `Store integrity / tamper evidence` section — an operator
who lands on that tab after an unexplained restart does not have to switch tabs to see the verdict. The
producer reads the fingerprint chain through the same shared reader the Database tab's overview uses
(`StoreFingerprintVerdictReader`), so the two tabs cannot disagree, and it verifies the ledger chain with
the same Core verifier.

The section also names its own inputs, because the Diagnostic report does not render section timings
anywhere else: it prints whether the snapshot is partial and the outcome of the `StoreFingerprint` and
`StoreIntegrity` sections, so an `UNKNOWN` verdict carries the reason it happened instead of asserting it.

The fingerprint verdict is read from disk **before** any database section and is deliberately independent
of the database: a store that cannot be opened is exactly when that verdict has to arrive.
