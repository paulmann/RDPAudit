# SPEC.md - RDPAudit 2.0

Requirements specification for the RDPAudit 2.0 service and configurator solution.
Derived from PROJECT_MAP.md and the solution layout: .NET 8 / WinForms, six src
projects (RdpAudit.Core, RdpAudit.Service, RdpAudit.Configurator, RdpAudit.Mikrotik, RdpAudit.Notifier,
RdpAudit.Web), seven test projects (RdpAudit.Core.Tests, RdpAudit.Service.Tests, RdpAudit.Mikrotik.Tests,
RdpAudit.Configurator.Tests, RdpAudit.Notifier.Tests, RdpAudit.ScenarioTests, RdpAudit.Web.Tests) and the
standalone RdpAudit.Benchmarks BenchmarkDotNet project (not part of the solution).

---

## 1. Product overview

RDPAudit is a Windows service plus a WinForms configurator that turns raw Windows
security-event telemetry into an operationally focused RDP attack monitor:

- **Ingest** Windows security and terminal-services events in near real time
  (EventLogWatcher and a hybrid ETW transport), including bounded historical backfill.
- **Normalize** events into canonical facts (raw events, atomic authentication-
  attempt facts, RDP connection facts) with per-IP correlation.
- **Detect** attack patterns via a configurable alert-rule engine.
- **Correlate** auth-attempt facts across multiple agent hosts into deduplicated
  attack chains (P4-18 cross-host correlation) raised as CROSS_HOST_CHAIN alerts.
- **Block** offending source IPs automatically through Windows Firewall and/or a
  MikroTik RouterOS v7 REST provider, with honest live enforcement reconciliation
  (the service never claims an IP is blocked unless a real backend object exists).
- **Expose** an optional read-only HTTPS REST API (disabled by default, fail-closed)
  over the same audited read commands that back the named-pipe IPC.
- **Serve** an optional IIS-hosted read-only Web dashboard (RdpAudit.Web) whose
  static HTML/JS pages call only the read-only REST endpoints; the bearer token
  is injected by the in-process proxy and never reaches the browser.
- **Present** SOC-operator tooling: per-IP attack statistics with threat scoring,
  live event inspection, remote RDP session control, report exports, diagnostics,
  and a durable program-action audit log.

External integrations: AbuseIPDB v2 (reputation reporting with dedup / rate limits)
and MikroTik RouterOS v7 (external firewall provider).

Value proposition: closing the visibility and response loop for RDP brute force /
lateral movement on Windows hosts, including hosts where the Security log is large
or the operator's Windows UI culture is non-English.

---

## 2. Use cases

### UC-1 SOC analyst monitors attacks
A SOC operator opens the Configurator: Overview shows attack counts, active blocks,
failed logins and service health. Attack Statistics shows one row per source IP with
a cameyo-style green / yellow / red threat band, filterable by IP, min threat,
blocked-only and recent period. Live Events shows a recent event tail with field
filters and per-cell actions (copy, filter, block, whitelist, login tip-wire).

### UC-2 SOC analyst investigates an IP
On one attacker IP the analyst exports: All IP Events, Connection Facts, or Auth
Success (per login) as JSON / TXT / Markdown / CSV. Reports are bounded, sanitized
(no raw event bodies in fact listings), and summary-first (one row per login, never
one per attempt). The analyst checks why an IP is not reportable via the
IpReportability classification and the per-IP unresolved-IP reason taxonomy.

### UC-3 SOC analyst manages active sessions
Remote RDP Clients tab lists active/inactive/disconnected RDP sessions with client
IP enrichment, operator-scoped "Current?" marking, and confirmation-gated
disconnect / logoff / shadow actions. Shadow respects the Terminal Services shadow
policy with the same two-tier gating (service IPC approval + local registry policy
fallback).

### UC-4 Administrator configures and hardens
Firewall tab: provider status, auto-block policy knobs, blocklist / whitelist
(CIDR-friendly), login trip-wire rules, active blocks with per-attempt backend
diagnostics and repair. Prerequisites tab: 19 probes with per-row fixes. RDP
Configuration tab: live terminal-services surface (port, NLA/security layer,
single-session, hide-users, shadowing) with backup-guarded writes. AbuseIPDB and
MikroTik tabs configure external providers without ever displaying plaintext
secrets.

### UC-5 Administrator maintains the deployment
Service tab: authoritative SCM state, binary fingerprint comparison (installed vs
distribution), install / update / uninstall with transactional copy and install
logs. Tools Diag tab: read-only probes for external tools with per-step command
detail. Diagnostics tab: LLM-friendly snapshot (effective channels / event ids,
DB counts, config-repair report, pipeline errors) with copy / export. Backup /
restore captures audit policy, registry/SACL state, service config and
appsettings.json into timestamped snapshots.

### UC-6 Administrator recovers from a broken database
A failed EF migration leaves a durable marker; the Configurator offers a guided
"backup and reset database" flow (back up database + WAL/SHM, drop, let the service
re-create) instead of a Win32 1067 restart loop.

### UC-7 SOC analyst investigates a cross-host attack chain
The Cross-Host tab lists persisted cross-host attack chains (newest first) with rule
and acknowledgment filters. Selecting a chain shows its ordered hop (link) details;
the Acknowledge action flips the chain flag and clears the linked CROSS_HOST_CHAIN
alert server-side. Agent hosts export only fact projections (never raw event XML).

### UC-8 Integration tooling reads telemetry over HTTPS
An integration host with a read-only bearer token polls the optional HTTPS REST API
(status, alerts, sessions, configuration, raw events). Every endpoint is served by
the audited IPC read handlers or the dedicated read-only event reader, so the REST
surface adds zero write paths; it is disabled by default and fail-closed.

### UC-9 Operator receives tray notifications
An operator configures the Notifications tab (enable, autostart, poll interval,
minimum severity, toast budget, native-toast preference, per-rule / per-event
visibility). The elevated RdpAudit.Notifier tray app polls the service over IPC
and surfaces new alerts as balloon or native WinRT toasts, filtered by the policy
and rate-limited per minute. When the service is unreachable the notifier degrades
to a safe polling interval and stays silent about the outage.

### UC-10 Administrator enables the optional IIS web dashboard
An administrator enables the Configurator's optional "Web Access" tab, runs the
Install IIS and/or Configure IIS workflows and gets the RdpAudit.Web dashboard
served over HTTPS on a loopback-only site. The tab's privacy-first switch
(off by default), the phase-gated management checkbox, the live IIS/Web status
and the two workflow buttons (enabled only after a successful status probe)
are the only controls.

---

## 3. Functional requirements

### 3.1 Ingestion transports
- FR-ING-1: IngestionMode selects EventLogWatcher, real-time ETW, or Auto
  (ETW first, EventLogWatcher on probe failure) with an out-of-range enum value
  clamped to the safe EventLogWatcher default.
- FR-ING-2: Channels transport-routed from EtwProviderMap: real-time capable
  channels go to ETW, the rest (including the protected Security channel) go to
  EventLogWatcher.
- FR-ING-3: Security ingestion pins a narrow canonical XPath over the v3 atomic-
  outcome event set 4624 / 4625 / 4648 / 4768 / 4769 / 4771 / 4776 / 4825.
  RdpCoreTS / TCP / WTS / LSM events must never be used as the atomic auth source.
- FR-ING-4: SecurityBackfillWorker and TerminalServicesBackfillWorker backfill
  historical windows per event id (ReverseDirection=true, bounded MaxEvents per id)
  so one failing id never starves the others and a stale bookmark cannot leave the
  service permanently zero-event.
- FR-ING-5: EventLogWatcher bookmarks round-trip through BookmarkSerializer and
  commit over the same durability boundary as the events they cover
  (BookmarkCheckpointLedger).
- FR-ING-6: ChannelHealthPolicy classifies channels critical/optional, debounces
  invalid-handle failures, grants a single bookmark-reset retry, and permanently
  disables a channel after a saturating fault burst without spamming the
  Application log.
- FR-ING-7: The event pipe is an IEventPipe over a configurable SPSC or MPMC
  ring buffer; the async wait is semaphore-backed (no polling); hot paths remain
  zero-allocation.

### 3.2 Normalization and facts
- FR-NORM-1: Every event is normalized into a RawEvent with canonical source IP
  via PerEventIpResolver; hostname-only fields never land in SourceIp, missing IPs
  mark SourceIpUnresolved without synthetic placeholders.
- FR-NORM-2: IpNormalizer is the single canonicalization point; all writers/readers
  of IPs run through it (leading-dot, brackets, port suffixes, IPv6 zone ids,
  IPv4-mapped IPv6 collapse to one key).
- FR-NORM-3: AuthAttemptFact is the atomic per-event fact, created ONLY from the
  authoritative Security events. Rebuilding facts from scratch always yields
  identical counters (v3 invariant).
- FR-NORM-4: NLA-stripped 4625/4624 events recover their IP from RdpCoreTS 131/140
  (and TS-RCM 261) observations in the -2s..+15s window: unique candidate attaches
  at High confidence, multiple candidates at Medium with CorrelationAmbiguous.
- FR-NORM-5: RdpConnectionFacts are seeded by strong-key events (LogonId, or
  WtsSessionId+UserName) even without a direct IP yet; the IP is backfilled by a
  later observation in the same logon chain. SessionIpCorrelations keyed by
  LogonId / (WtsSessionId, UserName) / UserName persist IP correlation across
  service restarts.
- FR-NORM-6: NtStatusFormatter canonicalizes the three textual NTSTATUS forms
  (0xXXXXXXXX, unsigned decimal, signed decimal) to one canonical string;
  SubStatusCatalog provides one translation per 4625/4776/4771 SubStatus code.

### 3.3 Attack statistics
- FR-STAT-1: AttackStatsRefreshWorker materializes per-IP AttackStat rows from
  AuthAttemptFacts + ActiveBlocks on a bounded newest-first pass, with a full-
  rebuild IPC action for debugging.
- FR-STAT-2: ThreatScore 0..100 with cameyo-style green/yellow/red bands is
  computed by the single-destination AttackThreatScoring helper; counters (total /
  successful / failed) derive exclusively from AuthAttemptFact.
- FR-STAT-3: Unresolved-IP rows are grouped by a machine-readable reason taxonomy
  (parser error, missing IP, correlation miss, invalid value, private/loopback).

### 3.4 Alert rules
- FR-ALERT-1: The AlertWorker applies registered rules to fresh events only
  (historical age gate AlertEventMaxAgeMinutes, default 5); backfill/replay events
  are marked processed but never alerted.
- FR-ALERT-2: Rules delivered per the catalog: brute force 4625, NTLM 4776,
  Kerberos spray 4771, Pass-the-Hash, Golden/Silver Ticket, LSASS access/PPL tamper,
  privileged group change, privileged logon 4672, new account 4720, new/changed
  scheduled task, service install 4697, Sticky-Keys IFEO hijack, RDP port change,
  RDP session hijack, rapid reconnect, off-hours logon, unknown-IP-success,
  external RDP logon, process anomaly, pipeline log flood.
- FR-ALERT-3: Alerts use per-(rule,key) cooldown suppression; PRIVILEGED_LOGIN
  additionally filters well-known service SIDs and enforces a per-minute budget.
- FR-ALERT-4: Alert messages are complete and stable (e.g. ExternalRdpLoginRule
  must never emit a trailing "as " when the username is missing).

### 3.5 Firewall enforcement
- FR-FW-1: Auto-block policy from FirewallOptions: whitelist always bypasses,
  brute-force threshold blocks, login trip-wire immediate blocks, provider
  selection and block scope (RdpPortOnly vs AllInbound).
- FR-FW-2: WindowsFirewallProvider installs/removes blocks via netsh and
  PowerShell argument-list execution; reserved addresses are refused by policy;
  locale-independent signals are used (exit-code 1 = not found, never English text).
- FR-FW-3: MikroTik provider targets RouterOS v7 REST endpoints, only deletes rules
  carrying the configured comment prefix, is idempotent, and never logs the API
  password.
- FR-FW-4: RouteBlackholeProvider is experimental; it validates that the configured
  gateway is genuinely unreachable before relying on it. IPsecBlockProvider is
  delivered as a clean IFirewallProvider with explicit NotImplemented status.
- FR-FW-5: BlockExpiryCalculator defines the ExpiresUtc precedence: explicit
  duration > configured default > permanent (Never). FirewallExpirationWorker
  unblocks at ExpiresUtc.
- FR-FW-6: EnforcementReconciliationService maps DB intent + recorded enforcement +
  live backend scan into a single EnforcementStatus + confidence per (provider, ip).
  The Active Blocks view is built from reconciled DTOs, never raw DB rows; "remove
  all RdpAudit enforcement" cleanup deletes only RdpAudit-owned rules.
- FR-FW-7: RdpAuditFirewallRuleMatcher recognizes both Windows Firewall identity
  forms (canonical Name and GUID-named DisplayName) and reports duplicates.

### 3.6 Address lists
- FR-LIST-1: Blocklist / whitelist / login rules persist with auditable source
  (manual / automatic / external). Whitelist supports CIDR ranges; matching is
  family-aware bitwise prefix testing.
- FR-LIST-2: LIKE-pattern wildcards from user search are escaped (SqlLikeEscaper)
  so they match literally; values always travel as SQL parameters.

### 3.7 RDP session control
- FR-SESS-1: Session listing uses qwinsta/quser through the parse-stable English
  console (chcp 437) with header-agnostic, Cyrillic-tolerant parsers.
- FR-SESS-2: Disconnect / logoff run direct argument-list (no shell). Shadow launch
  is Configurator-side, gated by service approval AND local registry shadow policy.
- FR-SESS-3: ActiveSessionCounter and CurrentRdpSessionMatcher centralize the
  Overview "active sessions" KPI and the operator-scoped "Current?" column so
  Overview and Sessions tab never disagree.

### 3.8 AbuseIPDB reporting
- FR-ABUSE-1: Reports use the v2 form-urlencoded /api/v2/report endpoint with a
  sanitized, credential-free comment built by AbuseIpDbCommentBuilder.
- FR-ABUSE-2: The worker honours whitelist precedence, threshold policy, hourly /
  daily rate limits, and success-filtered cooldown/dedupe backed by
  AbuseIpDbReportHistory.
- FR-ABUSE-3: The API key is format-validated offline (80 hex chars) and tested
  read-only; it NEVER appears in logs, DTOs, or on disk in plaintext.
- FR-ABUSE-4: IpReportability forbids reporting local / reserved / whitelisted IPs
  and returns a machine-readable reason.

### 3.9 Settings, secrets and operations
- FR-CFG-1: SettingsManager validates, protects secret fields via ISecretProtector
  (DPAPI LocalMachine scope), and writes appsettings.json atomically.
- FR-CFG-2: MonitoringConfigRepair runs on every options materialization: Security
  channel + v3 auth event-id set always present in effective MonitoringOptions,
  IngestionMode clamped to EventLog on invalid values.
- FR-CFG-3: OperationLog records program actions (bans, settings, maintenance, IPC
  outcomes, startup/crash) durable in SQLite, with DEBUG-gated detail fields and a
  bounded paged Logs tab.
- FR-CFG-4: Backup/restore captures audit policy, registry/SACL, sc.exe service
  config and appsettings.json; restore always takes a pre-restore safety snapshot
  and never touches the audit database.

### 3.10 Diagnostics
- FR-DIAG-1: GetDiagnostics returns an LLM-friendly snapshot (channels, event ids,
  counts, config-repair report, pipeline errors) as plain JSON.
- FR-DIAG-2: Tools Diag runs read-only probes for external tools with full runner
  metadata; the temporary-firewall-rule probe always cleans up, even when
  verification fails.
- FR-DIAG-3: Firewall diagnostics aggregates provider/backend/scope, resolved RDP
  port, RdpAudit group rules, third-party interference and enforcement
  reconciliation into a single paste-able report.
- FR-DIAG-4: Service startup diagnostics work without IPC (SCM state and exit
  codes, log tails, Application event log reads, .NET runtime check, appsettings
  integrity, console self-test).
- FR-DIAG-5: CrashGuard installs process-wide last-resort handlers recording
  Critical OperationLogs, Windows Event Log entries and a ProgramData fallback
  file, even when the host is dying.

### 3.11 Storage
- FR-DB-1: SQLite via EF Core with WAL/synchronous/cache/FK PRAGMAs on every
  connection and a migration snapshot per stage; schema initialization runs before
  any dependent component.
- FR-DB-2: RetentionWorker prunes RawEvents governed by per-event retention
  without regressing durable per-IP summary counters; MaintenanceWorker handles
  Alerts, AbuseReports, ActiveBlocks, AttackStats, SessionIpCorrelations and
  RdpConnectionFacts past cutoffs.
- FR-DB-3: Forensic per-IP shards are fixed 128-byte records with CRC-32C guarded,
  double-buffered headers and O(1) ring eviction; ShardPath rejects traversal /
  reserved names and never derives paths from raw event text.
- FR-DB-4: The DEBUG-gated purge clears operational tables transactionally while
  preserving schema, migration history, DbProps and bookmarks.
- FR-DB-5: RetentionWorker can additionally run an optional frequency-oriented
  decimation pass (Storage.Decimation) that deletes only the middle of monotonically
  high-frequency (SourceIp, EventId) bursts; head/tail rows always survive, rare
  events and rows without a source IP are never candidates, and the pass is disabled
  by default so existing installations keep today's behaviour until an operator opts in.

### 3.12 Configurator UX conventions
- FR-UI-1: Every page with destructive actions confirms them; writes flow through
  the service IPC; the Configurator never opens the SQLite file directly in product
  paths.
- FR-UI-2: UI strings are English; grids sort by natural CLR type via
  GridValueComparer; timestamps render in local time via LocalTimeFormatter while
  the DB stays UTC.
- FR-UI-3: When public APIs exist for text output, stable English tokens are
  produced via the chcp-437 console or Get-NetFirewallRule JSON (locale-independent)
  for parsers.

### 3.13 Cross-host correlation (P4-18)
- FR-XH-1: CrossHostCorrelationWorker pulls bounded fact projections (summary only,
  never raw event XML) from each host in CrossHostOptions.AgentHosts over the
  admin-only named-pipe channel; poll interval, connect timeout and per-poll caps
  are configured in CrossHostOptions.
- FR-XH-2: CrossHostCorrelationEngine is pure and deterministic: the same fact set,
  host availability and nowUtc always produce the same chain candidates. Rules are
  plain data (CrossHostRules) and deduplication keys are lowercase hex SHA-256
  digests (CrossHostStableHash).
- FR-XH-3: One persisted CrossHostChain row exists per stable ChainKey (refreshed,
  never duplicated) and links exactly one CROSS_HOST_CHAIN alert; acknowledging a
  chain flips its flag and clears that alert.
- FR-XH-4: Agent-host credentials, when present, must be protected envelopes
  (ISecretProtector) - plaintext credentials never appear on disk, in logs or in
  IPC payloads.

### 3.14 Read-only REST API
- FR-API-1: The optional HTTPS REST API is disabled by default and fail-closed:
  RestApiPlanBuilder.Build resolves to Disabled / FailClosed / Listening, and no
  listener exists unless Enabled, a resolvable token and a trusted TLS certificate
  are all present.
- FR-API-2: Every GET/HEAD is answered by the existing audited IPC read handlers
  or the dedicated read-only event reader; the REST surface adds zero write paths
  (no settings, blocks, acknowledgements or session control).
- FR-API-3: The /events endpoint reads through a Mode=ReadOnly context factory, so
  its queries physically cannot write to the database; bearer-token auth guards
  every endpoint except /healthz; the token exists only as a protected DPAPI
  envelope and is never logged, echoed or returned over IPC.
- FR-API-4: The outer host itself binds no sockets (InertWebServer); the Kestrel
  listener is owned by RestApiHostedService, started after IPC and the database
  migrations.

### 3.15 SIEM export (Backlog #4)
- FR-SIEM-1: Core exposes pure CEF, LEEF 2.0 and NDJSON serializers over one neutral SiemEvent model; all external field values are escaped/neutralised per format before reaching the output stream.
- FR-SIEM-2: Events and correlated alerts are exported for one IP from the Configurator via the existing SaveFileDialog; the file is written as UTF-8 without BOM.
- FR-SIEM-3: The device version in CEF/LEEF headers comes from ServiceStatus.Version obtained over IPC GetStatus and is passed into the serializers as a parameter - never hardcoded.
- FR-SIEM-4: Per-IP alert export uses the append-only IPC ordinal 70 GetAlertsForIp (newest-first bounded window + TotalAlerts); ordinal 39 GetEventsForIp supplies the bounded raw-event window.
- FR-SIEM-5: Times render in UTC: CEF uses MMM dd yyyy HH:mm:ss +00:00, LEEF/NDJSON use ISO-8601 UTC, without any local time-zone shift.

### 3.16 Session Map timeline (Backlog #6)
- FR-TL-1: The Session Map feature is strictly read-only: one IPC command
  (GetSessionTimeline, append-only ordinal 72) and one Configurator tab; it
  never mutates service state and uses no new tables or migrations.
- FR-TL-2: Lifecycle phases (logon start, connected, reconnected,
  disconnected, logoff) are derived from RdpConnectionFacts; missing phases
  degrade gracefully (no exception, no empty value placeholders).
- FR-TL-3: Process/file activity is derived from RawEvents inside the fact's
  observation window, classified by event id (4688/4689 Process;
  4656/4657/4658/4663/5140/5145 File; otherwise Other); Other events are
  suppressed unless IncludeOtherEvents is true.
- FR-TL-4: All responses are bounded: activity cap default 500, clamped
  50..2000 server-side; when candidates exceed the cap the response carries
  Truncated=true and the pre-cap TotalMatching.
- FR-TL-5: Correlation is transparent: activity nodes carry an explicit
  correlation method (LogonId > SessionId > UserWindow); the weakest
  UserWindow fallback is always labelled so the operator sees the lower
  forensic confidence.
- FR-TL-6: The Configurator's Session Map tab lists facts through the existing
  ListConnectionFacts command, shows the selected timeline as an event table,
  and renders a GDI+ Gantt overview (SessionGanttPanel) with an active-session
  indicator and a truncation badge; no third-party chart libraries.

### 3.17 Threat-intel enrichment (Backlog #5)
- FR-TI-1: ThreatIntelEnrichmentWorker runs as a timed background worker
  (default interval 300 s, clamped via ThreatIntelLimits) and refreshes the
  reputation cache only for public, non-whitelisted IPs seen on AttackStats or
  recent RdpConnectionFacts; the pass silently no-ops when CheckEnabled,
  Enabled or CacheLookups is false, or when the API key is empty.
- FR-TI-2: Every provider lookup passes the fixed per-minute window
  (ThreatIntelRateLimiter) and the persisted daily budget
  (ThreatIntelUsageCounters); the worker stops the pass when either is
  exhausted.
- FR-TI-3: AbuseIpDbThreatIntelClient performs
  GET /api/v2/check?ipAddress&maxAgeInDays&verbose with the Key header taken
  from the DPAPI-protected AbuseIPDB key; private / reserved IPs are never
  sent to the provider.
- FR-TI-4: ThreatIntelLookupStore persists ThreatIntelLookups rows and arms
  NextRetryUtc from Retry-After on HTTP 429, clearing it on success; a fresh
  snapshot requires Outcome=Success and LookedUpUtc within CheckMaxAgeInDays.
- FR-TI-5: ThreatIntelClassifier is pure and fail-closed: IsHighRisk is true
  only for Successful, public, non-whitelisted lookups with a clamped score at
  or above ReportThreshold, so broken provider data can never manufacture a
  High-risk mark.
- FR-TI-6: The IPC read path stamps from cache only: GetAttackStats,
  ListConnectionFacts and GetRecentEvents receive IsHighRisk and
  ThreatIntelConfidenceScore through append-only DTO keys (AttackStatEntryDto
  21-22, ConnectionFactDto 23-24, RecentEventDto 13-14). No HTTP is ever
  issued on the IPC path, and the flag is informational - it never feeds
  auto-block enforcement.
- FR-TI-7: GetThreatIntelStatus (append-only ordinal 71) returns the
  ThreatIntelStatusDto cache status: CheckEnabled, TotalCacheRows,
  SuccessCacheRows, FreshSuccessRows, DailyUsage, DailyBudget,
  HighRiskThreshold, last-pass telemetry and per-outcome counts; the API key
  never leaves the service.
- FR-TI-8: The Check* settings live in AbuseIpDbOptions and are clamped
  server-side: CheckMaxLookupsPerMinute 1..300 (default 30),
  CheckMaxLookupsPerDay 1..995 (default 500), CheckMaxAgeInDays 1..365
  (default 30), CheckWorkerIntervalSeconds 30..86400 (default 300).
- FR-TI-9: The Stage15ThreatIntel migration creates the ThreatIntelLookups and
  ThreatIntelUsageCounters tables (append-only schema); Down removes both.
- FR-TI-10: The Configurator surfaces a High risk column in the Attack
  Statistics and Live Events grids (AttackStatRow.HighRiskDisplay /
  LiveEventRow.HighRiskDisplay) backed solely by the IPC High-risk fields.

### 3.18 Tray notifications
- FR-NOT-1: The RdpAudit.Notifier tray app runs elevated in the user's session
  and polls the service over the named-pipe IPC for new alerts; when disabled
  or the service is unreachable it exits / degrades silently without touching
  any file.
- FR-NOT-2: Notification filters honour the policy: enabled by default, minimum
  severity, per-rule and per-event visibility maps; disabled categories never
  surface a toast.
- FR-NOT-3: The toaster rate-limits to a sliding-window budget (default 10,
  clamped 1..60); surplus alerts within a window collapse into one aggregate
  toast with a count.
- FR-NOT-4: Phase 1 uses tray balloon tips; phase 2 (UseNativeToasts) prefers
  WinRT XML toasts and falls back to balloons when the native channel is
  unavailable. XML is built by a pure builder with strict escaping of
  untrusted text.
- FR-NOT-5: Autostart is opt-in: StartWithWindows registers / removes a logon
  task (schtasks ONLOGON /RL HIGHEST) pointing at the published notifier
  executable; absence of the exe or a failed registration surfaces as a client
  error, never silently.
- FR-NOT-6: Configuration round-trips through IPC GetNotificationSettings (78)
  and SaveNotificationSettings (79). The service clamps poll 1..60 and toasts
  1..60, normalizes severity with High fallback, and persists only the
  RdpAudit.Notifications section of appsettings.json; missing config resolves
  to safe defaults.
- FR-NOT-7: The notifier opens the database in read-only mode, never writes,
  and holds no secrets; all settings travel through IPC, never through shared
  files.

### 3.19 Read-only IIS web dashboard (RdpAudit.Web)
- FR-WEB-1: RdpAudit.Web serves the static read-only dashboard and proxies only
  /api/* to the loopback REST backend; the web surface adds zero write paths.
- FR-WEB-2: The proxy injects the vault bearer token server-side and strips any
  browser-supplied Authorization header; the token never reaches the browser or
  logs.
- FR-WEB-3: BackendBaseUrl is loopback-only and the backend TLS certificate is
  pinned by thumbprint; any request whose Host header is not a loopback literal
  (127.0.0.1 / localhost / ::1) is rejected with 400 before static files,
  security headers or the proxy run (DNS-rebinding defense).
- FR-WEB-4: Hardcoded security headers (nosniff, frame deny, referrer policy)
  are applied to every response; with AllowInlineScripts=false the CSP forbids
  inline script/style, so the dashboard ships external JS/CSS only.
- FR-WEB-5: The dashboard renders exclusively through DOM APIs (textContent);
  no innerHTML/eval; all data comes from the read-only REST endpoints.
- FR-WEB-6: Startup is fail-fast: an unreadable token vault or invalid
  configuration aborts the app instead of serving requests.
- FR-WEB-7: The Configurator "Web Access" tab owns the operator controls: a
  privacy-first Show switch (off by default), a phase-gated management checkbox
  (visible but disabled), the live IIS/web status, and the elevation-guarded,
  idempotent Install IIS / Configure IIS workflows whose buttons are enabled
  only after a successful fail-closed status probe.

---

## 4. Non-functional requirements

- NFR-PERF-1: Ingest/normalize hot paths are zero-allocation; no LINQ, string
  interpolation or boxed enumeration in per-event code; idle paths avoid busy-
  polling and 100% CPU spin.
- NFR-PERF-2: Bounded queries everywhere: page sizes, depth limits, row caps and
  time windows are clamped server-side so no request can scan/serialize whole
  tables; bounded newest-first slicing for stats.
- NFR-SEC-1: Secrets (AbuseIPDB key, MikroTik password, REST API bearer token,
  cross-host agent credentials) are DPAPI-protected at rest, never logged, never in
  DTOs, never leaked in IPC payloads; test/status DTOs carry only CredentialPresent
  flags.
- NFR-SEC-2: All external commands run via ProcessStartInfo.ArgumentList or fixed
  whitelisted command factories - no shell string concatenation with operator
  input, ever; path handling rejects traversal and derives nothing from raw event
  text.
- NFR-SEC-3: Event XML parsing is hardened against XXE, DTD injection, entity
  expansion, oversized documents and malformed encodings.
- NFR-REL-1: Durability boundaries are explicit: events + bookmarks cross one
  commit; shard commits use a dedicated connection and retain the pending queue on
  failure; atomic config writes (temp + rename); torn-write detection via
  double-buffered CRC headers.
- NFR-REL-2: Restart-safe exactly-once accounting via durable IngestionSequence
  with partial unique index backfill.
- NFR-LOC-1: Product behavior must not depend on the Windows UI culture:
  parsers are header-agnostic or pull English-stable JSON labels, OEM/console
  encodings are resolved per legacy code pages (cp866/cp437), SCM state decisions
  use numeric codes, UI remains English.
- NFR-MAINT-1: The complete solution builds and tests on Windows only: every project
  targets net8.0-windows and CI runs on the windows-latest runner
  (.github/workflows/build.yml). Core keeps its pure logic free of Win32 / I-O so it
  stays host-independent as a library, but the repository exercises it on Windows tests.
- NFR-MAINT-2: Every regression ships with a pinned test that reproduces the
  original evidence (real-host fixtures) and locks the stable contract.

---

## 5. Architecture boundaries

- **RdpAudit.Core** - domain models, EF entities/configurations, IPC contracts,
  config options, pure parsers/builders/formatters and decision helpers. No I/O,
  no Win32 APIs, no EF-session orchestration in helpers; platform-specific probes
  live behind interfaces. The Core keeps its pure logic free of Win32 / I-O so it
  stays host-independent as a library (it still builds as net8.0-windows like every
  project, and the repository's tests run on Windows).
- **RdpAudit.Service** - Windows service host: workers, EF-backed data access,
  firewall providers, IPC server, process spawning, registry/SACL access,
  bookmarks, retention/maintenance. All platform-coupled code lives here.
- **RdpAudit.Configurator** - WinForms UI: tabs, services for install/update/
  backup, IPC client, registry writer with backup guard, mstsc shadow launcher.
  Reads data through IPC only; local fallbacks only when the service is
  unreachable, clearly labeled as such.
- **RdpAudit.Mikrotik** - separate RouterOS setup/management tool (wizard,
  SSH/API clients, CA/PKI management, apply-sync panels).
- **RdpAudit.Web** - IIS-hosted read-only dashboard (site `RdpAuditWebUi`,
  loopback literal `https://127.0.0.1/`): serves the static HTML/JS pages and a
  loopback-only YARP proxy that injects the DPAPI vault bearer into `/api/*`
  calls to the REST listener; browser tokens are stripped, the backend
  certificate is pinned, and startup fails fast on an unreadable vault.
- Cross-cutting rule: anything two hosts need (Service + Configurator) belongs
  in Core behind a pure interface; both hosts supply platform-specific facts or
  runners into the pure engine.

---

## 6. Conventions and ABI stability rules

- C-1 Purpose headers: every source module starts with a Purpose comment
  describing responsibility and key invariants; PROJECT_MAP.md is generated from
  these headers.
- C-2 Pure-first design: logic is lifted into Core as static/pure classes
  whenever testable without a UI/OS host; UI seams stay thin.
- C-3 Append-only ABI: enum ordinals persisted to SQLite, IpcCommand ordinals,
  MessagePack [Key] indices, AttackThreatLevel ordinals and OperationLogSeverity
  ordinals are append-only: never reorder, never reuse, never remove; DTO fields
  may only be added at the end with safe defaults.
- C-4 Version pins: every release pins the exact version in assembly metadata
  plus tests that fail on drift; the RDP listener port must come from
  RdpListenerPortResolver - hardcoding 3389 (or any other literal) in product code
  is forbidden (55554 is documentation-example only).
- C-5 Localization contract: internal state is locale-independent (numeric codes,
  English-stable JSON keys, chcp-437 console); operator-facing time uses local
  clock via LocalTimeFormatter; DB and logs stay UTC.
- C-6 Tests: every change ships with unit tests that lock the contract and assert
  mock interactions; mock injections must assert what was called.
- C-7 Docs: README.md (user-facing), docs/50-ipc.md (IPC protocol),
  docs/51-rest-api.md (REST API contract), docs/20-service.md (service architecture),
  docs/91-troubleshooting.md, CHANGELOG.md; PROJECT_MAP.md regenerated from Purpose
  headers.

---

## 7. Out of scope / future

- Full IPsecBlockProvider implementation (composing with existing local/domain
  policies safely).
- Pure-ETW transport for the Security channel (protected system provider cannot
  be enabled by non-kernel real-time consumers - HybridEventSourceFactory keeps
  Security on EventLogWatcher).
- Direct EVTX binary readers and cross-boundary IPC event shims (interfaces
  reserved).
- Localized (non-English) Configurator UI.
- Additional external firewall providers beyond Windows Firewall, MikroTik and
  the experimental route-blackhole backend.
