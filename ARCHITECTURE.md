# ARCHITECTURE.md - RDPAudit 2.0

LLM-oriented architecture guide for the RDPAudit codebase. This document is the
navigation layer: system organization, data movement, and safe feature addition.
Sources of truth for details:

- PROJECT_MAP.md - per-file responsibilities (generated from Purpose headers).
- SPEC.md - requirements and invariants.
- docs/20-service.md - service internals (workers, durability, hardening).
- docs/50-ipc.md - the full named-pipe IPC ABI and command tables.
- docs/51-rest-api.md - the optional read-only HTTPS REST API (fail-closed plan, auth, endpoints).
- docs/91-troubleshooting.md - operator-facing failure playbooks.

---

## 1. LLM navigation guide

Read this before working on the code. Answer in order:

| Question | Where to look |
|---|---|
| Which files implement feature X? | §10 Symptom-to-File Map, then PROJECT_MAP.md. |
| How does data flow from event log to screen? | §4 End-to-end data flows. |
| Where may this code live (Core / Service / Configurator)? | §3 Dependency rules. |
| Which hard rules must not be broken? | §8 Key invariants. |
| How to add a feature of type Y? | §9 Change recipes - follow the matching recipe. |
| Which tests to add? | §11 Test strategy + per-recipe checklist. |
| Legacy edges and known limitations? | §12 Known limitations. |

Workflow rules:

1. Read SPEC.md first - it is the authoritative requirements document. If a
   requirement is ambiguous, search the code for the FR id in Purpose headers or
   tests before guessing.
2. Touch Core only when the logic is pure. Changes needing I/O, Win32, EF
   sessions or live processes belong in Service/Configurator behind interfaces.
3. Every change ships with a pinned test that reproduces the original evidence
   (real-host fixtures when available) and locks the stable contract.
4. ABI surfaces are append-only: enums persisted to SQLite, IpcCommand ordinals,
   MessagePack [Key] indices, IpcResultStatus ordinals.
5. Respect existing style: Purpose header on top of each source file, zero-
   allocation hot paths (no LINQ / string interpolation in per-event code),
   English-only code comments and UI strings.

---

## 2. System overview

RDPAudit is a Windows service + WinForms configurator stack for RDP attack
monitoring. Six runtime components:

| Project | Role | Runtime |
|---|---|---|
| RdpAudit.Service | Windows worker service (LocalSystem): ingest, persist, alert, enforce blocks, host the IPC server. | Windows only. |
| RdpAudit.Configurator | WinForms operator UI; reads/writes go through Service IPC, local fallbacks when service is down. | Windows only (admin). |
| RdpAudit.Mikrotik | Standalone RouterOS v7 setup wizard (SSH/REST API, CA/PKI management). | Windows only. |
| RdpAudit.Notifier | Elevated tray notifier: polls the service over IPC for new alerts and shows balloon / native WinRT toasts, degrading to a safe interval while the service is unreachable. | Windows session. |
| RdpAudit.Web | IIS-hosted read-only web dashboard + loopback YARP proxy: serves the static HTML/JS dashboard from wwwroot and forwards /api/* to the REST listener with the vault bearer injected server-side; no writes, no secrets ever reach the browser. | Windows only (IIS + ASP.NET Core Hosting Bundle). |
| RdpAudit.Core | Shared pure domain: models, EF entities, IPC contracts, config, parsers/formatters, decision engines, the cross-host correlation engine and the REST read model. No I/O, no Win32. | Windows-targeted build (net8.0-windows like every project); the logic itself is platform-independent. |

Test projects: RdpAudit.Core.Tests (pure logic), RdpAudit.Service.Tests
(workers/dispatcher with in-memory SQLite + fakes), RdpAudit.Mikrotik.Tests, RdpAudit.Configurator.Tests, RdpAudit.Notifier.Tests,
RdpAudit.Web.Tests,
RdpAudit.ScenarioTests. All test projects target net8.0-windows and run only on the windows-latest CI runner (.github/workflows/build.yml).
A standalone BenchmarkDotNet project (tests/RdpAudit.Benchmarks) benchmarks the ring buffer
and serializers outside the solution; run it via benchmarks.ps1.

Runtime topology (logical):
  Event Log + ETW (hybrid) --> Service --> SQLite (WAL) + per-IP shard files
  Firewall / MikroTik REST / AbuseIPDB v2 <--> Service (enforcement, outbound reports)
  Agent hosts --named pipe (CrossHost)--> Service (cross-host fact pulls)
  Configurator <--named pipe IPC--> Service
  Notifier <--named pipe IPC--> Service (polls for new alerts)
  Integration tooling <--HTTPS REST (read-only)--> Service (own Kestrel listener)
  Browser <--HTTPS loopback (RdpAuditWebUi site)--> RdpAudit.Web (YARP) --> Service (vault bearer injected on /api/*)
  Service --> ProgramData logs / backups / crash files

Service startup order (Program.cs + hosted workers):
1. ConfigureSerilog, then the single-instance mutex Global\RdpAuditService (SingleInstanceGuard; refusal exits with code 0x1000).
2. DI registration; options binding repairs stale appsettings.json (MonitoringConfigPostConfigure).
3. DatabaseInitializationWorker migrates schema and hydrates bookmarks; a fatal migration failure ends startup with exit code 20260814 (MigrationFailureExitCode).
4. IpcServerWorker, then RestApiHostedService (which resolves the fail-closed REST plan and owns the only Kestrel listener; the outer host runs on InertWebServer and binds no sockets).
5. Session-correlation hydration, event collection (collector + processor), backfill workers, alert/stats/block/reporting/maintenance workers, CrossHostCorrelationWorker and ThreatIntelEnrichmentWorker.

---
## 3. Dependency rules

Strict layered direction:
  Configurator --> Core
  Notifier     --> Core
  Service      --> Core
  Mikrotik     --> Core
  Core           (no outward project references)

Placement rules:
- Core: entities and EF configurations, IPC contracts, config option classes, pure parsers/builders/formatters/classifiers, decision engines and value models. Anything testable without a UI host, filesystem, network or OS API belongs here. Core targets net8.0-windows like every other project and its tests run on the windows-latest CI runner.
- Service: everything requiring Windows privileges or host lifecycle: workers, EF-backed queries, firewall providers, command spawning, registry/SACL access, named-pipe server, bookmarks, retention.
- Configurator: WinForms tabs and UI services. It never writes the SQLite database on product paths; mutations always go through IPC. Local fallback readers exist only so tabs work when the service is down, and they are clearly labeled as fallback origin (RdpConfigurationSnapshotSource, session fallback orchestrator).
- Notifier: elevated session tray app; polls the service over IPC for new alerts, holds no secrets and persists nothing, and degrades to a safe polling interval while the service is unreachable.
- Mikrotik: self-contained wizard; only the Core types it needs are shared.

Cross-cutting rule: when Service and Configurator need the same rule or evaluation, extract it into Core as a pure class taking plain data or delegates, and let each host inject its platform-specific readers/runners. Examples in the tree: LocalSessionEnricher, RdpSessionFallbackOrchestrator, ShadowGateDecision, FirewallProviderClassifier, EnforcementReconciler.

Hard no-gos:
- No WinForms / Win32 APIs / file I/O / HTTP in Core.
- No Service<->Configurator references in either direction.
- No direct DB writes from Configurator.
- No shell string concatenation with operator input anywhere.
- No hard-coded RDP port: always RdpListenerPortResolver.

---
## 4. End-to-end data flows

### 4.1 Real-time ingestion
1. EventCollectorHostedWorker (thin BackgroundService shim) builds per-channel sources and starts EventCollectorHost.
2. EventCollectorHost composes one IEventSource per channel via the selected IEventSourceFactory: HybridEventSourceFactory routes real-time-capable channels to EtwEventSource, the rest to EventLogWatcherEventSource (Security always stays on EventLogWatcher).
3. Each source converts events to canonical XML (EtwPayloadXmlFormatter for ETW, serialized EventRecord XML for EventLog) and writes RawEventDto into the shared IEventPipe.
4. FloodGuardEventPipe decorates the pipe: when FloodGuardEnabled, per-channel / source-IP flood decisions are applied before enqueue; AggregateOnly events are counted (FloodSuppressed) without entering the ring buffer, Sampled ones pass through, so a flood cannot evict higher-value evidence.
5. The pipe is RingBufferEventPipe over IRawEventBackend (SPSC RingBufferEventChannel or MPMC MpmcEventChannel); config selects the backend. TryWrite signals a semaphore that wakes the consumer.
6. EventProcessorWorker drains the pipe in batches, normalizes (EventNormalizer: PerEventIpResolver / IpNormalizer / session correlation cache), upserts facts, and commits RawEvents + bookmarks in one SQLite transaction.
7. BookmarkCheckpointLedger ties placeholders to ingestion sequences: a bookmark persists only after the events it would skip are committed.
8. Post-commit, ShardIngestionSink flushes forensic per-IP shard records on a dedicated connection (durability details in section 8).

### 4.2 Historical backfill
- SecurityBackfillWorker queries the Security log per event id (ReverseDirection=true, bounded MaxEvents, 24h latest backfill on first tick) so one failing id never starves the others; per-id outcomes land in ServiceMetrics.
- TerminalServicesBackfillWorker backfills TS-RCM / TS-LSM / RdpCoreTS channels through IEventPipe.TryWrite so they share the same processing path.
- Backfilled events pass through the alert historical-age gate (see 4.4).

### 4.3 Normalization and fact building
EventNormalizer converts XML to RawEvent (fields per FR-NORM-* in SPEC.md). Still inside the processor batch:
- AuthAttemptFactUpserter creates exactly one fact per authoritative Security event (4624/4625/4648/4768/4769/4771/4776/4825). RdpCoreTS / TCP / WTS never produce facts. NLA-stripped events recover IPs via RdpTransportIpCache at High/Medium confidence.
- RdpConnectionFactUpserter merges strong-key events into lifecycle facts, backfilling IPs later. SessionIpCorrelationUpserter records LogonId / (WtsSessionId, UserName) / UserName correlations.
- SessionCorrelationCache (in-memory, hydrated from DB by SessionCorrelationHydrationWorker) enriches IP-less events without touching the database.

### 4.4 Alert evaluation
1. AlertWorker picks unprocessed RawEvent rows inside the age ceiling (Alerts.AlertEventMaxAgeMinutes, default 5); older rows are marked processed without alerting.
2. It walks every registered IAlertRule (composed via AlertRuleRegistration); rules evaluate against IAlertContext (DbAlertContext over EF).
3. Emission goes through AlertCooldownTracker (per rule+key suppression). PrivilegedLoginRule additionally applies the service-SID filter, logon-type gate and per-minute budget.

### 4.5 Auto-block + enforcement reconciliation
1. FirewallAutoBlockWorker reads fresh alerts and applies the auto-block policy (whitelist precedence, threshold trips, login trip-wire). Provider failure never persists ghost ActiveBlock/BlocklistEntry rows.
2. IFirewallProvider implementations (WindowsFirewallProvider, MikroTikFirewallProvider, RouteBlackholeProvider, and the stubbed IPsecBlockProvider) drive the actual backends.
3. FirewallExpirationWorker unblocks due rows at ExpiresUtc and flips the row to Removed / Failed.
4. EnforcementReconciliationWorker + EnforcementReconciliationService compare DB intent against live backend scans (IFirewallRuleScanner) and publish reconciled status / repair / cleanup. The UI renders only reconciled data.

### 4.6 Attack statistics projection
1. AttackStatsRefreshWorker materializes per-IP AttackStat rows from AuthAttemptFact + ActiveBlocks, newest-first, bounded by MaxRawEventsPerPass and the look-back window.
2. AttackStatsAggregator does the deterministic projection; AttackThreatScoring computes the 0..100 score and green/yellow/red band.
3. The GetAttackStats IPC handler serves the projection with filters and clamping.

### 4.7 AbuseIPDB reporting
AbuseIpDbReportWorker periodically scans high-threat rows, passes the AbuseIpDbReportDecision policy (whitelist precedence, threshold, dedup window, hourly/daily caps) and submits via IAbuseIpDbClient. Each attempt persists to AbuseIpDbReportHistory; only successful rows gate the cooldown. AbuseIpDbCommentBuilder produces the sanitized report body; IpReportability blocks local/reserved IPs.

### 4.8 IPC round-trip
1. Configurator page calls IpcClient (SendAsync / SendRawAsync / SendDetailedAsync) with a per-command deadline from IpcConstants.TimeoutMsFor.
2. The client writes the uint32-LE + MessagePack frame to \\.\pipe\RdpAuditService.
3. IpcServerWorker accepts (instances = MaxConcurrent + 1, semaphore backpressure, per-connection deadline), decodes the frame and hands the command ordinal + JSON payload to IpcDispatcher.DispatchAsync.
4. The dispatcher routes to the operation handler, wraps failures in curated IpcResponse (no raw exceptions / secrets), and returns the JSON payload.
5. The page renders the payload; transport failures collapse to a typed outcome (legacy default / IpcCallResult), never an exception on the UI thread.

### 4.9 Cross-host correlation (P4-18)
1. CrossHostCorrelationWorker ticks on CrossHostOptions.PollIntervalSeconds (default 60) and walks the configured Hosts; ConnectTimeoutMs and MaxFactsPerPoll bound every pull (all three have hard clamps).
2. RemoteHostFactSource pulls one bounded fact projection per host over the same admin-only named-pipe channel the Configurator uses, without a group-wide guard delay.
3. Each host reports CrossHostAvailability (Available / Unavailable / Unknown); an unavailable host is fail-closed - no facts are ever invented for it.
4. CrossHostCorrelationEngine consumes the pure fact set + availability + nowUtc and emits deterministic chain candidates under the data-driven CrossHostRules; CrossHostStableHash builds the lowercase-hex dedup keys.
5. CrossHostFactExporter persists the pulled projections and upserts CrossHostChain rows (one row per stable ChainKey - refreshed, never duplicated).
6. CrossHostChainAlertProcessor projects each new/unacknowledged chain into a single CROSS_HOST_CHAIN alert via the pure CrossHostChainAlertFactory and links Chain.AlertId; IpcDispatcher exposes the tab's queries (ordinals 66-69).

### 4.10 REST API read path
1. RestApiPlanBuilder.Build resolves the fail-closed plan once at startup (Disabled / FailClosed / Listening); only a Listening plan attaches the Kestrel listener owned by RestApiHostedService - the outer worker host itself runs on InertWebServer and binds no sockets.
2. Every GET/HEAD route is answered by the existing audited IpcDispatcher read handlers (no mutation command is ever exposed) or by IPagedEventReader for /events.
3. /events reads through ReadOnlyAuditDbContextFactory (Mode=ReadOnly), so that surface physically cannot write to the database. Bearer-token auth protects every endpoint except /healthz; the token exists only as a protected DPAPI envelope, never in logs or DTOs.

### 4.11 Retention, maintenance, backup
- RetentionWorker prunes RawEvents per per-event retention without regressing durable per-IP summary counters, and runs the optional StorageOptions.Decimation pass after ordinary pruning (frequency-oriented burst decimation; head/tail rows always survive).
- MaintenanceWorker prunes alerts / abuse reports / active blocks / attack stats / session correlations / connection facts past cutoffs, snapshots DbSize into DbProps, runs PRAGMA incremental_vacuum, decays Address.ThreatScore.
- BackupRunner / RestoreRunner (Configurator) capture/restore audit policy (auditpol), registry/SACL (reg), service config (sc) and appsettings.json into ProgramData\RdpAudit\Backups\<yyyyMMdd-HHmmss> snapshots.

### 4.12 Threat-intel enrichment (Backlog #5, Stage 15)
1. ThreatIntelEnrichmentWorker ticks on AbuseIpDbOptions.CheckWorkerIntervalSeconds and picks candidate public, non-whitelisted IPs from AttackStats + recent RdpConnectionFacts (batch-capped); the per-minute fixed-window ThreatIntelRateLimiter and the persisted daily budget (ThreatIntelUsageCounters) gate every provider lookup.
2. AbuseIpDbThreatIntelClient issues AbuseIPDB GET /api/v2/check (Key header from the protected key, Retry-After back-off) through the 'AbuseIpDb' HttpClient; every response is classified fail-closed into a ThreatIntelLookupOutcome.
3. ThreatIntelLookupStore upserts ThreatIntelLookups cache rows (NextRetryUtc armed on 429, cleared on success) and increments the daily usage counter in the same pass.
4. The IPC read path (GetAttackStats, ListConnectionFacts, GetRecentEvents) stamps IsHighRisk + ThreatIntelConfidenceScore on rows from FRESH Success cache entries only, via the pure ThreatIntelClassifier; GetThreatIntelStatus (ordinal 71) reports cache counts, daily usage and last-pass telemetry. No HTTP ever runs on the IPC request path, and the flag never feeds auto-block.

### 4.13 Tray notifications
1. RdpAudit.Notifier (elevated session tray app) loads NotificationOptions through the named-pipe IPC GetNotificationSettings (78); the optional logon task (schtasks ONLOGON /RL HIGHEST) starts it after sign-in.
2. Each poll tick pulls the service's recent-alert window over the shared pipe and feeds candidates through NotificationFilter (minimum severity, per-rule / per-event visibility maps); disabled categories never surface.
3. ToastBudget rate-limits candidates in a sliding window (default 10, clamped 1..60); surplus alerts within a window collapse into one aggregate toast with a count.
4. Phase 1 presents tray balloon tips; with UseNativeToasts the ToastXmlBuilder produces strict-escaped WinRT XML and the router falls back to balloons when the native channel is unavailable.
5. While the service is unreachable the poller degrades to a safe interval; the app never writes files, holds no secrets, and never touches the database.

### 4.14 Web UI pipeline (RdpAudit.Web)
1. The Configurator "Web Access" tab runs a fail-closed IIS probe (registry InetStp, read-only DISM feature info, W3SVC service check) and enables the Install IIS / Configure IIS buttons only when the probe can actually declare the IIS state.
2. Install IIS runs the ordered plan in `IisInstallPlan`: elevation, then the DISM feature set (`IIS-WebServerRole`, `IIS-WebServer`, `IIS-StaticContent`, `IIS-DefaultDocument`, `IIS-HttpErrors`), then the IIS management tools (`IIS-WebServerManagementTools`, `IIS-ManagementScriptingTools`) that provide the `appcmd.exe` the Configure step drives, then the ASP.NET Core Hosting Bundle (`winget install --id Microsoft.DotNet.HostingBundle.8 --exact`) - the only source of the native `AspNetCoreModuleV2` that in-process hosting requires and no DISM feature provides - and finally a verification of what is on the machine. Already-satisfied items are skipped, so winget never runs when the module is present; every item is reported to `IisInstallProgressDialog`, which lists the plan before the run and marks each entry with a tick or a cross. No step adds `/Restart`: a requested reboot stays a warning.
3. Configure IIS stages the full RdpAudit.Web publish into %ProgramData%\RdpAudit\WebUI (SHA-256 manifest), stores the web bearer only as a DPAPI-protected envelope in the service appsettings.json, creates the `RdpAuditWebUi` site/app pool bound to `https://127.0.0.1:443` (loopback-only), and restarts the service.
4. A browser request hits the IIS site; static dashboard files are served from wwwroot with hardcoded security headers and strict CSP. Any Host header that is not a loopback literal is rejected with 400 before static files or the proxy run (DNS-rebinding defense).
5. `/api/*` requests are forwarded by the in-process YARP proxy to the REST listener at `https://127.0.0.1:8443`; the proxy injects the vault bearer server-side, strips any browser-supplied Authorization header, and pins the backend TLS certificate by thumbprint. No token ever reaches the browser or logs.

---
## 5. IPC contract (summary)

Authoritative detail lives in docs/50-ipc.md; this is the orientation layer.
- Transport: Windows named pipe \\.\pipe\RdpAuditService, ACL restricted to Builtin Administrators + LocalSystem, hosted by IpcServerWorker.
- Wire format: uint32 LE body length, then MessagePack IpcRequest / IpcResponse. The Payload inside is a JSON string (JsonOptions.Default); MessagePack carries optional Key-annotated DTO fields.
- Command ordinals: 0..79 defined (Ping=0 ... GetAlertsForIp=70, GetThreatIntelStatus=71, GetSessionTimeline=72, process-monitoring 73-77, notifications 78-79). Append-only; locked by IpcCommandStabilityTests.
- Timeouts: IpcConstants.TimeoutMsFor gives long-running commands (firewall repair / Tools Diag / temporary-rule probe) the long deadline, cheap reads the short one.
- Client: IpcClient swallows timeout/IO and returns default or IpcCallResult; never propagates to the UI thread.
- Server: handlers honour CancellationToken; responses never contain secrets; GetSettings masks secret envelopes as ***configured***.
- Concurrency: PipeInstances = MaxConcurrent + 1; semaphore backpressure between accept and handler handoff; silent clients reclaimed by deadline; ERROR_PIPE_BUSY classified as instance-cap saturation.

Command families by subsystem:
  Ordinals 0-10   Core status / events / settings
  Ordinals 11-17, 31, 36-37   Firewall, blocklist/whitelist/active blocks
  Ordinals 32-35  Login trip-wire rules
  Ordinal 18      Attack statistics
  Ordinals 19-26  RDP sessions + shadow policy
  Ordinals 27-28  AbuseIPDB status/test
  Ordinals 29-30  MikroTik status/test
  Ordinals 38-39  Overview summary + IP events export
  Ordinals 40-41  Connection facts list/query
  Ordinal 42      RDP listener configuration snapshot
  Ordinals 43-45  Diagnostics: snapshot, Security auth probe, firewall diagnostics
  Ordinals 46-50  Enforcement reconciliation / repair / emergency removal
  Ordinal 51      AbuseIPDB report log
  Ordinals 52-53  Tools Diag probes (read-only scan, temporary-rule probe)
  Ordinal 54      DB maintenance: blocklist dedupe
  Ordinals 55-57  Guarded cleanup (blocklist / firewall rules / app data)
  Ordinals 58-59  Operation logs query + long-job overview progress
  Ordinal 60      RDP Activity statistics rebuild
  Ordinals 61-62  MikroTik mTLS bootstrap push / status
  Ordinal 63      Auth success per-login export
  Ordinals 64-65  Event Collection settings get/save
  Ordinals 66-69  Cross-host correlation (facts pull, chains list/details, acknowledge)
  Ordinal 70      GetAlertsForIp - SIEM correlated-alert export for one IP
  Ordinal 71      GetThreatIntelStatus - threat-intel enrichment subsystem status (Stage 15)
  Ordinal 72      GetSessionTimeline - read-only per-session timeline (Session Map tab)
  Ordinals 73-77  Process monitoring (report observation, alert list/details, auto-close, status)
  Ordinals 78-79  Notifications (get/save notification settings)

Adding a command: see Recipe 9.1 in section 9 (DTO first under RdpAudit.Core.Ipc.Contracts, append the ordinal, handle in IpcDispatcher, consume via IpcClient).

---
## 6. Data model

Entity groups (all in RdpAudit.Core.Models, EF configs in Data/Configurations):

  Group        Entities                                            Notes
  Ingestion    RawEvent, Bookmark, IngestionSequence, EventCollectionAudit, EventEnablement, EventRetention   RawEvents carry ingestion metadata; bookmark XML keyed by channel.
  Facts        AuthAttemptFact, RdpConnectionFact, SessionIpCorrelation, Session    Atomic per-event facts (see invariants).
  Aggregates   Address, AttackStat, IpEventSummary, IpEventTypeCounter    Denormalized dashboards; derived from fact tables only.
  ThreatIntel  ThreatIntelLookup, ThreatIntelUsageCounter    Stage 15 /api/v2/check cache rows + persisted daily usage budget counters.
  Actions      Alert, ActiveBlock, BlocklistEntry, WhitelistEntry, LoginRule, AbuseReport, AbuseIpDbReportHistory   Auditable, source-tagged rows.
  CrossHost    CrossHostChain, CrossHostFact, CrossHostHostState, CrossHostLink    P4-18 persisted cross-host correlation facts, host states and attack chains.
  Ops          OperationLog, DbProp    Audit trail + generic key/value store.

Persistence conventions:
- SQLite via EF Core (AuditDbContext), PRAGMAs WAL / synchronous / FK enforced by SqlitePragmaInterceptor on every connection; migrations per stage; AuditDbInitializer serializes schema init before any dependent component.
- External SqliteTransaction sharing for the events+bookmarks durability boundary (BookmarkStore v2.0 raw UPSERT path).
- Timestamps UTC in DB; on-screen rendering local via LocalTimeFormatter.
- IPs normalized (IpNormalizer) before write; never a hostname, never a synthetic placeholder (SourceIpUnresolved flags missing values).
- Append-only integer-enum columns: ordinal reordering is a persisted-ABI break guarded by Stage2EnumStabilityTests / IpcCommandStabilityTests.
- Forensic shards are append-only files, not tables: fixed 128-byte ShardRecord with CRC-32C-guarded double-buffered ShardHeader, ring eviction, path canonicalized by ShardPath.

---
## 7. Configuration

- RdpAuditOptions (src/RdpAudit.Core/Config/RdpAuditOptions.cs) is the root service configuration, persisted into appsettings.json and hot-reloaded by IConfiguration.

Key sections (all in src/RdpAudit.Core/Config):
- MonitoringOptions: enabled channels + v3 auth event-id set (Security channel always present via MonitoringConfigRepair); IngestionMode (EventLog / Etw / Auto, invalid clamps to EventLog); pipeline flood protection.
- AlertOptions: alert thresholds + PRIVILEGED_LOGIN controls (AlertEventMaxAgeMinutes default 5, PrivilegedLoginSuppressionWindowMinutes default 5, PrivilegedLoginRateLimitPerMinute default 20).
- FirewallOptions: auto-block on thresholds, provider selection, static whitelist/blacklist arrays, instant-block triggers.
- FirewallEnforcementBackend: WindowsFirewall / RouteBlackhole (experimental) / IPsecPolicy (declared).
- FirewallBlockScope: RdpPortOnly vs AllInbound.
- MikroTikOptions: BaseUrl or Scheme/Host/Port composition, AddAttackerRules toggle, FilterChain/Action, BlockDuration, CommentPrefix; password wrapped by ISecretProtector before persistence.
- AbuseIpDbOptions: AbuseIPDB v2 key (DPAPI-protected), threshold and rate-limit settings, plus the Backlog #5 /api/v2/check enrichment switches (CheckEnabled, CheckMaxLookupsPerMinute, CheckMaxLookupsPerDay, CheckMaxAgeInDays, CheckWorkerIntervalSeconds - all clamped via ThreatIntelLimits).
- SessionControlOptions: AllowDisconnect / AllowLogoff / AllowShadow, RequireShadowPolicy.
- ShardingOptions: optional durable per-IP forensic shard storage.
- StorageOptions: database location, retention windows, log retention.
- LogsOptions: operation-log viewing depth and retention.
- DiagnosticsOptions: debug/log verbosity controls (DebugMode, LogEventXmlAtDebug, LogChannelDrops, LogAlertEvaluationTimings, MaxXmlBytesAtDebug).
- RingBufferBackend: SPSC vs MPMC event pipe.
- ApiOptions: optional, fail-closed read-only HTTPS REST API (Enabled switch, DPAPI-protected bearer token, listen address/port, TLS certificate resolution, rate limits). See docs/51-rest-api.md.
- CrossHostOptions: P4-18 pull transport schedule (poll interval, connect timeout, per-poll fact caps) plus the AgentHosts list; host credentials, when present, are protected envelopes.
- StorageOptions.Decimation: optional frequency-oriented decimation of raw event telemetry run by the retention worker after ordinary pruning (head/tail rows of each burst always survive).

Persistence and protection:
- SettingsManager validates, protects (ISecretProtector, DPAPI LocalMachine) and atomically writes appsettings.json.
- MonitoringConfigPostConfigure runs MonitoringConfigRepair on every materialization; ConfigRepairReporter surfaces the result in diagnostics.
- The ***configured*** placeholder sentinel never overwrites an existing protected envelope; explicit empty string clears a stored secret.

---
## 8. Key invariants

- Pure-first: all logic testable without UI/OS lives in Core as pure classes; OS host adapters stay thin.
- Zero-allocation hot path: no LINQ / string interpolation / boxed enumeration in per-event code.
- Atomic facts: AuthAttemptFact derives ONLY from authoritative Security events; rebuilding facts always yields identical counters.
- No ghost enforcement: IPs are reported blocked only when reconciliation finds a real backend object.
- Explicit durability boundaries: events + bookmarks share one commit; shard flush runs post-commit on a dedicated connection and retains its queue on failure.
- Append-only ABI: persisted enums, IpcCommand ordinals, MessagePack [Key] indices, IpcResultStatus ordinals.
- Secrets offline: keys/passwords never appear in logs, DTOs, IPC payloads or plaintext on disk.
- Locale-independence: state decisions use numeric codes / English-stable JSON; parsers tolerate Cyrillic input; UI stays English; DB/logs are UTC.
- No shell concat: all external commands use ProcessStartInfo.ArgumentList or fixed whitelisted factories.
- Port discipline: the only source of the RDP listener port is RdpListenerPortResolver; 3389 must never be a product constant.

---
## 9. Change recipes (scenario how-tos)

Each recipe lists the files to touch and the mandatory tests. Recipes are step-by-step; follow them in order. File paths are relative to the solution root.

### 9.1 Add an IPC command
1. Create request/response DTOs in src/RdpAudit.Core/Ipc/Contracts (MessagePack Key attributes; new keys append-only; never reuse retired indices).
2. Append the command to the IpcCommand enum (src/RdpAudit.Core/Ipc/IpcCommand.cs) at the next free ordinal.
3. Add the payload timeout to IpcConstants.TimeoutMsFor when the command is long-running.
4. Handle it in src/RdpAudit.Service/Ipc/IpcDispatcher.cs via DispatchAsync.
5. Consume it from the Configurator via src/RdpAudit.Configurator/Ipc/IpcClient.cs (SendAsync / SendRawAsync / SendDetailedAsync).
6. Document the command, payload and return shape in docs/50-ipc.md.
7. TESTS: RdpAudit.Service.Tests dispatcher test (fake deps); IpcCommandStabilityTests must stay green; no raw secrets / exceptions in responses; bounded clamping tests.

### 9.2 Add an alert rule
1. Implement IAlertRule or extend AlertRuleBase in src/RdpAudit.Service/Alerts; unique SCREAMING_SNAKE_CASE RuleId.
2. Register the rule in src/RdpAudit.Service/Alerts/AlertRuleRegistration.cs.
3. Add any new thresholds to src/RdpAudit.Core/Config/AlertOptions.cs (+ appsettings template in AppSettingsTemplate).
4. Hot path: return a cached null task without async/await when rejecting; allocate nothing per event.
5. TESTS: at least three in AlertRuleTests.cs - below threshold null, at threshold alert, whitelisted / wrong id null. Cooldown interplay via AlertCooldownTracker.

### 9.3 Add a table / column (EF Core migration)
1. Add/adjust the entity in src/RdpAudit.Core/Models and its mapping in src/RdpAudit.Core/Data/Configurations.
2. Generate a migration in src/RdpAudit.Core/Data/Migrations (timestamp_StageNName pattern); additive nullable/defaulted columns only; partial unique index pattern for backfilled columns (IngestionSequence precedent).
3. Update AuditDbContextModelSnapshot via the migration tooling.
4. TESTS: fresh-db schema test + upgrade-from-previous-stage test like Stage*SchemaTests / Stage*MigrationUpgradeTests; ordinal stability tests if the change touches persisted enums.

### 9.4 Add an event channel / event source
1. Register the event ids in src/RdpAudit.Core/Events/EventCatalog.cs (channel, layer, presets, criticality, dependencies, default retention).
2. Add/extend the ETW mapping in src/RdpAudit.Core/Events/EtwProviderMap.cs (or mark the channel non-realtime so HybridEventSourceFactory falls back to EventLogWatcher).
3. If it is an auth-outcome event, update SecurityAuthQuery XPath (src/RdpAudit.Core/Events/SecurityAuthQuery.cs) and AuthAttemptFactUpserter taxonomy (src/RdpAudit.Service/Processors/AuthAttemptFactUpserter.cs) - only if this event is meant to be an atomic fact carrier; otherwise leave facts alone.
4. Add the channel to the template appsettings (source: src/RdpAudit.Service/AppSettingsTemplate.cs) and to MonitoringConfigRepair defaults when the channel is mandatory.
5. TESTS: EventCatalog coverage/EtwProviderMap tests; parser tests with canned XML; backfill XPath shape tests; MonitoringConfigRepair tests when the default set changes.

### 9.5 Change firewall provider / auto-block policy
1. Policy comes first: adjust the auto-block decision tables in AutoBlockPolicy (src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs) and the pure routing/classification in src/RdpAudit.Core/Firewall (FirewallProviderClassifier, FirewallProviderRouting) with pure unit tests.
2. Implement IFirewallProvider (src/RdpAudit.Core/Firewall/IFirewallProvider.cs) in src/RdpAudit.Service/Firewall (look at WindowsFirewallProvider/RouteBlackholeProvider); also provide an IFirewallRuleScanner implementation for reconciliation and write OperationLog audit rows.
3. Wire the backend in appsettings (FirewallOptions.FirewallEnforcementBackend, FirewallBlockScope) and the provider selector.
4. TESTS: provider fake tests - switch returns expected provider; execution failure rolls back quarantine and never leaves ghost ActiveBlock/BlocklistEntry rows; scope RdpPortOnly vs AllInbound; reconciliation surfaces the emitted names/timestamps.

### 9.6 Tune auto-block sensitivity (no false blocks)
1. Re-read the decision semantics in AutoBlockPolicy (src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs) - thresholds, trip-wire, whitelist precedence - before changing numbers.
2. Change only thresholds/ranges in src/RdpAudit.Core/Config/FirewallOptions.cs and the template src/RdpAudit.Service/AppSettingsTemplate.cs; wire new knobs through SettingsManager validation.
3. Simulation: replay canned attack sequences against AutoBlockPolicy.Decide (tests/RdpAudit.Service.Tests/AutoBlockPolicyTests.cs) to prove boundary cases.
4. TESTS: below-trip-wire, exactly-at-threshold, over-threshold sequences; whitelist always wins; counting resets; no double-block for already-block IP (idempotence in ActiveBlock upserts).

### 9.7 Extend forensic shards
1. Extend ShardRecord layout only by adding fields after the last one; keep the 128-byte record size (src/RdpAudit.Core/Storage/Sharding/ShardRecord.cs); do not reorder existing fields.
2. Adjust the writer src/RdpAudit.Service/Storage/ShardIngestionSink.cs and the reader tools in tests.
3. TESTS: Shard journal tests - header CRC/sequence monotonicity, ring eviction, fixed record length, read-after-crash boundary (ShardWriterTests, ShardIngestionSinkTests, EventProcessorWorkerShardCommitTests, ShardCommitDurabilityScenarios).

### 9.8 Add a Configurator page / tab
1. Build the page in src/RdpAudit.Configurator/Forms (or extend an existing page); all data comes through IpcClient, never EF.
2. Render time values via LocalTimeFormatter; keep strings English (no localisation layer).
3. Long operations must be cancellable and must reflect transport failures as typed outcomes, not unhandled exceptions.
4. TESTS: page-logic tests inject a fake IpcClient and assert the IPC call, payload and render branch; no test may require WinForms runtime.

### 9.9 Add a settings option
1. Add the property to the matching RdpAuditOptions section in src/RdpAudit.Core/Config.
2. Add validation rules (range/allow-list) next to the property or in SettingsManager.
3. Update the template src/RdpAudit.Service/AppSettingsTemplate.cs and the settings page field mapping.
4. Secrets must go through ISecretProtector with the ***configured*** sentinel semantics, never plaintext.
5. TESTS: validation rejects bad values; save/load round-trip; secret envelope round-trip; config-repair keeps defaults when the file is broken.

---
## 10. Symptom-to-file map

  Symptom                                       Look here first
  Events stop flowing / pipe full               src/RdpAudit.Service/EventSources/EventCollectorHost.cs, Workers/EventProcessorWorker.cs, Infrastructure/RingBufferEventPipe.cs, src/RdpAudit.Core/Events/IEventPipe.cs
  Security events missing after config change   src/RdpAudit.Core/Config/MonitoringConfigRepair.cs, src/RdpAudit.Service/Services/MonitoringConfigPostConfigure.cs (hot-reload path)
  AuthAttemptFact table empty                    src/RdpAudit.Core/Events/SecurityAuthQuery.cs, src/RdpAudit.Service/Processors/AuthAttemptFactUpserter.cs
  RDP session IPs missing after NLA             src/RdpAudit.Service/Processors/RdpTransportIpCache.cs, SessionCorrelationCache.cs
  Alert fires / drops unexpectedly              src/RdpAudit.Service/Alerts/* + src/RdpAudit.Core/Config/AlertOptions.cs; cooldown interplay: AlertCooldownTracker
  Block not enforced / ghost rows               src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs (AutoBlockPolicy), src/RdpAudit.Core/Firewall/* (FirewallProviderClassifier, FirewallProviderRouting, EnforcementReconciler), providers, EnforcementReconciliation*
  AttackStats dashboard wrong                    src/RdpAudit.Core/Models/AttackStatsAggregator.cs, AttackThreatScoring.cs
  AbuseIPDB reports rejected / not sent         src/RdpAudit.Core/AbuseIpDb/AbuseIpDbReportDecision.cs, AbuseIpDbCommentBuilder.cs, src/RdpAudit.Core/Util/IpReportability.cs, src/RdpAudit.Service/AbuseIpDb/AbuseIpDbClient.cs
  Threat-intel cache cold / High-risk missing   src/RdpAudit.Service/Workers/ThreatIntelEnrichmentWorker.cs, ThreatIntel/AbuseIpDbThreatIntelClient.cs, ThreatIntel/ThreatIntelLookupStore.cs, ThreatIntel/ThreatIntelRateLimiter.cs, src/RdpAudit.Core/ThreatIntel/ThreatIntelClassifier.cs
  IPC hangs / deadlocks / busy                  src/RdpAudit.Service/Workers/IpcServerWorker.cs, src/RdpAudit.Service/Ipc/IpcDispatcher.cs; client: src/RdpAudit.Configurator/Ipc/IpcClient.cs, src/RdpAudit.Core/Ipc/IpcConstants.cs
  Settings lost / secret leaked                 src/RdpAudit.Service/Services/SettingsManager.cs, src/RdpAudit.Core/Security/*
  DB locked / idle corruption                   src/RdpAudit.Core/Data/SqlitePragmaInterceptor.cs, AuditDbInitializer.cs
  Migration breaks old database                  src/RdpAudit.Core/Data/Migrations/*
  Shard file corrupt / stops growing            src/RdpAudit.Core/Storage/Sharding/* + src/RdpAudit.Service/Storage/ShardIngestionSink.cs
  Backfill starves one event id                 src/RdpAudit.Service/Workers/SecurityBackfillWorker.cs
  Port 3389 hard-coded somewhere                src/RdpAudit.Core/Util/RdpListenerPortResolver.cs (the only allowed source)
  Cross-host tab empty / workers stuck          src/RdpAudit.Service/Workers/CrossHostCorrelationWorker.cs, CrossHost/RemoteHostFactSource.cs, src/RdpAudit.Core/CrossHost/CrossHostCorrelationEngine.cs
  REST API fails closed / 404 on /events        src/RdpAudit.Service/RestApi/RestApiPlanBuilder.cs, RestApiHostedService.cs, src/RdpAudit.Core/Data/ReadOnlySqlitePragmaInterceptor.cs
  Tray toasts skip / flood / settings lost      src/RdpAudit.Notifier/* (NotificationPoller, NotificationFilter, ToastBudget, ToastXmlBuilder), src/RdpAudit.Configurator/Forms/NotificationsPage.cs + Services/NotificationSettingsGateway.cs, service IpcDispatcher.Notifications.cs

Also see the file inventory inside src/RdpAudit.Service, src/RdpAudit.Core and src/RdpAudit.Configurator in PROJECT_MAP.md.

---
## 11. Test strategy

Test projects: tests/RdpAudit.Core.Tests, tests/RdpAudit.Service.Tests, tests/RdpAudit.Mikrotik.Tests, tests/RdpAudit.Configurator.Tests, tests/RdpAudit.Notifier.Tests, tests/RdpAudit.ScenarioTests.

- Layering: Core tests cover parsers, policies, catalog and format with canned XML / fixture samples; Service tests use in-memory SQLite + interfaces faked behind the host adapters; no test may require the real firewall, a real MikroTik device or a WinForms runtime.
- Pinned ABI suites: IpcCommandStabilityTests (IpcCommand ordinals), IpcResultStatus ordinal locks, MessagePack [Key] index locks, Stage*EnumStabilityTests for persisted enums. Any ordinal reordering fails CI by design.
- Migration tests: fresh-db schema test plus upgrade-from-previous-stage paths (Stage*SchemaTests / Stage*MigrationUpgradeTests).
- Shard tests: ShardJournalTests cover header CRC / sequence monotonicity, ring eviction, fixed record length and read-after-crash boundaries.
- Alert rules: AlertRuleTests pattern requires at least three cases per rule (below threshold null / at threshold alert / inapplicable null) plus cooldown interplay via AlertCooldownTracker.
- Page logic: Configurator tests inject a fake IpcClient and assert the IPC call, payload and render branch; transport failures collapse to typed outcomes.
- Test hygiene: per-test isolated SQLite files (PRAGMAs via SqlitePragmaInterceptor), no leaked static state between tests.

---
## 12. Known limitations

- Ingestion transport: EventLogWatcher + XML materialization is the default capture path (IngestionMode.EventLog). The hybrid ETW pipeline is implemented and selectable via IngestionMode.Etw / Auto (EtwEventSource, EventSourceFactorySelector, HybridEventSourceFactory, EtwProviderMap; see 4.1), but the protected Security channel always stays on EventLogWatcher and raw EVTX parsing is not implemented. High-rate behavior must be measured on the target host before an incident-response SLA is claimed. See docs/83-event-collection-implementation.md and docs/85-event-collection-residual-risks.md.
- SQLite write serialization: batching and WAL reduce but do not remove the single-writer model.
- Shards: live writing is disabled by default; no string heap (usernames, workstation/process names, domains, activity IDs are not retained); no cardinality guard (MaxShardFiles is only a creation budget); no disk-free floor, reader cache or operator timeline drill-down. Header/metadata commit follows the source SQLite transaction, so a crash in that interval can lose a derived record or leave metadata stale, but never makes a shard record authoritative over a missing RawEvents row. See docs/85-event-collection-residual-risks.md sections "Explicitly unimplemented work" and "Additional material risks".
- Incident timeline: IncidentTimelineBuilder is not implemented; no merged streaming timeline over detail rows + shard records.
- Install migration: the event-collection data migration is not resumable after interruption.
- Configurator caching: the Event Collection page has no independent cached snapshot layer or freshness policy; it refreshes through IPC.
- Enforcement backends: RouteBlackholeProvider is experimental (route.exe to an unreachable blackhole gateway on a full-device basis); IPsecPolicy is declared but not implemented. WindowsFirewall is the fully supported backend.
