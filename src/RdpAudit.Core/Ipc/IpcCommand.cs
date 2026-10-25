/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcCommand.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc)
// Purpose: Defines the append-only IPC command ABI shared by the Configurator and Service.
// Depends: System.Enum
// Extends: Append new commands at the end without changing any existing ordinal.

namespace RdpAudit.Core.Ipc;

/// <summary>Enumeration of IPC commands sent from Configurator to Service.</summary>
/// <remarks>
/// APPEND-ONLY ABI: ordinal values must NEVER be reused, reordered, or renumbered. Retired
/// commands are deprecated in place but keep their ordinal forever so deployed clients and
/// services across version skew never collide. Stage 1 reserves ordinals 11..31 even when the
/// corresponding handlers are not yet implemented in <c>IpcDispatcher</c>.
/// </remarks>
public enum IpcCommand
{
	Ping = 0,
	GetStatus = 1,
	GetRecentEvents = 2,
	GetRecentAlerts = 3,
	GetAddresses = 4,
	GetSessions = 5,
	AcknowledgeAlert = 6,
	BlockAddress = 7,
	UnblockAddress = 8,
	GetSettings = 9,
	SaveSettings = 10,

	// --- Stage 1 reservations (append-only). Handlers may return NotImplemented until later stages. ---
	GetFirewallStatus = 11,
	ListBlocklist = 12,
	ListWhitelist = 13,
	AddToBlocklist = 14,
	RemoveFromBlocklist = 15,
	AddToWhitelist = 16,
	RemoveFromWhitelist = 17,
	GetAttackStats = 18,
	ListRdpSessions = 19,
	DisconnectSession = 20,
	LogoffSession = 21,
	ShadowSession = 22,
	GetShadowPolicyStatus = 23,
	ApplyShadowPolicy = 24,
	BackupShadowPolicy = 25,
	RestoreShadowPolicy = 26,
	GetAbuseIpDbStatus = 27,
	TestAbuseIpDbKey = 28,
	GetMikroTikStatus = 29,
	TestMikroTik = 30,
	ListActiveBlocks = 31,

	// --- Stage 5 additions (append-only). ---
	ListLoginRules = 32,
	AddLoginRule = 33,
	RemoveLoginRule = 34,
	SetLoginRuleEnabled = 35,
	ListActiveBlocksDetailed = 36,
	UnblockActiveBlock = 37,

	// --- Stage A additions (append-only). ---
	/// <summary>Returns the operator-facing dashboard summary (attacks today, blocked IPs, sessions, failed logins, service health, DB size and growth).</summary>
	GetOverviewSummary = 38,

	/// <summary>Returns bounded recent / full-for-IP RawEvents plus summary metadata for one IP (export-all-IP-events context action).</summary>
	GetEventsForIp = 39,

	// --- Stage IP-D additions (append-only). ---

	/// <summary>Returns the most recent connection facts (LastSeenUtc desc), bounded by a server-clamped limit and filtered by optional IP / User substrings.</summary>
	ListConnectionFacts = 40,

	/// <summary>Returns bounded connection facts for a single IP plus aggregate counters (failed/successful logons, first/last seen, active flag).</summary>
	GetConnectionFactsForIp = 41,

	// --- Stage RDP-Config additions (append-only). ---

	/// <summary>Returns the current RDP listener configuration snapshot (port, fDenyTSConnections,
	/// NLA, SecurityLayer, single-session, hide-users, shadow mode, plus TermService context).</summary>
	GetRdpConfiguration = 42,

	// --- Stage Diag additions (append-only). ---

	/// <summary>Returns an LLM-friendly diagnostics snapshot: effective channels/event IDs, Security
	/// watcher state + last error + last event UTC, Security backfill telemetry, RawEvent and
	/// AuthAttemptFact counts grouped by channel/event ID, monitoring-config repair report, service
	/// version, install path, and recent pipeline errors. Used by the Configurator's Diagnostic tab.</summary>
	GetDiagnostics = 43,

	// --- Stage Diag2 additions (append-only). ---

	/// <summary>Runs a one-shot bounded Security-channel auth read inside the service process
	/// (under the service account) and returns AccessDenied vs Timeout vs NoEvents vs a parsed
	/// first event. The Configurator's "Run Security Auth Probe" button invokes this; it is the
	/// canonical way to disambiguate "Security Armed but zero events" symptoms from policy /
	/// permission / bookmark / backlog failure modes on a real host.</summary>
	RunSecurityAuthProbe = 44,

	// --- Stage 8 firewall-diagnostics addition (append-only). ---

	/// <summary>Returns a plain-text firewall enforcement diagnostics report: configured provider /
	/// backend / scope, resolved RDP listener port, per-provider availability, RdpAudit-group inbound
	/// block rules present in the Windows firewall store, enabled allow-inbound TCP ports, route /
	/// IPsec backend state, third-party firewall (e.g. Kaspersky) interference note, and a
	/// reconciliation of active-block database rows against verified firewall enforcement. Used by the
	/// Configurator's Firewall tab "Copy firewall diagnostics" button.</summary>
	GetFirewallDiagnostics = 45,

	// --- Stage 1.2.4 live enforcement reconciliation additions (append-only). ---

	/// <summary>Runs a live enforcement reconciliation pass: scans the real Windows Firewall (and
	/// other enabled backends) for RdpAudit rules, compares them against the DB-intended blocks, and
	/// returns a per-block status (Active / MissingRule / ParameterMismatch / Expired / Orphaned /
	/// ProviderUnavailable / EffectiveUnknown / Failed) plus a confidence (Verified /
	/// ExistsButProviderMayBypass / Missing / Failed / Unknown) and recommended next action. Also
	/// returns orphaned RdpAudit rules with no backing database row. RdpAudit never claims an IP is
	/// actively blocked unless a matching backend object is discovered here.</summary>
	ReconcileEnforcement = 46,

	/// <summary>Repairs one ActiveBlock row by id: re-installs the missing/mismatched firewall rule
	/// via the owning backend and re-reconciles, returning the post-repair reconciled row.</summary>
	RepairActiveBlock = 47,

	/// <summary>Emergency cleanup: removes every RdpAudit-created enforcement object (firewall rules,
	/// blackhole routes, IPsec objects if any) and marks the corresponding ActiveBlock rows Removed.
	/// Never deletes unrelated admin-created rules. Returns a per-category removal summary.</summary>
	RemoveAllEnforcement = 48,

	/// <summary>Repairs enforcement for one enabled BlockList row by id: ensures a matching ActiveBlock
	/// exists, (re-)installs the backend firewall rule, then re-reconciles to prove enforcement.
	/// Returns the post-repair reconciled row so the caller sees verified vs still-missing.</summary>
	RepairBlocklistEnforcement = 49,

	/// <summary>Repairs enforcement for every enabled BlockList row in one pass. Returns a summary
	/// with attempted / verified / failed counts plus per-row reconciled results.</summary>
	RepairAllEnabledBlocklistEnforcement = 50,

	// --- v1.2.6 AbuseIPDB report-log addition (append-only). ---

	/// <summary>Returns the most recent AbuseIPDB report-log rows (newest first), bounded by a
	/// server-clamped limit, for the Configurator's report-log grid. Never returns the API key.</summary>
	ListAbuseIpDbReportLog = 51,

	// --- v1.2.9 Tools Diag tab (append-only). ---

	/// <summary>Runs the read-only Tools Diag probe set (qwinsta / quser / netsh show rule / show
	/// allprofiles / command resolution / PowerShell firewall probe / RDP port read) through the
	/// English-command runner and returns each probe's full runner metadata plus a copyable report.
	/// Never creates or deletes firewall rules.</summary>
	RunToolsDiagnostics = 52,

	/// <summary>Runs the explicit, user-triggered temporary-firewall-rule probe for a supplied test IP:
	/// create a temporary block rule, verify it landed, then clean it up — reporting each step's exact
	/// command, exit code, stdout/stderr, rule name, rule handle and scanner backend.</summary>
	RunTemporaryFirewallRuleProbe = 53,

	// --- v1.3.1 DB maintenance (append-only). ---

	/// <summary>Collapses duplicate BlocklistEntry rows that share the same IP down to a single canonical
	/// row (preferring an enabled row, then the oldest by AddedUtc). Duplicates are soft-disabled and
	/// annotated with an audit trail rather than hard-deleted, so the action is reversible and traceable.
	/// Returns a structured report of the IPs collapsed and rows affected.</summary>
	DedupeBlocklistEntries = 54,

	// --- v1.3.2 guarded cleanup operations (append-only). ---

	/// <summary>Full blacklist cleanup: soft-disables every currently-enabled BlocklistEntry (per the
	/// reversible audit-trail convention, never hard-deleting rows), then synchronizes enforcement for
	/// every IP that no longer has an enabled entry — marking its Active / Pending ActiveBlock rows
	/// Removed and removing the RdpAudit-created firewall rules that backed them, plus any safe
	/// RdpAudit-owned orphan rules. Never touches unrelated / non-RdpAudit firewall rules. Returns a
	/// structured report with rows affected, active blocks removed, firewall and orphan rules removed,
	/// failures and a debug log.</summary>
	ClearAllBlocklist = 55,

	/// <summary>DEBUG-gated full firewall cleanup: removes every RdpAudit-owned firewall rule (matched
	/// strictly by the RdpAudit group / name convention) and synchronizes ActiveBlock rows to the
	/// non-enforced (Removed) state. Never deletes unrelated admin-created rules and never touches the
	/// BlocklistEntry table. Returns a structured report with rules found / removed, active blocks
	/// updated, failures and a debug log.</summary>
	ClearAllFirewallRules = 56,

	/// <summary>DEBUG-gated full application-data cleanup: transactionally clears the accumulated
	/// RdpAudit operational tables (raw events, auth-attempt facts, connection facts, active blocks,
	/// blocklist / whitelist entries, alerts, sessions, addresses, correlations, attack stats, abuse
	/// report history) while preserving schema, migrations and configuration. On SQLite it follows the
	/// purge with a WAL checkpoint (TRUNCATE) and a bounded <c>PRAGMA incremental_vacuum(5000)</c>, which
	/// releases free pages only when the store is in incremental auto-vacuum mode; a full VACUUM is never
	/// run on the live store, so the file itself shrinks only through the Configurator's offline compaction.
	/// Requires a typed confirmation phrase on the client. Returns a structured report with per-table row
	/// counts cleared, checkpoint / incremental-vacuum flags with the pages actually released, failures and
	/// a debug log.</summary>
	ClearAllApplicationData = 57,

	// --- v1.3.3 observability additions (append-only). ---

	/// <summary>Returns a bounded, filtered, paged window over the durable OperationLogs table (program
	/// actions — bans, firewall, settings, maintenance, IPC failures, background jobs — not security
	/// attack events) for the Configurator's Logs tab. The server clamps DepthDays and PageSize to safe
	/// ranges and populates DEBUG-only detail fields (DetailsJson, StackTrace) only when DEBUG mode is on.</summary>
	QueryOperationLogs = 58,

	/// <summary>Returns a light snapshot of the long-running historical analysis / backfill / indexing
	/// job (IsRunning, Stage, ProcessedRows, TotalRows, Percent, started/updated timestamps, current
	/// channel, last event, errors). Polled by the Overview tab so the UI opens immediately and shows a
	/// progress bar instead of blocking on a full historical analysis of a large database.</summary>
	GetOverviewProgress = 59,

	// --- v1.3.4 RDP Activity rebuild (append-only). ---

	/// <summary>Forces a single synchronous AttackStatsRefreshWorker projection pass (the same pass the
	/// 60-second background loop runs), then returns a short report with rows upserted, elapsed ms, and
	/// the post-rebuild AttackStats total. Used by the RDP Activity tab's DEBUG "Rebuild RDP Activity
	/// statistics" action to recover from a stale projection without restarting the service.</summary>
	RebuildAttackStats = 60,

	// --- v1.4.0 RdpAudit.Mikrotik module additions (append-only). ---

	/// <summary>Pushes a completed MikroTik api-ssl/mTLS bootstrap result from the RdpAudit.Mikrotik
	/// setup wizard into the running Service so the Service can adopt the mutual-TLS production channel
	/// (router IP, api-ssl port, DPAPI-wrapped service credentials, CA / client certificate thumbprints,
	/// address-list name and default ban timeout). The payload never carries plaintext secrets; the
	/// password travels as a DPAPI envelope and the certificates are referenced by thumbprint only.</summary>
	PushMikroTikConfig = 61,

	/// <summary>Returns the Service's current view of the MikroTik mutual-TLS channel health (configured
	/// router IP, api-ssl port, whether the firewall contour rules are installed, CA / client certificate
	/// thumbprints and a last-probe result). Polled by the RdpAudit.Mikrotik wizard's Apply &amp; Sync step
	/// to confirm the Service adopted the bootstrap. Never returns plaintext credentials.</summary>
	GetMikroTikMtlsStatus = 62,

	// --- v1.4.1 Auth Success per-login export (append-only). ---

	/// <summary>Returns a per-login (NormalizedUserName) roll-up of AuthAttemptFacts for one attacker
	/// IP: successful / failed / denied counts, first &amp; last seen, first &amp; last success, failed
	/// attempts before the first success, seconds-to-first-success, and the distinct success event ids,
	/// logon types, auth packages and failure reasons per login. Sourced entirely from AuthAttemptFacts
	/// (the v3 atomic source of truth) so it matches the Auth Success / Auth Failed grid columns. Backs
	/// the RDP Activity tab's "Export Auth Success (per login)" context action; the report is summary
	/// only — one row per account, never one row per attempt.</summary>
	GetAuthSuccessSummaryForIp = 63,

	// --- Stage 9 Event Collection additions (append-only). ---

	/// <summary>Returns the catalog-backed effective event collection and per-event retention settings.</summary>
	GetEventCollectionSettings = 64,

	/// <summary>Saves explicit Event Collection settings or applies a named catalog preset server-side.</summary>
	SaveEventCollectionSettings = 65,

	// --- Stage 13 cross-host correlation additions (append-only). ---

	/// <summary>Pulls bounded cross-host fact projections (summary only, no raw event XML) from an
	/// agent host over the admin-only named-pipe channel. The central correlation worker uses this
	/// as its poll transport; the Configurator uses it to verify an agent connection on demand.</summary>
	GetCrossHostFacts = 66,

	/// <summary>Returns a bounded, newest-first window over persisted cross-host attack chains for
	/// the Configurator's Cross-Host tab list grid.</summary>
	ListCrossHostChains = 67,

	/// <summary>Returns one persisted cross-host chain plus its ordered link list for the
	/// Configurator's Cross-Host tab details panel.</summary>
	GetCrossHostChainDetails = 68,

	/// <summary>Marks one persisted cross-host chain as acknowledged and clears the corresponding
	/// CROSS_HOST_CHAIN alert.</summary>
	AcknowledgeCrossHostChain = 69,

	// --- Stage SIEM additions (append-only). ---

	/// <summary>Returns bounded, newest-first correlated alerts for one IP plus a total counter,
	/// for the Configurator's SIEM export (CEF / LEEF / NDJSON). Deliberately omits alert Details
	/// so no raw forensic detail leaves the service through the export path.</summary>
	GetAlertsForIp = 70,

	// --- Stage 15 threat-intel additions (append-only). ---

	/// <summary>Returns the threat-intel enrichment subsystem status: whether checks are enabled,
	/// cache row counts, today's usage against the daily budget, the last background pass result
	/// and the latest per-outcome distribution of lookup results. Informational only - this status
	/// never exposes the AbuseIPDB API key and never performs a network call.</summary>
	GetThreatIntelStatus = 71,

	// --- Stage 16 session-map / session-timeline additions (append-only). ---

	/// <summary>Returns one session's bounded, chronologically ordered timeline: lifecycle phases
	/// from the RdpConnectionFact (logon start, connected, reconnected, disconnected, logoff) plus
	/// correlated process/file/other RawEvents activity inside the fact's observation window, with
	/// an explicit correlation method per activity node and a server-clamped activity cap
	/// (50..2000). Read-only; unknown fact ids return a typed NotFound status.</summary>
	GetSessionTimeline = 72,

	// --- Stage 16 process-monitoring additions (append-only). ---

	/// <summary>Forces one process identity (ProcessName, UserName, Domain, SessionId, optional
	/// auto-close flag) through the same baseline evaluation NewProcessRule uses, records a
	/// bounded ProcessObservations row and optionally raises a PROCESS_NEW alert. Used by the
	/// Configurator DEBUG "Report Process" button to verify the detector end-to-end.</summary>
	ReportProcessObservation = 73,

	/// <summary>Returns the bounded, newest-first list of PROCESS_NEW alert projections for the
	/// Configurator's process-monitoring alert panel. Deliberately omits raw alert Details so no
	/// raw forensic detail leaves the service through the list path.</summary>
	ListProcessAlerts = 74,

	/// <summary>Returns one PROCESS_NEW alert with its raw sanitised Details JSON and the
	/// persisted automated session-close response state (Queued / Completed / Failed).
	/// Unknown or non-PROCESS_NEW alert ids return a typed NotFound status.</summary>
	GetProcessAlertDetails = 75,

	/// <summary>Arms (or cancels, while still queued) the automated session-close response for
	/// one PROCESS_NEW alert. Append-only: a response already in a final state can never be
	/// re-queued, and arming always respects SessionControl.Enabled / AllowLogoff plus the
	/// auto-close rate limit. Disallowed states return Refused.</summary>
	SetProcessAutoClose = 76,

	/// <summary>Returns the effective process-monitoring configuration (baseline windows, alert
	/// window, auto-close default) and persisted subsystem statistics (KnownProcesses rows,
	/// alerts since start, auto-close queue counts). Informational only - never performs a
	/// session operation and never exposes raw event detail.</summary>
	GetProcessMonitoringStatus = 77,

// --- Stage Notifications additions (append-only). ---

/// <summary>Returns effective notification settings resolved to safe clamped values.</summary>
GetNotificationSettings = 78,

/// <summary>Saves notification settings; values are clamped server-side and persisted.</summary>
SaveNotificationSettings = 79,

// --- Stage 2a Database tab - server side (append-only). ---

/// <summary>Returns the bounded, sectioned snapshot of the evidence store for the Database
/// tab's Overview: database/WAL/SHM sizes, free space on the database and shard-tree volumes,
/// the shard-tree size and file count, per-table row counts, size growth and projected
/// time-to-cap from <c>DbSizeGrowthCalculator</c>, applied vs pending EF migrations, the
/// migration-failure-marker state, the effective retention-policy switches and the aggregated
/// deletion-ledger totals. Every section is bounded and independently failable: a section that
/// times out or fails degrades the snapshot to partial instead of failing the command.</summary>
GetDatabaseOverview = 80,

/// <summary>Returns the effective retention policy for the Database tab's Retention editor:
/// the global <c>StorageOptions</c> windows, every per-event-code <c>EventRetention</c>
/// override, and all <c>RetentionPolicyOptions</c> fields with both their configured and their
/// clamped effective values.</summary>
GetRetentionPolicy = 81,

/// <summary>Saves operator-edited retention settings: clamps and validates every value
/// server-side, refuses the whole request when any value is invalid (no partial write), merges
/// the retention sections into the existing appsettings.json document through
/// <c>SettingsManager</c>, upserts the per-event-code <c>EventRetention</c> rows, and writes an
/// OperationLog row carrying the old value, the new value and the invoking Windows identity.
/// The only mutating command of the Database tab's stage-2a surface.</summary>
SaveRetentionPolicy = 82,

/// <summary>Dry-run of the information-density retention pass. Uses the same trigger
/// enumeration, the same statistics snapshot and the same planner as the real pass, so the
/// reported per-code row counts equal what a real pass deletes on the same state. Read-only:
/// it never deletes a row and never writes a ledger entry.</summary>
PreviewRetention = 83,

/// <summary>Returns a bounded, newest-first, paged and filtered window over
/// <c>EventDeletionLedger</c> for the Database tab's Ledger grid. Read-only.</summary>
GetDeletionLedger = 84,

// --- Stage 2b Database backup and restore - server side (append-only). ---

/// <summary>Creates one consistent online snapshot of the live SQLite store without stopping the
/// service: the database copy plus a SHA-256 manifest under
/// <c>Backups\&lt;yyyyMMdd-HHmmss&gt;\db\rdpaudit.db</c>, then applies the snapshot retention. The
/// snapshot is refused, with the reason, when the destination volume cannot hold it, when there is no
/// database yet, or when the feature is disabled by <c>Storage:Backup:Enabled</c>. Mutating: writes
/// the artifact and one OperationLog row carrying the invoking identity, the snapshot count before
/// and after, and the resulting path.</summary>
CreateDatabaseBackup = 85,

/// <summary>Returns the newest-first inventory of database snapshots under the backup root with the
/// manifest verdict of each one, plus the effective retention and pre-migration settings. Read-only.
/// Directories in the same root that belong to another scope (settings, shadow policy) are counted but
/// not listed, so the operator can see that database retention will not touch them.</summary>
ListDatabaseBackups = 86,

/// <summary>Verifies one database snapshot, or the newest one when no name is supplied: recomputes the
/// SHA-256, runs <c>PRAGMA quick_check</c> on the copy, reads the manifest, and compares the snapshot's
/// schema against the running binaries so a restore that would downgrade the store is refused. Reports
/// damaged file, unreadable manifest and incompatible schema as distinct verdicts. Read-only: nothing
/// under the snapshot is written, moved or deleted.</summary>
VerifyDatabaseBackup = 87,

// --- Stage 3 Database tab UI support (append-only). ---

/// <summary>Returns the read-only shard-tree inventory for the Database tab's Shards section: every
/// .rdpshard file cross-referenced against the <c>IpEventSummary</c> shard metadata, plus orphan
/// files no summary row points at, plus a bounded tree aggregate. Read-safe: the command never
/// writes, moves, quarantines or deletes a shard file - capacity governance and orphan GC are later
/// stages - and the walk is bounded and skips reparse points so a pathological tree cannot turn a
/// read into an unbounded enumeration.</summary>
GetShardInventory = 88,

/// <summary>Runs ONE safe maintenance action selected by the request's kind (<c>quick_check</c>,
/// full <c>integrity_check</c>, <c>foreign_key_check</c>, <c>wal_checkpoint</c> PASSIVE or TRUNCATE,
/// bounded <c>incremental_vacuum</c>, or <c>optimize</c>) and returns a structured, monospace
/// report. Read-safe: no action deletes evidence rows. A full VACUUM does not exist in this surface
/// - the kind enum has no such member and any value outside the defined set is refused, because a
/// full VACUUM rewrites the entire file and can hold the writer lock for minutes on a live store
/// (docs/88 states the policy).</summary>
RunDatabaseMaintenance = 89,

/// <summary>Restores one database snapshot into an operator-chosen scratch directory: the snapshot
/// is verified first and a failed verification writes nothing; on success the database (and the
/// shard tree the snapshot carries) is copied into the requested directory through a staging file.
/// The live store is never touched, which is what makes this the safe restore path; replacing the
/// live database while the service is stopped is the Configurator's DatabaseRestoreService flow and
/// stays out of IPC. Mutating only inside the requested directory; writes one OperationLog row
/// carrying the invoking identity, the snapshot and the target.</summary>
RestoreDatabaseBackupToDirectory = 90,

/// <summary>Writes the whole shard capacity policy (enable, root, ring capacity, writer pool, file
/// budget, per-shard byte ceiling, whole-tree byte budget, disk floor, orphan grace period, and the
/// cardinality-guard thresholds) into the settings document through the existing settings writer, so
/// <c>IOptionsMonitor</c> picks it up with no service restart. Every value is validated and clamped on
/// the server before anything is written: a request with a structural fault is refused and NOTHING is
/// written. Writes one OperationLog row carrying the invoking identity plus the old and new policy.
/// This command governs shard writing only; it never moves, rewrites or deletes an existing shard.</summary>
SaveShardingPolicy = 91,

/// <summary>Collects shard files that no <c>IpEventSummary</c> row references any more and that have
/// not been written for at least the configured orphan grace period. <c>DryRun=true</c> returns the
/// candidate list and deletes nothing; an apply pass re-validates every candidate against the live
/// summary table, the live writer pool and the grace period, refuses anything outside the configured
/// actions root, and reports every path it removed. Deletions are audited per file with an
/// OperationLog row, and the pass is bounded by a per-run deletion budget so one call cannot
/// mass-delete a tree.</summary>
CollectShardGarbage = 92,

// --- Stage 5 storage hardening (append-only). ---

/// <summary>Compacts the evidence store. ALWAYS REFUSED on this path, and the refusal is the contract:
/// a full VACUUM rewrites the whole database file inside one write transaction, so on a
/// multi-gigabyte store it can hold the SQLite writer for minutes and stall ingestion. A service
/// that answers an IPC call is by definition running, so it can never be the process that performs
/// the rewrite. The answer carries the offline procedure plus the store's read-only page accounting
/// (page size, page count, freelist depth and the bytes currently allocated to freed pages) so the
/// operator can judge whether an offline compaction is worth stopping the service for. The compaction
/// itself lives in the Configurator (DatabaseCompactService): WAL checkpoint, VACUUM INTO a copy,
/// verify quick_check + row counts + migration history + foreign keys, then an atomic swap through
/// the same LiveDatabaseSwap mechanics the restore path uses.</summary>
CompactDatabase = 93,

/// <summary>Deletes every evidence row that belongs to one subject - a single IP, a CIDR range, a
/// login, or a UTC time window - across the tables that carry that dimension. <c>Apply=false</c> (the
/// default, and what an omitted payload means) is a pure DRY RUN that returns the per-table number of
/// affected rows and deletes nothing. An apply pass must carry the exact typed confirmation phrase,
/// is refused outright while a legal hold is in force, deletes in bounded batches inside short
/// transactions, and writes one EventDeletionLedger row per affected table with the honest scope,
/// window, reason and invoking identity - those rows join the ledger hash-chain like every other
/// deletion, so a subject purge is as auditable as a retention pass. Schema, EF migration history,
/// DbProps and event-log bookmarks are never touched, so the service stays reachable and never
/// re-reads the whole Security log.</summary>
PurgeBySubject = 94,

	/// <summary>Runs the RouterOS v7 security audit (rules S-00 … S-35 plus S-27b) against the
	/// configured router and returns the report: risk index, per-severity counts, one row per finding
	/// with evidence, reason, recommendation and ready commands, the menus the device does not have,
	/// and the finished Markdown. Read-only by construction — this command never writes to the router
	/// — and it never returns a credential: the SNMP community string and the /system note text are
	/// redacted before the report is built. When the provider is not configured or the router answers
	/// nothing, it returns IpcResultStatus.Unavailable with the transport reason, so an empty report
	/// can never be mistaken for a clean one.</summary>
	GetMikroTikSecurityAudit = 95,

	// --- Zabbix integration (append-only; ordinals 96-101). ---

	/// <summary>Reads the Zabbix connection settings with both credentials masked. The echo never
	/// carries a stored envelope, so a screenshot or a log of this DTO cannot leak a token.</summary>
	GetZabbixSettings = 96,

	/// <summary>Persists operator edits, clamped to the supported ranges, merged into the live settings
	/// document so every other section survives. An unchanged credential arrives as the mask
	/// placeholder and the stored envelope is written back verbatim; a blank value clears it.</summary>
	SaveZabbixSettings = 97,

	/// <summary>Probes the two endpoints separately — the trapper port the push needs and the JSON-RPC
	/// API provisioning needs — and reports which of them answered. A sender port that is not reachable
	/// is the single most common deployment fault (10051 is rarely forwarded through NAT), so the
	/// message names the port instead of saying "connection failed".</summary>
	TestZabbixConnection = 98,

	/// <summary>Runs one push cycle immediately and returns the server's own accounting of it. Runs even
	/// when the background worker is disabled (the operator asked explicitly) but still refuses a
	/// missing endpoint. The position is advanced only when the server accepted every value.</summary>
	PushZabbixNow = 99,

	/// <summary>Ensures the host group, the host, its seven items, its trigger set and the shared
	/// dashboard exist in Zabbix. Idempotent by construction: every object is looked up before it is
	/// created, nothing is updated and nothing is ever deleted. Read-only towards existing objects, so
	/// a second run reports "already present" instead of rewriting an operator's tuning.</summary>
	ProvisionZabbix = 100,

	/// <summary>Reads the push pipeline state: last attempt, last success, sequence, consecutive
	/// failures, the pending backlog and the incidents carried by the last accepted batch. Touches no
	/// network, so the tab can poll it freely.</summary>
	GetZabbixStatus = 101,

	// --- Editions (append-only; ordinal 102). ---

	/// <summary>Reports the edition, licence and capability matrix of the RUNNING service build: the
	/// edition name and ordinal, the product version, the cross-host host budget and one row per known
	/// capability with the lowest edition that contains it and whether this build has it. Read-only:
	/// it answers from compile-time constants only, so it cannot fail because a database, a provider or
	/// a network peer is unavailable. A Community service answering this command is the evidence that
	/// the gated workers are absent from the build rather than merely switched off by configuration.</summary>
	GetEditionInfo = 102,
}
