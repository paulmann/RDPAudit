// File:    src/RdpAudit.Core/Ipc/IpcCommand.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Enumeration of IPC commands sent from Configurator to Service.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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
	/// purge with a WAL checkpoint and VACUUM to reclaim space. Requires a typed confirmation phrase on
	/// the client. Returns a structured report with per-table row counts cleared, vacuum / checkpoint
	/// flags, failures and a debug log.</summary>
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
}
