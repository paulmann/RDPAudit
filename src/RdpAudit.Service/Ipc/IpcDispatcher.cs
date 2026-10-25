/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcDispatcher.cs
// Project: RdpAudit.Service (RdpAudit.Service.Ipc)
// Purpose: Dispatches IPC commands to service operations while returning curated client-safe responses.
// Depends: AuditDbContext, IpcRequest, IpcResponse, EventCatalog, IOperationLogWriter
// Extends: Add a handler and append-only IPC command when exposing a new service operation.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.MikroTik.SecurityAudit;
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Sessions;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Core.Util;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Services;
using RdpAudit.Service.Sessions;
using RdpAudit.Service.ThreatIntel;

namespace RdpAudit.Service.Ipc;

/// <summary>Dispatches IpcRequests to handlers and produces an IpcResponse.</summary>
public sealed partial class IpcDispatcher
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly SettingsManager _settings;
	private readonly FirewallManager _firewall;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly ILogger<IpcDispatcher> _logger;
	private readonly RdpSessionManager? _sessions;
	private readonly ShadowPolicyManager? _shadow;
	private readonly RdpConfigurationReader? _rdpConfigReader;
	private readonly IAbuseIpDbClient? _abuseClient;
	private readonly ISecretProtector? _protector;
	private readonly IMikroTikClient? _mikroTikClient;
	private readonly ConfigRepairReporter? _configRepair;
	private readonly SecurityAuthProbeService? _securityAuthProbe;
	private readonly Firewall.IRdpPortProvider? _rdpPortProvider;
	private readonly EnforcementReconciliationService? _reconciliation;
	private readonly ToolsDiagnosticsService? _toolsDiagnostics;
	private readonly ApplicationDataPurgeService? _dataPurge;
	private readonly IOperationLogWriter? _opLog;
	private readonly Core.Diagnostics.OverviewProgressState? _overviewProgress;
	private readonly Workers.AttackStatsRefreshWorker? _attackStatsWorker;
	private readonly Firewall.IFirewallRuleScanner? _ruleScanner;
	private readonly ThreatIntelLookupStore? _threatIntelStore;
	private readonly Workers.ThreatIntelEnrichmentWorker? _threatIntelWorker;
	private readonly KnownProcessStore? _processStore;
	private readonly SessionTimelineQueryService? _timelineQuery;
	private readonly DatabaseOverviewService? _databaseOverview;
	private readonly RetentionPolicyService? _retentionPolicy;
	private readonly RetentionPreviewService? _retentionPreview;
	private readonly DeletionLedgerQueryService? _deletionLedger;
	private readonly DatabaseBackupService? _databaseBackups;
	private readonly ShardInventoryService? _shardInventory;
	private readonly DatabaseMaintenanceService? _databaseMaintenance;
	private readonly ShardingPolicyService? _shardingPolicy;
	private readonly ShardGarbageCollectorService? _shardGarbageCollector;
	private readonly DatabaseCompactionService? _databaseCompaction;
	private readonly PurgeBySubjectService? _purgeBySubject;

	/// <summary>Zabbix push pipeline. Nullable by design: a host where the integration is composed
	/// away, or a test that builds this dispatcher by hand, reports the feature as unavailable
	/// instead of failing every Zabbix command.</summary>
	private readonly Zabbix.ZabbixPushService? _zabbix;

	/// <summary>B25: the fingerprint store, read only to render the tamper verdict on the Diagnostic tab.
	/// Nullable by design — a host that does not carry the store reports the chain state as UNKNOWN, which
	/// the UI must show as unknown rather than as a pass.</summary>
	private readonly StoreFingerprintStore? _fingerprints;

	/// <summary>Optional third-party firewall detection probe. Nullable by design: this
	/// dispatcher is shared across hosts, and not every host (or platform) registers a probe.
	/// Callers MUST null-check before use and fall back to "not suspected, not evaluated"
	/// rather than throwing — third-party detection is informational only and must never
	/// block a GetFirewallDiagnostics response.</summary>
	private readonly IThirdPartyFirewallProbe? _thirdPartyProbe;

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		FirewallManager firewall,
		IEnumerable<IFirewallProvider> providers,
		ILogger<IpcDispatcher> logger,
		RdpSessionManager? sessions = null,
		ShadowPolicyManager? shadow = null,
		IAbuseIpDbClient? abuseClient = null,
		ISecretProtector? protector = null,
		IMikroTikClient? mikroTikClient = null,
		RdpConfigurationReader? rdpConfigReader = null,
		ConfigRepairReporter? configRepair = null,
		SecurityAuthProbeService? securityAuthProbe = null,
		Firewall.IRdpPortProvider? rdpPortProvider = null,
		EnforcementReconciliationService? reconciliation = null,
		ToolsDiagnosticsService? toolsDiagnostics = null,
		ApplicationDataPurgeService? dataPurge = null,
		IOperationLogWriter? opLog = null,
		Core.Diagnostics.OverviewProgressState? overviewProgress = null,
		Workers.AttackStatsRefreshWorker? attackStatsWorker = null,
		Firewall.IFirewallRuleScanner? ruleScanner = null,
		IThirdPartyFirewallProbe? thirdPartyProbe = null,
		ThreatIntelLookupStore? threatIntelStore = null,
		Workers.ThreatIntelEnrichmentWorker? threatIntelWorker = null,
		SessionTimelineQueryService? timelineQuery = null,
		KnownProcessStore? processStore = null,
		DatabaseOverviewService? databaseOverview = null,
		RetentionPolicyService? retentionPolicy = null,
		RetentionPreviewService? retentionPreview = null,
		DeletionLedgerQueryService? deletionLedger = null,
		DatabaseBackupService? databaseBackups = null,
		ShardInventoryService? shardInventory = null,
		DatabaseMaintenanceService? databaseMaintenance = null,
		ShardingPolicyService? shardingPolicy = null,
		ShardGarbageCollectorService? shardGarbageCollector = null,
		DatabaseCompactionService? databaseCompaction = null,
		PurgeBySubjectService? purgeBySubject = null,
		StoreFingerprintStore? fingerprints = null,
		Zabbix.ZabbixPushService? zabbix = null)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
		_metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
		_options = options ?? throw new ArgumentNullException(nameof(options));
		_settings = settings ?? throw new ArgumentNullException(nameof(settings));
		_firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
		_providers = providers ?? throw new ArgumentNullException(nameof(providers));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_sessions = sessions;
		_shadow = shadow;
		_abuseClient = abuseClient;
		_protector = protector;
		_mikroTikClient = mikroTikClient;
		_rdpConfigReader = rdpConfigReader;
		_configRepair = configRepair;
		_securityAuthProbe = securityAuthProbe;
		_rdpPortProvider = rdpPortProvider;
		_reconciliation = reconciliation;
		_toolsDiagnostics = toolsDiagnostics;
		_dataPurge = dataPurge;
		_opLog = opLog;
		_overviewProgress = overviewProgress;
		_attackStatsWorker = attackStatsWorker;
		_ruleScanner = ruleScanner;
		_thirdPartyProbe = thirdPartyProbe;
		_threatIntelStore = threatIntelStore;
		_threatIntelWorker = threatIntelWorker;
		_timelineQuery = timelineQuery;
		_processStore = processStore;
		_databaseOverview = databaseOverview;
		_retentionPolicy = retentionPolicy;
		_retentionPreview = retentionPreview;
		_deletionLedger = deletionLedger;
		_databaseBackups = databaseBackups;
		_shardInventory = shardInventory;
		_databaseMaintenance = databaseMaintenance;
		_shardingPolicy = shardingPolicy;
		_shardGarbageCollector = shardGarbageCollector;
		_databaseCompaction = databaseCompaction;
		_purgeBySubject = purgeBySubject;
		_fingerprints = fingerprints;
		_zabbix = zabbix;
	}
	
	/// <summary>Best-effort durable operation-log record for an operator action taken through IPC.
	/// Never throws and never blocks the action (the writer is itself best-effort).</summary>
	private void LogOperation(OperationLogSeverity severity, string operation, string message, string? detailsJson = null)
	{
		if (_opLog is null)
		{
			return;
		}

		_ = _opLog.WriteAsync(new OperationLogEntry
		{
			Severity = severity,
			Source = "Ipc",
			Operation = operation,
			Message = message,
			DetailsJson = detailsJson,
			Actor = "Configurator",
		});
	}

	/// <summary>v1.3.9: DEBUG-only structured trace of a block create/update, capturing the exact
	/// expiry derivation so an operator can see WHY a row shows a finite expiry or "Never". Emitted only
	/// when <c>Diagnostics.DebugMode</c> is on; best-effort and never blocks the mutation.</summary>
	private void LogBlockMutationDebug(
		string operation,
		string ip,
		DateTime addedUtc,
		int requestedDurationMinutes,
		int defaultDurationMinutes,
		DateTime? expiresUtc,
		string source)
	{
		if (_opLog is null || !_options.CurrentValue.Diagnostics.DebugMode)
		{
			return;
		}

		int resolvedMinutes = BlockExpiryCalculator.ResolveDurationMinutes(
			requestedDurationMinutes, defaultDurationMinutes);
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"{0} {1}: AddedUtc={2:o}; RequestedDurationMinutes={3}; DefaultDurationMinutes={4}; "
				+ "ResolvedDurationMinutes={5}; ExpiresUtc={6}; Source={7}; Actor={8}.",
			operation,
			ip,
			addedUtc,
			requestedDurationMinutes,
			defaultDurationMinutes,
			resolvedMinutes,
			expiresUtc is { } e ? e.ToString("o", CultureInfo.InvariantCulture) : "Never",
			source,
			"Configurator");

		_ = _opLog.WriteAsync(new OperationLogEntry
		{
			Severity = OperationLogSeverity.Information,
			Source = "Ipc",
			Operation = operation,
			Message = message,
			Actor = "Configurator",
		});
	}

	/// <summary>v1.4.1: DEBUG-only structured trace for a Firewall-related IPC operation (whitelist /
	/// blocklist mutation, status query, reconcile, repair, unblock). Emitted only when
	/// <c>Diagnostics.DebugMode</c> is on so an operator can see exactly which inputs were supplied,
	/// which decision branch was taken, and what the outcome was when an action reports a failure.
	/// The optional <paramref name="detailsBuilder"/> is invoked lazily (only when DEBUG is on) so we
	/// never pay the cost of building a details string on the hot path when diagnostics are off.
	/// Best-effort: never throws and never blocks the action.</summary>
	private void LogFirewallDebug(string operation, string message, Func<string?>? detailsBuilder = null)
	{
		if (_opLog is null || !_options.CurrentValue.Diagnostics.DebugMode)
		{
			return;
		}

		_ = _opLog.DebugAsync("Firewall", operation, message, detailsBuilder);
	}

	/// <summary>Dispatches one request. <paramref name="callerIdentity"/> is the Windows identity of
	/// the peer on the other end of the IPC pipe, when the transport could resolve it
	/// (<c>NamedPipeServerStream.GetImpersonationUserName</c>); it is passed to the mutating handlers
	/// so an audited change can name the operator who requested it. The parameter is optional because
	/// in-process callers (the REST surface, tests) have no pipe and fall back to the service
	/// identity.</summary>
	public async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken ct, string? callerIdentity = null)
	{
		// v1.3.9: DEBUG-gated per-command IPC diagnostic — records command, success and elapsed time so an
		// operator can correlate a slow / failing Configurator action with the exact backend command.
		bool ipcDebug = _options.CurrentValue.Diagnostics.DebugMode;
		System.Diagnostics.Stopwatch ipcStopwatch = ipcDebug
			? System.Diagnostics.Stopwatch.StartNew()
			: new System.Diagnostics.Stopwatch();
		try
		{
			object? payload = request.Command switch
			{
				IpcCommand.Ping => "pong",
				IpcCommand.GetStatus => BuildStatus(),
				IpcCommand.GetRecentEvents => await GetRecentEventsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetRecentAlerts => await GetRecentAlertsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetAddresses => await GetAddressesAsync(ct).ConfigureAwait(false),
				IpcCommand.GetSessions => await GetSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.AcknowledgeAlert => await AcknowledgeAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.BlockAddress => await BlockAddressAsync(request.Payload, true, ct).ConfigureAwait(false),
				IpcCommand.UnblockAddress => await BlockAddressAsync(request.Payload, false, ct).ConfigureAwait(false),
				IpcCommand.GetSettings => GetMaskedSettings(),
				IpcCommand.SaveSettings => SaveSettings(request.Payload),

				// --- Stage 3 handlers (backend-only). UI is deferred to a later stage. ---
				IpcCommand.GetFirewallStatus => await GetFirewallStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.ListBlocklist => await ListBlocklistAsync(ct).ConfigureAwait(false),
				IpcCommand.ListWhitelist => await ListWhitelistAsync(ct).ConfigureAwait(false),
				IpcCommand.AddToBlocklist => await AddToBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromBlocklist => await RemoveFromBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.AddToWhitelist => await AddToWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromWhitelist => await RemoveFromWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocks => await ListActiveBlocksAsync(ct).ConfigureAwait(false),

				// --- Stage 5 handlers (Firewall tab UI support). ---
				IpcCommand.ListLoginRules => await ListLoginRulesAsync(ct).ConfigureAwait(false),
				IpcCommand.AddLoginRule => await AddLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveLoginRule => await RemoveLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.SetLoginRuleEnabled => await SetLoginRuleEnabledAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocksDetailed => await ListActiveBlocksDetailedAsync(ct).ConfigureAwait(false),
				IpcCommand.UnblockActiveBlock => await UnblockActiveBlockAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 6 handlers (Attack Statistics tab). ---
				IpcCommand.GetAttackStats => await GetAttackStatsAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 7 handlers (Remote RDP Clients tab). ---
				IpcCommand.ListRdpSessions => await ListRdpSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.DisconnectSession => await DisconnectSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.LogoffSession => await LogoffSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ShadowSession => ShadowSessionPolicyCheck(request.Payload),
				IpcCommand.GetShadowPolicyStatus => GetShadowPolicyStatusHandler(),
				IpcCommand.ApplyShadowPolicy => ApplyShadowPolicyHandler(request.Payload),
				IpcCommand.BackupShadowPolicy => BackupShadowPolicyHandler(),
				IpcCommand.RestoreShadowPolicy => RestoreShadowPolicyHandler(request.Payload),

				// --- Stage 8 handlers (AbuseIPDB integration). ---
				IpcCommand.GetAbuseIpDbStatus => await GetAbuseIpDbStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.TestAbuseIpDbKey => await TestAbuseIpDbKeyAsync(ct).ConfigureAwait(false),
				IpcCommand.ListAbuseIpDbReportLog => await ListAbuseIpDbReportLogAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 9 handlers (MikroTik integration). ---
				IpcCommand.GetMikroTikStatus => await GetMikroTikStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.TestMikroTik => await TestMikroTikAsync(ct).ConfigureAwait(false),
				IpcCommand.GetMikroTikSecurityAudit => await GetMikroTikSecurityAuditAsync(ct).ConfigureAwait(false),

				// --- Zabbix integration (ordinals 96-101). Settings are merged into the live document
				// so IOptionsMonitor picks them up without a restart; the test, the push and the
				// provisioning call all run off the request path of the pipe thread already.
				IpcCommand.GetZabbixSettings => GetZabbixSettingsHandler(),
				IpcCommand.SaveZabbixSettings => SaveZabbixSettingsHandler(request.Payload),
				IpcCommand.GetZabbixStatus => await GetZabbixStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.TestZabbixConnection => await TestZabbixConnectionAsync(ct).ConfigureAwait(false),
				IpcCommand.PushZabbixNow => await PushZabbixNowAsync(ct).ConfigureAwait(false),
				IpcCommand.ProvisionZabbix => await ProvisionZabbixAsync(ct).ConfigureAwait(false),

				// --- Editions (ordinal 102). Compile-time constants only: no database, no network, no
				// provider, so the answer survives a degraded host.
				IpcCommand.GetEditionInfo => GetEditionInfoHandler(),

				// --- Stage A handlers (Overview dashboard + IP events export). ---
				IpcCommand.GetOverviewSummary => await GetOverviewSummaryAsync(ct).ConfigureAwait(false),
				IpcCommand.GetEventsForIp => await GetEventsForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage IP-D handlers (RdpConnectionFacts read paths). ---
				IpcCommand.ListConnectionFacts => await ListConnectionFactsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetConnectionFactsForIp => await GetConnectionFactsForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage RDP-Config handler (RDP Configuration tab). ---
				IpcCommand.GetRdpConfiguration => GetRdpConfigurationHandler(),

				// --- Stage Diag handler (Diagnostic tab). ---
				IpcCommand.GetDiagnostics => await GetDiagnosticsAsync(ct).ConfigureAwait(false),

				// --- Stage Diag2: Security auth probe ---
				IpcCommand.RunSecurityAuthProbe => RunSecurityAuthProbeHandler(),

				// --- Stage 8: Firewall enforcement diagnostics ---
				IpcCommand.GetFirewallDiagnostics => await GetFirewallDiagnosticsAsync(ct).ConfigureAwait(false),

				// --- Stage 1.2.4: live enforcement reconciliation ---
				IpcCommand.ReconcileEnforcement => await ReconcileEnforcementAsync(ct).ConfigureAwait(false),
				IpcCommand.RepairActiveBlock => await RepairActiveBlockAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveAllEnforcement => await RemoveAllEnforcementAsync(ct).ConfigureAwait(false),
				IpcCommand.RepairBlocklistEnforcement => await RepairBlocklistEnforcementAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RepairAllEnabledBlocklistEnforcement => await RepairAllEnabledBlocklistEnforcementAsync(ct).ConfigureAwait(false),

				// --- v1.2.9: Tools Diag tab ---
				IpcCommand.RunToolsDiagnostics => await RunToolsDiagnosticsAsync(ct).ConfigureAwait(false),
				IpcCommand.RunTemporaryFirewallRuleProbe => await RunTemporaryFirewallRuleProbeAsync(request.Payload, ct).ConfigureAwait(false),

				// --- v1.3.1: DB maintenance ---
				IpcCommand.DedupeBlocklistEntries => await DedupeBlocklistEntriesAsync(ct).ConfigureAwait(false),

				// --- v1.3.2: guarded cleanup operations ---
				IpcCommand.ClearAllBlocklist => await ClearAllBlocklistAsync(ct).ConfigureAwait(false),
				IpcCommand.ClearAllFirewallRules => await ClearAllFirewallRulesAsync(ct).ConfigureAwait(false),
				IpcCommand.ClearAllApplicationData => await ClearAllApplicationDataAsync(request.Payload, ct).ConfigureAwait(false),

				// --- v1.3.3: observability (Logs tab + Overview progress) ---
				IpcCommand.QueryOperationLogs => await QueryOperationLogsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetOverviewProgress => GetOverviewProgressHandler(),

				// --- v1.3.4: RDP Activity rebuild ---
				IpcCommand.RebuildAttackStats => await RebuildAttackStatsAsync(ct).ConfigureAwait(false),

				// --- v1.4.1: Auth Success per-login summary (RDP Activity export) ---
				IpcCommand.GetAuthSuccessSummaryForIp => await GetAuthSuccessSummaryForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 9: Event Collection ---
				IpcCommand.GetEventCollectionSettings => await GetEventCollectionSettingsAsync(ct).ConfigureAwait(false),
				IpcCommand.SaveEventCollectionSettings => await SaveEventCollectionSettingsAsync(request.Payload, ct).ConfigureAwait(false),

				// --- P4-18: Cross-host correlation (agent-side pull) ---
				IpcCommand.GetCrossHostFacts => await GetCrossHostFactsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListCrossHostChains => await ListCrossHostChainsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetCrossHostChainDetails => await GetCrossHostChainDetailsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.AcknowledgeCrossHostChain => await AcknowledgeCrossHostChainAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage SIEM: correlated alerts for one IP (CEF / LEEF / NDJSON export). ---
				IpcCommand.GetAlertsForIp => await GetAlertsForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 15 handlers (threat-intel enrichment). ---
				IpcCommand.GetThreatIntelStatus => await GetThreatIntelStatusAsync(ct).ConfigureAwait(false),

				// --- Stage 16: Session Map timeline (Backlog #6). ---
				IpcCommand.GetSessionTimeline => await GetSessionTimelineAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage PM: process monitoring (PROCESS_NEW baseline + auto-close). ---
				IpcCommand.ReportProcessObservation => await ReportProcessObservationAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListProcessAlerts => await ListProcessAlertsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetProcessAlertDetails => await GetProcessAlertDetailsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.SetProcessAutoClose => await SetProcessAutoCloseAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetProcessMonitoringStatus => await GetProcessMonitoringStatusAsync(ct).ConfigureAwait(false),

				// --- Stage Notifications: tray notifier settings ---
				IpcCommand.GetNotificationSettings => GetNotificationSettingsHandler(),
				IpcCommand.SaveNotificationSettings => SaveNotificationSettingsHandler(request.Payload),

				// --- Stage 2a: Database tab server side (overview, retention, preview, ledger) ---
				IpcCommand.GetDatabaseOverview => await GetDatabaseOverviewAsync(ct).ConfigureAwait(false),
				IpcCommand.GetRetentionPolicy => await GetRetentionPolicyAsync(ct).ConfigureAwait(false),
				IpcCommand.SaveRetentionPolicy => await SaveRetentionPolicyAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),
				IpcCommand.PreviewRetention => await PreviewRetentionAsync(ct).ConfigureAwait(false),
				IpcCommand.GetDeletionLedger => await GetDeletionLedgerAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 2b: database backup and restore (snapshot, list, verify) ---
				IpcCommand.CreateDatabaseBackup => await CreateDatabaseBackupAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),
				IpcCommand.ListDatabaseBackups => await ListDatabaseBackupsAsync(ct).ConfigureAwait(false),
				IpcCommand.VerifyDatabaseBackup => await VerifyDatabaseBackupAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 3: Database tab UI support (shard inventory, maintenance, scratch restore) ---
				IpcCommand.GetShardInventory => await GetShardInventoryAsync(ct).ConfigureAwait(false),
				IpcCommand.RunDatabaseMaintenance => await RunDatabaseMaintenanceAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RestoreDatabaseBackupToDirectory => await RestoreDatabaseBackupToDirectoryAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),

				// --- Stage 4: shard capacity governance (policy save + orphan collection) ---
				IpcCommand.SaveShardingPolicy => await SaveShardingPolicyAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),
				IpcCommand.CollectShardGarbage => await CollectShardGarbageAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),

				// --- Stage 5: storage hardening (offline-compaction refusal + subject purge) ---
				IpcCommand.CompactDatabase => await CompactDatabaseAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),
				IpcCommand.PurgeBySubject => await PurgeBySubjectAsync(request.Payload, callerIdentity, ct).ConfigureAwait(false),

				_ => throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Unknown command: {0}", request.Command)),
			};

			if (ipcDebug)
			{
				ipcStopwatch.Stop();
				LogOperation(OperationLogSeverity.Information, "IpcCommand.Completed",
					string.Format(CultureInfo.InvariantCulture, "{0} succeeded in {1} ms.",
						request.Command, ipcStopwatch.ElapsedMilliseconds));
			}

			return new IpcResponse
			{
				Success = true,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
			};
		}
		catch (IpcException ex)
		{
			// IpcException is a controlled error class — its Message is curated and safe to surface.
			_logger.LogWarning(ex, "IPC dispatch returned controlled error for {Command}", request.Command);
			if (ipcDebug)
			{
				ipcStopwatch.Stop();
				LogOperation(OperationLogSeverity.Warning, "IpcCommand.Failed",
					string.Format(CultureInfo.InvariantCulture, "{0} returned controlled error after {1} ms: {2}",
						request.Command, ipcStopwatch.ElapsedMilliseconds, ex.Message));
			}

			return new IpcResponse { Success = false, Error = ex.Message };
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			return new IpcResponse { Success = false, Error = "Request cancelled." };
		}
		catch (Exception ex)
		{
			// Log full exception server-side; surface only generic class to the client.
			_logger.LogError(ex, "IPC dispatch failed for {Command}", request.Command);
			if (ipcDebug)
			{
				ipcStopwatch.Stop();
				LogOperation(OperationLogSeverity.Error, "IpcCommand.Failed",
					string.Format(CultureInfo.InvariantCulture, "{0} failed after {1} ms: {2}: {3}",
						request.Command, ipcStopwatch.ElapsedMilliseconds, ex.GetType().Name, ex.Message));
			}

			return new IpcResponse
			{
				Success = false,
				Error = string.Format(CultureInfo.InvariantCulture,
					"Internal service error processing {0}. See service logs for details.",
					request.Command),
			};
		}
	}

	private ServiceStatus BuildStatus()
	{
		using Process self = Process.GetCurrentProcess();
		string version = ResolveRuntimeVersion();
		Dictionary<string, string> channelStatus = _metrics.SnapshotChannels();
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(
			new SecurityVisibilityInputs(
				SecurityEventsRead: _metrics.SecurityEventsRead,
				Security4624Count: _metrics.Security4624Count,
				Security4625Count: _metrics.Security4625Count,
				Security4648Count: _metrics.Security4648Count,
				RdpCorePreAuthOrphans: _metrics.RdpCorePreAuthOrphans,
				SecurityWatcherEnabled: _metrics.SecurityWatcherEnabled,
				LastSecurityChannelError: _metrics.LastSecurityChannelError,
				ChannelStatus: channelStatus,
				LastRdpCorePreAuthUtc: _metrics.LastRdpCorePreAuthUtc,
				LastSecurityEventUtc: _metrics.LastSecurityEventUtc,
				SecurityBackfillLastRunUtc: _metrics.SecurityBackfillLastRunUtc,
				SecurityBackfillRecordsRead: _metrics.SecurityBackfillRecordsRead));

		return new ServiceStatus
		{
			Version = version,
			StartedUtc = _metrics.StartedUtc,
			Uptime = DateTime.UtcNow - _metrics.StartedUtc,
			ProcessId = self.Id,
			EventsCaptured = _metrics.EventsCaptured,
			EventsDropped = _metrics.EventsDropped,
			AlertsRaised = _metrics.AlertsRaised,
			ChannelStatus = channelStatus,
			Security4625Count = _metrics.Security4625Count,
			Security4624Count = _metrics.Security4624Count,
			Security4648Count = _metrics.Security4648Count,
			RdpCorePreAuthOrphans = _metrics.RdpCorePreAuthOrphans,
			LastSecurityEventUtc = _metrics.LastSecurityEventUtc,
			LastRdpCorePreAuthUtc = _metrics.LastRdpCorePreAuthUtc,
			SecurityCorrelationDiagnostic = _metrics.SecurityCorrelationDiagnostic,
			SecurityWatcherEnabled = _metrics.SecurityWatcherEnabled,
			SecurityEventsRead = _metrics.SecurityEventsRead,
			SecurityEventsNormalized = _metrics.SecurityEventsNormalized,
			SecurityEventsRejected = _metrics.SecurityEventsRejected,
			SecurityBackfillLastRunUtc = _metrics.SecurityBackfillLastRunUtc,
			SecurityBackfillRecordsRead = _metrics.SecurityBackfillRecordsRead,
			SecurityBackfillRecordsForwarded = _metrics.SecurityBackfillRecordsForwarded,
			SecurityBackfillRecordsDeduped = _metrics.SecurityBackfillRecordsDeduped,
			LastSecurityChannelError = _metrics.LastSecurityChannelError,
			LastSecurityRejectReason = _metrics.LastSecurityRejectReason,
			SecurityRejectReasonCount = _metrics.SecurityRejectReasonCount,
			LastAuthAttemptFactCreatedUtc = _metrics.LastAuthAttemptFactCreatedUtc,
			AuthAttemptFactCreated = _metrics.AuthAttemptFactCreated,
			AuthAttemptFactFailed = _metrics.AuthAttemptFactFailed,
			AuthAttemptFactSucceeded = _metrics.AuthAttemptFactSucceeded,
			SecurityLogMissing = flags.SecurityLogMissing,
			AuditPolicyMissingLogon = flags.AuditPolicyMissingLogon,
			SecurityReadDenied = flags.SecurityReadDenied,
			ChannelDisabled = flags.ChannelDisabled,
			BookmarkStaleOrLogRetentionGap = flags.BookmarkStaleOrLogRetentionGap,
			FirewallScanBackend = _metrics.FirewallScanBackend,
			FirewallScanSwitchCount = _metrics.FirewallScanSwitchCount,
		};
	}

	/// <summary>Resolves the runtime version surfaced in <see cref="ServiceStatus.Version"/>.
	/// Delegates to <see cref="RuntimeVersionResolver"/>, which is single-file-publish-safe and
	/// never calls System.Reflection.Assembly.Location (avoids IL3000).</summary>
	private static string ResolveRuntimeVersion() => RuntimeVersionResolver.Resolve();

	private async Task<object?> GetEventCollectionSettingsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		Dictionary<int, bool> enablements = await db.EventEnablements.AsNoTracking()
			.ToDictionaryAsync(row => row.EventId, row => row.IsEnabled, ct)
			.ConfigureAwait(false);
		Dictionary<int, int> retentions = await db.EventRetentions.AsNoTracking()
			.ToDictionaryAsync(row => row.EventId, row => row.RetentionDays, ct)
			.ConfigureAwait(false);

		List<EventCollectionSettingsDto> settings = new(EventCatalog.All.Count);
		foreach (EventDescriptor descriptor in EventCatalog.All)
		{
			bool isEnabled = enablements.TryGetValue(descriptor.EventId, out bool overrideEnabled)
				? overrideEnabled
				: descriptor.IsInPreset(EventPreset.Essential);
			int retentionDays = retentions.TryGetValue(descriptor.EventId, out int overrideRetention)
				? overrideRetention
				: descriptor.DefaultRetentionDays;

			settings.Add(new EventCollectionSettingsDto
			{
				EventId = descriptor.EventId,
				Channel = descriptor.Channel,
				DisplayName = descriptor.Description,
				Description = descriptor.EffectivePurpose,
				Criticality = descriptor.Criticality,
				Layer = descriptor.Layer,
				IsEnabled = isEnabled,
				RetentionDays = retentionDays,
			});
		}

		return settings;
	}

	private async Task<object?> SaveEventCollectionSettingsAsync(string? payload, CancellationToken ct)
	{
		EventCollectionMutationRequest request = ParseEventCollectionMutationRequest(payload);
		List<EventCollectionSettingsDto> settings = ResolveEventCollectionSettings(request);
		ValidateEventCollectionSettings(settings);
		bool isPresetOperation = request.Preset is EventPreset.Minimal or EventPreset.Essential or EventPreset.Full;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		await using var transaction = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
		DateTime nowUtc = DateTime.UtcNow;
		long nowTicks = nowUtc.Ticks;
		int changedRows = 0;

		foreach (EventCollectionSettingsDto setting in settings)
		{
			EventEnablement? enablement = await db.EventEnablements.FindAsync([setting.EventId], ct).ConfigureAwait(false);
			if (enablement is null)
			{
				db.EventEnablements.Add(new EventEnablement
				{
					EventId = setting.EventId,
					IsEnabled = setting.IsEnabled,
					UpdatedUtc = nowTicks,
				});
				changedRows++;
			}
			else if (enablement.IsEnabled != setting.IsEnabled)
			{
				enablement.IsEnabled = setting.IsEnabled;
				enablement.UpdatedUtc = nowTicks;
				changedRows++;
			}

			if (!isPresetOperation)
			{
				EventRetention? retention = await db.EventRetentions.FindAsync([setting.EventId], ct).ConfigureAwait(false);
				if (retention is null)
				{
					db.EventRetentions.Add(new EventRetention
					{
						EventId = setting.EventId,
						RetentionDays = setting.RetentionDays,
						UpdatedUtc = nowTicks,
					});
					changedRows++;
				}
				else if (retention.RetentionDays != setting.RetentionDays)
				{
					retention.RetentionDays = setting.RetentionDays;
					retention.UpdatedUtc = nowTicks;
					changedRows++;
				}
			}
		}

		if (changedRows > 0)
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		await transaction.CommitAsync(ct).ConfigureAwait(false);

		string operation = isPresetOperation
			? "EventCollection.ApplyPreset"
			: "EventCollection.SaveSettings";
		LogOperation(
			OperationLogSeverity.Information,
			operation,
			string.Format(
				CultureInfo.InvariantCulture,
				"{0} completed for {1} event settings; {2} persisted values changed at {3:o}.",
				operation,
				settings.Count,
				changedRows,
				nowUtc));

		return await GetEventCollectionSettingsAsync(ct).ConfigureAwait(false);
	}

	private static EventCollectionMutationRequest ParseEventCollectionMutationRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("Event Collection settings are required.");
		}

		try
		{
			return JsonSerializer.Deserialize<EventCollectionMutationRequest>(payload, JsonOptions.Default)
				?? throw new IpcException("Event Collection settings are required.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("Event Collection settings are invalid.", ex);
		}
	}

	private static List<EventCollectionSettingsDto> ResolveEventCollectionSettings(EventCollectionMutationRequest request)
	{
		if (request.Preset is EventPreset.Minimal or EventPreset.Essential or EventPreset.Full)
		{
			HashSet<int> enabledEventIds = new(EventCatalog.ExpandPreset(request.Preset));
			List<EventCollectionSettingsDto> presetSettings = new(EventCatalog.All.Count);
			foreach (EventDescriptor descriptor in EventCatalog.All)
			{
				presetSettings.Add(new EventCollectionSettingsDto
				{
					EventId = descriptor.EventId,
					IsEnabled = enabledEventIds.Contains(descriptor.EventId),
					RetentionDays = descriptor.DefaultRetentionDays,
				});
			}

			return presetSettings;
		}

		return request.Settings;
	}

	private static void ValidateEventCollectionSettings(List<EventCollectionSettingsDto> settings)
	{
		if (settings.Count == 0)
		{
			throw new IpcException("At least one Event Collection setting is required.");
		}

		HashSet<int> eventIds = new(settings.Count);
		foreach (EventCollectionSettingsDto setting in settings)
		{
			if (!EventCatalog.TryGet(setting.EventId, out _))
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"Event ID {0} is not present in the Event Collection catalog.",
					setting.EventId));
			}

			if (!eventIds.Add(setting.EventId))
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"Event ID {0} was supplied more than once.",
					setting.EventId));
			}

			if (setting.RetentionDays < 0)
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"Retention for Event ID {0} cannot be negative.",
					setting.EventId));
			}
		}
	}

	private async Task<object?> GetRecentEventsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<LiveEventTailEntry> rows = await db.RawEvents.AsNoTracking()
			.OrderByDescending(e => e.Id)
			.Take(200)
			.Select(e => new LiveEventTailEntry
			{
				Id = e.Id,
				EventId = e.EventId,
				Channel = e.Channel,
				TimeUtc = e.TimeUtc,
				SourceIp = e.SourceIp,
				SourceIpDerived = e.SourceIpDerived,
				SourceIpUnresolved = e.SourceIpUnresolved,
				UserName = e.UserName,
				Domain = e.Domain,
				LogonId = e.LogonId,
				LogonType = e.LogonType,
				AuthPackage = e.AuthPackage,
				ProcessName = e.ProcessName,
			})
			.ToListAsync(ct)
			.ConfigureAwait(false);

		await StampLiveEventThreatIntelAsync(rows, ct).ConfigureAwait(false);
		await StampLiveEventProcessNewAsync(rows, ct).ConfigureAwait(false);
		return rows;
	}

	/// <summary>Live-tail row returned by <c>GetRecentEvents</c>. Serialized as camelCase JSON to
	/// match the Configurator's <c>LiveEventRow</c> contract. <c>isHighRisk</c> /
	/// <c>threatIntelConfidenceScore</c> are append-only, fail-closed fields (default false / 0).</summary>
	private sealed class LiveEventTailEntry
	{
		public long Id { get; set; }
		public int EventId { get; set; }
		public string Channel { get; set; } = string.Empty;
		public DateTime TimeUtc { get; set; }
		public string? SourceIp { get; set; }
		public bool SourceIpDerived { get; set; }
		public bool SourceIpUnresolved { get; set; }
		public string? UserName { get; set; }
		public string? Domain { get; set; }
		public string? LogonId { get; set; }
		public int? LogonType { get; set; }
		public string? AuthPackage { get; set; }
		public string? ProcessName { get; set; }
		public bool IsHighRisk { get; set; }
		public int ThreatIntelConfidenceScore { get; set; }
		public bool IsProcessNew { get; set; }
	}

	/// <summary>True when the full threat-intel enrichment pipeline is switched on. Mirrors the
	/// worker's gate so IPC never stamps flags the background pipeline is not producing.</summary>
	private bool ThreatIntelPipelineEnabled()
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		return opts.Enabled && opts.CheckEnabled && opts.CacheLookups;
	}

	private int ThreatIntelMaxAgeDays() =>
		ThreatIntelLimits.ClampMaxAgeInDays(_options.CurrentValue.AbuseIpDb.CheckMaxAgeInDays);

	/// <summary>Cache-only batch read of fresh Success snapshots for the supplied IPs. Returns an
	/// empty map whenever the pipeline is off or the store is absent - never touches HTTP.</summary>
	private async Task<Dictionary<string, ThreatIntelLookup>> LoadThreatIntelSnapshotsAsync(
		IEnumerable<string> ips,
		CancellationToken ct)
	{
		if (_threatIntelStore is null || !ThreatIntelPipelineEnabled())
		{
			return new Dictionary<string, ThreatIntelLookup>(StringComparer.OrdinalIgnoreCase);
		}

		return await _threatIntelStore.GetFreshSnapshotMapAsync(ips, ThreatIntelMaxAgeDays(), ct).ConfigureAwait(false);
	}

	/// <summary>Fail-closed classification of one cached snapshot. Missing / non-Success rows yield
	/// (false, 0) so stale provider data can never manufacture a High-risk mark.</summary>
	private (bool IsHighRisk, int Score) ClassifyCachedThreatIntel(ThreatIntelLookup? row)
	{
		ThreatIntelLookupResult? result = ThreatIntelLookupStore.ToLookupResult(row);
		if (result is null)
		{
			return (false, 0);
		}

		return (
			ThreatIntelClassifier.IsHighRisk(result, _options.CurrentValue.AbuseIpDb.ReportThreshold),
			ThreatIntelClassifier.ClampScore(result.AbuseConfidenceScore ?? 0));
	}

	/// <summary>Stamps the live tail rows from cached snapshots only. No HTTP and no per-row DB
	/// reads: one batch map query for the whole page.</summary>
	private async Task StampLiveEventThreatIntelAsync(List<LiveEventTailEntry> rows, CancellationToken ct)
	{
		if (!ThreatIntelPipelineEnabled())
		{
			return;
		}

		Dictionary<string, ThreatIntelLookup> snapshots = await LoadThreatIntelSnapshotsAsync(
			rows.Where(r => !string.IsNullOrEmpty(r.SourceIp)).Select(r => r.SourceIp!), ct)
			.ConfigureAwait(false);

		foreach (LiveEventTailEntry row in rows)
		{
			if (string.IsNullOrEmpty(row.SourceIp) || !snapshots.TryGetValue(row.SourceIp, out ThreatIntelLookup? tiRow))
			{
				continue;
			}

			(row.IsHighRisk, row.ThreatIntelConfidenceScore) = ClassifyCachedThreatIntel(tiRow);
		}
	}

	/// <summary>Stamps IsProcessNew for the live tail rows from the persisted PROCESS_NEW alerts.
	/// A row is highlighted only when an alert row explicitly references its RawEvent id (the
	/// TriggerEventId NewProcessRule records), so a manually acknowledged alert stops
	/// highlighting the event while keeping the flag history intact. One batch query for the
	/// whole page - never per-row DB reads and never alert creation.</summary>
	private async Task StampLiveEventProcessNewAsync(List<LiveEventTailEntry> rows, CancellationToken ct)
	{
		if (rows.Count == 0)
		{
			return;
		}

		long[] eventIds = rows
			.Where(r => r.Id > 0)
			.Select(r => r.Id)
			.Distinct()
			.ToArray();
		if (eventIds.Length == 0)
		{
			return;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<long> flaggedIds = await db.Alerts.AsNoTracking()
			.Where(a => a.RuleId == KnownProcessStore.ProcessNewRuleId && a.TriggerEventId > 0 && eventIds.Contains(a.TriggerEventId))
			.Select(a => a.TriggerEventId)
			.ToListAsync(ct)
			.ConfigureAwait(false);
		HashSet<long> flagged = flaggedIds.ToHashSet();

		foreach (LiveEventTailEntry row in rows)
		{
			row.IsProcessNew = flagged.Contains(row.Id);
		}
	}

	/// <summary>Stamps the attack-statistics page entries from cached snapshots only. One batch
	/// cache query for the whole page; never touches HTTP providers.</summary>
	private async Task StampAttackStatsThreatIntelAsync(List<AttackStatEntryDto> entries, CancellationToken ct)
	{
		if (!ThreatIntelPipelineEnabled())
		{
			return;
		}

		Dictionary<string, ThreatIntelLookup> snapshots = await LoadThreatIntelSnapshotsAsync(
			entries.Where(e => !AttackStatsAggregator.IsSentinelUnresolvedIp(e.Ip)).Select(e => e.Ip), ct)
			.ConfigureAwait(false);

		foreach (AttackStatEntryDto entry in entries)
		{
			if (!snapshots.TryGetValue(entry.Ip, out ThreatIntelLookup? tiRow))
			{
				continue;
			}

			(entry.IsHighRisk, entry.ThreatIntelConfidenceScore) = ClassifyCachedThreatIntel(tiRow);
		}
	}

	/// <summary>Stamps the connection-facts page entries from cached snapshots only. One batch
	/// cache query for the whole page; never touches HTTP providers.</summary>
	private async Task StampConnectionFactsThreatIntelAsync(List<ConnectionFactDto> facts, CancellationToken ct)
	{
		if (!ThreatIntelPipelineEnabled())
		{
			return;
		}

		Dictionary<string, ThreatIntelLookup> snapshots = await LoadThreatIntelSnapshotsAsync(
			facts.Select(f => f.Ip), ct)
			.ConfigureAwait(false);

		foreach (ConnectionFactDto fact in facts)
		{
			if (!snapshots.TryGetValue(fact.Ip, out ThreatIntelLookup? tiRow))
			{
				continue;
			}

			(fact.IsHighRisk, fact.ThreatIntelConfidenceScore) = ClassifyCachedThreatIntel(tiRow);
		}
	}

	/// <summary>Cache-only status report for the Configurator threat-intel panel: row counts by
	/// outcome, today's usage against the daily budget and the last background pass telemetry.
	/// Never touches HTTP clients and never returns provider payloads or secrets.</summary>
	private async Task<object?> GetThreatIntelStatusAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		ThreatIntelStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			CheckEnabled = opts.CheckEnabled,
			DailyBudget = ThreatIntelLimits.ClampLookupsPerDay(opts.CheckMaxLookupsPerDay),
			HighRiskThreshold = opts.ReportThreshold,
		};

		if (_threatIntelStore is null)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Threat-intel store is not composed on this host.";
			return dto;
		}

		(int total, int success, int fresh, List<(int Outcome, int Count)> outcomeCounts, int dailyUsage) =
			await _threatIntelStore.GetStatusCountsAsync(_threatIntelStore.TodayKey(), ThreatIntelMaxAgeDays(), ct)
				.ConfigureAwait(false);

		dto.TotalCacheRows = total;
		dto.SuccessCacheRows = success;
		dto.FreshSuccessRows = fresh;
		dto.DailyUsage = dailyUsage;
		dto.OutcomeCounts = outcomeCounts
			.Select(o => new ThreatIntelOutcomeCountDto { Outcome = o.Outcome, Count = o.Count })
			.ToList();

		ThreatIntelPassTelemetry pass = _threatIntelWorker?.LastPass ?? default;
		dto.LastPassStartedUtc = pass.StartedUtc;
		dto.LastPassFinishedUtc = pass.FinishedUtc;
		dto.LastPassLookups = pass.Lookups;
		dto.LastPassError = pass.Error;

		dto.Message = ThreatIntelPipelineEnabled()
			? string.Format(CultureInfo.InvariantCulture,
				"ThreatIntel cache rows={0} success={1} fresh={2}; lookups today={3}/{4}.",
				total, success, fresh, dailyUsage, dto.DailyBudget)
			: "Threat-intel enrichment is disabled in the current configuration.";

		return dto;
	}

	private async Task<object?> GetRecentAlertsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Alerts.AsNoTracking()
			.OrderByDescending(a => a.Id)
			.Take(200)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetAddressesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Addresses.AsNoTracking()
			.OrderByDescending(a => a.LastSeen)
			.ThenByDescending(a => a.Id)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetSessionsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Sessions.AsNoTracking()
			.OrderByDescending(s => s.ConnectUtc)
			.ThenByDescending(s => s.Id)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> AcknowledgeAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("AcknowledgeAlert requires a payload with the alert id.");
		}

		long id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var alert = await db.Alerts.FindAsync(new object?[] { id }, ct).ConfigureAwait(false);
		if (alert is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Alert {0} not found.", id));
		}

		alert.Acknowledged = true;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return true;
	}

	private async Task<object?> BlockAddressAsync(string? payload, bool blocked, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("BlockAddress requires a payload with the IP address.");
		}

		string ip = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default)
			?? throw new IpcException("Invalid IP payload.");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var addr = await db.Addresses.FirstOrDefaultAsync(a => a.Ip == ip, ct).ConfigureAwait(false);
		if (addr is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Address {0} not found.", ip));
		}

		addr.IsBlocked = blocked;
		addr.BlockReason = blocked ? "Manual block via Configurator" : null;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		// Apply (or remove) the firewall block rule. On non-Windows hosts (tests) skip silently.
		if (OperatingSystem.IsWindows())
		{
			await ApplyFirewallChangeAsync(ip, blocked, ct).ConfigureAwait(false);
		}

		LogOperation(
			OperationLogSeverity.Warning,
			blocked ? "BlockAddress" : "UnblockAddress",
			string.Format(CultureInfo.InvariantCulture, "{0} {1} via Configurator.", blocked ? "Blocked" : "Unblocked", ip));
		return true;
	}

	[SupportedOSPlatform("windows")]
	private async Task ApplyFirewallChangeAsync(string ip, bool blocked, CancellationToken ct)
	{
		string ruleName = _options.CurrentValue.Firewall.BlockRuleName;
		if (string.IsNullOrWhiteSpace(ruleName))
		{
			ruleName = "RdpAudit-Block";
		}

		FirewallOperationResult result = blocked
			? await _firewall.BlockAsync(ruleName, ip, ct).ConfigureAwait(false)
			: await _firewall.UnblockAsync(ruleName, ip, ct).ConfigureAwait(false);
		if (!result.Success)
		{
			_logger.LogWarning("Firewall {Action} for {Ip} returned exit={Exit}",
				blocked ? "block" : "unblock", ip, result.ExitCode);
		}
	}

	private object SaveSettings(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("SaveSettings requires a JSON payload.");
		}

		// The IPC payload is the JSON document string wrapped in a single string by JsonSerializer at client.
		// Accept either form: a direct JSON-string payload (escaped string) or a raw JSON document.
		string body = payload;
		if (body.Length > 0 && body[0] == '"')
		{
			try
			{
				string? unwrapped = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
				if (!string.IsNullOrWhiteSpace(unwrapped))
				{
					body = unwrapped;
				}
			}
			catch (JsonException)
			{
				// not a wrapped string — use as-is.
			}
		}

		try
		{
			_settings.Save(body);
			LogOperation(OperationLogSeverity.Information, "SaveSettings", "Settings saved via Configurator.");
			return new { saved = true };
		}
		catch (JsonException ex)
		{
			throw new IpcException("Settings JSON is invalid: " + ex.Message);
		}
		catch (InvalidOperationException ex)
		{
			throw new IpcException(ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 3 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetFirewallStatusAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		FirewallStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredProvider = cfg.Provider,
		};

		foreach (IFirewallProvider provider in _providers)
		{
			FirewallStatusReport report;
			try
			{
				report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Failed to query provider {ProviderId}", provider.ProviderId);
				LogFirewallDebug("GetFirewallStatus.ProviderQueryFailed",
					string.Format(CultureInfo.InvariantCulture, "Provider '{0}' status query threw: {1}", provider.ProviderId, ex.Message),
					() => ex.ToString());
				continue;
			}

			bool available = report.Status == FirewallProviderStatus.Available;
			LogFirewallDebug("GetFirewallStatus.Provider",
				string.Format(CultureInfo.InvariantCulture, "Provider '{0}' status={1} (available={2}).", provider.ProviderId, report.Status, available),
				() => report.Message);
			if (string.Equals(provider.ProviderId, "Windows", StringComparison.OrdinalIgnoreCase))
			{
				dto.WindowsAvailable = available;
			}
			else if (string.Equals(provider.ProviderId, "MikroTik", StringComparison.OrdinalIgnoreCase))
			{
				dto.MikroTikAvailable = available;
			}
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		dto.ActiveBlockCount = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);
		dto.WhitelistCount = await db.WhitelistEntries.CountAsync(ct).ConfigureAwait(false);
		dto.BlacklistCount = await db.BlocklistEntries.CountAsync(b => b.IsEnabled, ct).ConfigureAwait(false);

		int enabledBlocklistRows = dto.BlacklistCount;
		dto.EnabledBlocklistRows = enabledBlocklistRows;

		// Never claim enforcement from DB rows alone — only live reconciliation verifies real firewall rules.
		if (_reconciliation is not null)
		{
			try
			{
				ReconciliationReportDto rec = await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);

				// A rule that exists but whose effective enforcement a third-party product may bypass is
				// still PRESENT in the store. Counting it as "not verified" made the health header claim
				// MISSING RULE while the rules were right there, so it counts as enforced-with-caveat and
				// the caveat is reported separately (per-block line plus the two fields below).
				int caveated = 0;
				foreach (ReconciledBlockDto block in rec.Blocks)
				{
					if (block.Confidence == EnforcementConfidence.ExistsButProviderMayBypass)
					{
						caveated++;
					}
				}

				int enforced = rec.VerifiedCount + caveated;
				dto.VerifiedEnforcedCount = enforced;
				dto.RdpAuditFirewallRuleCount = rec.VerifiedCount + rec.Orphans.Count;
				dto.EnforcementHealth = EnforcementReconciler.DeriveHealth(enabledBlocklistRows, enforced, rec.UnenforcedCount);
				dto.ThirdPartyFirewallSuspected = caveated > 0;
				dto.ThirdPartyFirewallNote = caveated > 0
					? string.Format(
						CultureInfo.InvariantCulture,
						"{0} of {1} block rule(s) exist in the Windows Firewall store, but a third-party security product (e.g. Kaspersky) may control effective packet filtering.",
						caveated,
						rec.Blocks.Count)
					: null;
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "GetFirewallStatus reconciliation failed");
				dto.EnforcementHealth = FirewallEnforcementHealth.Unknown;
			}
		}
		else
		{
			dto.EnforcementHealth = FirewallEnforcementHealth.Unknown;
		}

		dto.Message = EnforcementReconciler.DescribeHealth(dto.EnforcementHealth, enabledBlocklistRows, dto.VerifiedEnforcedCount);
		LogFirewallDebug("GetFirewallStatus.Done",
			string.Format(CultureInfo.InvariantCulture,
				"Status summary: provider={0}; windowsAvailable={1}; mikrotikAvailable={2}; activeBlocks={3}; enabledBlocklistRows={4}; verifiedEnforced={5}; health={6}.",
				dto.ConfiguredProvider, dto.WindowsAvailable, dto.MikroTikAvailable, dto.ActiveBlockCount,
				enabledBlocklistRows, dto.VerifiedEnforcedCount, dto.EnforcementHealth));
		return dto;
	}

	private async Task<object?> GetFirewallDiagnosticsAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;

		List<FirewallProviderDiagnostic> providers = new();
		string routeState = "(not registered)";
		string ipsecState = "(not registered)";
		foreach (IFirewallProvider provider in _providers)
		{
			FirewallStatusReport report;
			try
			{
				report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Diagnostics: failed to query provider {ProviderId}", provider.ProviderId);
				providers.Add(new FirewallProviderDiagnostic(provider.ProviderId, false, 0, "status query failed"));
				continue;
			}

			bool available = report.Status == FirewallProviderStatus.Available;
			providers.Add(new FirewallProviderDiagnostic(
				provider.ProviderId, available, report.ActiveBlockCount, report.Status + (report.Message is null ? string.Empty : " — " + report.Message)));

			if (string.Equals(provider.ProviderId, FirewallProviderRouting.RouteBlackholeProviderId, StringComparison.Ordinal))
			{
				routeState = report.Status + (report.Message is null ? string.Empty : " — " + report.Message);
			}
			else if (string.Equals(provider.ProviderId, FirewallProviderRouting.IPsecProviderId, StringComparison.Ordinal))
			{
				ipsecState = report.Status + (report.Message is null ? string.Empty : " — " + report.Message);
			}
		}

		// Resolve the real RDP listener port without hardcoding 3389: registry-backed provider on
		// Windows, documented default elsewhere (e.g. when running cross-platform in tests/dev).
		int rdpPort;
		bool fromRegistry;
		if (_rdpPortProvider is not null)
		{
			rdpPort = _rdpPortProvider.GetRdpPort();
			fromRegistry = rdpPort != RdpConfigurationModel.DefaultRdpPort;
		}
		else
		{
			rdpPort = RdpConfigurationModel.DefaultRdpPort;
			fromRegistry = false;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		int blocklistRows = await db.BlocklistEntries.CountAsync(b => b.IsEnabled, ct).ConfigureAwait(false);
		int activeRows = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);

		// Live reconciliation: never claim enforcement from DB rows alone. When the reconciliation
		// service is available, the verified count and per-IP detail come from a real firewall scan.
		List<ReconciledEnforcementLine> reconciledLines = new();
		List<string> orphanNames = new();
		int verifiedEnforced = 0;
		int rdpAuditRuleCount = 0;
		int caveatedEnforced = 0;

		// Collect third-party firewall facts on-demand. The probe is optional by design:
		// some hosts / test setups may not register it. Third-party detection is purely
		// informational and must never break the diagnostics response when unavailable.
		FirewallProviderDetectedKind tpKind = FirewallProviderDetectedKind.Unknown;
		string tpName = "Unknown";
		bool thirdPartySuspected = false;
		string? thirdPartyNote = null;

		if (_thirdPartyProbe is not null)
		{
			ThirdPartyFirewallSnapshot tpSnapshot = await _thirdPartyProbe
				.CollectAsync(ct)
				.ConfigureAwait(false);

			(tpKind, tpName) = FirewallProviderClassifier.Classify(
				tpSnapshot.Services,
				tpSnapshot.CliTools,
				tpSnapshot.KasperskyManagesWindowsFirewall);

			thirdPartySuspected =
				tpKind is FirewallProviderDetectedKind.KasperskyDetected
					or FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall
					or FirewallProviderDetectedKind.ThirdPartyFirewallUnknown;

			if (thirdPartySuspected)
			{
				thirdPartyNote = string.Format(
					System.Globalization.CultureInfo.InvariantCulture,
					"Detected: {0} (kind={1}). IMPORTANT: detection confirms product presence only; it does not prove NDIS/LWF packet filtering behavior or end-to-end enforcement in the presence of a third-party filter driver.",
					string.IsNullOrWhiteSpace(tpName) ? "third-party firewall/security product" : tpName,
					tpKind);
			}
		}


		string scannerBackend = "None";
		string? scannerNote = null;
		if (_reconciliation is not null)
		{
			ReconciliationReportDto rec = await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);
			verifiedEnforced = rec.VerifiedCount;
			rdpAuditRuleCount = rec.VerifiedCount;
			scannerBackend = rec.ScannerBackend;
			scannerNote = rec.ScannerNote;
			foreach (ReconciledBlockDto b in rec.Blocks)
			{
				reconciledLines.Add(new ReconciledEnforcementLine(
					Ip: b.Ip,
					Status: EnforcementReconciler.DescribeStatus(b.Status),
					Confidence: EnforcementReconciler.DescribeConfidence(b.Confidence),
					EnforcementObjectId: b.EnforcementObjectId,
					RecommendedAction: b.RecommendedAction)
				{
					LastError = b.LastError,
					LastAttemptUtc = b.LastAttemptUtc,
					BackendCommand = b.BackendCommand,
					BackendStdoutPreview = b.BackendStdoutPreview,
					BackendStderrPreview = b.BackendStderrPreview,
					ExitCode = b.ExitCode,
					TimedOut = b.TimedOut,
					DurationMs = b.DurationMs,
					RuleName = b.RuleName,
					RuleHandle = b.RuleHandle,
					ScannerBackend = b.ScannerBackend,
					VerifierReason = b.VerifierReason,
				});

				if (b.Confidence == EnforcementConfidence.ExistsButProviderMayBypass)
				{
					thirdPartySuspected = true;
					thirdPartyNote ??= "Windows Firewall rule verified; a third-party provider (e.g. Kaspersky) "
						+ "may control effective enforcement.";
					caveatedEnforced++;
				}
			}

			// A rule that exists but may be bypassed is still PRESENT: without this the diagnostics text
			// reported "0 verified" next to a per-block line saying the rule was found.
			verifiedEnforced += caveatedEnforced;
			rdpAuditRuleCount += caveatedEnforced;

			foreach (ReconciledBlockDto o in rec.Orphans)
			{
				if (!string.IsNullOrEmpty(o.EnforcementObjectId))
				{
					orphanNames.Add(o.EnforcementObjectId);
				}
			}
		}
		else
		{
			// Fallback proxy when reconciliation is unavailable: an Active row with a rule handle.
			verifiedEnforced = await db.ActiveBlocks
				.CountAsync(b => b.Status == ActiveBlockStatus.Active && b.RuleHandle != null && b.RuleHandle != string.Empty, ct)
				.ConfigureAwait(false);
			rdpAuditRuleCount = verifiedEnforced;
		}

		// Project the live RdpAudit rule shapes so the report can flag rules that no longer match the
		// configured block scope (e.g. AllInbound rules left over after switching to RdpPortOnly). The
		// scan is best-effort: any failure leaves the shapes empty and the report says "not scanned"
		// rather than fabricating a mismatch.
		List<FirewallRuleShape> ruleShapes = new();
		if (_ruleScanner is not null)
		{
			try
			{
				string prefix = Firewall.NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);
				Firewall.FirewallScanResult shapeScan =
					await _ruleScanner.ScanRdpAuditBlockRulesAsync(prefix, ct).ConfigureAwait(false);
				foreach (DiscoveredBlockRule r in shapeScan.Rules)
				{
					if (r.DirectionInbound && r.ActionBlock)
					{
						ruleShapes.Add(new FirewallRuleShape(r.RuleName, r.Protocol, r.LocalPorts));
					}
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Firewall rule-shape scan for block-scope diagnostics failed");
			}
		}

		FirewallDiagnosticsInput input = new(
			ConfiguredProviderKind: cfg.Provider.ToString(),
			ConfiguredEnforcementBackend: cfg.EnforcementBackend.ToString(),
			ConfiguredBlockScope: cfg.BlockScope.ToString(),
			ResolvedRdpPort: rdpPort,
			RdpPortFromRegistry: fromRegistry,
			Providers: providers,
			RdpAuditGroupBlockRuleCount: rdpAuditRuleCount,
			EnabledAllowInboundTcpPorts: Array.Empty<int>(),
			RdpAuditAllowRuleForResolvedPort: false,
			RouteBackendState: routeState,
			IPsecBackendState: ipsecState,
			ThirdPartyFirewallSuspected: thirdPartySuspected,
			ThirdPartyFirewallNote: thirdPartyNote,
			BlocklistRowCount: blocklistRows,
			ActiveBlockRowCount: activeRows,
			VerifiedEnforcedCount: verifiedEnforced)
		{
			ReconciledBlocks = reconciledLines,
			OrphanedRuleNames = orphanNames,
			ScannerBackend = scannerBackend,
			ScannerNote = scannerNote,
			DiscoveredRuleShapes = ruleShapes,
		};

		return new FirewallDiagnosticsDto
		{
			Status = IpcResultStatus.Success,
			ReportText = FirewallDiagnosticsReportBuilder.Build(input),
			Message = "Firewall enforcement diagnostics snapshot with live reconciliation. Combine with the "
				+ "client-side netsh / provider probe shown above for the full picture.",
		};
	}

	private async Task<object?> RunToolsDiagnosticsAsync(CancellationToken ct)
	{
		if (_toolsDiagnostics is null)
		{
			return new ToolsDiagnosticsDto
			{
				Status = IpcResultStatus.Unavailable,
				GeneratedUtc = DateTime.UtcNow,
				Message = "Tools Diag service is not registered on this host.",
				ReportText = "Tools Diag service is not registered on this host.",
			};
		}

		return await _toolsDiagnostics.RunDiagnosticsAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> RunTemporaryFirewallRuleProbeAsync(string? payload, CancellationToken ct)
	{
		if (_toolsDiagnostics is null)
		{
			return new TemporaryFirewallProbeDto
			{
				Status = IpcResultStatus.Unavailable,
				GeneratedUtc = DateTime.UtcNow,
				Message = "Tools Diag service is not registered on this host.",
				ReportText = "Tools Diag service is not registered on this host.",
			};
		}

		string testIp = ParseTestIpPayload(payload);
		bool debug = _options.CurrentValue.Diagnostics.DebugMode;
		if (debug)
		{
			LogOperation(OperationLogSeverity.Information, "FirewallRuleProbe.Started",
				string.Format(CultureInfo.InvariantCulture, "Temporary firewall rule probe started for {0}.", testIp));
		}

		try
		{
			TemporaryFirewallProbeDto result =
				await _toolsDiagnostics.RunTemporaryFirewallRuleProbeAsync(testIp, ct).ConfigureAwait(false);
			if (debug)
			{
				foreach (ToolProbeResultDto step in result.Steps)
				{
					LogOperation(OperationLogSeverity.Information, "FirewallRuleProbe.StageCompleted",
						string.Format(
							CultureInfo.InvariantCulture,
							"{0}: passed={1}; exit={2}; durationMs={3}; timedOut={4}; backend={5}; cmd={6} {7}; note={8}",
							step.ToolName,
							step.Passed,
							step.ExitCode,
							step.DurationMs,
							step.TimedOut,
							step.RunnerMode,
							step.Executable,
							step.Arguments,
							step.Note ?? string.Empty));
				}

				LogOperation(OperationLogSeverity.Information, "FirewallRuleProbe.Completed",
					string.Format(
						CultureInfo.InvariantCulture,
						"Temporary firewall rule probe for {0} finished: status={1}; overall={2}; rule={3}; backend={4}.",
						result.TestIp,
						result.Status,
						result.CreatedVerifiedAndCleanedUp,
						result.RuleName,
						result.ScannerBackend ?? "(none)"));
			}

			return result;
		}
		catch (Exception ex) when (ex is not OperationCanceledException)
		{
			if (debug)
			{
				LogOperation(OperationLogSeverity.Error, "FirewallRuleProbe.Failed",
					string.Format(CultureInfo.InvariantCulture,
						"Temporary firewall rule probe for {0} raised {1}: {2}", testIp, ex.GetType().Name, ex.Message));
			}

			throw;
		}
	}

	/// <summary>Unwraps the temporary-probe test IP from the IPC payload. The client sends the IP as a
	/// JSON string; accept either a JSON-encoded string or a raw token.</summary>
	private static string ParseTestIpPayload(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return string.Empty;
		}

		string body = payload.Trim();
		if (body.Length > 0 && body[0] == '"')
		{
			try
			{
				string? unwrapped = JsonSerializer.Deserialize<string>(body, JsonOptions.Default);
				if (!string.IsNullOrWhiteSpace(unwrapped))
				{
					return unwrapped.Trim();
				}
			}
			catch (JsonException)
			{
				// Not a wrapped JSON string — fall through and use the raw token.
			}
		}

		return body;
	}

	private async Task<object?> ListBlocklistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<BlocklistEntry> rows = await db.BlocklistEntries.AsNoTracking()
			.OrderByDescending(b => b.AddedUtc)
			.ThenByDescending(b => b.Id)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Id = b.Id,
			Address = b.Ip ?? b.Login ?? string.Empty,
			Note = b.Reason,
			AddedUtc = b.AddedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Source.ToString(),
			IsEnabled = b.IsEnabled,
		});
	}

	/// <summary>DB maintenance: collapses duplicate BlocklistEntry rows that share an IP down to one
	/// canonical row. The canonical row is chosen deterministically — prefer an enabled row, then the
	/// oldest by AddedUtc, then the lowest Id. Every other row for that IP is soft-disabled (kept for
	/// audit, never hard-deleted) and its Reason annotated with the canonical row it was merged into.
	/// Login-only rows (no IP) are left untouched. Runs in a single transaction.</summary>
	private async Task<object?> DedupeBlocklistEntriesAsync(CancellationToken ct)
	{
		BlocklistDedupeResultDto result = new();

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx =
			await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);

		List<BlocklistEntry> all = await db.BlocklistEntries
			.Where(b => b.Ip != null && b.Ip != string.Empty)
			.ToListAsync(ct).ConfigureAwait(false);

		string nowStamp = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
		foreach (IGrouping<string, BlocklistEntry> group in all.GroupBy(b => b.Ip!, StringComparer.OrdinalIgnoreCase))
		{
			List<BlocklistEntry> rows = group.ToList();
			if (rows.Count <= 1)
			{
				continue;
			}

			BlocklistEntry canonical = rows
				.OrderByDescending(r => r.IsEnabled)
				.ThenBy(r => r.AddedUtc)
				.ThenBy(r => r.Id)
				.First();

			int disabledForIp = 0;
			foreach (BlocklistEntry row in rows)
			{
				if (row.Id == canonical.Id || !row.IsEnabled)
				{
					continue;
				}

				row.IsEnabled = false;
				row.Reason = Truncate2048(string.Format(CultureInfo.InvariantCulture,
					"{0} [deduped {1}: merged into canonical row Id={2}]", row.Reason, nowStamp, canonical.Id));
				disabledForIp++;
			}

			if (disabledForIp > 0)
			{
				result.IpsCollapsed++;
				result.RowsDisabled += disabledForIp;
				result.Audit.Add(string.Format(CultureInfo.InvariantCulture,
					"{0}: kept canonical Id={1} (enabled={2}); disabled {3} duplicate row(s).",
					group.Key, canonical.Id, canonical.IsEnabled, disabledForIp));
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		await tx.CommitAsync(ct).ConfigureAwait(false);

		result.Message = result.IpsCollapsed == 0
			? "No duplicate BlockList rows were found; nothing to collapse."
			: string.Format(CultureInfo.InvariantCulture,
				"Collapsed {0} IP(s) with duplicates; soft-disabled {1} duplicate row(s) with an audit trail.",
				result.IpsCollapsed, result.RowsDisabled);
		_logger.LogInformation(
			"DedupeBlocklistEntries collapsed {Ips} ip(s), disabled {Rows} duplicate row(s)",
			result.IpsCollapsed, result.RowsDisabled);
		return result;
	}

	private static string Truncate2048(string value) => value.Length <= 2048 ? value : value[..2048];

	private async Task<object?> ListWhitelistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<WhitelistEntry> rows = await db.WhitelistEntries.AsNoTracking()
			.OrderByDescending(w => w.AddedUtc)
			.ThenByDescending(w => w.Id)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(w => new AddressListEntryDto
		{
			Address = w.Ip,
			Note = w.Note,
			AddedUtc = w.AddedUtc,
			ExpiresUtc = null,
			Source = w.AddedBy ?? "Configurator",
		});
	}

	private async Task<object?> AddToBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToBlocklist");
		LogFirewallDebug("AddToBlocklist.Begin",
			string.Format(CultureInfo.InvariantCulture, "AddToBlocklist requested for raw address '{0}'.", req.Address),
			() => string.Format(CultureInfo.InvariantCulture, "RawAddress='{0}'; DurationMinutes={1}; Note='{2}'.",
				req.Address, req.DurationMinutes, req.Note ?? "(none)"));
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		// Whitelist precedence: refuse to add a row that contradicts an active whitelist entry.
		bool whitelisted = await db.WhitelistEntries.AnyAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (whitelisted)
		{
			LogFirewallDebug("AddToBlocklist.RefusedWhitelisted",
				string.Format(CultureInfo.InvariantCulture, "Refused to blocklist '{0}': an active whitelist entry exists for the exact value.", ip));
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Cannot add {0} to blocklist: it is whitelisted.", ip));
		}

		DateTime nowUtc = DateTime.UtcNow;
		// v1.3.9: honour DefaultBlockDurationMinutes for manual adds. The explicit per-request duration
		// wins; otherwise the configured default applies; only when BOTH resolve to non-positive is the
		// block permanent (ExpiresUtc == null → "Never"). Previously the configured default was ignored,
		// so manual rows showed "Never" even when the operator had set a positive default.
		int defaultDurationMinutes = _options.CurrentValue.Firewall.DefaultBlockDurationMinutes;
		DateTime? expiresUtc = BlockExpiryCalculator.ComputeExpiresUtc(
			nowUtc, req.DurationMinutes, defaultDurationMinutes);

		BlocklistEntry? existing = await db.BlocklistEntries
			.FirstOrDefaultAsync(b => b.Ip == ip && b.IsEnabled, ct).ConfigureAwait(false);

		bool created = existing is null;
		if (existing is null)
		{
			db.BlocklistEntries.Add(new BlocklistEntry
			{
				Ip = ip,
				Reason = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note!,
				AddedUtc = nowUtc,
				ExpiresUtc = expiresUtc,
				Source = BlocklistSource.Manual,
				IsEnabled = true,
			});
		}
		else
		{
			existing.ExpiresUtc = expiresUtc;
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Reason = req.Note!;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		LogBlockMutationDebug(
			operation: created ? "BlocklistAdd" : "BlocklistUpdate",
			ip: ip,
			addedUtc: nowUtc,
			requestedDurationMinutes: req.DurationMinutes,
			defaultDurationMinutes: defaultDurationMinutes,
			expiresUtc: expiresUtc,
			source: BlocklistSource.Manual.ToString());
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromBlocklist");

		// Defensive: a malformed client could send an address wrapped in quotes (e.g. a
		// double-serialized '"80.244.40.164"'). Strip surrounding quotes / whitespace before any
		// matching so the value compares equal to the canonical stored IP.
		string rawAddress = req.Address ?? string.Empty;
		string cleanedAddress = StripSurroundingQuotes(rawAddress);

		// Preferred path: a stable surrogate id targets exactly the selected row (including an
		// already-disabled one) and synchronizes the ActiveBlock / live firewall rule only when the
		// last enabled row for the IP is removed. Returns a structured result the operator can inspect.
		if (req.Id > 0 && _reconciliation is not null)
		{
			// Return the structured DTO as the payload even on failure so the Configurator's
			// Diagnostics DEBUG view can render the full DebugLog and Error. The IPC envelope stays
			// Success=true; the operator inspects removal.Status / removal.Error.
			return await _reconciliation
				.RemoveBlocklistEntryAsync(req.Id, cleanedAddress, ct).ConfigureAwait(false);
		}

		List<BlocklistEntry> rows;
		string matchMode;
		string? normalizedIp = null;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			// 1) Prefer the stable surrogate key so we delete exactly the selected row even when
			//    several rows share an address (e.g. one Manual + one AutoBlock).
			if (req.Id > 0)
			{
				matchMode = "Id";
				_logger.LogDebug("RemoveFromBlocklist by Id={Id} (address hint '{Address}')", req.Id, cleanedAddress);
				rows = await db.BlocklistEntries
					.Where(b => b.Id == req.Id && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);

				// 2) Fallback: the Id did not match an enabled row (stale grid selection / row already
				//    disabled). Try the normalized IP so the operator still gets the intended removal,
				//    and gather diagnostics describing exactly what DOES exist for that IP.
				if (rows.Count == 0 && !string.IsNullOrWhiteSpace(cleanedAddress)
					&& TryNormalizeAddress(cleanedAddress, out normalizedIp))
				{
					matchMode = "Id-miss→IP-fallback";
					rows = await db.BlocklistEntries
						.Where(b => b.Ip == normalizedIp && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);

					if (rows.Count == 0)
					{
						string diag = await BuildRemoveDiagnosticAsync(db, req.Id, rawAddress, cleanedAddress, normalizedIp, ct)
							.ConfigureAwait(false);
						throw new IpcException(diag);
					}
				}
			}
			else
			{
				matchMode = "IP";
				normalizedIp = NormalizeAndValidateAddress(cleanedAddress);
				_logger.LogDebug("RemoveFromBlocklist by address '{Address}'", normalizedIp);
				rows = await db.BlocklistEntries
					.Where(b => b.Ip == normalizedIp && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
			}

			foreach (BlocklistEntry row in rows)
			{
				row.IsEnabled = false;
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		int removed = rows.Count;
		string targetIp = normalizedIp ?? rows.Select(r => r.Ip).FirstOrDefault(x => x is not null) ?? cleanedAddress;
		_logger.LogInformation(
			"RemoveFromBlocklist soft-disabled {Removed} row(s) via {MatchMode} for Id={Id} address='{Address}'",
			removed, matchMode, req.Id, targetIp);

		if (removed == 0)
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			string diag = await BuildRemoveDiagnosticAsync(db, req.Id, rawAddress, cleanedAddress, normalizedIp, ct)
				.ConfigureAwait(false);
			throw new IpcException(diag);
		}

		return new { status = IpcResultStatus.Success.ToString(), address = targetIp, removed, matchMode };
	}

	/// <summary>Builds a precise "nothing removed" diagnostic listing the selected Id, the raw and
	/// normalized address received, and every blocklist row (enabled or disabled) currently matching
	/// that IP — so the operator sees exactly why the removal matched no enabled row.</summary>
	private static async Task<string> BuildRemoveDiagnosticAsync(
		AuditDbContext db,
		long selectedId,
		string rawAddress,
		string cleanedAddress,
		string? normalizedIp,
		CancellationToken ct)
	{
		List<BlocklistEntry> matching = string.IsNullOrWhiteSpace(normalizedIp)
			? new List<BlocklistEntry>()
			: await db.BlocklistEntries
				.AsNoTracking()
				.Where(b => b.Ip == normalizedIp)
				.OrderBy(b => b.Id)
				.ToListAsync(ct).ConfigureAwait(false);

		StringBuilder sb = new();
		sb.Append(CultureInfo.InvariantCulture,
			$"No enabled blocklist row matched the request, so nothing was removed (selected Id={selectedId}). ");
		sb.Append(CultureInfo.InvariantCulture,
			$"Address received raw='{rawAddress}', cleaned='{cleanedAddress}', normalized='{normalizedIp ?? "(invalid)"}'. ");
		if (matching.Count == 0)
		{
			sb.Append("No blocklist rows exist for that IP at all (enabled or disabled).");
		}
		else
		{
			sb.Append(CultureInfo.InvariantCulture, $"{matching.Count} row(s) exist for that IP: ");
			for (int i = 0; i < matching.Count; i++)
			{
				BlocklistEntry r = matching[i];
				if (i > 0)
				{
					sb.Append("; ");
				}

				sb.Append(CultureInfo.InvariantCulture,
					$"Id={r.Id} enabled={(r.IsEnabled ? "yes" : "no")} source={r.Source}");
			}

			sb.Append(". The row may already be disabled, or the grid selection Id is stale — refresh the list and retry.");
		}

		return sb.ToString();
	}

	/// <summary>Removes a single pair of surrounding ASCII double / single quotes (and whitespace)
	/// from <paramref name="value"/>. Defends against a malformed client that double-serializes the
	/// address field.</summary>
	internal static string StripSurroundingQuotes(string value)
	{
		string trimmed = value.Trim();
		if (trimmed.Length >= 2)
		{
			char first = trimmed[0];
			char last = trimmed[^1];
			if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
			{
				trimmed = trimmed[1..^1].Trim();
			}
		}

		return trimmed;
	}

	/// <summary>Non-throwing variant of <see cref="NormalizeAndValidateAddress"/>.</summary>
	private static bool TryNormalizeAddress(string address, out string? normalized)
	{
		if (!string.IsNullOrWhiteSpace(address) && IPAddress.TryParse(address.Trim(), out IPAddress? parsed))
		{
			normalized = parsed.ToString();
			return true;
		}

		normalized = null;
		return false;
	}

	private async Task<object?> AddToWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToWhitelist");
		LogFirewallDebug("AddToWhitelist.Begin",
			string.Format(CultureInfo.InvariantCulture, "AddToWhitelist requested for raw address '{0}'.", req.Address),
			() => string.Format(CultureInfo.InvariantCulture, "RawAddress='{0}'; Note='{1}'.", req.Address, req.Note ?? "(none)"));

		// v1.4.1: accept either a single IPv4 / IPv6 address or a CIDR range (e.g. 10.0.0.0/8, fc00::/7)
		// so the "Add local networks" action — which submits private-range CIDRs — no longer fails the
		// strict single-IP IPAddress.TryParse check that previously produced "N failed" with no detail.
		string ip = NormalizeAndValidateAddressOrCidr(req.Address);
		LogFirewallDebug("AddToWhitelist.Normalized",
			string.Format(CultureInfo.InvariantCulture, "Normalized whitelist entry '{0}' -> '{1}'.", req.Address, ip));

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (existing is null)
		{
			db.WhitelistEntries.Add(new WhitelistEntry
			{
				Ip = ip,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				AddedUtc = DateTime.UtcNow,
				AddedBy = "Configurator",
			});
		}
		else
		{
			existing.Note = string.IsNullOrWhiteSpace(req.Note) ? existing.Note : req.Note;
		}

		// Whitelist precedence: disable any active blocklist rows that reference this IP.
		// NOTE (v1.4.1): this exact-match disable only catches a blocklist row whose stored value equals
		// the normalized whitelist value. When the whitelist entry is a CIDR range it will NOT disable a
		// blocklist row for an individual member IP inside that range; the FirewallAutoBlockWorker is
		// responsible for honouring the whitelisted range going forward and skipping member IPs.
		List<BlocklistEntry> conflicting = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry row in conflicting)
		{
			row.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		LogFirewallDebug("AddToWhitelist.Done",
			string.Format(CultureInfo.InvariantCulture, "Whitelist entry '{0}' persisted (existing={1}, conflictingBlocklistDisabled={2}).",
				ip, existing is not null, conflicting.Count));
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromWhitelist");
		LogFirewallDebug("RemoveFromWhitelist.Begin",
			string.Format(CultureInfo.InvariantCulture, "RemoveFromWhitelist requested for raw address '{0}'.", req.Address));

		// v1.4.1: mirror the add path — a CIDR range must be removable using the same canonical form it was
		// stored under, so normalise via the CIDR-aware path before the exact-match lookup.
		string ip = NormalizeAndValidateAddressOrCidr(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);

		if (existing is not null)
		{
			db.WhitelistEntries.Remove(existing);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		LogFirewallDebug("RemoveFromWhitelist.Done",
			string.Format(CultureInfo.InvariantCulture, "RemoveFromWhitelist '{0}' completed (removed={1}).", ip, existing is not null));
		return new { status = IpcResultStatus.Success.ToString(), address = ip, removed = existing is not null };
	}

	private async Task<object?> ListActiveBlocksAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.ThenByDescending(b => b.Id)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Address = b.Ip,
			Note = string.IsNullOrEmpty(b.LastError) ? b.Reason : b.Reason + " (" + b.LastError + ")",
			AddedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Provider.ToString() + ":" + b.Status,
		});
	}

	private static AddressListMutationRequest DeserializeMutation(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with an Address field.", commandName));
		}

		AddressListMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<AddressListMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Address))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires an Address field.", commandName));
		}
		return parsed;
	}

	private static string NormalizeAndValidateAddress(string address)
	{
		if (string.IsNullOrWhiteSpace(address))
		{
			throw new IpcException("Address must not be empty.");
		}

		string trimmed = address.Trim();
		if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Address '{0}' is not a valid IPv4 / IPv6 address.", trimmed));
		}
		return parsed.ToString();
	}

	/// <summary>
	/// Validates and normalises a whitelist entry that may be either a single IPv4 / IPv6 address or
	/// a CIDR range (e.g. 10.0.0.0/8, fc00::/7). CIDR ranges are canonicalised to network/prefix form
	/// via <see cref="CidrRange"/> so the stored value is stable regardless of supplied host bits, and
	/// the auto-block worker matches source IPs against the range family-aware. Single addresses fall
	/// through to the strict single-IP path. Throws <see cref="IpcException"/> with a precise reason on
	/// invalid input so the operator sees exactly why an entry was rejected.
	/// </summary>
	private static string NormalizeAndValidateAddressOrCidr(string address)
	{
		if (string.IsNullOrWhiteSpace(address))
		{
			throw new IpcException("Address must not be empty.");
		}

		string trimmed = address.Trim();
		if (CidrRange.LooksLikeCidr(trimmed))
		{
			if (!CidrRange.TryParse(trimmed, out CidrRange? range) || range is null)
			{
				throw new IpcException(string.Format(CultureInfo.InvariantCulture,
					"Address '{0}' is not a valid IPv4 / IPv6 CIDR range (expected e.g. 192.168.0.0/16 or fd00::/8).", trimmed));
			}
			return range.ToString();
		}

		return NormalizeAndValidateAddress(trimmed);
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 5 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListLoginRulesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<LoginRule> rows = await db.LoginRules.AsNoTracking()
			.OrderByDescending(r => r.AddedUtc)
			.ThenByDescending(r => r.Id)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(r => new LoginRuleDto
		{
			Id = r.Id,
			Login = r.Login,
			DisplayLogin = string.IsNullOrEmpty(r.DisplayLogin) ? r.Login : r.DisplayLogin,
			Note = r.Note,
			Enabled = r.Enabled,
			AddedUtc = r.AddedUtc,
			TriggerCount = r.TriggerCount,
			FirstTriggeredUtc = r.FirstTriggeredUtc,
			LastTriggeredUtc = r.LastTriggeredUtc,
			LastSourceIp = r.LastSourceIp,
		});
	}

	private async Task<object?> AddLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "AddLoginRule");
		string login = NormalizeAndValidateLogin(req.Login);
		string displayLogin = req.Login.Trim();

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? existing = await db.LoginRules
			.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);

		if (existing is null)
		{
			db.LoginRules.Add(new LoginRule
			{
				Login = login,
				DisplayLogin = displayLogin,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				Enabled = true,
				AddedUtc = DateTime.UtcNow,
			});
		}
		else
		{
			existing.Enabled = true;
			if (string.IsNullOrEmpty(existing.DisplayLogin))
			{
				existing.DisplayLogin = displayLogin;
			}
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Note = req.Note;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), login };
	}

	private async Task<object?> RemoveLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "RemoveLoginRule");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = null;
		if (req.Id > 0)
		{
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		}

		if (target is null && !string.IsNullOrWhiteSpace(req.Login))
		{
			string login = NormalizeAndValidateLogin(req.Login);
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);
		}

		if (target is null)
		{
			throw new IpcException("Login rule not found.");
		}

		db.LoginRules.Remove(target);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, login = target.Login };
	}

	private async Task<object?> SetLoginRuleEnabledAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "SetLoginRuleEnabled");
		if (req.Id <= 0)
		{
			throw new IpcException("SetLoginRuleEnabled requires a positive Id.");
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		if (target is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Login rule {0} not found.", req.Id));
		}

		target.Enabled = req.Enabled;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, enabled = target.Enabled };
	}

	private async Task<object?> ListActiveBlocksDetailedAsync(CancellationToken ct)
	{
		// The Active Blocks view is built from live reconciliation results — never DB rows alone — so
		// RdpAudit never claims an IP is actively blocked unless a matching backend object is found.
		if (_reconciliation is not null)
		{
			return await _reconciliation.ReconcileToActiveBlockDtosAsync(ct).ConfigureAwait(false);
		}

		// Fallback (reconciliation service not wired): surface DB rows but mark enforcement unknown so
		// the operator is never misled into believing a row is verified.
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.ThenByDescending(b => b.Id)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new ActiveBlockDto
		{
			Id = b.Id,
			Ip = b.Ip,
			Provider = b.Provider,
			RuleHandle = b.RuleHandle,
			CreatedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Reason = b.Reason,
			Status = b.Status,
			LastError = b.LastError,
			EnforcementStatus = EnforcementStatus.EffectiveUnknown,
			EnforcementConfidence = EnforcementConfidence.Unknown,
			RecommendedAction = "Reconciliation service unavailable; enforcement not verified.",
		});
	}

	private async Task<object?> ReconcileEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await RunWithDebugTraceAsync(
			"FirewallReconciliation",
			"reconcile enforcement",
			() => _reconciliation.ReconcileAsync(ct)).ConfigureAwait(false);
	}

	/// <summary>v1.3.9: wraps a reconciliation/repair operation with DEBUG-gated Started / Completed /
	/// Failed structured OperationLogs. The logs are emitted only when <c>Diagnostics.DebugMode</c> is on
	/// and never alter the operation's result or swallow its exception.</summary>
	private async Task<TResult> RunWithDebugTraceAsync<TResult>(
		string operationBase, string description, Func<Task<TResult>> action)
	{
		bool debug = _options.CurrentValue.Diagnostics.DebugMode;
		System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
		if (debug)
		{
			LogOperation(OperationLogSeverity.Information, operationBase + ".Started",
				string.Format(CultureInfo.InvariantCulture, "{0} started.", description));
		}

		try
		{
			TResult result = await action().ConfigureAwait(false);
			sw.Stop();
			if (debug)
			{
				LogOperation(OperationLogSeverity.Information, operationBase + ".Completed",
					string.Format(CultureInfo.InvariantCulture, "{0} completed in {1} ms.", description, sw.ElapsedMilliseconds));
			}

			return result;
		}
		catch (Exception ex) when (ex is not OperationCanceledException)
		{
			sw.Stop();
			if (debug)
			{
				LogOperation(OperationLogSeverity.Error, operationBase + ".Failed",
					string.Format(CultureInfo.InvariantCulture, "{0} failed after {1} ms: {2}: {3}",
						description, sw.ElapsedMilliseconds, ex.GetType().Name, ex.Message));
			}

			throw;
		}
	}

	private async Task<object?> RepairActiveBlockAsync(string? payload, CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("RepairActiveBlock requires a JSON payload with the row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("RepairActiveBlock payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("RepairActiveBlock requires a positive Id.");
		}

		return await RunWithDebugTraceAsync(
			"FirewallRepairSelected",
			string.Format(CultureInfo.InvariantCulture, "repair active block id={0}", id),
			() => _reconciliation.RepairAsync(id, ct)).ConfigureAwait(false);
	}

	private async Task<object?> RepairBlocklistEnforcementAsync(string? payload, CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("RepairBlocklistEnforcement requires a JSON payload with the BlockList row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("RepairBlocklistEnforcement payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("RepairBlocklistEnforcement requires a positive Id.");
		}

		return await RunWithDebugTraceAsync(
			"FirewallRepairSelected",
			string.Format(CultureInfo.InvariantCulture, "repair blocklist entry id={0}", id),
			() => _reconciliation.RepairBlocklistAsync(id, ct)).ConfigureAwait(false);
	}

	private async Task<object?> RepairAllEnabledBlocklistEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await RunWithDebugTraceAsync(
			"FirewallRepairSelected",
			"repair all enabled blocklist entries",
			() => _reconciliation.RepairAllEnabledBlocklistAsync(ct)).ConfigureAwait(false);
	}

	private async Task<object?> RemoveAllEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await RunWithDebugTraceAsync(
			"FirewallRemoveAllEnforcement",
			"remove all live firewall enforcement",
			() => _reconciliation.RemoveAllEnforcementAsync(ct)).ConfigureAwait(false);
	}

	/// <summary>Server-side guard phrase for the destructive full application-data purge. The client must
	/// echo this exact phrase (typed by the operator) or the purge is refused — a second barrier behind the
	/// DEBUG gate and the typed-confirmation dialog so the data is never wiped by an accidental call.</summary>
	private const string ClearAllDataConfirmationPhrase = "CLEAR ALL RDP AUDIT DATA";

	/// <summary>Full blacklist cleanup (Req A): soft-disables every enabled BlocklistEntry and synchronizes
	/// enforcement for the cleared IPs (ActiveBlocks Removed + RdpAudit firewall rules removed).</summary>
	private async Task<object?> ClearAllBlocklistAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		LogOperation(OperationLogSeverity.Warning, "ClearAllBlocklist", "Full blacklist cleanup requested via Configurator.");
		return await _reconciliation.ClearAllBlocklistAsync(ct).ConfigureAwait(false);
	}

	/// <summary>DEBUG-gated full firewall cleanup (Req B): removes every RdpAudit-owned firewall rule and
	/// synchronizes ActiveBlock rows to Removed. Never touches the BlocklistEntry table.</summary>
	private async Task<object?> ClearAllFirewallRulesAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		LogOperation(OperationLogSeverity.Warning, "ClearAllFirewallRules", "DEBUG firewall-rules cleanup requested via Configurator.");
		return await _reconciliation.ClearAllRdpAuditFirewallAsync(ct).ConfigureAwait(false);
	}

	/// <summary>DEBUG-gated full application-data cleanup (Req C): transactionally clears the accumulated
	/// operational tables (preserving schema / migrations / config / bookmarks) and reclaims SQLite space.
	/// Requires the exact typed confirmation phrase in the payload; refuses otherwise.</summary>
	private async Task<object?> ClearAllApplicationDataAsync(string? payload, CancellationToken ct)
	{
		if (_dataPurge is null)
		{
			throw new IpcException("Application data purge service is not available in this build.");
		}

		string confirmation = ParseTestIpPayload(payload);
		if (!string.Equals(confirmation, ClearAllDataConfirmationPhrase, StringComparison.Ordinal))
		{
			return new AppDataPurgeResultDto
			{
				Status = IpcResultStatus.Refused,
				Message = "Application-data purge refused: the exact confirmation phrase was not supplied.",
			};
		}

		LogOperation(OperationLogSeverity.Warning, "ClearAllApplicationData", "DEBUG application-data purge requested via Configurator.");
		return await _dataPurge.PurgeAllAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> UnblockActiveBlockAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("UnblockActiveBlock requires a JSON payload with the row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("UnblockActiveBlock payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("UnblockActiveBlock requires a positive Id.");
		}

		LogFirewallDebug("UnblockActiveBlock.Begin",
			string.Format(CultureInfo.InvariantCulture, "UnblockActiveBlock requested for ActiveBlock id={0}.", id));

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ActiveBlock? row = await db.ActiveBlocks.FirstOrDefaultAsync(b => b.Id == id, ct).ConfigureAwait(false);
		if (row is null)
		{
			LogFirewallDebug("UnblockActiveBlock.NotFound",
				string.Format(CultureInfo.InvariantCulture, "ActiveBlock id={0} not found.", id));
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"ActiveBlock {0} not found.", id));
		}

		string ip = row.Ip;
		bool providerOk = true;
		string? providerError = null;

		if (row.Provider == FirewallProviderKind.Windows && OperatingSystem.IsWindows())
		{
			try
			{
				FirewallOperationResult res = await _firewall.UnblockAsync(
					_options.CurrentValue.Firewall.BlockRuleName, ip, ct).ConfigureAwait(false);
				providerOk = res.Success || res.ExitCode == 1;
				if (!providerOk)
				{
					providerError = "netsh exit " + res.ExitCode.ToString(CultureInfo.InvariantCulture);
				}
			}
			catch (Exception ex)
			{
				providerOk = false;
				providerError = ex.GetType().Name;
				_logger.LogWarning(ex, "Provider unblock failed for {Ip}", ip);
				LogFirewallDebug("UnblockActiveBlock.ProviderFailed",
					string.Format(CultureInfo.InvariantCulture, "Provider unblock for '{0}' threw: {1}", ip, ex.Message),
					() => ex.ToString());
			}
		}

		row.Status = providerOk ? ActiveBlockStatus.Removed : ActiveBlockStatus.Failed;
		row.LastError = providerError;
		LogFirewallDebug("UnblockActiveBlock.ProviderOutcome",
			string.Format(CultureInfo.InvariantCulture, "Provider unblock for '{0}' providerOk={1} (error={2}); ActiveBlock status set to {3}.",
				ip, providerOk, providerError ?? "(none)", row.Status));

		List<BlocklistEntry> related = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry entry in related)
		{
			entry.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		LogFirewallDebug("UnblockActiveBlock.Done",
			string.Format(CultureInfo.InvariantCulture, "UnblockActiveBlock id={0} ('{1}') done (providerOk={2}, blocklistDisabled={3}).",
				row.Id, ip, providerOk, related.Count));
		return new
		{
			status = (providerOk ? IpcResultStatus.Success : IpcResultStatus.Unavailable).ToString(),
			id = row.Id,
			address = ip,
			providerOk,
			providerError,
			blocklistDisabled = related.Count,
		};
	}

	private static LoginRuleMutationRequest DeserializeLoginRuleRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload.", commandName));
		}

		LoginRuleMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<LoginRuleMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}
		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 6 handlers
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on rows returned by <c>GetAttackStats</c> when no limit is supplied.</summary>
	internal const int AttackStatsDefaultLimit = 500;

	/// <summary>Upper bound on rows returned by <c>GetAttackStats</c> regardless of caller intent.</summary>
	internal const int AttackStatsMaxLimit = 2000;

	/// <summary>Earliest instant accepted as <c>GetAttackStats</c> window bound.</summary>
	/// <remarks>
	/// Below this the default seven-day window subtraction underflows (DateTime.MinValue minus any
	/// span throws), so the bound is refused as malformed instead of surfacing as a fault.
	/// </remarks>
	internal static readonly DateTime AttackStatsMinWindowInstant = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	private async Task<object?> GetAttackStatsAsync(string? payload, CancellationToken ct)
	{
		AttackStatsRequest req = ParseAttackStatsRequest(payload);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		DateTime windowEnd = req.UntilUtc ?? DateTime.UtcNow;
		if (windowEnd < AttackStatsMinWindowInstant)
		{
			throw new IpcException(
				"GetAttackStats: UntilUtc is earlier than 2000-01-01 and cannot bound a report window.");
		}

		DateTime windowStart = req.SinceUtc ?? (windowEnd - TimeSpan.FromDays(7));

		IQueryable<AttackStat> q = db.AttackStats.AsNoTracking();

		if (!string.IsNullOrWhiteSpace(req.IpQuery))
		{
			string needle = SqlLikeEscaper.Escape(req.IpQuery.Trim());
			q = q.Where(s => EF.Functions.Like(s.Ip, "%" + needle + "%", SqlLikeEscaper.EscapeString));
		}

		if (req.MinThreatScore.HasValue)
		{
			double min = req.MinThreatScore.Value;
			q = q.Where(s => s.ThreatScore >= min);
		}

		if (req.OnlyBlocked)
		{
			q = q.Where(s => s.IsBlocked);
		}

		if (req.SinceUtc.HasValue)
		{
			DateTime since = req.SinceUtc.Value;
			q = q.Where(s => s.LastSeenUtc >= since);
		}

		if (req.UntilUtc.HasValue)
		{
			DateTime until = req.UntilUtc.Value;
			q = q.Where(s => s.LastSeenUtc <= until);
		}

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		int limit = req.Limit <= 0 ? AttackStatsDefaultLimit : req.Limit;
		if (limit > AttackStatsMaxLimit)
		{
			limit = AttackStatsMaxLimit;
		}

		List<AttackStat> rows = await q
			.OrderByDescending(s => s.LastSeenUtc)
			.ThenByDescending(s => s.ThreatScore)
			.ThenBy(s => s.Ip)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		// Window summary counters — computed against AuthAttemptFacts in the requested window.
		// Detect_Attack_Strategy_v3.md §8.1 makes AuthAttemptFact the atomic source of truth for
		// authentication outcomes. RDP/Operational, RdpCoreTS, and TerminalServices events are
		// context / enrichment only — they MUST NOT move Total / Failed / Successful counters.
		// Querying AuthAttemptFacts directly (rather than RawEvents + Classify) keeps the IPC
		// window summary consistent with the per-IP Fact* columns and with AttackStat rows
		// projected by AttackStatsRefreshWorker.
		// Aggregate in SQL. The window is caller-supplied (REST query string or IPC payload), so
		// materialising its rows would let a single request pull the whole fact table into memory.
		// The counts and the distinct-address population are produced by the database; the sentinel
		// handling reproduces the previous single-pass walk exactly, including the case where a row
		// literally carries the sentinel address.
		string unresolvedSentinel = AttackStatsAggregator.SentinelUnresolvedIp;
		var windowFacts = db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.TimeUtc >= windowStart && f.TimeUtc <= windowEnd);

		var outcomeCounts = await windowFacts
			.GroupBy(f => f.Outcome)
			.Select(g => new { Outcome = g.Key, Count = g.Count() })
			.ToListAsync(ct).ConfigureAwait(false);

		long failed = 0;
		long successful = 0;
		foreach (var outcomeRow in outcomeCounts)
		{
			switch (outcomeRow.Outcome)
			{
				case AuthAttemptOutcome.Failed:
				case AuthAttemptOutcome.Denied:
					failed += outcomeRow.Count;
					break;
				case AuthAttemptOutcome.Succeeded:
					successful += outcomeRow.Count;
					break;
			}
		}

		long unresolvedFailed = await windowFacts
			.Where(f => (f.Outcome == AuthAttemptOutcome.Failed || f.Outcome == AuthAttemptOutcome.Denied)
				&& (f.SourceIp == null || f.SourceIp == string.Empty))
			.LongCountAsync(ct).ConfigureAwait(false);

		long resolvedIpCount = await windowFacts
			.Where(f => f.SourceIp != null && f.SourceIp != string.Empty)
			.Select(f => f.SourceIp!)
			.Distinct()
			.LongCountAsync(ct).ConfigureAwait(false);

		bool sawUnresolved = unresolvedFailed > 0;
		long sentinelRows = 0;
		if (sawUnresolved)
		{
			sentinelRows = await windowFacts
				.Where(f => f.SourceIp == unresolvedSentinel)
				.LongCountAsync(ct).ConfigureAwait(false);
		}

		long distinctIps = sawUnresolved && sentinelRows == 0 ? resolvedIpCount + 1 : resolvedIpCount;
		// The sentinel is never a genuine attacker IP — exclude it from the resolved-IP population.
		long distinctResolvedIps = sawUnresolved ? distinctIps - 1 : distinctIps;
		long alertsRaised = await db.Alerts.AsNoTracking()
			.Where(a => a.TimeUtc >= windowStart && a.TimeUtc <= windowEnd)
			.LongCountAsync(ct).ConfigureAwait(false);
		long autoBlocked = await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.CreatedUtc >= windowStart && b.CreatedUtc <= windowEnd
				&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending))
			.LongCountAsync(ct).ConfigureAwait(false);

		AttackStatsDto dto = new()
		{
			Status = IpcResultStatus.Success,
			WindowStartUtc = windowStart,
			WindowEndUtc = windowEnd,
			FailedLogons = failed,
			SuccessfulLogons = successful,
			DistinctSourceIps = distinctIps,
			AlertsRaised = alertsRaised,
			AddressesAutoBlocked = autoBlocked,
			Message = string.Format(CultureInfo.InvariantCulture,
				"Stage 6 attack statistics snapshot. matching={0} returned={1}",
				totalMatching, rows.Count),
			TotalMatching = totalMatching,
			AppliedLimit = limit,
			UnresolvedFailedLogons = unresolvedFailed,
			DistinctResolvedSourceIps = distinctResolvedIps,
		};

		// Stage IP-D: augment with RdpConnectionFacts aggregates for the IPs in this page. We never
		// overwrite the AttackStat columns — the augmentation lives on dedicated fact-* fields so the
		// existing UI keeps rendering AttackStat as today, and forward-looking pages can opt in.
		Dictionary<string, FactAggregate> factAggregates = await LoadFactAggregatesAsync(db, rows.Select(r => r.Ip), ct).ConfigureAwait(false);

		foreach (AttackStat row in rows)
		{
			bool isUnresolved = AttackStatsAggregator.IsSentinelUnresolvedIp(row.Ip);
			IpReportabilityResult classification = IpReportability.Classify(row.Ip);

			AttackStatEntryDto entry = new()
			{
				Ip = row.Ip,
				TotalAttempts = row.TotalAttempts,
				Successful = row.Successful,
				Failed = row.Failed,
				FirstSeenUtc = row.FirstSeenUtc,
				LastSeenUtc = row.LastSeenUtc,
				DurationSeconds = row.DurationSeconds,
				Top10AttemptedLogins = row.Top10AttemptedLogins,
				LastLoginType = row.LastLoginType,
				ThreatScore = row.ThreatScore,
				ThreatLevel = AttackThreatScoring.ClassifyScore(row.ThreatScore),
				IsBlocked = row.IsBlocked,
				LastUpdatedUtc = row.LastUpdatedUtc,
				IsUnresolved = isUnresolved,
				Classification = isUnresolved
					? IpReportability.Describe(IpReportClassification.Unresolved)
					: IpReportability.Describe(classification.Classification),
				DisplayIp = isUnresolved ? AttackStatsAggregator.SentinelDisplayLabel : row.Ip,
			};

			if (factAggregates.TryGetValue(row.Ip, out FactAggregate agg))
			{
				entry.HasActiveConnectionFact = agg.AnyActive;
				entry.FactFailedLogons = agg.Failed;
				entry.FactSuccessfulLogons = agg.Successful;
				entry.FactFirstSeenUtc = agg.FirstSeen;
				entry.FactLastSeenUtc = agg.LastSeen;
			}

			dto.Entries.Add(entry);
		}

		await StampAttackStatsThreatIntelAsync(dto.Entries, ct).ConfigureAwait(false);

		return dto;
	}

	internal readonly struct FactAggregate
	{
		public FactAggregate(DateTime firstSeen, DateTime lastSeen, long failed, long successful, bool anyActive)
		{
			FirstSeen = firstSeen;
			LastSeen = lastSeen;
			Failed = failed;
			Successful = successful;
			AnyActive = anyActive;
		}

		public DateTime FirstSeen { get; }

		public DateTime LastSeen { get; }

		public long Failed { get; }

		public long Successful { get; }

		public bool AnyActive { get; }
	}

	internal static async Task<Dictionary<string, FactAggregate>> LoadFactAggregatesAsync(
		AuditDbContext db,
		IEnumerable<string> ips,
		CancellationToken ct)
	{
		HashSet<string> set = new(ips, StringComparer.Ordinal);
		if (set.Count == 0)
		{
			return new Dictionary<string, FactAggregate>(StringComparer.Ordinal);
		}

		// v3 invariant (Detect_Attack_Strategy_v3.md §8.1): "All counters in IpFact and UserIpFact
		// are computed only from AuthAttemptFact." The Configurator's Fact Failed / Fact Success
		// columns therefore aggregate AuthAttemptFacts, not RdpConnectionFacts (which mix in
		// LSM-21 / RCM-1149 session telemetry that is NOT authoritative for outcome).
		var groupedAuth = await db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.SourceIp != null && set.Contains(f.SourceIp))
			.GroupBy(f => f.SourceIp!)
			.Select(g => new
			{
				Ip = g.Key,
				FirstSeen = g.Min(f => f.TimeUtc),
				LastSeen = g.Max(f => f.TimeUtc),
				Failed = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Failed || f.Outcome == AuthAttemptOutcome.Denied),
				Successful = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Succeeded),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		// "Active fact" is still a connection-state question (is there an open RDP session from
		// this IP?), so it continues to be sourced from RdpConnectionFacts.IsActive — that field
		// is a session-lifecycle bit, not a counter.
		Dictionary<string, bool> activeByIp = (await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => set.Contains(r.Ip))
			.GroupBy(r => r.Ip)
			.Select(g => new { Ip = g.Key, AnyActive = g.Any(r => r.IsActive) })
			.ToListAsync(ct).ConfigureAwait(false))
			.ToDictionary(x => x.Ip, x => x.AnyActive, StringComparer.Ordinal);

		var grouped = groupedAuth.Select(g => new
		{
			g.Ip,
			g.FirstSeen,
			g.LastSeen,
			g.Failed,
			g.Successful,
			AnyActive = activeByIp.TryGetValue(g.Ip, out bool active) && active,
		}).ToList();

		Dictionary<string, FactAggregate> result = new(StringComparer.Ordinal);
		foreach (var g in grouped)
		{
			result[g.Ip] = new FactAggregate(g.FirstSeen, g.LastSeen, g.Failed, g.Successful, g.AnyActive);
		}

		return result;
	}

	private static AttackStatsRequest ParseAttackStatsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new AttackStatsRequest();
		}

		try
		{
			AttackStatsRequest? parsed = JsonSerializer.Deserialize<AttackStatsRequest>(payload, JsonOptions.Default);
			return parsed ?? new AttackStatsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetAttackStats payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 7 handlers — Remote RDP Clients tab.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListRdpSessionsAsync(CancellationToken ct)
	{
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new RdpSessionListDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Session enumeration is only available on Windows hosts.",
				QueriedUtc = DateTime.UtcNow,
			};
		}

		RdpSessionListDto list = await _sessions.ListAsync(ct).ConfigureAwait(false);

		// Stage IP-B: resolve missing ClientAddress from the durable SessionIpCorrelations table.
		// Preference order per session: (WtsSessionId + UserName) → UserName fallback. We never
		// fall back to a 24h RawEvents heuristic any more — the dedicated correlation table
		// already carries the deterministic facts the processor persists.
		if (list.Sessions.Count > 0)
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			await EnrichSessionsFromCorrelationsAsync(db, list.Sessions, ct).ConfigureAwait(false);
		}

		return list;
	}

	/// <summary>Stage IP-B helper: enriches the supplied sessions with <c>ClientAddress</c> values
	/// resolved from <see cref="SessionIpCorrelation"/> rows. Exposed internally for unit testing
	/// without needing a Windows <c>RdpSessionManager</c>.</summary>
	internal static async Task EnrichSessionsFromCorrelationsAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		List<RdpSessionDto> needIp = new(sessions.Count);
		foreach (RdpSessionDto s in sessions)
		{
			if (string.IsNullOrEmpty(s.ClientAddress) && !string.IsNullOrEmpty(s.UserName))
			{
				needIp.Add(s);
			}
		}

		if (needIp.Count == 0)
		{
			return;
		}

		HashSet<int> wtsIds = new();
		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in needIp)
		{
			wtsIds.Add(s.SessionId);
			usernames.Add(s.UserName);
		}

		List<SessionIpCorrelation> wtsMatches = await db.SessionIpCorrelations
			.AsNoTracking()
			.Where(r => r.WtsSessionId != null
				&& wtsIds.Contains(r.WtsSessionId.Value)
				&& r.UserName != null
				&& usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<(int Wts, string User), string> wtsUserToIp = new();
		foreach (SessionIpCorrelation row in wtsMatches)
		{
			if (row.WtsSessionId is int wts && row.UserName is string u)
			{
				(int, string) key = (wts, u.Trim());
				if (!wtsUserToIp.ContainsKey(key))
				{
					wtsUserToIp[key] = row.Ip;
				}
			}
		}

		List<SessionIpCorrelation> userMatches = await db.SessionIpCorrelations
			.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string> userToIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (SessionIpCorrelation row in userMatches)
		{
			if (row.UserName is string u && !userToIp.ContainsKey(u.Trim()))
			{
				userToIp[u.Trim()] = row.Ip;
			}
		}

		foreach (RdpSessionDto session in needIp)
		{
			if (wtsUserToIp.TryGetValue((session.SessionId, session.UserName.Trim()), out string? ip))
			{
				session.ClientAddress = ip;
				continue;
			}

			if (userToIp.TryGetValue(session.UserName.Trim(), out ip))
			{
				session.ClientAddress = ip;
			}
		}

		// Stage IP-C: fallback historical enrichment from RdpConnectionFacts. Only fills in
		// ClientAddress that remained empty after the active SessionIpCorrelations pass — the
		// correlations table is still authoritative for live sessions, the connection facts only
		// add the most recent historical observation when no live correlation exists.
		await EnrichSessionsFromConnectionFactsAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage IP-C helper: enriches sessions with the most recent <see cref="RdpConnectionFact"/>
	/// IP for the same (WtsSessionId, UserName) or UserName. Only fills <c>ClientAddress</c> when it
	/// is still empty — does not override values set by the live correlation lookup.</summary>
	internal static async Task EnrichSessionsFromConnectionFactsAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		List<RdpSessionDto> needIp = new(sessions.Count);
		foreach (RdpSessionDto s in sessions)
		{
			if (string.IsNullOrEmpty(s.ClientAddress) && !string.IsNullOrEmpty(s.UserName))
			{
				needIp.Add(s);
			}
		}

		if (needIp.Count == 0)
		{
			return;
		}

		HashSet<int> wtsIds = new();
		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in needIp)
		{
			wtsIds.Add(s.SessionId);
			usernames.Add(s.UserName);
		}

		List<RdpConnectionFact> wtsMatches = await db.RdpConnectionFacts
			.AsNoTracking()
			.Where(r => r.WtsSessionId != null
				&& wtsIds.Contains(r.WtsSessionId.Value)
				&& r.UserName != null
				&& usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<(int Wts, string User), string> wtsUserToIp = new();
		foreach (RdpConnectionFact row in wtsMatches)
		{
			if (row.WtsSessionId is int wts && row.UserName is string u)
			{
				(int, string) key = (wts, u.Trim());
				if (!wtsUserToIp.ContainsKey(key))
				{
					wtsUserToIp[key] = row.Ip;
				}
			}
		}

		List<RdpConnectionFact> userMatches = await db.RdpConnectionFacts
			.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string> userToIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpConnectionFact row in userMatches)
		{
			if (row.UserName is string u && !userToIp.ContainsKey(u.Trim()))
			{
				userToIp[u.Trim()] = row.Ip;
			}
		}

		foreach (RdpSessionDto session in needIp)
		{
			if (wtsUserToIp.TryGetValue((session.SessionId, session.UserName.Trim()), out string? ip))
			{
				session.ClientAddress = ip;
				continue;
			}

			if (userToIp.TryGetValue(session.UserName.Trim(), out ip))
			{
				session.ClientAddress = ip;
			}
		}

		// Stage IP-D: fill historical context (first/last seen, counters, attempted usernames)
		// for every session that has a UserName, even those whose ClientAddress was already known
		// from the live correlation lookup. We never overwrite ClientAddress here — that path is
		// authoritative for the live row — but the historical context is purely additive.
		await EnrichSessionsHistoricalContextAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage IP-D helper: fills historical-only fields on each session from RdpConnectionFacts.
	/// Never overwrites live <c>ClientAddress</c>; only sets the dedicated Historical* columns and
	/// only when the live row has none. Exposed internally so unit tests can validate without a
	/// Windows session manager.</summary>
	internal static async Task EnrichSessionsHistoricalContextAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		if (sessions.Count == 0)
		{
			return;
		}

		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in sessions)
		{
			if (!string.IsNullOrEmpty(s.UserName))
			{
				usernames.Add(s.UserName.Trim());
			}
		}

		if (usernames.Count == 0)
		{
			return;
		}

		var grouped = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.GroupBy(r => r.UserName!)
			.Select(g => new
			{
				UserName = g.Key,
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, (DateTime First, DateTime Last, long Failed, long Successful)> byUser =
			new(StringComparer.OrdinalIgnoreCase);
		foreach (var g in grouped)
		{
			byUser[g.UserName.Trim()] = (g.FirstSeen, g.LastSeen, g.Failed, g.Successful);
		}

		// Pull attempted-username summaries by joining each session's user back to facts.
		List<RdpConnectionFact> usernameFacts = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.Select(r => new RdpConnectionFact
			{
				UserName = r.UserName,
				UserNamesAttempted = r.UserNamesAttempted,
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string?> attemptedByUser = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpConnectionFact r in usernameFacts)
		{
			if (r.UserName is null)
			{
				continue;
			}

			string key = r.UserName.Trim();
			if (!attemptedByUser.ContainsKey(key))
			{
				attemptedByUser[key] = r.UserNamesAttempted;
			}
		}

		foreach (RdpSessionDto session in sessions)
		{
			if (string.IsNullOrEmpty(session.UserName))
			{
				continue;
			}

			string key = session.UserName.Trim();
			if (byUser.TryGetValue(key, out var agg))
			{
				session.HistoricalFirstSeenUtc = agg.First;
				session.HistoricalLastSeenUtc = agg.Last;
				session.HistoricalFailedLogons = agg.Failed;
				session.HistoricalSuccessfulLogons = agg.Successful;
			}

			if (attemptedByUser.TryGetValue(key, out string? attempted) && !string.IsNullOrEmpty(attempted))
			{
				session.HistoricalUserNamesAttempted = attempted;
			}
		}

		// Stage 2: per-IP historical aggregation. Populates HistoricalFailedLogonsByIp /
		// HistoricalSuccessfulLogonsByIp / HistoricalUsersAttemptedFromIp / HistoricalFirstSeenByIpUtc /
		// HistoricalLastSeenByIpUtc from RdpConnectionFacts keyed on the session's ClientAddress.
		// Sessions without a resolved IP keep these fields null (operator sees blank, not 0).
		await EnrichSessionsHistoricalByIpAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage 2 helper: fills per-IP historical context on each session from RdpConnectionFacts.
	/// Populates the *ByIp fields only — never touches the user-keyed historical columns. Sessions
	/// whose <c>ClientAddress</c> is empty or unparseable are skipped, leaving the new fields null so
	/// the UI can distinguish unknown IP from a real zero.</summary>
	internal static async Task EnrichSessionsHistoricalByIpAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		if (sessions.Count == 0)
		{
			return;
		}

		HashSet<string> ips = new(StringComparer.Ordinal);
		foreach (RdpSessionDto s in sessions)
		{
			if (!string.IsNullOrEmpty(s.ClientAddress))
			{
				ips.Add(s.ClientAddress.Trim());
			}
		}

		if (ips.Count == 0)
		{
			return;
		}

		var grouped = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => ips.Contains(r.Ip))
			.GroupBy(r => r.Ip)
			.Select(g => new
			{
				Ip = g.Key,
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, (DateTime First, DateTime Last, long Failed, long Successful)> byIp =
			new(StringComparer.Ordinal);
		foreach (var g in grouped)
		{
			byIp[g.Ip] = (g.FirstSeen, g.LastSeen, g.Failed, g.Successful);
		}

		// Distinct attempted usernames per IP (deduplicated, bounded). Order by LastSeenUtc desc so
		// the most recently attempted usernames come first.
		List<RdpConnectionFact> userFacts = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => ips.Contains(r.Ip) && r.UserName != null && r.UserName != string.Empty)
			.OrderByDescending(r => r.LastSeenUtc)
			.Select(r => new RdpConnectionFact
			{
				Ip = r.Ip,
				UserName = r.UserName,
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, List<string>> distinctUsersByIp = new(StringComparer.Ordinal);
		const int maxUsersPerIp = 20;
		foreach (RdpConnectionFact r in userFacts)
		{
			if (string.IsNullOrEmpty(r.UserName))
			{
				continue;
			}

			if (!distinctUsersByIp.TryGetValue(r.Ip, out List<string>? list))
			{
				list = new List<string>();
				distinctUsersByIp[r.Ip] = list;
			}

			if (list.Count >= maxUsersPerIp)
			{
				continue;
			}

			string trimmed = r.UserName.Trim();
			if (trimmed.Length == 0)
			{
				continue;
			}

			bool exists = false;
			foreach (string u in list)
			{
				if (string.Equals(u, trimmed, StringComparison.OrdinalIgnoreCase))
				{
					exists = true;
					break;
				}
			}

			if (!exists)
			{
				list.Add(trimmed);
			}
		}

		foreach (RdpSessionDto session in sessions)
		{
			if (string.IsNullOrEmpty(session.ClientAddress))
			{
				continue;
			}

			string ipKey = session.ClientAddress.Trim();
			if (byIp.TryGetValue(ipKey, out var agg))
			{
				session.HistoricalFirstSeenByIpUtc = agg.First;
				session.HistoricalLastSeenByIpUtc = agg.Last;
				session.HistoricalFailedLogonsByIp = agg.Failed;
				session.HistoricalSuccessfulLogonsByIp = agg.Successful;
			}
			else
			{
				// No fact rows yet for this IP — still populate counters with 0 so operators can
				// distinguish "we know the IP, just no history" from "no IP at all" (which leaves
				// the fields null and shows blank).
				session.HistoricalFailedLogonsByIp = 0;
				session.HistoricalSuccessfulLogonsByIp = 0;
			}

			if (distinctUsersByIp.TryGetValue(ipKey, out List<string>? users) && users.Count > 0)
			{
				session.HistoricalUsersAttemptedFromIp = string.Join(", ", users);
			}
		}
	}

	private async Task<object?> DisconnectSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "DisconnectSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowDisconnect)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Disconnect is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued disconnect for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.DisconnectAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	private async Task<object?> LogoffSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "LogoffSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowLogoff)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Logoff is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued logoff for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.LogoffAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	/// <summary>The actual <c>mstsc.exe /shadow</c> spawn must happen in the operator's interactive
	/// desktop session — the service runs under LocalSystem and cannot launch interactive UI. This
	/// handler therefore only enforces policy and returns a Success/Refused result; the Configurator
	/// is responsible for spawning mstsc with sanitized arguments built by the same Core helper.</summary>
	private SessionActionResult ShadowSessionPolicyCheck(string? payload)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "ShadowSession");
		if (!OperatingSystem.IsWindows())
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Shadow is only available on Windows hosts.",
			};
		}

		SessionControlOptions cfg = _options.CurrentValue.SessionControl;
		if (!cfg.Enabled || !cfg.AllowShadow)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Shadow is disabled by SessionControl policy.",
			};
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(req.SessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = req.SessionId,
				Message = v.Error,
			};
		}

		if (cfg.RequireShadowPolicy && _shadow is not null)
		{
			ShadowPolicyStatusDto status = _shadow.GetStatus();
			ShadowPolicyMode policy = ShadowPolicyModel.FromRawValue(status.ShadowMode);
			SessionCommandBuilder.ShadowMode requested = req.ShadowMode switch
			{
				1 => SessionCommandBuilder.ShadowMode.Control,
				2 => SessionCommandBuilder.ShadowMode.ControlNoConsent,
				_ => SessionCommandBuilder.ShadowMode.ViewOnly,
			};
			if (!ShadowPolicyModel.AllowsMode(policy, requested))
			{
				return new SessionActionResult
				{
					Status = IpcResultStatus.Refused,
					SessionId = req.SessionId,
					Message = string.Format(CultureInfo.InvariantCulture,
						"Shadow {0} refused — current policy '{1}' does not permit it. Use Apply Shadow Policy first.",
						requested, ShadowPolicyModel.Describe(policy)),
				};
			}
		}

		_logger.LogInformation("Operator-approved shadow request for session {Id} mode={Mode} reason='{Reason}'",
			req.SessionId, req.ShadowMode, req.Reason ?? string.Empty);
		return new SessionActionResult
		{
			Status = IpcResultStatus.Success,
			SessionId = req.SessionId,
			Message = "Shadow request approved by policy. Configurator must launch mstsc in the operator's desktop.",
		};
	}

	private RdpConfigurationDto GetRdpConfigurationHandler()
	{
		if (!OperatingSystem.IsWindows() || _rdpConfigReader is null)
		{
			return new RdpConfigurationDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "RDP configuration is only available on Windows hosts.",
			};
		}

		return _rdpConfigReader.Read();
	}

	private ShadowPolicyStatusDto GetShadowPolicyStatusHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		return _shadow.GetStatus();
	}

	private ShadowPolicyStatusDto ApplyShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		ShadowPolicyApplyRequest req = DeserializeApplyRequest(payload);
		_logger.LogInformation(
			"Operator-issued ApplyShadowPolicy mode={Mode} enableAll={Enable} backup={Backup} reason='{Reason}'",
			req.ShadowMode, req.EnableAllPermissions, req.TakeBackupFirst, req.Reason ?? string.Empty);
		return _shadow.Apply(req);
	}

	private ShadowPolicyStatusDto BackupShadowPolicyHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		_logger.LogInformation("Operator-issued BackupShadowPolicy");
		return _shadow.Backup();
	}

	private ShadowPolicyStatusDto RestoreShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		string? snapshotId = null;
		if (!string.IsNullOrWhiteSpace(payload))
		{
			try
			{
				snapshotId = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
			}
			catch (JsonException ex)
			{
				throw new IpcException("RestoreShadowPolicy payload is not a valid JSON string: " + ex.Message);
			}
		}

		_logger.LogInformation("Operator-issued RestoreShadowPolicy snapshot='{Snapshot}'", snapshotId ?? string.Empty);
		return _shadow.Restore(snapshotId);
	}

	private static SessionActionRequest DeserializeSessionRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with the SessionId.", commandName));
		}

		SessionActionRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<SessionActionRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(parsed.SessionId);
		if (!v.Ok)
		{
			throw new IpcException(v.Error ?? "Invalid SessionId.");
		}

		return parsed;
	}

	private static ShadowPolicyApplyRequest DeserializeApplyRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new ShadowPolicyApplyRequest();
		}

		try
		{
			ShadowPolicyApplyRequest? parsed = JsonSerializer.Deserialize<ShadowPolicyApplyRequest>(payload, JsonOptions.Default);
			return parsed ?? new ShadowPolicyApplyRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ApplyShadowPolicy payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------

	/// <summary>Returns a copy of the current settings with every secret field masked.</summary>
	private RdpAuditOptions GetMaskedSettings() => BuildMaskedSettings(_options.CurrentValue);

	/// <summary>Builds the client-safe settings document: every <see cref="RdpAuditOptions"/>
	/// section is carried, with its secret fields replaced by the mask placeholder.
	/// <para>
	/// Every section MUST be carried. The Configurator pages save the whole document back
	/// (GetSettings → mutate one subtree → SaveSettings), and SettingsManager replaces the incoming
	/// RdpAudit root. A section omitted here is therefore serialized at its CLR default and
	/// overwrites the operator's real values on the next save from any other tab — which reset
	/// Sharding / Logs / CrossHost / Notifications (including cross-host agent credentials) before
	/// this was fixed. Internal so the completeness contract is unit-testable without a live IPC
	/// pipe.
	/// </para></summary>
	internal static RdpAuditOptions BuildMaskedSettings(RdpAuditOptions src)
	{
		ArgumentNullException.ThrowIfNull(src);
		RdpAuditOptions copy = new()
		{
			Monitoring = src.Monitoring,
			Alerts = src.Alerts,
			Firewall = src.Firewall,
			Storage = src.Storage,
			Sharding = src.Sharding,
			Diagnostics = src.Diagnostics,
			Logs = src.Logs,
			AbuseIpDb = CloneAbuse(src.AbuseIpDb),
			MikroTik = CloneMikroTik(src.MikroTik),
			Api = CloneApi(src.Api),
			CrossHost = CloneCrossHost(src.CrossHost),
			SessionControl = src.SessionControl,
			ProcessMonitoring = src.ProcessMonitoring,
			Notifications = src.Notifications,
		};
		copy.AbuseIpDb.ApiKey = MaskSecret(src.AbuseIpDb.ApiKey);
		copy.MikroTik.Password = MaskSecret(src.MikroTik.Password);
		copy.Api.Token = MaskSecret(src.Api.Token);
		return copy;
	}

	/// <summary>Clones the cross-host section while masking every per-host credential envelope.
	/// Host names and timing knobs are preserved verbatim so a GetSettings/SaveSettings round-trip
	/// from any tab cannot reset them; each credential is replaced with the shared mask placeholder,
	/// which SettingsManager resolves back to the stored envelope on save.</summary>
	private static CrossHostOptions CloneCrossHost(CrossHostOptions src)
	{
		CrossHostOptions copy = new()
		{
			Enabled = src.Enabled,
			PollIntervalSeconds = src.PollIntervalSeconds,
			ConnectTimeoutMs = src.ConnectTimeoutMs,
			MaxFactsPerPoll = src.MaxFactsPerPoll,
			Hosts = new List<CrossHostHostOptions>(src.Hosts.Count),
		};
		foreach (CrossHostHostOptions host in src.Hosts)
		{
			copy.Hosts.Add(new CrossHostHostOptions
			{
				HostName = host.HostName,
				Credential = MaskSecret(host.Credential),
			});
		}

		return copy;
	}

	private static AbuseIpDbOptions CloneAbuse(AbuseIpDbOptions src) => new()
	{
		Enabled = src.Enabled,
		ReportAttacks = src.ReportAttacks,
		ApiKey = src.ApiKey,
		BaseUrl = src.BaseUrl,
		EndpointUrl = src.EndpointUrl,
		TimeoutSeconds = src.TimeoutSeconds,
		MaxReportsPerMinute = src.MaxReportsPerMinute,
		MaxReportsPerHour = src.MaxReportsPerHour,
		MaxReportsPerDay = src.MaxReportsPerDay,
		DeduplicationWindowMinutes = src.DeduplicationWindowMinutes,
		CacheLookups = src.CacheLookups,
		CacheTtlMinutes = src.CacheTtlMinutes,
		ReportThreshold = src.ReportThreshold,
		MinThreatScore = src.MinThreatScore,
		MinFailedAttempts = src.MinFailedAttempts,
		ReportCategories = new List<int>(src.ReportCategories),
	};

	private static MikroTikOptions CloneMikroTik(MikroTikOptions src) => new()
	{
		Enabled = src.Enabled,
		AddAttackerRules = src.AddAttackerRules,
		BaseUrl = src.BaseUrl,
		UseHttps = src.UseHttps,
		Host = src.Host,
		Port = src.Port,
		UserName = src.UserName,
		Password = src.Password,
		TimeoutSeconds = src.TimeoutSeconds,
		AddressList = src.AddressList,
		FilterChain = src.FilterChain,
		FilterAction = src.FilterAction,
		CommentTemplate = src.CommentTemplate,
		CommentPrefix = src.CommentPrefix,
		ValidateServerCertificate = src.ValidateServerCertificate,
		MaxOperationsPerMinute = src.MaxOperationsPerMinute,
		BlockDurationDays = src.BlockDurationDays,
		BlockDurationHours = src.BlockDurationHours,
		BlockDurationMinutes = src.BlockDurationMinutes,
	};

	private static ApiOptions CloneApi(ApiOptions src) => new()
	{
		Enabled = src.Enabled,
		Token = src.Token,
		ListenAddress = src.ListenAddress,
		Port = src.Port,
		CertificateThumbprint = src.CertificateThumbprint,
		CertificateSubject = src.CertificateSubject,
		AllowInsecureLoopback = src.AllowInsecureLoopback,
		MaxConnections = src.MaxConnections,
		RateLimitPerMinute = src.RateLimitPerMinute,
	};

	private static string MaskSecret(string raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}
		// Never echo the protected envelope or the plaintext. Just signal that a value is set.
		return "***configured***";
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 8 handlers — AbuseIPDB integration.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetAbuseIpDbStatusAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		AbuseIpDbStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			CredentialPresent = !string.IsNullOrWhiteSpace(opts.ApiKey),
			ReportingEnabled = opts.Enabled && opts.ReportAttacks,
			EndpointUrl = string.IsNullOrWhiteSpace(opts.EndpointUrl)
				? "https://api.abuseipdb.com/api/v2/report"
				: opts.EndpointUrl,
			DeduplicationWindowMinutes = Math.Max(15, opts.DeduplicationWindowMinutes),
			MaxReportsPerHour = Math.Max(1, opts.MaxReportsPerHour),
			MaxReportsPerDay = Math.Max(1, opts.MaxReportsPerDay),
			ReportDedupeEnabled = opts.ReportDedupeEnabled,
			ReportCooldownHours = Math.Clamp(opts.ReportCooldownHours, 1, 8760),
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			DateTime nowUtc = DateTime.UtcNow;

			dto.TotalReports = await db.AbuseReports.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
			dto.ReportsLastHour = await db.AbuseReports.AsNoTracking()
				.LongCountAsync(r => r.ReportedUtc >= nowUtc.AddHours(-1), ct).ConfigureAwait(false);
			dto.ReportsLastDay = await db.AbuseReports.AsNoTracking()
				.LongCountAsync(r => r.ReportedUtc >= nowUtc.AddDays(-1), ct).ConfigureAwait(false);

			AbuseReport? last = await db.AbuseReports.AsNoTracking()
				.OrderByDescending(r => r.ReportedUtc)
				.FirstOrDefaultAsync(ct)
				.ConfigureAwait(false);
			if (last is not null)
			{
				dto.LastResponseCode = last.ResponseCode;
				dto.LastReportUtc = last.ReportedUtc;
				dto.LastReportedIp = last.Ip;
				if (!string.IsNullOrEmpty(last.Error))
				{
					dto.LastError = last.Error;
				}
			}

			dto.RateLimited = dto.ReportsLastHour >= dto.MaxReportsPerHour
				|| dto.ReportsLastDay >= dto.MaxReportsPerDay;

			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"AbuseIPDB status: enabled={0} reportAttacks={1} credential={2} lastHour={3} lastDay={4}",
				opts.Enabled,
				opts.ReportAttacks,
				dto.CredentialPresent ? "configured" : "missing",
				dto.ReportsLastHour,
				dto.ReportsLastDay);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetAbuseIpDbStatus database lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "AbuseIPDB status: database lookup failed.";
		}

		return dto;
	}

	private async Task<object?> TestAbuseIpDbKeyAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		AbuseIpDbTestResult result = new();

		if (string.IsNullOrWhiteSpace(opts.ApiKey))
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.KeyFormatValid = false;
			result.RemoteVerified = false;
			result.ResponseCode = 0;
			result.Message = "No API key configured.";
			return result;
		}

		string? plaintext = null;
		if (_protector is not null)
		{
			try
			{
				plaintext = _protector.Unprotect(opts.ApiKey);
			}
			catch (SecretProtectionException)
			{
				plaintext = null;
			}
		}
		else
		{
			plaintext = opts.ApiKey;
		}

		bool formatOk = AbuseIpDbApiKeyValidator.IsLikelyValid(plaintext);
		result.KeyFormatValid = formatOk;

		if (!formatOk)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "Key format check failed.";
			return result;
		}

		if (_abuseClient is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "AbuseIPDB client is not registered on this host.";
			return result;
		}

		AbuseIpDbReportResult probe = await _abuseClient.ValidateKeyAsync(ct).ConfigureAwait(false);
		result.ResponseCode = probe.ResponseCode;
		result.Message = probe.Message;
		switch (probe.Outcome)
		{
			case AbuseIpDbReportOutcome.Accepted:
				result.RemoteVerified = true;
				result.Status = IpcResultStatus.Success;
				break;
			case AbuseIpDbReportOutcome.Rejected:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Refused;
				break;
			case AbuseIpDbReportOutcome.RateLimited:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
			case AbuseIpDbReportOutcome.NotConfigured:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.InvalidRequest;
				break;
			default:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
		}
		return result;
	}

	private const int AbuseIpDbReportLogDefaultLimit = 200;
	private const int AbuseIpDbReportLogMaxLimit = 1000;

	private async Task<object?> ListAbuseIpDbReportLogAsync(string? payload, CancellationToken ct)
	{
		int limit = AbuseIpDbReportLogDefaultLimit;
		if (!string.IsNullOrWhiteSpace(payload))
		{
			try
			{
				int requested = JsonSerializer.Deserialize<int>(payload, JsonOptions.Default);
				if (requested > 0)
				{
					limit = requested;
				}
			}
			catch (JsonException)
			{
				// Tolerate a missing / malformed limit and fall back to the default.
			}
		}

		if (limit > AbuseIpDbReportLogMaxLimit)
		{
			limit = AbuseIpDbReportLogMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<AbuseIpDbReportHistory> rows = await db.AbuseIpDbReportHistory.AsNoTracking()
			.OrderByDescending(r => r.ReportedAtUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		return rows.ConvertAll(r => new AbuseIpDbReportLogDto
		{
			Id = r.Id,
			TimeUtc = r.ReportedAtUtc,
			SourceIp = r.IpAddress,
			Classification = r.Classification,
			Action = r.Action,
			Reason = r.Reason,
			HttpStatusCode = r.HttpStatusCode,
			ReportId = r.ReportId,
			CooldownExpiresUtc = r.CooldownExpiresUtc,
			FailedCount = r.FailedCount,
			SuccessfulCount = r.SuccessfulCount,
			FirstSeenUtc = r.FirstSeenUtc,
			LastSeenUtc = r.LastSeenUtc,
			UsernamesSample = r.UsernamesSample,
			CommentPreview = r.CommentPreview,
			Source = r.Source,
		});
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 9 handlers — MikroTik integration.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetMikroTikStatusAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		MikroTikUrlBuilder.Result built = MikroTikUrlBuilder.Build(opts);
		string endpoint = built.Ok ? built.Url : opts.DescribeEndpoint();

		MikroTikStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Configured = built.Ok && !string.IsNullOrWhiteSpace(opts.UserName),
			CredentialPresent = !string.IsNullOrWhiteSpace(opts.Password),
			Enabled = opts.Enabled,
			AddAttackerRules = opts.AddAttackerRules,
			Endpoint = endpoint,
			Scheme = built.Ok && !string.IsNullOrEmpty(endpoint) && endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
				? "https"
				: (built.Ok && !string.IsNullOrEmpty(endpoint) ? "http" : string.Empty),
			Host = opts.Host,
			Port = opts.Port,
			FilterChain = opts.FilterChain,
			FilterAction = opts.FilterAction,
			CommentPrefix = string.IsNullOrWhiteSpace(opts.CommentPrefix) ? "RdpAudit" : opts.CommentPrefix,
			BlockDurationSeconds = (long)opts.ComposedBlockDuration().TotalSeconds,
			ValidateServerCertificate = opts.ValidateServerCertificate,
			AuditBackupUser = opts.AuditBackupUser,
			AuditManagementNetworks = opts.AuditManagementNetworks,
			AuditClockToleranceSeconds = opts.AuditClockToleranceSeconds,
			ProviderStatus = FirewallProviderStatus.NotConfigured.ToString(),
		};

		if (!built.Ok)
		{
			dto.LastError = built.Error;
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			dto.ActiveBlockCount = await db.ActiveBlocks.AsNoTracking()
				.LongCountAsync(b => b.Provider == FirewallProviderKind.MikroTik
					&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending), ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetMikroTikStatus active-block lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
		}

		// Resolve the actual provider status from the registered providers when available.
		foreach (IFirewallProvider provider in _providers)
		{
			if (!string.Equals(provider.ProviderId, "MikroTik", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			try
			{
				FirewallStatusReport report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
				dto.ProviderStatus = report.Status.ToString();
				if (report.Status != FirewallProviderStatus.Available && !string.IsNullOrWhiteSpace(report.Message))
				{
					dto.LastError = report.Message;
				}
				else if (report.Status == FirewallProviderStatus.Available)
				{
					dto.LastError = null;
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "MikroTik provider GetStatus threw");
				dto.ProviderStatus = FirewallProviderStatus.Unreachable.ToString();
				dto.LastError = ex.GetType().Name;
			}
			break;
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"MikroTik status: enabled={0} addRules={1} credential={2} endpoint={3} active={4}",
			opts.Enabled,
			opts.AddAttackerRules,
			dto.CredentialPresent ? "configured" : "missing",
			string.IsNullOrEmpty(endpoint) ? "(unset)" : endpoint,
			dto.ActiveBlockCount);
		return dto;
	}

	/// <summary>
	/// Runs the RouterOS security audit for the Configurator: read the snapshot, evaluate the
	/// catalogue, render the report. Read-only, and honest about its own coverage — a channel failure
	/// answers Unavailable with the reason instead of a report with zero findings.
	/// </summary>
	private async Task<object?> GetMikroTikSecurityAuditAsync(CancellationToken ct)
	{
		MikroTikSecurityAuditDto dto = new();

		if (_mikroTikClient is null)
		{
			dto.Status = IpcResultStatus.NotImplemented;
			dto.Verdict = "not evaluated";
			dto.Message = "The MikroTik client is not registered in this host.";
			return dto;
		}

		try
		{
			(MikroTikOperationResult result, MikroTikSecuritySnapshot snapshot) =
				await _mikroTikClient.ReadSecuritySnapshotAsync(ct).ConfigureAwait(false);

			if (result.Outcome != MikroTikOutcome.Accepted)
			{
				dto.Status = IpcResultStatus.Unavailable;
				dto.Verdict = "not evaluated";
				dto.Message = result.Message;
				return dto;
			}

			// The profile is configuration, not a constant: without the emergency account the audit
			// reports S-01 (critical) for the very account kept as the way out of a lockout.
			MikroTikOptions auditOptions = _options.CurrentValue.MikroTik;
			SecurityAuditProfile profile = new()
			{
				BackupUser = auditOptions.AuditBackupUser?.Trim() ?? string.Empty,
				ManagementNetworks = string.IsNullOrWhiteSpace(auditOptions.AuditManagementNetworks)
					? "192.168.31.0/24"
					: auditOptions.AuditManagementNetworks.Trim(),
				ClockToleranceSeconds = auditOptions.AuditClockToleranceSeconds > 0
					? auditOptions.AuditClockToleranceSeconds
					: 300,
			};

			SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot, profile, DateTime.Now);

			dto.Status = IpcResultStatus.Success;
			dto.DeviceName = report.DeviceName;
			dto.RouterOsVersion = report.RouterOsVersion;
			dto.BoardName = report.BoardName;
			dto.Uptime = report.Uptime;
			dto.CapturedUtc = report.CapturedUtc;
			dto.RiskIndex = report.RiskIndex;
			dto.Verdict = report.Verdict;
			dto.Total = report.Total;
			dto.Critical = report.CountOf(SecurityAuditSeverity.Critical);
			dto.High = report.CountOf(SecurityAuditSeverity.High);
			dto.Medium = report.CountOf(SecurityAuditSeverity.Medium);
			dto.Low = report.CountOf(SecurityAuditSeverity.Low);
			dto.Info = report.CountOf(SecurityAuditSeverity.Info);
			dto.AutoFixable = report.AutoFixableCount;
			dto.Message = result.Message;
			dto.UnavailableMenus = report.UnavailableMenus.ToList();
			dto.Markdown = SecurityAuditMarkdown.Render(report);
			dto.Findings = new List<MikroTikSecurityFindingDto>(report.Findings.Count);
			foreach (SecurityAuditFinding finding in report.Findings)
			{
				dto.Findings.Add(new MikroTikSecurityFindingDto
				{
					RuleId = finding.RuleId,
					Severity = SecurityAuditMarkdown.SeverityLabel(finding.Severity),
					Title = finding.Title,
					Menu = finding.Menu,
					Evidence = finding.Evidence,
					Why = finding.Why,
					Recommendation = finding.Recommendation,
					Autofix = SecurityAuditMarkdown.AutofixLabel(finding.Autofix),
					Commands = new List<string>(finding.Commands),
				});
			}

			return dto;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "MikroTik security audit failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Verdict = "not evaluated";
			dto.Message = "Security audit failed: " + ex.GetType().Name;
			return dto;
		}
	}
	private async Task<object?> TestMikroTikAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		MikroTikUrlBuilder.Result built = MikroTikUrlBuilder.Build(opts);
		MikroTikTestResult result = new()
		{
			Endpoint = built.Ok ? built.Url : opts.DescribeEndpoint(),
		};

		if (!built.Ok)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.CredentialFormatValid = false;
			result.RemoteVerified = false;
			result.Message = built.Error ?? "Endpoint composition failed.";
			return result;
		}

		if (string.IsNullOrWhiteSpace(opts.UserName) || string.IsNullOrWhiteSpace(opts.Password))
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.CredentialFormatValid = false;
			result.RemoteVerified = false;
			result.Message = "Username and password must be configured before testing.";
			return result;
		}

		result.CredentialFormatValid = true;

		if (_mikroTikClient is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.RemoteVerified = false;
			result.Message = "MikroTik client is not registered on this host.";
			return result;
		}

		MikroTikOperationResult probe = await _mikroTikClient.PingAsync(ct).ConfigureAwait(false);
		result.ResponseCode = probe.ResponseCode;
		result.Message = probe.Message;

		switch (probe.Outcome)
		{
			case MikroTikOutcome.Accepted:
				result.RemoteVerified = true;
				result.Status = IpcResultStatus.Success;
				break;
			case MikroTikOutcome.Rejected:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Refused;
				break;
			case MikroTikOutcome.RateLimited:
			case MikroTikOutcome.ServerError:
			case MikroTikOutcome.TransportError:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
			case MikroTikOutcome.NotConfigured:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.InvalidRequest;
				break;
			default:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
		}
		return result;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage A handlers — Overview dashboard summary + IP events export.
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on RawEvents returned by <c>GetEventsForIp</c> when no limit is supplied.</summary>
	internal const int EventsForIpDefaultLimit = 1000;

	/// <summary>Upper bound on RawEvents returned by <c>GetEventsForIp</c> regardless of caller intent.</summary>
	internal const int EventsForIpMaxLimit = 5000;

	/// <summary>Default cap on alerts returned by <c>GetAlertsForIp</c> when no limit is supplied.</summary>
	internal const int AlertsForIpDefaultLimit = 200;

	/// <summary>Upper bound on alerts returned by <c>GetAlertsForIp</c> regardless of caller intent.</summary>
	internal const int AlertsForIpMaxLimit = 2000;

	private async Task<object?> GetOverviewSummaryAsync(CancellationToken ct)
	{
		DateTime nowUtc = DateTime.UtcNow;
		DateTime dayStart = nowUtc.Date;
		DateTime cutoff24h = nowUtc - TimeSpan.FromDays(1);

		OverviewSummaryDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			DatabaseSizeBytes = -1,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

			dto.AttacksToday = await db.Alerts.AsNoTracking()
				.LongCountAsync(a => a.TimeUtc >= dayStart, ct).ConfigureAwait(false);

			dto.BlockedIps = await db.ActiveBlocks.AsNoTracking()
				.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				.Select(b => b.Ip)
				.Distinct()
				.LongCountAsync(ct).ConfigureAwait(false);

			dto.FailedLogins24h = await db.RawEvents.AsNoTracking()
				.LongCountAsync(
					e => e.TimeUtc >= cutoff24h && e.EventId == AttackStatsAggregator.EventIdLogonFailure,
					ct).ConfigureAwait(false);

			List<DbProp> snapshots = await db.DbProps.AsNoTracking()
				.Where(p => p.Key.StartsWith("OverviewDbSize:"))
				.ToListAsync(ct).ConfigureAwait(false);

			string dbPath = _options.CurrentValue.Storage.ResolveDatabasePath();
			try
			{
				FileInfo fi = new(dbPath);
				dto.DatabaseSizeBytes = fi.Exists ? fi.Length : -1;
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
			{
				_logger.LogDebug(ex, "Database file size lookup failed");
				dto.DatabaseSizeBytes = -1;
			}

			if (dto.DatabaseSizeBytes >= 0)
			{
				List<DbSizeSnapshot> parsed = new();
				foreach (DbProp prop in snapshots)
				{
					if (DbSizeGrowthCalculator.TryDecode(prop.Value, out DbSizeSnapshot s))
					{
						parsed.Add(s);
					}
				}

				DbSizeGrowth growth = DbSizeGrowthCalculator.Compute(parsed, dto.DatabaseSizeBytes, nowUtc);
				dto.DatabaseGrowthBytesDay = growth.GrowthBytesDay;
				dto.DatabaseGrowthBytesWeek = growth.GrowthBytesWeek;
				dto.DatabaseGrowthBytesMonth = growth.GrowthBytesMonth;
			}

			RdpSessionListDto? sessions = null;
			if (OperatingSystem.IsWindows() && _sessions is not null)
			{
				try
				{
					sessions = await _sessions.ListAsync(ct).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "GetOverviewSummary session enumeration failed");
				}
			}
			dto.ActiveSessions = sessions is null
				? 0
				: ActiveSessionCounter.CountActiveUserSessions(sessions.Sessions);

			dto.ServiceHealth = "Running";
			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"attacksToday={0} blockedIps={1} activeSessions={2} failed24h={3} dbBytes={4}",
				dto.AttacksToday, dto.BlockedIps, dto.ActiveSessions, dto.FailedLogins24h, dto.DatabaseSizeBytes);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetOverviewSummary lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Overview summary lookup failed — see service log.";
		}

		return dto;
	}

	/// <summary>Returns a light snapshot of the long-running historical-analysis job so the Overview
	/// tab can show a progress bar. Never touches the database; always succeeds.</summary>
	private OverviewProgressDto GetOverviewProgressHandler()
	{
		Core.Diagnostics.OverviewProgressSnapshot s = _overviewProgress?.Snapshot()
			?? new Core.Diagnostics.OverviewProgressSnapshot { LastUpdatedUtc = DateTime.UtcNow };

		return new OverviewProgressDto
		{
			Status = IpcResultStatus.Success,
			IsRunning = s.IsRunning,
			Stage = s.Stage,
			ProcessedRows = s.ProcessedRows,
			TotalRows = s.TotalRows,
			Percent = s.Percent,
			StartedUtc = s.StartedUtc,
			LastUpdatedUtc = s.LastUpdatedUtc,
			CurrentChannel = s.CurrentChannel,
			LastEventUtc = s.LastEventUtc,
			Errors = s.Errors,
			Message = s.Message,
		};
	}

	/// <summary>Bounded, filtered, paged query over the durable OperationLogs table for the Logs tab.
	/// DepthDays and PageSize are clamped server-side; DEBUG-only detail fields are populated only when
	/// DEBUG mode is enabled so a normal-mode client receives compact rows.</summary>
	private async Task<object?> QueryOperationLogsAsync(string? payload, CancellationToken ct)
	{
		LogsOptions logs = _options.CurrentValue.Logs;
		bool debug = _options.CurrentValue.Diagnostics.DebugMode;

		OperationLogQueryRequest req = string.IsNullOrWhiteSpace(payload)
			? new OperationLogQueryRequest()
			: JsonSerializer.Deserialize<OperationLogQueryRequest>(payload, JsonOptions.Default) ?? new OperationLogQueryRequest();

		int depthDays = req.DepthDays > 0 && LogsOptions.IsValidDepth(req.DepthDays)
			? req.DepthDays
			: logs.ResolveViewDepthDays();
		int pageSize = logs.ResolvePageSize(req.PageSize);
		int page = req.Page < 0 ? 0 : req.Page;

		DateTime nowUtc = DateTime.UtcNow;
		DateTime cutoff = nowUtc - TimeSpan.FromDays(depthDays);

		OperationLogPageDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Page = page,
			PageSize = pageSize,
			DepthDays = depthDays,
			DebugMode = debug,
			QueriedUtc = nowUtc,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

			IQueryable<OperationLog> q = db.OperationLogs.AsNoTracking()
				.Where(r => r.TimeUtc >= cutoff);

			if (req.MinSeverity is { } minSev)
			{
				q = q.Where(r => r.Severity >= minSev);
			}

			if (!string.IsNullOrWhiteSpace(req.Source))
			{
				string src = req.Source.Trim();
				q = q.Where(r => r.Source == src);
			}

			if (!string.IsNullOrWhiteSpace(req.SearchText))
			{
				string term = SqlLikeEscaper.Escape(req.SearchText.Trim());
				q = q.Where(r =>
					EF.Functions.Like(r.Operation, "%" + term + "%", SqlLikeEscaper.EscapeString)
					|| EF.Functions.Like(r.Message, "%" + term + "%", SqlLikeEscaper.EscapeString)
					|| EF.Functions.Like(r.Source, "%" + term + "%", SqlLikeEscaper.EscapeString));
			}

			// Default-view noise suppression: hide Debug-classified rows and the high-volume IPC
			// accept-loop / connection chatter so the operator sees meaningful operations and errors.
			// A genuine fault is recorded above Debug (Error/Critical) and is never suppressed here.
			if (req.ExcludeDebugNoise)
			{
				q = q.Where(r => !r.IsDebug
					&& !(r.Source == IpcLogSource && r.Severity < OperationLogSeverity.Warning));
			}

			dto.TotalMatching = await q.LongCountAsync(ct).ConfigureAwait(false);

			List<OperationLog> rows = await q
				.OrderByDescending(r => r.TimeUtc)
				.ThenByDescending(r => r.Id)
				.Skip(page * pageSize)
				.Take(pageSize)
				.ToListAsync(ct)
				.ConfigureAwait(false);

			List<OperationLogDto> projected = new(rows.Count);
			foreach (OperationLog r in rows)
			{
				projected.Add(new OperationLogDto
				{
					Id = r.Id,
					TimeUtc = r.TimeUtc,
					Severity = r.Severity,
					Source = r.Source,
					Operation = r.Operation,
					Message = r.Message,
					DetailsJson = debug ? r.DetailsJson : null,
					ExceptionType = r.ExceptionType,
					ExceptionMessage = r.ExceptionMessage,
					StackTrace = debug ? r.StackTrace : null,
					CorrelationId = r.CorrelationId,
					DurationMs = r.DurationMs,
					IsDebug = r.IsDebug,
					Actor = r.Actor,
					OccurrenceCount = 1,
				});
			}

			// Collapse consecutive identical rows (same Source + Operation + Message) within the served
			// page into a single representative carrying an occurrence count, so a repeated identical
			// entry does not flood the view. The DEBUG "expand repeated entries" view sets
			// GroupDuplicates=false to see every row individually.
			dto.Items = req.GroupDuplicates ? CollapseConsecutiveDuplicates(projected) : projected;

			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"matched={0} page={1} pageSize={2} depthDays={3} debug={4} excludeNoise={5} grouped={6} shown={7}",
				dto.TotalMatching, page, pageSize, depthDays, debug,
				req.ExcludeDebugNoise, req.GroupDuplicates, dto.Items.Count);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "QueryOperationLogs lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Operation-log query failed — see service log.";
		}

		return dto;
	}

	/// <summary>Operation-log Source used for IPC-channel records; below-Warning entries from this source
	/// are the high-volume accept-loop / connection chatter suppressed from the default Logs view.</summary>
	private const string IpcLogSource = "Ipc";

	/// <summary>Collapses runs of consecutive rows that share the same Source + Operation + Message into a
	/// single representative row whose <see cref="OperationLogDto.OccurrenceCount"/> records how many rows
	/// it stands in for. Input order is preserved; the representative is the first (newest) row of each run.
	/// Non-consecutive duplicates are intentionally left distinct so the operator still sees the timeline.</summary>
	internal static List<OperationLogDto> CollapseConsecutiveDuplicates(List<OperationLogDto> rows)
	{
		List<OperationLogDto> result = new(rows.Count);
		foreach (OperationLogDto row in rows)
		{
			OperationLogDto? last = result.Count > 0 ? result[^1] : null;
			if (last is not null
				&& string.Equals(last.Source, row.Source, StringComparison.Ordinal)
				&& string.Equals(last.Operation, row.Operation, StringComparison.Ordinal)
				&& string.Equals(last.Message, row.Message, StringComparison.Ordinal)
				&& last.Severity == row.Severity)
			{
				last.OccurrenceCount++;
			}
			else
			{
				result.Add(row);
			}
		}

		return result;
	}

	private async Task<object?> GetEventsForIpAsync(string? payload, CancellationToken ct)
	{
		EventsForIpRequest req = ParseEventsForIpRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? EventsForIpDefaultLimit : req.Limit;
		if (limit > EventsForIpMaxLimit)
		{
			limit = EventsForIpMaxLimit;
		}

		DateTime nowUtc = DateTime.UtcNow;
		EventsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = nowUtc,
		};

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<RawEvent> recent = await db.RawEvents.AsNoTracking()
			.Where(e => e.SourceIp == ip)
			.OrderByDescending(e => e.TimeUtc)
			.ThenByDescending(e => e.Id)
			.Take(limit)
			.ToListAsync(ct).ConfigureAwait(false);

		dto.TotalEvents = await db.RawEvents.AsNoTracking()
			.LongCountAsync(e => e.SourceIp == ip, ct).ConfigureAwait(false);

		if (dto.TotalEvents > 0)
		{
			dto.FirstSeenUtc = await db.RawEvents.AsNoTracking()
				.Where(e => e.SourceIp == ip)
				.MinAsync(e => (DateTime?)e.TimeUtc, ct).ConfigureAwait(false);
			dto.LastSeenUtc = await db.RawEvents.AsNoTracking()
				.Where(e => e.SourceIp == ip)
				.MaxAsync(e => (DateTime?)e.TimeUtc, ct).ConfigureAwait(false);
			dto.FailedCount = await db.RawEvents.AsNoTracking()
				.LongCountAsync(e => e.SourceIp == ip && e.EventId == AttackStatsAggregator.EventIdLogonFailure, ct)
				.ConfigureAwait(false);
			// Only an RDP-relevant 4624 counts as a success here, matching the AuthAttemptFact
			// classification and Attack Statistics shown beside this column. A Service (5) /
			// Batch (4) logon is created locally by the Service Control Manager and can never be
			// the attacker's login; counting it made the grid disagree with the facts it is
			// derived from. The logon-type set is inlined because the SQLite provider cannot
			// translate IsRdpRelevantLogonType; AttackStatsAggregatorTests locks it against the
			// predicate.
			dto.SuccessCount = await db.RawEvents.AsNoTracking()
				.LongCountAsync(
					e => e.SourceIp == ip
						&& e.EventId == AttackStatsAggregator.EventIdLogonSuccess
						&& (e.LogonType == null
							|| AttackStatsAggregator.RdpRelevantLogonTypeCodes.Contains(e.LogonType.Value)),
					ct)
				.ConfigureAwait(false);

			if (dto.FirstSeenUtc.HasValue && dto.LastSeenUtc.HasValue)
			{
				dto.DurationSeconds = Math.Max(0, (long)(dto.LastSeenUtc.Value - dto.FirstSeenUtc.Value).TotalSeconds);
			}
		}

		dto.AttemptedUserNames = await db.RawEvents.AsNoTracking()
			.Where(e => e.SourceIp == ip && e.UserName != null && e.UserName != string.Empty)
			.Select(e => e.UserName!)
			.Distinct()
			.OrderBy(u => u)
			.Take(20)
			.ToListAsync(ct).ConfigureAwait(false);

		AttackStat? stat = await db.AttackStats.AsNoTracking()
			.FirstOrDefaultAsync(s => s.Ip == ip, ct).ConfigureAwait(false);
		if (stat is not null)
		{
			dto.ThreatLevel = AttackThreatScoring.ClassifyScore(stat.ThreatScore).ToString();
			dto.IsBlocked = stat.IsBlocked;
			dto.AttackType = (stat.Failed > 0 && stat.Successful == 0)
				? "BruteForce"
				: (stat.Failed > 0 && stat.Successful > 0)
					? "BruteForceWithSuccess"
					: "LogonActivity";
		}
		else
		{
			dto.IsBlocked = await db.ActiveBlocks.AsNoTracking()
				.AnyAsync(b => b.Ip == ip
					&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending), ct)
				.ConfigureAwait(false);
		}

		foreach (RawEvent ev in recent)
		{
			dto.Events.Add(new IpEventEntryDto
			{
				Id = ev.Id,
				TimeUtc = ev.TimeUtc,
				EventId = ev.EventId,
				Channel = ev.Channel,
				UserName = ev.UserName,
				Domain = ev.Domain,
				LogonType = ev.LogonType,
				AuthPackage = ev.AuthPackage,
				ProcessName = ev.ProcessName,
				Status = ev.Status,
			});
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"events for {0}: returned={1} total={2}",
			ip, recent.Count, dto.TotalEvents);
		return dto;
	}

	private static EventsForIpRequest ParseEventsForIpRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetEventsForIp requires a JSON payload with an Ip field.");
		}

		EventsForIpRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<EventsForIpRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetEventsForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetEventsForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage SIEM handler - correlated alerts for one IP (export).
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetAlertsForIpAsync(string? payload, CancellationToken ct)
	{
		AlertsForIpRequest req = ParseAlertsForIpRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? AlertsForIpDefaultLimit : req.Limit;
		if (limit > AlertsForIpMaxLimit)
		{
			limit = AlertsForIpMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<Alert> alerts = await db.Alerts.AsNoTracking()
			.Where(a => a.SourceIp == ip)
			.OrderByDescending(a => a.TimeUtc)
			.ThenByDescending(a => a.Id)
			.Take(limit)
			.ToListAsync(ct).ConfigureAwait(false);

		AlertsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = DateTime.UtcNow,
			TotalAlerts = await db.Alerts.AsNoTracking()
				.LongCountAsync(a => a.SourceIp == ip, ct).ConfigureAwait(false),
		};

		foreach (Alert a in alerts)
		{
			dto.Alerts.Add(new AlertEntryDto
			{
				Id = a.Id,
				RuleId = a.RuleId,
				Severity = a.Severity,
				TimeUtc = a.TimeUtc,
				SourceIp = a.SourceIp,
				UserName = a.UserName,
				Message = a.Message,
				Acknowledged = a.Acknowledged,
				TriggerEventId = a.TriggerEventId,
			});
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"alerts for {0}: returned={1} total={2}",
			ip, dto.Alerts.Count, dto.TotalAlerts);
		return dto;
	}

	private static AlertsForIpRequest ParseAlertsForIpRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetAlertsForIp requires a JSON payload with an Ip field.");
		}

		AlertsForIpRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<AlertsForIpRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetAlertsForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetAlertsForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage IP-D handlers — RdpConnectionFacts read paths.
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on rows returned by <c>ListConnectionFacts</c> when no limit is supplied.</summary>
	internal const int ConnectionFactsDefaultLimit = 200;

	/// <summary>Upper bound on rows returned by <c>ListConnectionFacts</c> / <c>GetConnectionFactsForIp</c>.</summary>
	internal const int ConnectionFactsMaxLimit = 1000;

	private async Task<object?> ListConnectionFactsAsync(string? payload, CancellationToken ct)
	{
		ConnectionFactsRequest req = ParseConnectionFactsRequest(payload);

		int limit = req.Limit <= 0 ? ConnectionFactsDefaultLimit : req.Limit;
		if (limit > ConnectionFactsMaxLimit)
		{
			limit = ConnectionFactsMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<RdpConnectionFact> q = db.RdpConnectionFacts.AsNoTracking();

		if (!string.IsNullOrWhiteSpace(req.IpQuery))
		{
			string needle = SqlLikeEscaper.Escape(req.IpQuery.Trim());
			q = q.Where(r => EF.Functions.Like(r.Ip, "%" + needle + "%", SqlLikeEscaper.EscapeString));
		}

		if (!string.IsNullOrWhiteSpace(req.UserQuery))
		{
			string needleU = SqlLikeEscaper.Escape(req.UserQuery.Trim());
			q = q.Where(r => r.UserName != null && EF.Functions.Like(r.UserName, "%" + needleU + "%", SqlLikeEscaper.EscapeString));
		}

		if (req.SinceUtc.HasValue)
		{
			DateTime since = req.SinceUtc.Value;
			q = q.Where(r => r.LastSeenUtc >= since);
		}

		if (req.UntilUtc.HasValue)
		{
			DateTime until = req.UntilUtc.Value;
			q = q.Where(r => r.LastSeenUtc <= until);
		}

		if (req.OnlyActive)
		{
			q = q.Where(r => r.IsActive);
		}

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		List<RdpConnectionFact> rows = await q
			.OrderByDescending(r => r.LastSeenUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		HashSet<string> whitelist = await LoadWhitelistSetAsync(db, ct).ConfigureAwait(false);

		ConnectionFactsDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			TotalMatching = totalMatching,
			AppliedLimit = limit,
			Message = string.Format(CultureInfo.InvariantCulture,
				"connection facts: matching={0} returned={1}",
				totalMatching, rows.Count),
		};

		foreach (RdpConnectionFact row in rows)
		{
			dto.Facts.Add(ProjectFact(row, whitelist));
		}

		await StampConnectionFactsThreatIntelAsync(dto.Facts, ct).ConfigureAwait(false);

		return dto;
	}

	private static async Task<HashSet<string>> LoadWhitelistSetAsync(AuditDbContext db, CancellationToken ct)
	{
		List<string> ips = await db.WhitelistEntries.AsNoTracking()
			.Select(w => w.Ip)
			.ToListAsync(ct)
			.ConfigureAwait(false);
		return new HashSet<string>(ips, StringComparer.OrdinalIgnoreCase);
	}

	private async Task<object?> GetConnectionFactsForIpAsync(string? payload, CancellationToken ct)
	{
		ConnectionFactsForIpRequest req = ParseConnectionFactsForIpRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? ConnectionFactsDefaultLimit : req.Limit;
		if (limit > ConnectionFactsMaxLimit)
		{
			limit = ConnectionFactsMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<RdpConnectionFact> q = db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.Ip == ip);

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		ConnectionFactsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = DateTime.UtcNow,
			TotalMatching = totalMatching,
			AppliedLimit = limit,
		};

		if (totalMatching == 0)
		{
			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"no connection facts recorded for {0}", ip);
			return dto;
		}

		List<RdpConnectionFact> rows = await q
			.OrderByDescending(r => r.LastSeenUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		// Aggregate counters span the entire IP, not just the bounded page — operators want totals.
		var aggregate = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.Ip == ip)
			.GroupBy(r => r.Ip)
			.Select(g => new
			{
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
				AnyActive = g.Any(r => r.IsActive),
			})
			.FirstOrDefaultAsync(ct).ConfigureAwait(false);

		if (aggregate is not null)
		{
			dto.FirstSeenUtc = aggregate.FirstSeen;
			dto.LastSeenUtc = aggregate.LastSeen;
			dto.FailedLogons = aggregate.Failed;
			dto.SuccessfulLogons = aggregate.Successful;
			dto.HasActiveFact = aggregate.AnyActive;
		}

		HashSet<string> whitelist = await LoadWhitelistSetAsync(db, ct).ConfigureAwait(false);

		foreach (RdpConnectionFact row in rows)
		{
			dto.Facts.Add(ProjectFact(row, whitelist));
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"connection facts for {0}: matching={1} returned={2}",
			ip, totalMatching, rows.Count);
		return dto;
	}

	private static ConnectionFactDto ProjectFact(RdpConnectionFact row, HashSet<string>? whitelist = null)
	{
		Func<string, bool>? isWhitelisted = whitelist is null
			? null
			: ip => whitelist.Contains(ip);

		IpReportabilityResult classification = IpReportability.Classify(row.Ip, isWhitelisted);

		return new ConnectionFactDto
		{
			Id = row.Id,
			Ip = row.Ip,
			UserName = row.UserName,
			Domain = row.Domain,
			WtsSessionId = row.WtsSessionId,
			LogonId = row.LogonId,
			FirstSeenUtc = row.FirstSeenUtc,
			LastSeenUtc = row.LastSeenUtc,
			ConnectedUtc = row.ConnectedUtc,
			AuthenticatedUtc = row.AuthenticatedUtc,
			DisconnectedUtc = row.DisconnectedUtc,
			ReconnectedUtc = row.ReconnectedUtc,
			LoggedOffUtc = row.LoggedOffUtc,
			FailedLogons = row.FailedLogons,
			SuccessfulLogons = row.SuccessfulLogons,
			ObservedEventIds = row.ObservedEventIds,
			UserNamesAttempted = row.UserNamesAttempted,
			IsActive = row.IsActive,
			Classification = IpReportability.Describe(classification.Classification),
			IsPublic = classification.IsPublic,
			IsWhitelisted = classification.Classification == IpReportClassification.Whitelisted,
			IsReportableToAbuseIPDB = classification.IsReportable,
			IsEligibleForAutoBlock = classification.IsReportable
				&& classification.Classification != IpReportClassification.Whitelisted,
		};
	}

	private static ConnectionFactsRequest ParseConnectionFactsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new ConnectionFactsRequest();
		}

		try
		{
			ConnectionFactsRequest? parsed = JsonSerializer.Deserialize<ConnectionFactsRequest>(payload, JsonOptions.Default);
			return parsed ?? new ConnectionFactsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ListConnectionFacts payload is not valid JSON: " + ex.Message);
		}
	}

	private static ConnectionFactsForIpRequest ParseConnectionFactsForIpRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetConnectionFactsForIp requires a JSON payload with an Ip field.");
		}

		ConnectionFactsForIpRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<ConnectionFactsForIpRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetConnectionFactsForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetConnectionFactsForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------

	private static string NormalizeAndValidateLogin(string login)
	{
		if (string.IsNullOrWhiteSpace(login))
		{
			throw new IpcException("Login must not be empty.");
		}

		string trimmed = login.Trim();
		if (trimmed.Length > 256)
		{
			throw new IpcException("Login is too long (max 256 characters).");
		}

		foreach (char c in trimmed)
		{
			if (char.IsControl(c))
			{
				throw new IpcException("Login contains control characters.");
			}
		}

		return trimmed.ToLowerInvariant();
	}

	// ----------------------------------------------------------------------------------------------
	// Stage Diag: GetDiagnostics
	// ----------------------------------------------------------------------------------------------

	/// <summary>Build the LLM-friendly diagnostics snapshot exposed via IpcCommand.GetDiagnostics.
	/// All DB lookups go through Microsoft.Data.Sqlite via EF Core — no external sqlite3.exe.</summary>
	/// <summary>Returns the distinct items of <paramref name="source"/>, preserving first-occurrence order.</summary>
	internal static List<string> DistinctPreserveOrder(IEnumerable<string> source, IEqualityComparer<string> comparer)
	{
		HashSet<string> seen = new(comparer);
		List<string> result = new();
		foreach (string item in source)
		{
			if (seen.Add(item))
			{
				result.Add(item);
			}
		}
		return result;
	}

	private async Task<DiagnosticsSnapshotDto> GetDiagnosticsAsync(CancellationToken ct)
	{
		DiagnosticsSnapshotDto dto = new()
		{
			GeneratedUtc = DateTime.UtcNow,
			ServiceVersion = ResolveRuntimeVersion(),
			ChannelStatus = _metrics.SnapshotChannels(),
			SecurityWatcherEnabled = _metrics.SecurityWatcherEnabled,
			SecurityEventsRead = _metrics.SecurityEventsRead,
			SecurityEventsNormalized = _metrics.SecurityEventsNormalized,
			SecurityEventsRejected = _metrics.SecurityEventsRejected,
			LastSecurityChannelError = _metrics.LastSecurityChannelError,
			LastSecurityEventUtc = _metrics.LastSecurityEventUtc,
			SecurityBackfillLastRunUtc = _metrics.SecurityBackfillLastRunUtc,
			SecurityBackfillRecordsRead = _metrics.SecurityBackfillRecordsRead,
			SecurityBackfillRecordsForwarded = _metrics.SecurityBackfillRecordsForwarded,
			SecurityBackfillRecordsDeduped = _metrics.SecurityBackfillRecordsDeduped,
			Security4624Count = _metrics.Security4624Count,
			Security4625Count = _metrics.Security4625Count,
			Security4648Count = _metrics.Security4648Count,
			AuthAttemptFactCreated = _metrics.AuthAttemptFactCreated,
			AuthAttemptFactFailed = _metrics.AuthAttemptFactFailed,
			AuthAttemptFactSucceeded = _metrics.AuthAttemptFactSucceeded,
			LastAuthAttemptFactCreatedUtc = _metrics.LastAuthAttemptFactCreatedUtc,
			StatsWorkerLastRunUtc = _metrics.StatsWorkerLastRunUtc,
			StatsWorkerLastRowsUpserted = _metrics.StatsWorkerLastRowsUpserted,
			StatsWorkerRunCount = _metrics.StatsWorkerRunCount,
			StatsWorkerLastError = _metrics.StatsWorkerLastError,
			StatsWorkerEnabled = _metrics.StatsWorkerEnabled,
			StatsWorkerLastStartedUtc = _metrics.StatsWorkerLastStartedUtc,
			StatsWorkerLastCompletedUtc = _metrics.StatsWorkerLastCompletedUtc,
			StatsWorkerLastRunFullRebuild = _metrics.StatsWorkerLastRunFullRebuild,
		};

		// v1.3.4: surface the resolved RDP listener port and the firewall block scope so an operator on
		// a host that moved RDP off 3389 (e.g. to 55554) can confirm the service tracks the live port —
		// never a hardcoded 3389. The provider abstraction yields the port; on Windows we also resolve
		// the source (registry vs documented default) for the diagnostic detail line.
		PopulateRdpPortDiagnostics(dto);
		dto.FirewallBlockScope = _options.CurrentValue.Firewall.BlockScope.ToString();

		// Effective channels/event IDs come from the live options snapshot — the post-configure
		// repair has already run by the time options are materialised here.
		RdpAuditOptions opts = _options.CurrentValue;
		// Deduplicate channels case-insensitively: repeated post-configure repair passes can append the
		// same channel name multiple times (e.g. "Security" 8×), which inflated the effective-channel
		// list (7 unique channels appeared as 56). Event IDs are deduplicated numerically. Order is
		// preserved (first occurrence wins) so the operator sees a stable, readable list.
		dto.EnabledChannels.AddRange(DistinctPreserveOrder(opts.Monitoring.EnabledChannels, StringComparer.OrdinalIgnoreCase));
		dto.EnabledEventIds.AddRange(opts.Monitoring.EnabledEventIds.Distinct());
		dto.DatabasePath = opts.Storage.ResolveDatabasePath();

		// Service install path — best-effort runtime discovery via AppContext.BaseDirectory
		// (RdpAudit.Service.exe lives next to the worker DLLs). For SCM-authoritative ImagePath
		// resolution use ServiceInstallationInfo on the Configurator side.
		try
		{
			dto.InstallPath = AppContext.BaseDirectory;
		}
		catch (Exception ex)
		{
			dto.RecentPipelineErrors.Add("InstallPath probe failed: " + ex.Message);
		}

		if (_configRepair?.LastReport is { } report)
		{
			dto.MonitoringConfigRepairChanged = report.Changed;
			dto.MonitoringConfigRepairAddedChannels.AddRange(DistinctPreserveOrder(report.AddedChannels, StringComparer.OrdinalIgnoreCase));
			dto.MonitoringConfigRepairAddedEventIds.AddRange(report.AddedEventIds.Distinct());
			dto.MonitoringConfigRepairReason = report.Reason;
			dto.MonitoringConfigRepairUtc = _configRepair.LastReportUtc;
			dto.MonitoringConfigRepairChangedRunCount = _configRepair.ChangedRunCount;
		}

		if (!string.IsNullOrEmpty(_metrics.LastSecurityChannelError))
		{
			dto.RecentPipelineErrors.Add("Security channel: " + _metrics.LastSecurityChannelError);
		}
		if (!string.IsNullOrEmpty(_metrics.LastSecurityRejectReason))
		{
			dto.RecentPipelineErrors.Add(string.Format(
				CultureInfo.InvariantCulture,
				"Last reject ({0}): {1}",
				_metrics.SecurityRejectReasonCount,
				_metrics.LastSecurityRejectReason));
		}
		if (!string.IsNullOrEmpty(_metrics.SecurityCorrelationDiagnostic))
		{
			dto.RecentPipelineErrors.Add("Correlation diagnostic: " + _metrics.SecurityCorrelationDiagnostic);
		}

		// v1.3.9: assemble the DB-backed diagnostics as discrete, individually-bounded SECTIONS so a slow
		// or hung section (a large RawEvents GROUP BY, a locked DB) never blocks the cheap basics and the
		// snapshot is always returned with whatever completed. Each section runs under its own timeout and
		// records its duration / status; the DEBUG OperationLog mirrors the timings.
		bool diagDebug = _options.CurrentValue.Diagnostics.DebugMode;

		// Schema-aware section FIRST (cheap PRAGMA reads) so later sections — and the operator — know which
		// columns actually exist before any assumption is made. Problem 6: never assume AttackStats.TimeUtc
		// or AuthAttemptFacts.UserName exist; read the real schema and the LastSeenUtc / TimeUtc watermarks
		// defensively.
		await RunDiagnosticsSectionAsync(dto, "DbSchema", diagDebug, async (db, sct) =>
		{
			await PopulateSchemaAwareDiagnosticsAsync(db, dto, sct).ConfigureAwait(false);
		}, ct).ConfigureAwait(false);

		// B25: the store-integrity verdict, from the same sources the Database tab reads — the fingerprint
		// chain on disk (through StoreFingerprintVerdictReader, shared with the overview so the two tabs cannot
		// disagree) and the deletion-ledger hash chain (through the same Core verifier the overview uses).
		// The Diagnostic tab is where an operator lands after an unexplained restart, which is exactly when a
		// tamper verdict has to be on the screen. Nothing here runs a check: both verdicts are readings of
		// state that already exists, so opening the tab cannot impose a page scan on the store.
		await RunDiagnosticsProbeAsync(dto, "StoreFingerprint", diagDebug, () =>
		{
			PopulateFingerprintVerdict(dto);
			return Task.CompletedTask;
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "StoreIntegrity", diagDebug, async (db, sct) =>
		{
			await PopulateStoreIntegrityDiagnosticsAsync(db, dto, sct).ConfigureAwait(false);
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "DbCounts", diagDebug, async (db, sct) =>
		{
			dto.RawEventsTotal = await db.RawEvents.AsNoTracking().LongCountAsync(sct).ConfigureAwait(false);
			dto.AuthAttemptFactsTotal = await db.AuthAttemptFacts.AsNoTracking().LongCountAsync(sct).ConfigureAwait(false);
			dto.AttackStatsTotal = await db.AttackStats.AsNoTracking().LongCountAsync(sct).ConfigureAwait(false);
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "DbFreshness", diagDebug, async (db, sct) =>
		{
			// v1.3.4: freshness markers across the three pipeline stages so a stale RDP Activity tab can be
			// localised — newest RawEvent (ingest), newest AuthAttemptFact (normalisation), newest
			// AttackStat.LastUpdatedUtc (projection). Diverging timestamps tell the operator which stage stalled.
			if (dto.RawEventsTotal > 0)
			{
				dto.LatestRawEventUtc = await db.RawEvents.AsNoTracking().MaxAsync(e => (DateTime?)e.TimeUtc, sct).ConfigureAwait(false);
			}
			if (dto.AuthAttemptFactsTotal > 0)
			{
				dto.LatestAuthAttemptFactUtc = await db.AuthAttemptFacts.AsNoTracking().MaxAsync(f => (DateTime?)f.TimeUtc, sct).ConfigureAwait(false);
				dto.LatestSourceFactUtc = dto.LatestAuthAttemptFactUtc;
			}
			if (dto.AttackStatsTotal > 0)
			{
				dto.LatestAttackStatUpdatedUtc = await db.AttackStats.AsNoTracking().MaxAsync(s => (DateTime?)s.LastUpdatedUtc, sct).ConfigureAwait(false);
				// v1.3.6: projection OUTPUT watermark. The RDP Activity week filter uses LastSeenUtc.
				dto.LatestAttackStatLastSeenUtc = await db.AttackStats.AsNoTracking().MaxAsync(s => (DateTime?)s.LastSeenUtc, sct).ConfigureAwait(false);
			}
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "OperationLogTail", diagDebug, async (db, sct) =>
		{
			List<DiagnosticsOperationLogLine> opLogTail = await db.OperationLogs.AsNoTracking()
				.OrderByDescending(o => o.Id)
				.Take(20)
				.Select(o => new DiagnosticsOperationLogLine
				{
					TimeUtc = o.TimeUtc,
					Severity = o.Severity.ToString(),
					Source = o.Source,
					Operation = o.Operation,
					Message = o.Message,
				})
				.ToListAsync(sct).ConfigureAwait(false);
			dto.RecentOperationLog.AddRange(opLogTail);
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "RawEventsByChannel", diagDebug, async (db, sct) =>
		{
			List<DiagnosticsChannelCount> byChannel = await db.RawEvents.AsNoTracking()
				.GroupBy(e => e.Channel)
				.Select(g => new DiagnosticsChannelCount { Channel = g.Key, Count = g.LongCount() })
				.OrderByDescending(x => x.Count)
				.ThenBy(x => x.Channel)
				.Take(20)
				.ToListAsync(sct).ConfigureAwait(false);
			dto.RawEventsByChannel.AddRange(byChannel);
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "RawEventsByEventId", diagDebug, async (db, sct) =>
		{
			List<DiagnosticsEventIdCount> byEventId = await db.RawEvents.AsNoTracking()
				.GroupBy(e => new { e.Channel, e.EventId })
				.Select(g => new DiagnosticsEventIdCount
				{
					Channel = g.Key.Channel,
					EventId = g.Key.EventId,
					Count = g.LongCount(),
				})
				.OrderByDescending(x => x.Count)
				.ThenBy(x => x.Channel)
				.ThenBy(x => x.EventId)
				.Take(30)
				.ToListAsync(sct).ConfigureAwait(false);
			dto.RawEventsByEventId.AddRange(byEventId);
		}, ct).ConfigureAwait(false);

		await RunDiagnosticsSectionAsync(dto, "AuthFactsByOutcome", diagDebug, async (db, sct) =>
		{
			List<DiagnosticsFactOutcomeCount> byOutcome = await db.AuthAttemptFacts.AsNoTracking()
				.GroupBy(f => new { f.EvidenceEventId, f.Outcome })
				.Select(g => new DiagnosticsFactOutcomeCount
				{
					EvidenceEventId = g.Key.EvidenceEventId,
					Outcome = g.Key.Outcome.ToString(),
					Count = g.LongCount(),
				})
				.OrderByDescending(x => x.Count)
				.ThenBy(x => x.EvidenceEventId)
				.ThenBy(x => x.Outcome)
				.Take(30)
				.ToListAsync(sct).ConfigureAwait(false);
			dto.AuthAttemptFactsByOutcome.AddRange(byOutcome);
		}, ct).ConfigureAwait(false);

		if (dto.IsPartial && dto.Status == IpcResultStatus.Success)
		{
			dto.Status = IpcResultStatus.Unavailable;
		}

		dto.Message = string.Format(
			CultureInfo.InvariantCulture,
			"Snapshot built at {0:O}. RawEvents={1} AuthAttemptFacts={2} SecurityWatcher={3} RepairChanged={4} Partial={5}",
			dto.GeneratedUtc,
			dto.RawEventsTotal,
			dto.AuthAttemptFactsTotal,
			dto.SecurityWatcherEnabled,
			dto.MonitoringConfigRepairChanged,
			dto.IsPartial);

		return dto;
	}

	/// <summary>Per-section timeout (ms) for the bounded diagnostics assembly. Each DB section gets its
	/// own budget so one slow section yields a partial snapshot instead of stalling the whole call.</summary>
	private const int DiagnosticsSectionTimeoutMs = 8000;

	/// <summary>v1.3.9: runs one bounded diagnostics section under its own timeout, recording duration /
	/// status into <see cref="DiagnosticsSnapshotDto.SectionTimings"/> and flipping
	/// <see cref="DiagnosticsSnapshotDto.IsPartial"/> on timeout / failure. Each section gets a fresh
	/// DbContext so a fault in one does not poison the connection for the next. Never throws.</summary>
	private async Task RunDiagnosticsSectionAsync(
		DiagnosticsSnapshotDto dto,
		string section,
		bool debug,
		Func<AuditDbContext, CancellationToken, Task> body,
		CancellationToken ct)
	{
		Stopwatch sw = Stopwatch.StartNew();
		using CancellationTokenSource sectionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		sectionCts.CancelAfter(DiagnosticsSectionTimeoutMs);
		string status;
		string? error = null;
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sectionCts.Token).ConfigureAwait(false);
			await body(db, sectionCts.Token).ConfigureAwait(false);
			status = "Completed";
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// The whole request was cancelled by the caller — propagate rather than masking as a timeout.
			throw;
		}
		catch (OperationCanceledException)
		{
			status = "TimedOut";
			error = string.Format(CultureInfo.InvariantCulture,
				"Section '{0}' exceeded its {1} ms budget.", section, DiagnosticsSectionTimeoutMs);
			dto.IsPartial = true;
			dto.RecentPipelineErrors.Add("Diagnostics " + error);
		}
		catch (Exception ex)
		{
			status = "Failed";
			error = ex.GetType().Name + " — " + ex.Message;
			dto.IsPartial = true;
			dto.RecentPipelineErrors.Add(string.Format(CultureInfo.InvariantCulture,
				"Diagnostics section '{0}' failed: {1}", section, error));
		}

		sw.Stop();
		dto.SectionTimings.Add(new DiagnosticsSectionTiming
		{
			Section = section,
			DurationMs = sw.ElapsedMilliseconds,
			Status = status,
			Error = error,
		});

		if (debug)
		{
			LogOperation(
				status == "Completed" ? OperationLogSeverity.Information : OperationLogSeverity.Warning,
				"DiagnosticsSnapshot.Section",
				string.Format(CultureInfo.InvariantCulture, "{0}: {1} in {2} ms.{3}",
					section, status, sw.ElapsedMilliseconds, error is null ? string.Empty : " " + error));
		}
	}

	/// <summary>B25: runs one bounded diagnostics probe that does NOT touch the database, recording its
	/// duration and status exactly like a database section. The fingerprint verdict is a set of small files
	/// on disk, and it deliberately stays readable when the STORE is the thing in question — coupling it to a
	/// DbContext that may itself be the failure would hide the one verdict that explains the failure.</summary>
	private async Task RunDiagnosticsProbeAsync(
		DiagnosticsSnapshotDto dto,
		string section,
		bool debug,
		Func<Task> body,
		CancellationToken ct)
	{
		Stopwatch sw = Stopwatch.StartNew();
		string status;
		string? error = null;
		try
		{
			await body().ConfigureAwait(false);
			status = "Completed";
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			status = "Failed";
			error = ex.GetType().Name + " — " + ex.Message;
			dto.IsPartial = true;
			dto.RecentPipelineErrors.Add(string.Format(CultureInfo.InvariantCulture,
				"Diagnostics section '{0}' failed: {1}", section, error));
		}

		sw.Stop();
		dto.SectionTimings.Add(new DiagnosticsSectionTiming
		{
			Section = section,
			DurationMs = sw.ElapsedMilliseconds,
			Status = status,
			Error = error,
		});

		if (debug)
		{
			LogOperation(
				status == "Completed" ? OperationLogSeverity.Information : OperationLogSeverity.Warning,
				"DiagnosticsSnapshot.Section",
				string.Format(CultureInfo.InvariantCulture, "{0}: {1} in {2} ms.{3}",
					section, status, sw.ElapsedMilliseconds, error is null ? string.Empty : " " + error));
		}
	}

	/// <summary>B25: reports the store-fingerprint chain verdict and the anomaly marker on the Diagnostic tab.
	/// The read is shared with the Database-tab overview (<see cref="StoreFingerprintVerdictReader"/>), so the
	/// two tabs cannot word or grade the same verdict differently.
	/// <para>
	/// A host that did not provide the fingerprint store leaves <see cref="DiagnosticsSnapshotDto.FingerprintChainState"/>
	/// null. That is intentional and load-bearing: the Diagnostic report renders a null state as UNKNOWN and
	/// never as <c>ok</c>, so "the verdict could not be read" cannot pass for "the store is intact".
	/// </para>
	/// </summary>
	private void PopulateFingerprintVerdict(DiagnosticsSnapshotDto dto)
	{
		if (_fingerprints is null)
		{
			return;
		}

		StoreFingerprintVerdictRead read = StoreFingerprintVerdictReader.Read(
			_fingerprints.FingerprintPath,
			_fingerprints.AnomalyMarkerPath,
			_fingerprints);
		dto.FingerprintChainState = read.ChainState;
		dto.FingerprintChainEntryCount = read.ChainEntryCount;
		dto.FingerprintChainMessage = read.ChainMessage;
		dto.FingerprintChainMirrorAvailable = read.MirrorAvailable;
		dto.FingerprintCleanShutdownUtc = read.CleanShutdownUtc;
		dto.FingerprintPeriodicUtc = read.PeriodicUtc;
		dto.IntegrityAnomalyMarkerPresent = read.AnomalyMarkerPresent;
		dto.IntegrityAnomalyDetail = read.AnomalyDetail;
	}

	/// <summary>B25: verifies the deletion-ledger hash chain and reads the newest journaled outcome of the
	/// quick, full and ledger-chain checks, exactly as the Database-tab overview does. A broken ledger chain
	/// is the one integrity signal a reader of the ledger cannot see for themselves, and the journal rows are
	/// the recorded evidence behind an anomaly.
	/// <para>
	/// The connection is opened here because the verifier takes a raw <c>SqliteConnection</c> and issues its
	/// own command; EF closes a connection it opened itself once its last query finishes. The same sharp edge
	/// bit the overview's end-to-end smoke test, so it is handled the same way here rather than assumed away.
	/// </para>
	/// </summary>
	private static async Task PopulateStoreIntegrityDiagnosticsAsync(
		AuditDbContext db, DiagnosticsSnapshotDto dto, CancellationToken ct)
	{
		Microsoft.Data.Sqlite.SqliteConnection connection =
			(Microsoft.Data.Sqlite.SqliteConnection)db.Database.GetDbConnection();
		bool openedHere = connection.State != System.Data.ConnectionState.Open;
		if (openedHere)
		{
			await db.Database.OpenConnectionAsync(ct).ConfigureAwait(false);
		}

		try
		{
			LedgerChainVerification verification =
				await LedgerChainVerifier.VerifyAsync(connection, ct).ConfigureAwait(false);
			dto.LedgerChainIntact = verification.IsIntact;
			dto.LedgerChainedRows = verification.ChainedRows;
			dto.LedgerUnchainedRows = verification.UnchainedRows;
			dto.LedgerChainMessage = verification.Message;
		}
		finally
		{
			if (openedHere)
			{
				await db.Database.CloseConnectionAsync().ConfigureAwait(false);
			}
		}

		foreach (DatabaseIntegrityCheckKind kind in new[]
		{
			DatabaseIntegrityCheckKind.QuickCheck,
			DatabaseIntegrityCheckKind.FullIntegrityCheck,
			DatabaseIntegrityCheckKind.LedgerChainVerify,
		})
		{
			DatabaseIntegrityCheckResult? row = await db.DatabaseIntegrityCheckResults
				.AsNoTracking()
				.Where(entry => entry.Kind == kind)
				.OrderByDescending(entry => entry.CompletedUtc)
				.ThenByDescending(entry => entry.Id)
				.FirstOrDefaultAsync(ct)
				.ConfigureAwait(false);
			if (row is null)
			{
				continue;
			}

			DiagnosticsIntegrityCheckRow projected = new()
			{
				Kind = row.Kind.ToString(),
				Outcome = row.Outcome.ToString(),
				CompletedUtc = row.CompletedUtc,
				DurationMs = row.DurationMs,
				InitiatedBy = row.InitiatedBy,
				Detail = row.Detail,
			};
			switch (kind)
			{
				case DatabaseIntegrityCheckKind.QuickCheck:
					dto.LastQuickCheck = projected;
					break;
				case DatabaseIntegrityCheckKind.FullIntegrityCheck:
					dto.LastFullIntegrityCheck = projected;
					break;
				default:
					dto.LastLedgerChainCheck = projected;
					break;
			}
		}
	}

	/// <summary>v1.3.9 (Problem 6): reads the REAL schema of the key tables via PRAGMA table_info /
	/// index_list and the LastSeenUtc / TimeUtc watermarks defensively, so the snapshot never assumes a
	/// column that does not exist (notably NOT AttackStats.TimeUtc and NOT AuthAttemptFacts.UserName).
	/// All reads go through the EF Core connection — no external sqlite3.exe.</summary>
	private static async Task PopulateSchemaAwareDiagnosticsAsync(
		AuditDbContext db, DiagnosticsSnapshotDto dto, CancellationToken ct)
	{
		System.Data.Common.DbConnection conn = db.Database.GetDbConnection();
		if (conn.State != System.Data.ConnectionState.Open)
		{
			await conn.OpenAsync(ct).ConfigureAwait(false);
		}

			foreach (DiagnosticSchemaTable table in new[]
				{
					DiagnosticSchemaTable.RawEvents,
					DiagnosticSchemaTable.AuthAttemptFacts,
					DiagnosticSchemaTable.AttackStats,
					DiagnosticSchemaTable.OperationLogs,
				})
			{
				DiagnosticsTableSchema schema = new() { Table = GetDiagnosticSchemaTableName(table) };
				schema.Columns.AddRange(await ReadPragmaListAsync(conn, table, DiagnosticPragmaKind.TableInfo, columnIndex: 1, ct).ConfigureAwait(false));
				schema.Indexes.AddRange(await ReadPragmaListAsync(conn, table, DiagnosticPragmaKind.IndexList, columnIndex: 1, ct).ConfigureAwait(false));
				schema.Exists = schema.Columns.Count > 0;
				dto.TableSchemas.Add(schema);
			}

			dto.SchemaAwareLatestRawEventUtc =
				await ReadMaxUtcAsync(conn, DiagnosticWatermark.RawEventsTimeUtc, dto, ct).ConfigureAwait(false);
			dto.SchemaAwareLatestAuthAttemptFactUtc =
				await ReadMaxUtcAsync(conn, DiagnosticWatermark.AuthAttemptFactsTimeUtc, dto, ct).ConfigureAwait(false);
			// AttackStats has LastSeenUtc, NOT TimeUtc — the week filter keys on LastSeenUtc.
			dto.SchemaAwareLatestAttackStatLastSeenUtc =
				await ReadMaxUtcAsync(conn, DiagnosticWatermark.AttackStatsLastSeenUtc, dto, ct).ConfigureAwait(false);
		}

		/// <summary>Runs a single-column PRAGMA (e.g. <c>PRAGMA table_info(T)</c>) and returns the values of
		/// the requested result column. Returns an empty list when the table is absent or the PRAGMA fails.</summary>
		private static async Task<List<string>> ReadPragmaListAsync(
			System.Data.Common.DbConnection conn, DiagnosticSchemaTable table, DiagnosticPragmaKind pragma, int columnIndex, CancellationToken ct)
		{
			List<string> values = new();
			try
			{
				await using System.Data.Common.DbCommand cmd = conn.CreateCommand();
				SetDiagnosticPragmaCommandText(cmd, table, pragma);
				await using System.Data.Common.DbDataReader reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
				while (await reader.ReadAsync(ct).ConfigureAwait(false))
				{
					if (columnIndex < reader.FieldCount && !reader.IsDBNull(columnIndex))
					{
						values.Add(reader.GetValue(columnIndex)?.ToString() ?? string.Empty);
					}
				}
			}
			catch (Exception)
			{
				// Absent table / older schema — leave the list empty; the caller marks Exists=false.
			}

			return values;
		}

		/// <summary>Reads a fixed diagnostic watermark defensively: if the column does
		/// not exist on this schema the query throws and we return null (recording a note) rather than
		/// assuming the column is present. Parses the stored value as a UTC DateTime.</summary>
		private static async Task<DateTime?> ReadMaxUtcAsync(
			System.Data.Common.DbConnection conn, DiagnosticWatermark watermark, DiagnosticsSnapshotDto dto, CancellationToken ct)
		{
			try
			{
				await using System.Data.Common.DbCommand cmd = conn.CreateCommand();
				SetDiagnosticWatermarkCommandText(cmd, watermark);
				object? raw = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
				if (raw is null || raw is DBNull)
				{
					return null;
				}

				if (raw is DateTime dt)
				{
					return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
				}

				string? text = raw.ToString();
				if (!string.IsNullOrWhiteSpace(text)
					&& DateTime.TryParse(text, CultureInfo.InvariantCulture,
						System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
						out DateTime parsed))
				{
					return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
				}

				return null;
			}
			catch (Exception ex)
			{
				dto.RecentPipelineErrors.Add(string.Format(CultureInfo.InvariantCulture,
					"Schema-aware {0} unavailable: {1}", GetDiagnosticWatermarkLabel(watermark), ex.GetType().Name));
				return null;
			}
		}

		/// <summary>Returns the display name for a fixed diagnostics table allow-list entry.</summary>
		private static string GetDiagnosticSchemaTableName(DiagnosticSchemaTable table) =>
			table switch
			{
				DiagnosticSchemaTable.RawEvents => "RawEvents",
				DiagnosticSchemaTable.AuthAttemptFacts => "AuthAttemptFacts",
				DiagnosticSchemaTable.AttackStats => "AttackStats",
				DiagnosticSchemaTable.OperationLogs => "OperationLogs",
				_ => throw new ArgumentOutOfRangeException(nameof(table), table, "Unknown diagnostics table."),
			};

		/// <summary>Assigns literal PRAGMA SQL for a fixed diagnostics table/kind allow-list.</summary>
		private static void SetDiagnosticPragmaCommandText(
			System.Data.Common.DbCommand cmd, DiagnosticSchemaTable table, DiagnosticPragmaKind pragma)
		{
			switch (table, pragma)
			{
				case (DiagnosticSchemaTable.RawEvents, DiagnosticPragmaKind.TableInfo):
					cmd.CommandText = "PRAGMA table_info('RawEvents');";
					break;
				case (DiagnosticSchemaTable.RawEvents, DiagnosticPragmaKind.IndexList):
					cmd.CommandText = "PRAGMA index_list('RawEvents');";
					break;
				case (DiagnosticSchemaTable.AuthAttemptFacts, DiagnosticPragmaKind.TableInfo):
					cmd.CommandText = "PRAGMA table_info('AuthAttemptFacts');";
					break;
				case (DiagnosticSchemaTable.AuthAttemptFacts, DiagnosticPragmaKind.IndexList):
					cmd.CommandText = "PRAGMA index_list('AuthAttemptFacts');";
					break;
				case (DiagnosticSchemaTable.AttackStats, DiagnosticPragmaKind.TableInfo):
					cmd.CommandText = "PRAGMA table_info('AttackStats');";
					break;
				case (DiagnosticSchemaTable.AttackStats, DiagnosticPragmaKind.IndexList):
					cmd.CommandText = "PRAGMA index_list('AttackStats');";
					break;
				case (DiagnosticSchemaTable.OperationLogs, DiagnosticPragmaKind.TableInfo):
					cmd.CommandText = "PRAGMA table_info('OperationLogs');";
					break;
				case (DiagnosticSchemaTable.OperationLogs, DiagnosticPragmaKind.IndexList):
					cmd.CommandText = "PRAGMA index_list('OperationLogs');";
					break;
				default:
					throw new ArgumentOutOfRangeException(nameof(pragma), pragma, "Unknown diagnostics PRAGMA.");
			}
		}

		/// <summary>Assigns literal SQL for a fixed diagnostics watermark allow-list.</summary>
		private static void SetDiagnosticWatermarkCommandText(
			System.Data.Common.DbCommand cmd, DiagnosticWatermark watermark)
		{
			switch (watermark)
			{
				case DiagnosticWatermark.RawEventsTimeUtc:
					cmd.CommandText = "SELECT MAX(\"TimeUtc\") FROM \"RawEvents\";";
					break;
				case DiagnosticWatermark.AuthAttemptFactsTimeUtc:
					cmd.CommandText = "SELECT MAX(\"TimeUtc\") FROM \"AuthAttemptFacts\";";
					break;
				case DiagnosticWatermark.AttackStatsLastSeenUtc:
					cmd.CommandText = "SELECT MAX(\"LastSeenUtc\") FROM \"AttackStats\";";
					break;
				default:
					throw new ArgumentOutOfRangeException(nameof(watermark), watermark, "Unknown diagnostics watermark.");
			}
		}

		/// <summary>Returns a human-readable label for a diagnostics watermark.</summary>
		private static string GetDiagnosticWatermarkLabel(DiagnosticWatermark watermark) =>
			watermark switch
			{
				DiagnosticWatermark.RawEventsTimeUtc => "MAX(RawEvents.TimeUtc)",
				DiagnosticWatermark.AuthAttemptFactsTimeUtc => "MAX(AuthAttemptFacts.TimeUtc)",
				DiagnosticWatermark.AttackStatsLastSeenUtc => "MAX(AttackStats.LastSeenUtc)",
				_ => "unknown watermark",
			};

		private enum DiagnosticSchemaTable
		{
			RawEvents,
			AuthAttemptFacts,
			AttackStats,
			OperationLogs,
		}

		private enum DiagnosticPragmaKind
		{
			TableInfo,
			IndexList,
		}

		private enum DiagnosticWatermark
		{
			RawEventsTimeUtc,
			AuthAttemptFactsTimeUtc,
			AttackStatsLastSeenUtc,
		}

	/// <summary>v1.3.4: fill the resolved-RDP-port diagnostic fields. On Windows the registry resolver
	/// supplies both the port and its source (registry vs documented default); off Windows (CI / tests)
	/// the injected provider's port is reported with an Unknown source so the field is never blank. Never
	/// throws — a registry failure resolves to the documented default rather than failing the snapshot.</summary>
	private void PopulateRdpPortDiagnostics(DiagnosticsSnapshotDto dto)
	{
		try
		{
			if (OperatingSystem.IsWindows())
			{
				RdpListenerPortResolution res = RdpListenerPortResolver.Resolve();
				dto.ResolvedRdpPort = res.Port;
				dto.ResolvedRdpPortSource = res.Source.ToString();
				dto.ResolvedRdpPortDetail = res.Detail;
				return;
			}

			int port = _rdpPortProvider?.GetRdpPort() ?? RdpConfigurationModel.DefaultRdpPort;
			dto.ResolvedRdpPort = port;
			dto.ResolvedRdpPortSource = "Unknown";
			dto.ResolvedRdpPortDetail = "Port provider reported " + port.ToString(CultureInfo.InvariantCulture)
				+ " (registry source resolution is Windows-only).";
		}
		catch (Exception ex)
		{
			dto.ResolvedRdpPort = RdpConfigurationModel.DefaultRdpPort;
			dto.ResolvedRdpPortSource = "Default";
			dto.ResolvedRdpPortDetail = "Port resolution failed (" + ex.GetType().Name + "); using default.";
			dto.RecentPipelineErrors.Add("RDP port resolution failed: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	/// <summary>v1.3.4: forces one synchronous AttackStatsRefreshWorker projection pass (DEBUG-gated on
	/// the client) and reports rows upserted, elapsed ms, and the post-rebuild AttackStats total. Shares
	/// the worker's re-entrancy gate so a concurrent background pass cannot double-run.</summary>
	private async Task<AttackStatsRebuildResultDto> RebuildAttackStatsAsync(CancellationToken ct)
	{
		AttackStatsRebuildResultDto result = new() { GeneratedUtc = DateTime.UtcNow };

		if (_attackStatsWorker is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "AttackStats projection worker is not registered in this build.";
			return result;
		}

		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			// v1.3.6: the DEBUG action forces a FULL rebuild — page through every in-window fact and
			// re-derive every AttackStat row's LastSeenUtc from current facts. This guarantees a manual
			// rebuild advances stale rows even when the incremental window backlog exceeded the cap.
			Workers.AttackStatsRefreshResult refresh = await _attackStatsWorker
				.RefreshOnceDetailedAsync(true, ct)
				.ConfigureAwait(false);
			sw.Stop();
			result.RowsUpserted = refresh.RowsUpserted;
			result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
			result.FullRebuild = refresh.FullRebuild;
			result.RowsBefore = refresh.RowsBefore;
			result.RowsAfter = refresh.RowsAfter;
			result.LatestSourceFactUtc = refresh.LatestSourceFactUtc;
			result.LatestAttackStatLastSeenUtc = refresh.LatestAttackStatLastSeenUtc;
			result.AttackStatsTotal = refresh.RowsAfter;

			result.Status = IpcResultStatus.Success;
			result.Message = string.Format(
				CultureInfo.InvariantCulture,
				"Full rebuild complete: {0} rows upserted in {1} ms; AttackStats {2} -> {3} rows; latest source fact {4:O}, latest stat LastSeen {5:O}.",
				refresh.RowsUpserted,
				result.ElapsedMilliseconds,
				refresh.RowsBefore,
				refresh.RowsAfter,
				refresh.LatestSourceFactUtc,
				refresh.LatestAttackStatLastSeenUtc);
			LogOperation(OperationLogSeverity.Information, "RebuildAttackStats", result.Message);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Rebuild cancelled.";
		}
		catch (Exception ex)
		{
			sw.Stop();
			result.Status = IpcResultStatus.Unavailable;
			result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
			result.Message = "Rebuild failed: " + ex.GetType().Name + " — " + ex.Message;
			LogOperation(OperationLogSeverity.Error, "RebuildAttackStats", result.Message);
		}

		return result;
	}

	// ----------------------------------------------------------------------------------------------
	// v1.4.1: Auth Success per-login summary (RDP Activity "Export Auth Success (per login)")
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on per-login rows returned by <c>GetAuthSuccessSummaryForIp</c>.</summary>
	internal const int AuthSuccessSummaryDefaultLimit = 500;

	/// <summary>Upper bound on per-login rows returned by <c>GetAuthSuccessSummaryForIp</c>.</summary>
	internal const int AuthSuccessSummaryMaxLimit = 5000;

	/// <summary>Cap on the number of distinct labels (event ids / logon types / auth packages /
	/// failure reasons) collected per login so a pathological account cannot bloat the payload.</summary>
	internal const int AuthSuccessLabelCapPerLogin = 50;

	/// <summary>Builds a per-login (NormalizedUserName) authentication-success summary for one IP,
	/// aggregated entirely from <c>AuthAttemptFacts</c> (the v3 atomic source of truth). Every counter
	/// is a database-side aggregation, so no per-attempt rows ever cross the pipe — the report stays
	/// compact even for IPs with tens of thousands of attempts.</summary>
	private async Task<object?> GetAuthSuccessSummaryForIpAsync(string? payload, CancellationToken ct)
	{
		AuthSuccessSummaryRequest req = ParseAuthSuccessSummaryRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? AuthSuccessSummaryDefaultLimit : req.Limit;
		if (limit > AuthSuccessSummaryMaxLimit)
		{
			limit = AuthSuccessSummaryMaxLimit;
		}

		DateTime nowUtc = DateTime.UtcNow;
		AuthSuccessSummaryDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = nowUtc,
			SucceededLoginsOnly = req.SucceededLoginsOnly,
		};

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<AuthAttemptFact> ipFacts = db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.SourceIp == ip);

		// IP-wide totals — one grouped aggregation, independent of the per-login page.
		var ipTotals = await ipFacts
			.GroupBy(_ => 1)
			.Select(g => new
			{
				Total = g.LongCount(),
				Succeeded = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Succeeded),
				Failed = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Failed),
				Denied = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Denied),
				FirstSeen = g.Min(f => (DateTime?)f.TimeUtc),
				LastSeen = g.Max(f => (DateTime?)f.TimeUtc),
			})
			.FirstOrDefaultAsync(ct).ConfigureAwait(false);

		if (ipTotals is not null)
		{
			dto.TotalAuthFacts = ipTotals.Total;
			dto.TotalSuccessfulAuth = ipTotals.Succeeded;
			dto.TotalFailedAuth = ipTotals.Failed;
			dto.TotalDeniedAuth = ipTotals.Denied;
			dto.FirstSeenUtc = ipTotals.FirstSeen;
			dto.LastSeenUtc = ipTotals.LastSeen;
		}

		if (dto.TotalAuthFacts == 0)
		{
			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"no authentication facts recorded for {0}", ip);
			return dto;
		}

		// Per-login roll-up. Group by the canonical join key; the display name / domain are pulled
		// from the newest fact per login further below so the report shows a human-friendly label.
		var grouped = await ipFacts
			.Where(f => f.NormalizedUserName != null && f.NormalizedUserName != string.Empty)
			.GroupBy(f => f.NormalizedUserName!)
			.Select(g => new
			{
				Login = g.Key,
				Total = g.LongCount(),
				Succeeded = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Succeeded),
				Failed = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Failed),
				Denied = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Denied),
				FirstSeen = g.Min(f => (DateTime?)f.TimeUtc),
				LastSeen = g.Max(f => (DateTime?)f.TimeUtc),
				FirstSuccess = g.Where(f => f.Outcome == AuthAttemptOutcome.Succeeded)
					.Min(f => (DateTime?)f.TimeUtc),
				LastSuccess = g.Where(f => f.Outcome == AuthAttemptOutcome.Succeeded)
					.Max(f => (DateTime?)f.TimeUtc),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		dto.DistinctLoginsObserved = grouped.Count;
		dto.DistinctSucceededLogins = grouped.Count(x => x.Succeeded > 0);

		// Keep only the logins the report is about, then order and page.
		var selected = grouped
			.Where(x => !req.SucceededLoginsOnly || x.Succeeded > 0)
			.OrderBy(x => x.FirstSuccess ?? DateTime.MaxValue)
			.ThenByDescending(x => x.Succeeded)
			.ThenBy(x => x.Login, StringComparer.OrdinalIgnoreCase)
			.Take(limit)
			.ToList();

		foreach (var row in selected)
		{
			ct.ThrowIfCancellationRequested();

			AuthSuccessLoginDto login = new()
			{
				NormalizedUserName = row.Login,
				SuccessfulAuthCount = row.Succeeded,
				FailedAuthCount = row.Failed,
				DeniedAuthCount = row.Denied,
				TotalAuthCount = row.Total,
				FirstSeenUtc = row.FirstSeen,
				LastSeenUtc = row.LastSeen,
				FirstSuccessUtc = row.FirstSuccess,
				LastSuccessUtc = row.LastSuccess,
				HasSuccess = row.Succeeded > 0,
			};

			if (row.FirstSuccess.HasValue && row.FirstSeen.HasValue)
			{
				login.SecondsToFirstSuccess = Math.Max(0,
					(long)(row.FirstSuccess.Value - row.FirstSeen.Value).TotalSeconds);
			}

			// Display name / domain: newest fact wins.
			var identity = await ipFacts
				.Where(f => f.NormalizedUserName == row.Login)
				.OrderByDescending(f => f.TimeUtc)
				.Select(f => new { f.TargetUser, f.TargetDomain })
				.FirstOrDefaultAsync(ct).ConfigureAwait(false);
			if (identity is not null)
			{
				login.DisplayUserName = identity.TargetUser;
				login.Domain = identity.TargetDomain;
			}

			// Failed / denied strictly before the first success — the "attempts to crack" number.
			if (row.FirstSuccess.HasValue)
			{
				DateTime firstSuccess = row.FirstSuccess.Value;
				login.FailedBeforeFirstSuccess = await ipFacts
					.Where(f => f.NormalizedUserName == row.Login
						&& f.TimeUtc < firstSuccess
						&& (f.Outcome == AuthAttemptOutcome.Failed || f.Outcome == AuthAttemptOutcome.Denied))
					.LongCountAsync(ct).ConfigureAwait(false);
			}
			else
			{
				// Never succeeded: every failure / denial counts as "before a success that never came".
				login.FailedBeforeFirstSuccess = row.Failed + row.Denied;
			}

			// Distinct success event ids.
			login.SuccessEventIds = await ipFacts
				.Where(f => f.NormalizedUserName == row.Login && f.Outcome == AuthAttemptOutcome.Succeeded)
				.Select(f => f.EvidenceEventId)
				.Distinct()
				.OrderBy(id => id)
				.Take(AuthSuccessLabelCapPerLogin)
				.ToListAsync(ct).ConfigureAwait(false);

			// Distinct logon types on successful facts.
			List<int?> logonTypes = await ipFacts
				.Where(f => f.NormalizedUserName == row.Login
					&& f.Outcome == AuthAttemptOutcome.Succeeded
					&& f.LogonType != null)
				.Select(f => f.LogonType)
				.Distinct()
				.OrderBy(t => t)
				.Take(AuthSuccessLabelCapPerLogin)
				.ToListAsync(ct).ConfigureAwait(false);
			login.SuccessLogonTypes = logonTypes.Where(t => t.HasValue).Select(t => t!.Value).ToList();

			// Distinct auth packages on successful facts.
			List<string> authPackages = await ipFacts
				.Where(f => f.NormalizedUserName == row.Login
					&& f.Outcome == AuthAttemptOutcome.Succeeded
					&& f.AuthPackage != null && f.AuthPackage != string.Empty)
				.Select(f => f.AuthPackage!)
				.Distinct()
				.OrderBy(p => p)
				.Take(AuthSuccessLabelCapPerLogin)
				.ToListAsync(ct).ConfigureAwait(false);
			login.SuccessAuthPackages = authPackages.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

			// Distinct failure reasons (translated SubStatus) across failed / denied facts.
			List<string> reasons = await ipFacts
				.Where(f => f.NormalizedUserName == row.Login
					&& (f.Outcome == AuthAttemptOutcome.Failed || f.Outcome == AuthAttemptOutcome.Denied)
					&& f.SubStatusMeaning != null && f.SubStatusMeaning != string.Empty)
				.Select(f => f.SubStatusMeaning!)
				.Distinct()
				.OrderBy(r => r)
				.Take(AuthSuccessLabelCapPerLogin)
				.ToListAsync(ct).ConfigureAwait(false);
			login.FailureReasons = reasons.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToList();

			dto.Logins.Add(login);
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"auth-success summary for {0}: succeeded-logins={1} observed-logins={2} rows-returned={3} (successOnly={4})",
			ip, dto.DistinctSucceededLogins, dto.DistinctLoginsObserved, dto.Logins.Count, req.SucceededLoginsOnly);
		return dto;
	}

	private static AuthSuccessSummaryRequest ParseAuthSuccessSummaryRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetAuthSuccessSummaryForIp requires a JSON payload with an Ip field.");
		}

		AuthSuccessSummaryRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<AuthSuccessSummaryRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetAuthSuccessSummaryForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetAuthSuccessSummaryForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage Diag2: RunSecurityAuthProbe
	// ----------------------------------------------------------------------------------------------

	/// <summary>Run a one-shot bounded Security-channel auth read inside the service process and
	/// return AccessDenied vs Timeout vs NoEvents vs a parsed first event. This is the canonical
	/// way to disambiguate "Security Armed but zero events" symptoms on a real host.</summary>
	private SecurityAuthProbeDto RunSecurityAuthProbeHandler()
	{
		if (_securityAuthProbe is null)
		{
			return new SecurityAuthProbeDto
			{
				Status = IpcResultStatus.Unavailable,
				Outcome = "Unavailable",
				Message = "Security auth probe service is not registered in this build.",
				GeneratedUtc = DateTime.UtcNow,
			};
		}

		return _securityAuthProbe.Run();
	}

	/// <summary>Agent-side GetCrossHostFacts handler: exports bounded fact projections from the
	/// local database using the exporter. Never returns raw event XML; the cap is clamped by the
	/// service configuration.</summary>
	private async Task<CrossHostFactsDto> GetCrossHostFactsAsync(string? payload, CancellationToken ct)
	{
		CrossHostFactsRequest request = ParseCrossHostFactsRequest(payload);
		CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.TimeoutMsFor(IpcCommand.GetCrossHostFacts)));

		await using AuditDbContext db = await _factory.CreateDbContextAsync(cts.Token).ConfigureAwait(false);

		RdpAudit.Core.Config.CrossHostOptions options = _options.CurrentValue.CrossHost;
		CrossHostFactExporter exporter = new();
		return await exporter.ExportAsync(db, request, options, cts.Token).ConfigureAwait(false);
	}

	private static CrossHostFactsRequest ParseCrossHostFactsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			// MaxFacts 0 means "use the service-configured cap" (see exporter ResolveCap).
			return new CrossHostFactsRequest { SinceUtc = null, MaxFacts = 0 };
		}

		try
		{
			CrossHostFactsRequest? parsed = JsonSerializer.Deserialize<CrossHostFactsRequest>(payload, JsonOptions.Default);
			return parsed ?? new CrossHostFactsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetCrossHostFacts payload is not valid JSON: " + ex.Message);
		}
	}

	private const int CrossHostChainListDefaultLimit = 50;
	private const int CrossHostChainListMaxLimit = 200;

	/// <summary>Configurator Cross-Host tab: bounded newest-first list of persisted chains.</summary>
	private async Task<CrossHostChainListDto> ListCrossHostChainsAsync(string? payload, CancellationToken ct)
	{
		CrossHostChainsRequest request = ParseCrossHostChainsRequest(payload);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<CrossHostChain> query = db.CrossHostChains.Include(c => c.Links).AsNoTracking();
		if (!string.IsNullOrWhiteSpace(request.RuleId))
		{
			query = query.Where(c => c.RuleId == request.RuleId);
		}

		if (!request.IncludeAcknowledged)
		{
			query = query.Where(c => !c.IsAcknowledged);
		}

		int total = await query.CountAsync(ct).ConfigureAwait(false);
		int limit = Math.Clamp(
			request.MaxRows > 0 ? request.MaxRows : CrossHostChainListDefaultLimit,
			1,
			CrossHostChainListMaxLimit);

		List<CrossHostChain> chains = await query
			.OrderByDescending(c => c.DetectedUtc)
			.ThenByDescending(c => c.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		return new CrossHostChainListDto
		{
			QueriedUtc = DateTime.UtcNow,
			TotalMatching = total,
			AppliedLimit = limit,
			Chains = chains.Select(ToChainDto).ToList(),
		};
	}

	private static CrossHostChainsRequest ParseCrossHostChainsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new CrossHostChainsRequest();
		}

		try
		{
			return JsonSerializer.Deserialize<CrossHostChainsRequest>(payload, JsonOptions.Default)
				?? new CrossHostChainsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ListCrossHostChains payload is not valid JSON: " + ex.Message);
		}
	}

	private static CrossHostChainDto ToChainDto(CrossHostChain chain)
	{
		List<CrossHostLink> links = chain.Links.OrderBy(l => l.Ordinal).ToList();
		return new CrossHostChainDto
		{
			Id = chain.Id,
			ChainKey = chain.ChainKey,
			RuleId = chain.RuleId,
			NormalizedUserName = chain.NormalizedUserName,
			FirstSeenUtc = chain.FirstSeenUtc,
			LastSeenUtc = chain.LastSeenUtc,
			Score = chain.Score,
			FailedAttemptCount = chain.FailedAttemptCount,
			HostPath = links.Select(l => l.HostName).ToList(),
			LastSourceIp = links.Count > 0 ? links[links.Count - 1].SourceIp : null,
			IsAcknowledged = chain.IsAcknowledged,
		};
	}

	/// <summary>Configurator Cross-Host tab: one chain plus its ordered links; InvalidRequest
	/// when the row id is unknown.</summary>
	private async Task<CrossHostChainDetailsDto> GetCrossHostChainDetailsAsync(string? payload, CancellationToken ct)
	{
		CrossHostChainDetailsRequest request = ParseCrossHostChainDetailsRequest(payload);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		CrossHostChain? chain = await db.CrossHostChains
			.Include(c => c.Links)
			.AsNoTracking()
			.FirstOrDefaultAsync(c => c.Id == request.ChainId, ct)
			.ConfigureAwait(false);

		if (chain is null)
		{
			return new CrossHostChainDetailsDto
			{
				Status = IpcResultStatus.InvalidRequest,
				QueriedUtc = DateTime.UtcNow,
				Message = string.Format(CultureInfo.InvariantCulture, "Chain {0} not found.", request.ChainId),
			};
		}

		List<CrossHostLink> links = chain.Links.OrderBy(l => l.Ordinal).ToList();
		return new CrossHostChainDetailsDto
		{
			QueriedUtc = DateTime.UtcNow,
			Id = chain.Id,
			ChainKey = chain.ChainKey,
			RuleId = chain.RuleId,
			NormalizedUserName = chain.NormalizedUserName,
			FirstSeenUtc = chain.FirstSeenUtc,
			LastSeenUtc = chain.LastSeenUtc,
			Score = chain.Score,
			FailedAttemptCount = chain.FailedAttemptCount,
			IsAcknowledged = chain.IsAcknowledged,
			Links = links.Select(l => new CrossHostChainLinkDto
			{
				Ordinal = l.Ordinal,
				HostName = l.HostName,
				Kind = l.Kind,
				EventId = l.EventId,
				TimeUtc = l.TimeUtc,
				SourceIp = l.SourceIp,
				UserName = l.UserName,
			}).ToList(),
		};
	}

	private static CrossHostChainDetailsRequest ParseCrossHostChainDetailsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetCrossHostChainDetails requires a payload with the chain id.");
		}

		try
		{
			return JsonSerializer.Deserialize<CrossHostChainDetailsRequest>(payload, JsonOptions.Default)
				?? throw new IpcException("GetCrossHostChainDetails payload is empty.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetCrossHostChainDetails payload is not valid JSON: " + ex.Message);
		}
	}

	/// <summary>Configurator Cross-Host tab: acknowledge a chain. Sets the chain's flag and, when
	/// the chain has a linked CROSS_HOST_CHAIN alert, marks that alert acknowledged too, so a
	/// single operator action clears both views. InvalidRequest when the row id is unknown.</summary>
	private async Task<CrossHostChainAckResultDto> AcknowledgeCrossHostChainAsync(string? payload, CancellationToken ct)
	{
		CrossHostChainAckRequest request = ParseCrossHostChainAckRequest(payload);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		CrossHostChain? chain = await db.CrossHostChains
			.FirstOrDefaultAsync(c => c.Id == request.ChainId, ct)
			.ConfigureAwait(false);

		if (chain is null)
		{
			return new CrossHostChainAckResultDto
			{
				Status = IpcResultStatus.InvalidRequest,
				Message = string.Format(CultureInfo.InvariantCulture, "Chain {0} not found.", request.ChainId),
			};
		}

		chain.IsAcknowledged = true;

		// Clearing the alert must cascade into the alert table without touching retention:
		// the DeleteBehavior.SetNull on CrossHostChain.AlertId keeps the chain row alive.
		if (chain.AlertId is not null)
		{
			Alert? linkedAlert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == chain.AlertId.Value, ct).ConfigureAwait(false);
			if (linkedAlert is not null && !linkedAlert.Acknowledged)
			{
				linkedAlert.Acknowledged = true;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new CrossHostChainAckResultDto { ChainId = chain.Id };
	}

	private static CrossHostChainAckRequest ParseCrossHostChainAckRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("AcknowledgeCrossHostChain requires a payload with the chain id.");
		}

		try
		{
			return JsonSerializer.Deserialize<CrossHostChainAckRequest>(payload, JsonOptions.Default)
				?? throw new IpcException("AcknowledgeCrossHostChain payload is empty.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("AcknowledgeCrossHostChain payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------
	// Stage 16 handlers - Session Map timeline (Backlog #6).
	// ----------------------------------------------------------------------------------

	/// <summary>Configurator Session Map tab: one session's bounded, chronologically ordered
	/// timeline built from the fact's lifecycle phases plus correlated RawEvents activity.
	/// NotFound when the fact id is unknown; Details in event nodes are DEBUG-gated.</summary>
	private async Task<SessionTimelineDto> GetSessionTimelineAsync(string? payload, CancellationToken ct)
	{
		GetSessionTimelineRequest req = ParseGetSessionTimelineRequest(payload);

		SessionTimelineQueryService query = _timelineQuery ?? new SessionTimelineQueryService(_factory);
		SessionTimelineQueryResult loaded = await query
			.LoadAsync(req.SessionId, req.ActivityCap, req.IncludeOtherEvents, _options.CurrentValue.Diagnostics.DebugMode, ct)
			.ConfigureAwait(false);

		int appliedCap = loaded.AppliedCap;

		if (loaded.Fact is null)
		{
			return new SessionTimelineDto
			{
				Status = IpcResultStatus.NotFound,
				QueriedUtc = DateTime.UtcNow,
				SessionId = req.SessionId,
				AppliedCap = appliedCap,
				Message = string.Format(CultureInfo.InvariantCulture,
					"Connection fact {0} not found.", req.SessionId),
			};
		}

		RdpConnectionFact fact = loaded.Fact;
		DateTime nowUtc = DateTime.UtcNow;
		SessionTimeline timeline = SessionTimelineBuilder.Build(
			fact, loaded.Slices, loaded.TotalMatching, appliedCap, req.IncludeOtherEvents, nowUtc);

		SessionTimelineDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			SessionId = fact.Id,
			Ip = fact.Ip,
			UserName = fact.UserName,
			Domain = fact.Domain,
			WtsSessionId = fact.WtsSessionId,
			LogonId = fact.LogonId,
			StartUtc = timeline.StartUtc,
			EndUtc = timeline.EndUtc,
			IsActive = timeline.IsActive,
			DurationSeconds = timeline.DurationSeconds,
			TotalMatching = timeline.TotalMatching,
			Truncated = timeline.Truncated,
			AppliedCap = appliedCap,
			Message = string.Format(CultureInfo.InvariantCulture,
				"session timeline: events={0}, activityMatching={1}, cap={2}{3}",
				timeline.Events.Count, timeline.TotalMatching, appliedCap,
				timeline.Truncated ? ", truncated" : string.Empty),
		};

		foreach (SessionTimelineEvent node in timeline.Events)
		{
			dto.Events.Add(new SessionTimelineEventDto
			{
				TimeUtc = node.TimeUtc,
				Kind = node.Kind,
				EventId = node.EventId,
				Channel = node.Channel,
				CorrelationMethod = node.CorrelationMethod,
				ProcessName = node.ProcessName,
				CommandLine = node.CommandLine,
				ObjectName = node.ObjectName,
				AccessMask = node.AccessMask,
				Status = node.Status,
				Details = node.Details,
			});
		}

		return dto;
	}

	private static GetSessionTimelineRequest ParseGetSessionTimelineRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetSessionTimeline requires a JSON payload with a SessionId field.");
		}

		try
		{
			return JsonSerializer.Deserialize<GetSessionTimelineRequest>(payload, JsonOptions.Default)
				?? throw new IpcException("GetSessionTimeline payload is empty.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetSessionTimeline payload is not valid JSON: " + ex.Message);
		}
	}
}