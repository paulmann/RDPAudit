// File:    src/RdpAudit.Core/Ipc/IpcConstants.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Shared constants for the Named Pipe IPC channel, including per-command operation
//          timeouts. Long-running maintenance commands (firewall Repair / Verify / Tools Diag /
//          temporary-rule probe) spawn several netsh / PowerShell processes and routinely exceed
//          the default short timeout; capping those at 5 s caused the client to abandon a request
//          the service was still completing, which the UI then misread as "service not running".
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc;

/// <summary>Shared constants for the Named Pipe IPC channel.</summary>
public static class IpcConstants
{
	public const string PipeName = "RdpAuditService";

	public const int MaxFrameBytes = 16 * 1024 * 1024;

	/// <summary>Serializer options used by every IPC sender and receiver.</summary>
	/// <remarks>
	/// <see cref="MessagePackSecurity.UntrustedData"/> enables the nesting limit and hash
	/// randomisation for string-keyed collections. Frames arrive over a pipe whose DACL is limited to
	/// Administrators and LocalSystem, so this is defence in depth rather than a live exposure - but a
	/// receiver should not trust a frame's shape merely because the sender held a privileged token.
	/// The wire format is unchanged: this is a decoding policy, not a contract change.
	/// </remarks>
	public static readonly MessagePackSerializerOptions SerializerOptions =
		MessagePackSerializerOptions.Standard.WithSecurity(MessagePackSecurity.UntrustedData);

	public const int ConnectTimeoutMs = 2_000;

	/// <summary>Default round-trip deadline for cheap, read-only commands (status, list queries).</summary>
	public const int OperationTimeoutMs = 5_000;

	public const int AntiSpinInstantIterationThreshold = 100;

	public const int AntiSpinInstantIterationMaxElapsedMs = 1;

	public const int AntiSpinPauseMilliseconds = 1_000;

	/// <summary>Round-trip deadline for long-running commands that shell out to several netsh /
	/// PowerShell processes (firewall repair / verify / reconcile, Tools Diag, temporary-rule probe).
	/// Bounded so the UI never hangs indefinitely, but long enough that a multi-rule repair on a busy
	/// host completes within one round-trip instead of being abandoned and misreported as a dead
	/// service.</summary>
	public const int LongOperationTimeoutMs = 60_000;

	/// <summary>Returns the appropriate client/server round-trip deadline (in milliseconds) for the
	/// supplied command. Commands that drive external tooling or scale with the size of the store get the
	/// long deadline; every other command keeps the short default. Both the client and the server consult
	/// this so the two ends of a single round-trip never disagree on how long the call is allowed to take.
	/// Every command defined in <see cref="IpcCommand"/> states its deadline here explicitly - the
	/// catch-all below is a safety net, not a policy, and
	/// <c>IpcConstantsTimeoutTests.TimeoutMsFor_EveryDefinedCommand_HasAnExplicitEntry</c> fails when a new
	/// command tries to inherit the short default silently.</summary>
	public static int TimeoutMsFor(IpcCommand command) => command switch
	{
		IpcCommand.RunToolsDiagnostics => LongOperationTimeoutMs,
		IpcCommand.RunTemporaryFirewallRuleProbe => LongOperationTimeoutMs,
		IpcCommand.GetFirewallStatus => LongOperationTimeoutMs,
		IpcCommand.GetFirewallDiagnostics => LongOperationTimeoutMs,
		IpcCommand.ListActiveBlocksDetailed => LongOperationTimeoutMs,
		IpcCommand.ReconcileEnforcement => LongOperationTimeoutMs,
		IpcCommand.RepairActiveBlock => LongOperationTimeoutMs,
		IpcCommand.RemoveAllEnforcement => LongOperationTimeoutMs,
		IpcCommand.RepairBlocklistEnforcement => LongOperationTimeoutMs,
		IpcCommand.RepairAllEnabledBlocklistEnforcement => LongOperationTimeoutMs,
		IpcCommand.BlockAddress => LongOperationTimeoutMs,
		IpcCommand.UnblockAddress => LongOperationTimeoutMs,
		IpcCommand.AddToBlocklist => LongOperationTimeoutMs,
		IpcCommand.RemoveFromBlocklist => LongOperationTimeoutMs,
		IpcCommand.UnblockActiveBlock => LongOperationTimeoutMs,
		IpcCommand.ClearAllBlocklist => LongOperationTimeoutMs,
		IpcCommand.ClearAllFirewallRules => LongOperationTimeoutMs,
		IpcCommand.ClearAllApplicationData => LongOperationTimeoutMs,
		IpcCommand.RebuildAttackStats => LongOperationTimeoutMs,
		IpcCommand.GetCrossHostFacts => LongOperationTimeoutMs,
		IpcCommand.ListCrossHostChains => LongOperationTimeoutMs,
		IpcCommand.GetCrossHostChainDetails => LongOperationTimeoutMs,

		// --- Stage 2b database backup / restore (ordinals 85-87). All three spend their time in file
		// I/O that scales with the store rather than with the IPC frame, so on a multi-gigabyte database
		// they legitimately exceed the short default and used to be abandoned mid-flight (the client then
		// reported a false timeout while the service kept working to completion):
		//   85 CreateDatabaseBackup copies the live store - plus the whole shard tree when IncludeShards
		//      is set - into a snapshot directory;
		//   86 ListDatabaseBackups walks the backup folder, stats every snapshot and reads each manifest;
		//   87 VerifyDatabaseBackup hashes the entire snapshot to compare it with the manifest digest -
		//      the longest of the three.
		IpcCommand.CreateDatabaseBackup => LongOperationTimeoutMs,
		IpcCommand.ListDatabaseBackups => LongOperationTimeoutMs,
		IpcCommand.VerifyDatabaseBackup => LongOperationTimeoutMs,

		// --- Stage 3 Database tab: a bounded integrity check on a large store, a bounded shard-tree
		// walk and a snapshot copy into a scratch directory routinely exceed the short default, so
		// they get the long deadline like the firewall/tooling commands above. Only the three new
		// ordinals are affected; existing commands keep their timeouts.
		IpcCommand.GetShardInventory => LongOperationTimeoutMs,
		IpcCommand.RunDatabaseMaintenance => LongOperationTimeoutMs,
		IpcCommand.RestoreDatabaseBackupToDirectory => LongOperationTimeoutMs,

		// --- Stage 4 shard governance: a collection pass may walk the tree, re-read orphan headers and
		// delete up to its per-run budget one file at a time, each with its own audit row, so it gets the
		// long deadline for the same reason the Stage 3 walk does.
		IpcCommand.CollectShardGarbage => LongOperationTimeoutMs,

		// --- Stage 5 storage hardening. CompactDatabase only reads page accounting before refusing, so
		// it keeps the short deadline. PurgeBySubject deletes in bounded batches across many tables and
		// writes one ledger row per affected table, which routinely exceeds the short default on a large
		// store.
		IpcCommand.PurgeBySubject => LongOperationTimeoutMs,

		// --- Everything else answers on the short deadline: cheap status / list reads and commands that
		// return as soon as a bounded query is done. They are enumerated one by one rather than left to the
		// catch-all because the deadline is a contract, not a default:
		// IpcConstantsTimeoutTests.TimeoutMsFor_EveryDefinedCommand_HasAnExplicitEntry fails when a command is
		// defined in the enum without stating its deadline here, so a future storage / maintenance command
		// cannot silently inherit 5 s (the defect that produced the false "service not running" reports).
		IpcCommand.Ping => OperationTimeoutMs,
		IpcCommand.GetStatus => OperationTimeoutMs,
		IpcCommand.GetRecentEvents => OperationTimeoutMs,
		IpcCommand.GetRecentAlerts => OperationTimeoutMs,
		IpcCommand.GetAddresses => OperationTimeoutMs,
		IpcCommand.GetSessions => OperationTimeoutMs,
		IpcCommand.AcknowledgeAlert => OperationTimeoutMs,
		IpcCommand.GetSettings => OperationTimeoutMs,
		IpcCommand.SaveSettings => OperationTimeoutMs,
		IpcCommand.ListBlocklist => OperationTimeoutMs,
		IpcCommand.ListWhitelist => OperationTimeoutMs,
		IpcCommand.AddToWhitelist => OperationTimeoutMs,
		IpcCommand.RemoveFromWhitelist => OperationTimeoutMs,
		IpcCommand.GetAttackStats => OperationTimeoutMs,
		IpcCommand.ListRdpSessions => OperationTimeoutMs,
		IpcCommand.DisconnectSession => OperationTimeoutMs,
		IpcCommand.LogoffSession => OperationTimeoutMs,
		IpcCommand.ShadowSession => OperationTimeoutMs,
		IpcCommand.GetShadowPolicyStatus => OperationTimeoutMs,
		IpcCommand.ApplyShadowPolicy => OperationTimeoutMs,
		IpcCommand.BackupShadowPolicy => OperationTimeoutMs,
		IpcCommand.RestoreShadowPolicy => OperationTimeoutMs,
		IpcCommand.GetAbuseIpDbStatus => OperationTimeoutMs,
		IpcCommand.TestAbuseIpDbKey => OperationTimeoutMs,
		IpcCommand.GetMikroTikStatus => OperationTimeoutMs,
		IpcCommand.TestMikroTik => OperationTimeoutMs,
		IpcCommand.ListActiveBlocks => OperationTimeoutMs,
		IpcCommand.ListLoginRules => OperationTimeoutMs,
		IpcCommand.AddLoginRule => OperationTimeoutMs,
		IpcCommand.RemoveLoginRule => OperationTimeoutMs,
		IpcCommand.SetLoginRuleEnabled => OperationTimeoutMs,
		IpcCommand.GetOverviewSummary => OperationTimeoutMs,
		IpcCommand.GetEventsForIp => OperationTimeoutMs,
		IpcCommand.ListConnectionFacts => OperationTimeoutMs,
		IpcCommand.GetConnectionFactsForIp => OperationTimeoutMs,
		IpcCommand.GetRdpConfiguration => OperationTimeoutMs,
		IpcCommand.GetDiagnostics => OperationTimeoutMs,
		IpcCommand.RunSecurityAuthProbe => OperationTimeoutMs,
		IpcCommand.ListAbuseIpDbReportLog => OperationTimeoutMs,
		IpcCommand.DedupeBlocklistEntries => OperationTimeoutMs,
		IpcCommand.QueryOperationLogs => OperationTimeoutMs,
		IpcCommand.GetOverviewProgress => OperationTimeoutMs,
		IpcCommand.PushMikroTikConfig => OperationTimeoutMs,
		IpcCommand.GetMikroTikMtlsStatus => OperationTimeoutMs,
		IpcCommand.GetMikroTikSecurityAudit => LongOperationTimeoutMs,

		// --- Zabbix integration (ordinals 96-101). The test opens two independent network
		// round-trips (trapper port and API), the manual push waits for a TCP answer from a server
		// that may be across a VPN, and provisioning issues one API call per object — all three
		// routinely exceed the short default, so they get the long deadline. The three settings and
		// status reads touch no network and keep the short one.
		IpcCommand.TestZabbixConnection => LongOperationTimeoutMs,
		IpcCommand.PushZabbixNow => LongOperationTimeoutMs,
		IpcCommand.ProvisionZabbix => LongOperationTimeoutMs,
		IpcCommand.GetAuthSuccessSummaryForIp => OperationTimeoutMs,
		IpcCommand.GetEventCollectionSettings => OperationTimeoutMs,
		IpcCommand.SaveEventCollectionSettings => OperationTimeoutMs,
		IpcCommand.AcknowledgeCrossHostChain => OperationTimeoutMs,
		IpcCommand.GetAlertsForIp => OperationTimeoutMs,
		IpcCommand.GetThreatIntelStatus => OperationTimeoutMs,
		IpcCommand.GetSessionTimeline => OperationTimeoutMs,
		IpcCommand.ReportProcessObservation => OperationTimeoutMs,
		IpcCommand.ListProcessAlerts => OperationTimeoutMs,
		IpcCommand.GetProcessAlertDetails => OperationTimeoutMs,
		IpcCommand.SetProcessAutoClose => OperationTimeoutMs,
		IpcCommand.GetProcessMonitoringStatus => OperationTimeoutMs,
		IpcCommand.GetNotificationSettings => OperationTimeoutMs,
		IpcCommand.SaveNotificationSettings => OperationTimeoutMs,
		IpcCommand.GetDatabaseOverview => OperationTimeoutMs,
		IpcCommand.GetRetentionPolicy => OperationTimeoutMs,
		IpcCommand.SaveRetentionPolicy => OperationTimeoutMs,
		IpcCommand.PreviewRetention => OperationTimeoutMs,
		IpcCommand.GetDeletionLedger => OperationTimeoutMs,
		IpcCommand.SaveShardingPolicy => OperationTimeoutMs,
		IpcCommand.CompactDatabase => OperationTimeoutMs,
		IpcCommand.GetZabbixSettings => OperationTimeoutMs,
		IpcCommand.SaveZabbixSettings => OperationTimeoutMs,
		IpcCommand.GetZabbixStatus => OperationTimeoutMs,
		IpcCommand.GetEditionInfo => OperationTimeoutMs,
		_ => OperationTimeoutMs,
	};
}
