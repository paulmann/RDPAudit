/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcCommandStabilityTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks append-only IPC and result-status ordinals against breaking ABI changes.
// Depends: IpcCommand, IpcResultStatus, xUnit
// Extends: Append stable ordinal assertions whenever a new IPC command is added.

using RdpAudit.Core.Ipc;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Locks the IpcCommand ABI to its current ordinals.</summary>
public class IpcCommandStabilityTests
{
	[Fact]
	public void Ordinals_HaveNoDuplicates()
	{
		int[] values = Enum.GetValues<IpcCommand>().Select(v => (int)v).ToArray();
		Assert.Equal(values.Length, values.Distinct().Count());
	}

	[Theory]
	[InlineData(IpcCommand.Ping, 0)]
	[InlineData(IpcCommand.GetStatus, 1)]
	[InlineData(IpcCommand.GetRecentEvents, 2)]
	[InlineData(IpcCommand.GetRecentAlerts, 3)]
	[InlineData(IpcCommand.GetAddresses, 4)]
	[InlineData(IpcCommand.GetSessions, 5)]
	[InlineData(IpcCommand.AcknowledgeAlert, 6)]
	[InlineData(IpcCommand.BlockAddress, 7)]
	[InlineData(IpcCommand.UnblockAddress, 8)]
	[InlineData(IpcCommand.GetSettings, 9)]
	[InlineData(IpcCommand.SaveSettings, 10)]
	[InlineData(IpcCommand.GetFirewallStatus, 11)]
	[InlineData(IpcCommand.ListBlocklist, 12)]
	[InlineData(IpcCommand.ListWhitelist, 13)]
	[InlineData(IpcCommand.AddToBlocklist, 14)]
	[InlineData(IpcCommand.RemoveFromBlocklist, 15)]
	[InlineData(IpcCommand.AddToWhitelist, 16)]
	[InlineData(IpcCommand.RemoveFromWhitelist, 17)]
	[InlineData(IpcCommand.GetAttackStats, 18)]
	[InlineData(IpcCommand.ListRdpSessions, 19)]
	[InlineData(IpcCommand.DisconnectSession, 20)]
	[InlineData(IpcCommand.LogoffSession, 21)]
	[InlineData(IpcCommand.ShadowSession, 22)]
	[InlineData(IpcCommand.GetShadowPolicyStatus, 23)]
	[InlineData(IpcCommand.ApplyShadowPolicy, 24)]
	[InlineData(IpcCommand.BackupShadowPolicy, 25)]
	[InlineData(IpcCommand.RestoreShadowPolicy, 26)]
	[InlineData(IpcCommand.GetAbuseIpDbStatus, 27)]
	[InlineData(IpcCommand.TestAbuseIpDbKey, 28)]
	[InlineData(IpcCommand.GetMikroTikStatus, 29)]
	[InlineData(IpcCommand.TestMikroTik, 30)]
	[InlineData(IpcCommand.ListActiveBlocks, 31)]
	[InlineData(IpcCommand.ListLoginRules, 32)]
	[InlineData(IpcCommand.AddLoginRule, 33)]
	[InlineData(IpcCommand.RemoveLoginRule, 34)]
	[InlineData(IpcCommand.SetLoginRuleEnabled, 35)]
	[InlineData(IpcCommand.ListActiveBlocksDetailed, 36)]
	[InlineData(IpcCommand.UnblockActiveBlock, 37)]
	[InlineData(IpcCommand.GetOverviewSummary, 38)]
	[InlineData(IpcCommand.GetEventsForIp, 39)]
	[InlineData(IpcCommand.ListConnectionFacts, 40)]
	[InlineData(IpcCommand.GetConnectionFactsForIp, 41)]
	[InlineData(IpcCommand.GetRdpConfiguration, 42)]
	[InlineData(IpcCommand.GetDiagnostics, 43)]
	[InlineData(IpcCommand.RunSecurityAuthProbe, 44)]
	[InlineData(IpcCommand.GetFirewallDiagnostics, 45)]
	[InlineData(IpcCommand.ReconcileEnforcement, 46)]
	[InlineData(IpcCommand.RepairActiveBlock, 47)]
	[InlineData(IpcCommand.RemoveAllEnforcement, 48)]
	[InlineData(IpcCommand.RepairBlocklistEnforcement, 49)]
	[InlineData(IpcCommand.RepairAllEnabledBlocklistEnforcement, 50)]
	[InlineData(IpcCommand.ListAbuseIpDbReportLog, 51)]
	[InlineData(IpcCommand.RunToolsDiagnostics, 52)]
	[InlineData(IpcCommand.RunTemporaryFirewallRuleProbe, 53)]
	[InlineData(IpcCommand.DedupeBlocklistEntries, 54)]
	[InlineData(IpcCommand.ClearAllBlocklist, 55)]
	[InlineData(IpcCommand.ClearAllFirewallRules, 56)]
	[InlineData(IpcCommand.ClearAllApplicationData, 57)]
	[InlineData(IpcCommand.QueryOperationLogs, 58)]
	[InlineData(IpcCommand.GetOverviewProgress, 59)]
	[InlineData(IpcCommand.RebuildAttackStats, 60)]
	[InlineData(IpcCommand.PushMikroTikConfig, 61)]
	[InlineData(IpcCommand.GetMikroTikMtlsStatus, 62)]
	[InlineData(IpcCommand.GetAuthSuccessSummaryForIp, 63)]
	[InlineData(IpcCommand.GetEventCollectionSettings, 64)]
	[InlineData(IpcCommand.SaveEventCollectionSettings, 65)]
	[InlineData(IpcCommand.GetCrossHostFacts, 66)]
	[InlineData(IpcCommand.ListCrossHostChains, 67)]
	[InlineData(IpcCommand.GetCrossHostChainDetails, 68)]
	[InlineData(IpcCommand.AcknowledgeCrossHostChain, 69)]
	[InlineData(IpcCommand.GetAlertsForIp, 70)]
	[InlineData(IpcCommand.GetThreatIntelStatus, 71)]
	[InlineData(IpcCommand.GetSessionTimeline, 72)]
	[InlineData(IpcCommand.ReportProcessObservation, 73)]
	[InlineData(IpcCommand.ListProcessAlerts, 74)]
	[InlineData(IpcCommand.GetProcessAlertDetails, 75)]
	[InlineData(IpcCommand.SetProcessAutoClose, 76)]
	[InlineData(IpcCommand.GetProcessMonitoringStatus, 77)]
	[InlineData(IpcCommand.GetNotificationSettings, 78)]
	[InlineData(IpcCommand.SaveNotificationSettings, 79)]
	[InlineData(IpcCommand.GetDatabaseOverview, 80)]
	[InlineData(IpcCommand.GetRetentionPolicy, 81)]
	[InlineData(IpcCommand.SaveRetentionPolicy, 82)]
	[InlineData(IpcCommand.PreviewRetention, 83)]
	[InlineData(IpcCommand.GetDeletionLedger, 84)]
	[InlineData(IpcCommand.CreateDatabaseBackup, 85)]
	[InlineData(IpcCommand.ListDatabaseBackups, 86)]
	[InlineData(IpcCommand.VerifyDatabaseBackup, 87)]
	[InlineData(IpcCommand.GetShardInventory, 88)]
	[InlineData(IpcCommand.RunDatabaseMaintenance, 89)]
	[InlineData(IpcCommand.RestoreDatabaseBackupToDirectory, 90)]
	[InlineData(IpcCommand.SaveShardingPolicy, 91)]
	[InlineData(IpcCommand.CollectShardGarbage, 92)]
	public void Ordinal_IsStable(IpcCommand command, int expected)
	{
		Assert.Equal(expected, (int)command);
	}

	/// <summary>Given the append-only ABI, when the Stage 2a commands were appended, then no existing
	/// ordinal may have moved and the new commands must be the highest ones in the enum. This is the
	/// counterfactual to <see cref="Ordinal_IsStable"/>: it fails if a new command is inserted in the
	/// middle or an old one is renumbered to make room.</summary>
	[Fact]
	public void Stage2aCommands_WereAppendedAfterThePreviousMaximum()
	{
		Assert.Equal(79, (int)IpcCommand.SaveNotificationSettings);
		Assert.Equal(80, (int)IpcCommand.GetDatabaseOverview);
		Assert.Equal(84, (int)IpcCommand.GetDeletionLedger);
	}

	/// <summary>Counterfactual to <see cref="Ordinal_IsStable"/> for the backup surface: the three
	/// snapshot commands must sit directly after the Stage 2a maximum, so nothing below them can have
	/// been renumbered to make room.</summary>
	[Fact]
	public void Stage2bCommands_WereAppendedAfterTheStage2aMaximum()
	{
		Assert.Equal(85, (int)IpcCommand.CreateDatabaseBackup);
		Assert.Equal(86, (int)IpcCommand.ListDatabaseBackups);
		Assert.Equal(87, (int)IpcCommand.VerifyDatabaseBackup);
	}

	/// <summary>Counterfactual to <see cref="Ordinal_IsStable"/> for the Stage 3 UI surface: the three
	/// Database-tab commands must sit directly after the Stage 2b maximum and must be the last
	/// ordinals in the enum, so nothing below them can have been renumbered to make room.</summary>
	[Fact]
	public void Stage3Commands_WereAppendedAfterTheStage2bMaximum()
	{
		Assert.Equal(88, (int)IpcCommand.GetShardInventory);
		Assert.Equal(89, (int)IpcCommand.RunDatabaseMaintenance);
		Assert.Equal(90, (int)IpcCommand.RestoreDatabaseBackupToDirectory);
	}

	/// <summary>Counterfactual to <see cref="Ordinal_IsStable"/> for the Stage 4 shard-governance
	/// surface: the policy writer and the orphan collector must sit directly after the Stage 3 maximum
	/// and must be the last ordinals in the enum, so nothing below them can have been renumbered to make
	/// room.</summary>
	[Fact]
	public void Stage4Commands_WereAppendedAfterTheStage3Maximum()
	{
		Assert.Equal(91, (int)IpcCommand.SaveShardingPolicy);
		Assert.Equal(92, (int)IpcCommand.CollectShardGarbage);
	}

	/// <summary>Counterfactual for the Stage 5 storage-hardening surface: the compaction refusal and the
	/// subject purge sit directly after the Stage 4 maximum and are the last ordinals in the enum, so nothing
	/// below them can have been renumbered to make room.</summary>
	[Fact]
	public void Stage5Commands_WereAppendedAfterTheStage4Maximum()
	{
		Assert.Equal(93, (int)IpcCommand.CompactDatabase);
		Assert.Equal(94, (int)IpcCommand.PurgeBySubject);
		Assert.Equal(95, (int)IpcCommand.GetMikroTikSecurityAudit);
	}

	/// <summary>Counterfactual for the Zabbix surface: the six new commands sit directly after the
	/// MikroTik maximum and are the last ordinals in the enum, so every earlier command kept its
	/// number.</summary>
	[Fact]
	public void ZabbixCommands_WereAppendedAfterTheMikroTikMaximum()
	{
		Assert.Equal(96, (int)IpcCommand.GetZabbixSettings);
		Assert.Equal(97, (int)IpcCommand.SaveZabbixSettings);
		Assert.Equal(98, (int)IpcCommand.TestZabbixConnection);
		Assert.Equal(99, (int)IpcCommand.PushZabbixNow);
		Assert.Equal(100, (int)IpcCommand.ProvisionZabbix);
		Assert.Equal(101, (int)IpcCommand.GetZabbixStatus);

		// Editions (AppendAfterZabbix): nothing above the Zabbix block was renumbered when the
		// edition report was added - it took the next free number and the count grew by exactly one.
		Assert.Equal(102, (int)IpcCommand.GetEditionInfo);
		Assert.Equal(103, Enum.GetValues<IpcCommand>().Length);
	}

	[Fact]
	public void ResultStatus_HasExpectedOrdinals()
	{
		Assert.Equal(0, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Success);
		Assert.Equal(1, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.NotImplemented);
		Assert.Equal(2, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Unavailable);
		Assert.Equal(3, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Refused);
		Assert.Equal(4, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.InvalidRequest);
		Assert.Equal(5, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.NotFound);
	}
}
