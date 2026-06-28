// File:    tests/RdpAudit.Core.Tests/IpcCommandStabilityTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the IpcCommand ABI. Fails if any ordinal is renumbered, removed, or duplicated.
//          The IPC contract is append-only; this test is the canary that catches breaking edits.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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
	public void Ordinal_IsStable(IpcCommand command, int expected)
	{
		Assert.Equal(expected, (int)command);
	}

	[Fact]
	public void ResultStatus_HasExpectedOrdinals()
	{
		Assert.Equal(0, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Success);
		Assert.Equal(1, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.NotImplemented);
		Assert.Equal(2, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Unavailable);
		Assert.Equal(3, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.Refused);
		Assert.Equal(4, (int)RdpAudit.Core.Ipc.Contracts.IpcResultStatus.InvalidRequest);
	}
}
