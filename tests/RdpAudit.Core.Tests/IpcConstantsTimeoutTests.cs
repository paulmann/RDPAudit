// File:    tests/RdpAudit.Core.Tests/IpcConstantsTimeoutTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the per-command IPC round-trip deadline policy that fixed the historic
//          "service not running" misreport: long-running firewall / diagnostics commands MUST
//          get the long (60 s) deadline so the client and server never abandon a request the
//          service is still completing, while cheap read-only commands keep the short default.
//          Both ends of a round-trip consult IpcConstants.TimeoutMsFor, so this single map is the
//          contract — if it regresses (e.g. a Repair command drops back to 5 s) the bug returns.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the IPC per-command timeout policy that keeps long firewall / diagnostics calls
/// from being abandoned mid-flight and misreported as a dead service.</summary>
public class IpcConstantsTimeoutTests
{
	public static TheoryData<IpcCommand> LongRunningCommands => new()
	{
		IpcCommand.RunToolsDiagnostics,
		IpcCommand.RunTemporaryFirewallRuleProbe,
		IpcCommand.GetFirewallStatus,
		IpcCommand.GetFirewallDiagnostics,
		IpcCommand.ListActiveBlocksDetailed,
		IpcCommand.ReconcileEnforcement,
		IpcCommand.RepairActiveBlock,
		IpcCommand.RemoveAllEnforcement,
		IpcCommand.RepairBlocklistEnforcement,
		IpcCommand.RepairAllEnabledBlocklistEnforcement,
		IpcCommand.BlockAddress,
		IpcCommand.UnblockAddress,
		IpcCommand.AddToBlocklist,
		IpcCommand.RemoveFromBlocklist,
		IpcCommand.UnblockActiveBlock,
		IpcCommand.ClearAllBlocklist,
		IpcCommand.ClearAllFirewallRules,
		IpcCommand.ClearAllApplicationData,
	};

	public static TheoryData<IpcCommand> CheapCommands => new()
	{
		IpcCommand.Ping,
		IpcCommand.GetStatus,
	};

	[Theory]
	[MemberData(nameof(LongRunningCommands))]
	public void TimeoutMsFor_LongRunningCommand_UsesLongDeadline(IpcCommand command)
	{
		Assert.Equal(IpcConstants.LongOperationTimeoutMs, IpcConstants.TimeoutMsFor(command));
	}

	[Theory]
	[MemberData(nameof(CheapCommands))]
	public void TimeoutMsFor_CheapCommand_UsesShortDefault(IpcCommand command)
	{
		Assert.Equal(IpcConstants.OperationTimeoutMs, IpcConstants.TimeoutMsFor(command));
	}

	[Fact]
	public void LongDeadline_IsStrictlyGreaterThanShortDefault()
	{
		// The server only widens its deadline when the per-command budget exceeds the short default
		// (IpcServerWorker), so the long deadline must be strictly larger or the widening is a no-op.
		Assert.True(IpcConstants.LongOperationTimeoutMs > IpcConstants.OperationTimeoutMs);
	}

	[Fact]
	public void ConnectTimeout_IsShorterThanShortDefault()
	{
		// Connect must fail fast (service stopped / not installed) well before the round-trip deadline,
		// so the UI can distinguish ConnectFailed from a slow-but-reachable service.
		Assert.True(IpcConstants.ConnectTimeoutMs < IpcConstants.OperationTimeoutMs);
	}
}
