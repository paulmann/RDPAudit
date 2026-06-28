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

namespace RdpAudit.Core.Ipc;

/// <summary>Shared constants for the Named Pipe IPC channel.</summary>
public static class IpcConstants
{
	public const string PipeName = "RdpAuditService";

	public const int MaxFrameBytes = 16 * 1024 * 1024;

	public const int ConnectTimeoutMs = 2_000;

	/// <summary>Default round-trip deadline for cheap, read-only commands (status, list queries).</summary>
	public const int OperationTimeoutMs = 5_000;

	/// <summary>Round-trip deadline for long-running commands that shell out to several netsh /
	/// PowerShell processes (firewall repair / verify / reconcile, Tools Diag, temporary-rule probe).
	/// Bounded so the UI never hangs indefinitely, but long enough that a multi-rule repair on a busy
	/// host completes within one round-trip instead of being abandoned and misreported as a dead
	/// service.</summary>
	public const int LongOperationTimeoutMs = 60_000;

	/// <summary>Returns the appropriate client/server round-trip deadline (in milliseconds) for the
	/// supplied command. Commands that drive external firewall tooling get the long deadline; every
	/// other command keeps the short default. Both the client and the server consult this so the two
	/// ends of a single round-trip never disagree on how long the call is allowed to take.</summary>
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
		_ => OperationTimeoutMs,
	};
}
