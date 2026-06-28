// File:    src/RdpAudit.Core/Ipc/Contracts/ProviderTestResult.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by TestAbuseIpDbKey / TestMikroTik IPC commands. Never carries the
//          plaintext secret used during the test.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by provider test IPC commands.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProviderTestResult
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public bool Reachable { get; set; }

	[Key(2)]
	public bool Authenticated { get; set; }

	[Key(3)]
	public int LatencyMilliseconds { get; set; }

	/// <summary>Operator-facing message; MUST NOT include API keys, passwords, or response bodies.</summary>
	[Key(4)]
	public string? Message { get; set; }
}
