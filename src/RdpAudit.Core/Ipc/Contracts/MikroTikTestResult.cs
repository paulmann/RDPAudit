// File:    src/RdpAudit.Core/Ipc/Contracts/MikroTikTestResult.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by TestMikroTik. Surfaces the outcome of a controlled, read-only probe
//          against the RouterOS v7 REST endpoint without ever leaking the password.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>TestMikroTik</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class MikroTikTestResult
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the basic URL/credential composition succeeded locally before any HTTP call.</summary>
	[Key(1)]
	public bool CredentialFormatValid { get; set; }

	/// <summary>True when the router accepted the credential and the probe succeeded.</summary>
	[Key(2)]
	public bool RemoteVerified { get; set; }

	/// <summary>HTTP status code observed during the probe; 0 when no call was made.</summary>
	[Key(3)]
	public int ResponseCode { get; set; }

	/// <summary>Endpoint URL the probe was sent to (sanitised, no credentials).</summary>
	[Key(4)]
	public string Endpoint { get; set; } = string.Empty;

	/// <summary>Sanitised description of the probe outcome.</summary>
	[Key(5)]
	public string Message { get; set; } = string.Empty;
}
