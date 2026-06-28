// File:    src/RdpAudit.Core/Ipc/Contracts/AbuseIpDbTestResult.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by TestAbuseIpDbKey. The validation is read-only — it does NOT submit fake
//          abuse reports. The result reports whether the configured key is structurally valid and,
//          when possible, whether a safe check endpoint accepted it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>TestAbuseIpDbKey</c> describing the outcome of a read-only key check.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AbuseIpDbTestResult
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the key is present and passes format validation.</summary>
	[Key(1)]
	public bool KeyFormatValid { get; set; }

	/// <summary>True when a safe HTTP probe (e.g. /check on 127.0.0.1) accepted the credential.</summary>
	[Key(2)]
	public bool RemoteVerified { get; set; }

	/// <summary>HTTP response code from the safe probe call; 0 when no remote call was made.</summary>
	[Key(3)]
	public int ResponseCode { get; set; }

	/// <summary>Sanitised human-readable message; never contains the API key.</summary>
	[Key(4)]
	public string Message { get; set; } = string.Empty;
}
