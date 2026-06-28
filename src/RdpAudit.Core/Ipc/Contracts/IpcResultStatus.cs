// File:    src/RdpAudit.Core/Ipc/Contracts/IpcResultStatus.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Discriminator carried in operation-result DTOs so handlers can distinguish between
//          "operation succeeded", "feature not yet implemented", "feature unavailable on host",
//          and "operation refused for a known reason" without per-command bespoke shapes.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Discriminator for the outcome of an IPC operation.</summary>
/// <remarks>Append-only enum: values must never be reused or reordered.</remarks>
public enum IpcResultStatus
{
	/// <summary>The operation completed successfully.</summary>
	Success = 0,

	/// <summary>The feature is recognised but the handler is not implemented in this build.</summary>
	NotImplemented = 1,

	/// <summary>The feature is recognised but the host or provider cannot service it right now.</summary>
	Unavailable = 2,

	/// <summary>The operation was refused because of policy / configuration constraints.</summary>
	Refused = 3,

	/// <summary>The supplied request payload failed validation.</summary>
	InvalidRequest = 4,
}
