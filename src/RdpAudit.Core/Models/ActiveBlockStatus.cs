// File:    src/RdpAudit.Core/Models/ActiveBlockStatus.cs
// Module:  RdpAudit.Core.Models
// Purpose: Health state of a single ActiveBlock row, used by the eventual AutoBlockWorker to drive
//          retries and to surface a row's operational status in the Configurator.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Health state of a single <see cref="ActiveBlock"/> row.</summary>
/// <remarks>
/// Append-only enum: ordinals are persisted to SQLite and MUST NEVER be reused or reordered.
/// </remarks>
public enum ActiveBlockStatus
{
	/// <summary>Block is requested but has not yet been confirmed by the provider.</summary>
	Pending = 0,

	/// <summary>Block is installed and confirmed by the provider.</summary>
	Active = 1,

	/// <summary>Last attempt to install or refresh the block failed; retry policy will apply.</summary>
	Failed = 2,

	/// <summary>Block has been removed (either by expiration or by an explicit unblock).</summary>
	Removed = 3,

	/// <summary>Block is recorded for audit only; no firewall provider was driven (provider == None).</summary>
	AuditOnly = 4,
}
