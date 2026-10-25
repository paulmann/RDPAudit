// File:    src/RdpAudit.Core/Models/CrossHostHostState.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted operational state of one configured agent host: availability, last
//          successful poll, and last transport error. The correlation worker updates this row
//          after every pull so the Configurator and the alert layer can render fail-closed
//          decisions without re-polling.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.CrossHost;

namespace RdpAudit.Core.Models;

/// <summary>Persisted availability state of one agent host.</summary>
public sealed class CrossHostHostState
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Configured agent host name; unique - one state row per host.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>Availability as seen during the last poll.</summary>
	public CrossHostAvailability Availability { get; set; }

	/// <summary>UTC timestamp of the last successful fact pull; null when never polled or the
	/// host is currently unavailable/fail-closed.</summary>
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Last transport/validation error, when the host is unavailable.</summary>
	public string? LastError { get; set; }

	/// <summary>UTC timestamp of the last poll attempt (successful or not).</summary>
	public DateTime LastPolledUtc { get; set; }
}
