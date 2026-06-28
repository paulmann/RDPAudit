// File:    src/RdpAudit.Core/Models/Session.cs
// Module:  RdpAudit.Core.Models
// Purpose: Tracks the lifecycle of a single RDP session.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Tracks the lifecycle of a single RDP session.</summary>
public sealed class Session
{
	public long Id { get; set; }

	public int WtsSessionId { get; set; }

	public string? UserName { get; set; }

	public string? Domain { get; set; }

	public string? SourceIp { get; set; }

	public DateTime ConnectUtc { get; set; }

	public DateTime? DisconnectUtc { get; set; }

	public DateTime? LogoffUtc { get; set; }

	public int? LogonType { get; set; }

	public string? LogonId { get; set; }

	public SessionStatus Status { get; set; }

	public string? Flags { get; set; }
}
