// File:    src/RdpAudit.Core/Models/SessionStatus.cs
// Module:  RdpAudit.Core.Models
// Purpose: Lifecycle state of an RDP session.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Lifecycle state of an RDP session.</summary>
public enum SessionStatus
{
	Active = 0,
	Disconnected = 1,
	LoggedOff = 2,
}
