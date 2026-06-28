// File:    src/RdpAudit.Core/Models/AlertSeverity.cs
// Module:  RdpAudit.Core.Models
// Purpose: Severity classification for generated alerts.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Severity classification for generated alerts.</summary>
public enum AlertSeverity
{
	Info = 0,
	Low = 1,
	Medium = 2,
	High = 3,
	Critical = 4,
}
