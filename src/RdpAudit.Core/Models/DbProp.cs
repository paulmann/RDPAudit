// File:    src/RdpAudit.Core/Models/DbProp.cs
// Module:  RdpAudit.Core.Models
// Purpose: Generic key-value store persisted alongside the audit database.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Generic key-value store persisted alongside the audit database.</summary>
public sealed class DbProp
{
	public string Key { get; set; } = string.Empty;

	public string? Value { get; set; }

	public DateTime UpdatedUtc { get; set; }
}
