// File:    src/RdpAudit.Core/Models/WhitelistEntry.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent IP whitelist record. Whitelisted IPs always bypass automatic blocking even
//          when other rules would match. The table is intentionally small and indexed for fast
//          membership lookups from the future AutoBlockWorker.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent IP whitelist record that bypasses automatic blocking.</summary>
public sealed class WhitelistEntry
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>IP address in IPv4 or IPv6 textual form.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>Operator-supplied note explaining why this address is whitelisted.</summary>
	public string? Note { get; set; }

	/// <summary>UTC timestamp when the entry was created.</summary>
	public DateTime AddedUtc { get; set; }

	/// <summary>Identity of the operator that added the entry, where known.</summary>
	public string? AddedBy { get; set; }
}
