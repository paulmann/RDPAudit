// File:    src/RdpAudit.Core/Models/BlocklistEntry.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent manual or automatic blocklist record. A row matches an inbound logon attempt
//          when its Ip and/or Login match. Rows are auditable, reversible, and reference the alert
//          that produced them (when produced automatically).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent manual or automatic blocklist record (IP and/or login).</summary>
/// <remarks>
/// At least one of <see cref="Ip"/> or <see cref="Login"/> must be populated; the constraint is
/// enforced at write time by the caller (not by SQLite) so that operators can stage records via
/// the Configurator without partial transactions.
/// </remarks>
public sealed class BlocklistEntry
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Optional source IP (IPv4 or IPv6 textual form). Null for login-only entries.</summary>
	public string? Ip { get; set; }

	/// <summary>Optional login (sAMAccountName or UPN). Null for IP-only entries.</summary>
	public string? Login { get; set; }

	/// <summary>Operator-supplied or rule-supplied reason; surfaced in audit trails.</summary>
	public string Reason { get; set; } = string.Empty;

	/// <summary>UTC timestamp when the entry was created.</summary>
	public DateTime AddedUtc { get; set; }

	/// <summary>UTC timestamp when the entry should be considered expired; null means permanent.</summary>
	public DateTime? ExpiresUtc { get; set; }

	/// <summary>Origin of the entry (manual operator, auto rule, external feed, etc.).</summary>
	public BlocklistSource Source { get; set; }

	/// <summary>Optional foreign key to the <see cref="Alert"/> that produced this entry.</summary>
	public long? LinkedAlertId { get; set; }

	/// <summary>Soft-disable flag; disabled rows are retained for audit but not enforced.</summary>
	public bool IsEnabled { get; set; } = true;
}
