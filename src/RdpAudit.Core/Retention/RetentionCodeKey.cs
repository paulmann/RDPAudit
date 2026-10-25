/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionCodeKey.cs
// Project: RdpAudit.Core (RdpAudit.Core.Retention)
// Purpose: Identity of an information-density retention code: the unit that owns one never-deletable
//          anchor and one protected tail.
// Depends: System, System.Globalization
// Extends: Add a new key component only together with the statistics SQL that groups by it and the
//          ledger scope that persists it.

using System.Globalization;

namespace RdpAudit.Core.Retention;

/// <summary>
/// Identity of a retention code. With <see cref="IpBinary16"/> null the code is host-wide
/// <c>(EventId, Channel)</c>; when set, the code is per source address
/// <c>(EventId, Channel, source IP)</c>.
/// </summary>
public sealed record RetentionCodeKey
{
	/// <summary>Windows event identifier.</summary>
	public required int EventId { get; init; }

	/// <summary>Windows event channel name.</summary>
	public required string Channel { get; init; }

	/// <summary>Canonical 16-byte source address key, or null for a host-wide code.</summary>
	public byte[]? IpBinary16 { get; init; }

	/// <summary>
	/// Uppercase hexadecimal form of <see cref="IpBinary16"/>, or an empty string for a host-wide
	/// code. This is the deterministic tie-break key and the operator-facing address label.
	/// </summary>
	public string IpHex => IpBinary16 is { Length: > 0 } ? Convert.ToHexString(IpBinary16) : string.Empty;

	/// <summary>Operator-facing label of the code, e.g. <c>Security/4625</c> or
	/// <c>Security/4625/C0A80101</c>.</summary>
	public string Describe()
		=> IpBinary16 is null
			? Channel + "/" + EventId.ToString(CultureInfo.InvariantCulture)
			: Channel + "/" + EventId.ToString(CultureInfo.InvariantCulture) + "/" + IpHex;
}
