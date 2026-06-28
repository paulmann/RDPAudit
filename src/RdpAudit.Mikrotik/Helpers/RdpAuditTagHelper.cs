/*
 * File   : RdpAuditTagHelper.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Helpers)
 * Purpose: Builds and recognises the comment tag RdpAudit stamps onto every RouterOS object it
 *          creates (firewall rules, address-list entries, the service user, certificates). The tag
 *          is how rollback and re-runs know which objects are RdpAudit-owned and therefore safe to
 *          remove — and which operator objects must never be touched.
 * Depends: System.String
 * Extends: If a new object category needs a distinct sub-purpose, pass it as the purpose argument;
 *          if the ownership-marker syntax ever changes, update both BuildComment and IsRdpAuditManaged
 *          together so creation and recognition stay symmetric.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Globalization;

namespace RdpAudit.Mikrotik.Helpers;

/// <summary>Builds and recognises the RdpAudit ownership comment tag on RouterOS objects.</summary>
public static class RdpAuditTagHelper
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Project URL appended to every tag so a router operator can trace the object's origin.</summary>
	public const string ProjectUrl = "https://github.com/paulmann/RDPAudit";

	/// <summary>Case-insensitive marker that identifies an RdpAudit-owned object.</summary>
	public const string OwnershipMarker = "[rdpaudit:";

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Returns the canonical comment for an RdpAudit-owned RouterOS object, in the exact form
	/// <c>[rdpaudit: &lt;purpose&gt;] https://github.com/paulmann/RDPAudit</c>.
	/// </summary>
	/// <param name="purpose">Short, human-readable role of the object (e.g. "rdp blocklist drop").</param>
	public static string BuildComment(string purpose)
	{
		string safePurpose = string.IsNullOrWhiteSpace(purpose) ? "managed" : purpose.Trim();
		return string.Format(CultureInfo.InvariantCulture, "{0} {1}] {2}", OwnershipMarker, safePurpose, ProjectUrl);
	}

	/// <summary>
	/// True when <paramref name="comment"/> contains the RdpAudit ownership marker. Used by rollback
	/// and idempotent re-runs to avoid touching operator-created objects.
	/// </summary>
	public static bool IsRdpAuditManaged(string? comment)
		=> !string.IsNullOrEmpty(comment)
			&& comment.Contains(OwnershipMarker, StringComparison.OrdinalIgnoreCase);
}
