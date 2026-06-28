// File:    src/RdpAudit.Core/Events/SecurityAuthQuery.cs
// Module:  RdpAudit.Core.Events
// Purpose: Canonical narrow XPath builder for Security-channel authentication ingestion.
//          The push-based EventLogWatcher cannot honour ReverseDirection / MaxEvents — on a
//          host with a multi-gigabyte Security log a broad catalog scan stalls forever and
//          reports Armed-but-zero-events. cameyo/rdpmon and PowerShell both succeed because
//          they pin the query to a tiny canonical auth-event set; mirror that contract here
//          so the realtime watcher and the bounded backfill / probe paths all share one
//          XPath shape. 4624 / 4625 / 4648 / 4768 / 4769 / 4771 / 4776 / 4825 are the v3
//          atomic-outcome carriers (Detect_Attack_Strategy_v3.md §6.3, §8.1).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Events;

/// <summary>Canonical narrow XPath builder for Security-channel authentication ingestion.</summary>
public static class SecurityAuthQuery
{
	/// <summary>The canonical Security-channel authentication event IDs RdpAudit must ingest
	/// reliably even when a host's Security log is huge. This set is intentionally tight: it
	/// matches the cameyo/rdpmon Security read path and the PowerShell Get-WinEvent FilterXml
	/// PowerShell operators use during incident triage. Wider Security ids (object access,
	/// process creation, persistence, etc.) are best collected with their own narrow queries
	/// or via separate hosted collectors so a slow read on one ID never starves another.</summary>
	public static readonly IReadOnlyList<int> AuthEventIds = new[]
	{
		4624, // Successful logon
		4625, // Failed logon
		4648, // Explicit credentials
		4768, // Kerberos TGT requested
		4769, // Kerberos service ticket requested
		4771, // Kerberos pre-authentication failed
		4776, // NTLM credential validation
		4825, // RDP access denied (not in Remote Desktop Users)
	};

	/// <summary>Build an XPath that selects events from <see cref="AuthEventIds"/> only.</summary>
	public static string BuildXPath()
	{
		return BuildXPath(AuthEventIds);
	}

	/// <summary>Build an XPath that selects events from the supplied id set only.</summary>
	public static string BuildXPath(IReadOnlyCollection<int> ids)
	{
		ArgumentNullException.ThrowIfNull(ids);
		if (ids.Count == 0)
		{
			// Defensive: refuse to emit a wildcard. Callers asked for narrow auth.
			return "*[System[(EventID=4625)]]";
		}

		return "*[System[(" + string.Join(" or ", ids.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture))) + ")]]";
	}

	/// <summary>Build an XPath that adds a time lower bound to the auth-event filter. The
	/// timestamp is rendered as an invariant ISO-8601 string with millisecond precision and
	/// explicit Z so Windows accepts it across locales.</summary>
	public static string BuildXPath(IReadOnlyCollection<int> ids, DateTime sinceUtc)
	{
		ArgumentNullException.ThrowIfNull(ids);
		string iso = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
		string idClause = ids.Count == 0
			? "EventID=4625"
			: string.Join(" or ", ids.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)));
		return "*[System[(" + idClause + ") and TimeCreated[@SystemTime >= '" + iso + "']]]";
	}

	/// <summary>Build a single-EventID XPath bounded by the supplied lower-bound timestamp.
	/// Used by the backfill worker to issue one query per EventID so a per-ID timeout never
	/// starves the other authentication IDs.</summary>
	public static string BuildXPathSingleId(int eventId, DateTime sinceUtc)
	{
		string iso = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
		return "*[System[(EventID=" + eventId.ToString(CultureInfo.InvariantCulture)
			+ ") and TimeCreated[@SystemTime >= '" + iso + "']]]";
	}
}
