// File:    src/RdpAudit.Core/Util/ActiveRdpTcpEnricher.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure live-TCP enricher used as a last-resort fallback when the DB-backed
//          LocalSessionEnricher cannot supply a Client IP for an Active RDP session
//          (typical when SessionCorrelationCache is empty, e.g. fresh install). Given:
//            * the set of currently-active RDP user sessions (RdpSessionDto);
//            * the set of currently-established TCP endpoints on the configured RDP port;
//          the enricher assigns a remote IP ONLY when both sides are unambiguous —
//          exactly one active session and exactly one non-loopback / non-wildcard
//          established endpoint. Multi-session / multi-endpoint situations are left
//          untouched (Client IP remains blank) so the operator is never lied to. The
//          enricher never overwrites a session that already has a ClientAddress set and
//          never touches disconnected / listener / non-RDP rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Sockets;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>One TCP endpoint observed on the local RDP listener port. <see cref="RemoteIp"/>
/// is the dotted-quad / IPv6 string of the peer; <see cref="RemotePort"/> is the peer's TCP
/// port (typically ephemeral / high).</summary>
public sealed record ActiveRdpTcpEndpoint(string RemoteIp, int RemotePort);

/// <summary>Outcome of <see cref="ActiveRdpTcpEnricher.Enrich"/>.</summary>
public sealed record ActiveRdpTcpEnrichmentResult(
	int ActiveSessionsConsidered,
	int EligibleTcpEndpoints,
	int IpsAssigned,
	ActiveRdpTcpEnrichmentOutcome Outcome,
	string Detail)
{
	/// <summary>True when at least one session received a Client IP from this enricher.</summary>
	public bool AnyApplied => IpsAssigned > 0;
}

/// <summary>Why the TCP enricher did or did not assign a Client IP. Exposed in status text
/// so the operator can tell which branch was taken.</summary>
public enum ActiveRdpTcpEnrichmentOutcome
{
	/// <summary>Nothing eligible — either no active sessions or no eligible TCP endpoints.</summary>
	NotApplicable = 0,

	/// <summary>Exactly one active session and exactly one eligible endpoint — assignment performed.</summary>
	SingleUnambiguousAssignment = 1,

	/// <summary>More than one active session and more than one endpoint — left blank intentionally.</summary>
	AmbiguousMultipleSessions = 2,

	/// <summary>One active session, no eligible endpoint — left blank.</summary>
	NoEligibleEndpoint = 3,

	/// <summary>Active session(s) already had Client IP set (e.g. from DB enrichment) — skipped.</summary>
	AlreadyEnriched = 4,
}

/// <summary>Pure live-TCP enricher for Active RDP sessions.</summary>
public static class ActiveRdpTcpEnricher
{
	/// <summary>Filter and assign. Modifies <paramref name="sessions"/> in place when an
	/// unambiguous assignment is possible.</summary>
	public static ActiveRdpTcpEnrichmentResult Enrich(
		IList<RdpSessionDto> sessions,
		IReadOnlyList<ActiveRdpTcpEndpoint> endpoints)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		ArgumentNullException.ThrowIfNull(endpoints);

		List<RdpSessionDto> activeNeedingIp = new();
		int activeAlreadyEnriched = 0;
		foreach (RdpSessionDto s in sessions)
		{
			if (!IsActiveRdpUserSession(s))
			{
				continue;
			}

			if (!string.IsNullOrWhiteSpace(s.ClientAddress))
			{
				activeAlreadyEnriched++;
				continue;
			}

			activeNeedingIp.Add(s);
		}

		List<ActiveRdpTcpEndpoint> eligible = FilterEligible(endpoints);

		if (activeNeedingIp.Count == 0)
		{
			ActiveRdpTcpEnrichmentOutcome outcome = activeAlreadyEnriched > 0
				? ActiveRdpTcpEnrichmentOutcome.AlreadyEnriched
				: ActiveRdpTcpEnrichmentOutcome.NotApplicable;
			return new ActiveRdpTcpEnrichmentResult(
				ActiveSessionsConsidered: activeAlreadyEnriched,
				EligibleTcpEndpoints: eligible.Count,
				IpsAssigned: 0,
				Outcome: outcome,
				Detail: outcome == ActiveRdpTcpEnrichmentOutcome.AlreadyEnriched
					? "all active sessions already have Client IP"
					: "no active RDP user sessions needing Client IP");
		}

		if (eligible.Count == 0)
		{
			return new ActiveRdpTcpEnrichmentResult(
				ActiveSessionsConsidered: activeNeedingIp.Count,
				EligibleTcpEndpoints: 0,
				IpsAssigned: 0,
				Outcome: ActiveRdpTcpEnrichmentOutcome.NoEligibleEndpoint,
				Detail: "no established remote TCP endpoint on the RDP listener port");
		}

		if (activeNeedingIp.Count != 1 || eligible.Count != 1)
		{
			return new ActiveRdpTcpEnrichmentResult(
				ActiveSessionsConsidered: activeNeedingIp.Count,
				EligibleTcpEndpoints: eligible.Count,
				IpsAssigned: 0,
				Outcome: ActiveRdpTcpEnrichmentOutcome.AmbiguousMultipleSessions,
				Detail: string.Format(System.Globalization.CultureInfo.InvariantCulture,
					"ambiguous: {0} active session(s), {1} endpoint(s) — Client IP left blank",
					activeNeedingIp.Count, eligible.Count));
		}

		activeNeedingIp[0].ClientAddress = eligible[0].RemoteIp;
		return new ActiveRdpTcpEnrichmentResult(
			ActiveSessionsConsidered: 1,
			EligibleTcpEndpoints: 1,
			IpsAssigned: 1,
			Outcome: ActiveRdpTcpEnrichmentOutcome.SingleUnambiguousAssignment,
			Detail: "assigned " + eligible[0].RemoteIp + " from sole established TCP endpoint");
	}

	/// <summary>True when this row represents a logged-on RDP user session in Active state.
	/// Listener / services / console rows are excluded.</summary>
	public static bool IsActiveRdpUserSession(RdpSessionDto s)
	{
		ArgumentNullException.ThrowIfNull(s);
		if (!s.IsActive)
		{
			return false;
		}

		if (string.IsNullOrWhiteSpace(s.UserName))
		{
			return false;
		}

		string? name = s.SessionName?.Trim();
		if (string.IsNullOrEmpty(name))
		{
			return false;
		}

		return name.StartsWith("rdp-tcp", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Filters the supplied endpoint list down to "eligible" remote peers. An eligible
	/// endpoint has a parseable IP that is not loopback, not the unspecified wildcard
	/// (0.0.0.0 / ::), and not a link-local IPv6 / IPv6 multicast address. The same remote IP
	/// can appear more than once (multiple TCP connections from the same peer) — we de-duplicate
	/// to a stable list so multi-connection same-peer cases still resolve unambiguously.</summary>
	public static List<ActiveRdpTcpEndpoint> FilterEligible(IReadOnlyList<ActiveRdpTcpEndpoint> endpoints)
	{
		ArgumentNullException.ThrowIfNull(endpoints);

		HashSet<string> seenIps = new(StringComparer.OrdinalIgnoreCase);
		List<ActiveRdpTcpEndpoint> result = new();
		foreach (ActiveRdpTcpEndpoint ep in endpoints)
		{
			if (!IsEligibleRemote(ep.RemoteIp))
			{
				continue;
			}

			if (seenIps.Add(ep.RemoteIp))
			{
				result.Add(ep);
			}
		}

		return result;
	}

	private static bool IsEligibleRemote(string? remoteIp)
	{
		if (string.IsNullOrWhiteSpace(remoteIp))
		{
			return false;
		}

		if (!IPAddress.TryParse(remoteIp, out IPAddress? addr) || addr is null)
		{
			return false;
		}

		if (IPAddress.IsLoopback(addr))
		{
			return false;
		}

		if (addr.AddressFamily == AddressFamily.InterNetwork)
		{
			byte[] bytes = addr.GetAddressBytes();
			// 0.0.0.0 wildcard / unassigned
			if (bytes[0] == 0)
			{
				return false;
			}
		}
		else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
		{
			if (addr.Equals(IPAddress.IPv6Any) || addr.Equals(IPAddress.IPv6None))
			{
				return false;
			}

			if (addr.IsIPv6Multicast)
			{
				return false;
			}
		}
		else
		{
			return false;
		}

		return true;
	}
}
