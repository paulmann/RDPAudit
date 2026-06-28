// File:    src/RdpAudit.Core/Util/LocalSessionEnricher.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure local-fallback enricher for RdpSessionDto rows when the Configurator cannot
//          reach the service IPC. Given an in-memory snapshot of SessionIpCorrelations and
//          RdpConnectionFacts (typically loaded once from the local SQLite DB through a
//          read-only EF Core context), it populates ClientAddress (only when the live row
//          lacks one), HistoricalFirstSeenUtc / LastSeenUtc, HistoricalFailedLogons /
//          SuccessfulLogons, and HistoricalUserNamesAttempted. The match order mirrors the
//          service-side enrichment so the Configurator never invents stronger evidence than
//          the service has — and never enriches non-RDP rows (services / console / listener).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Util;

/// <summary>Outcome of one <see cref="LocalSessionEnricher.Enrich"/> call.</summary>
public sealed record LocalSessionEnrichmentResult(
	int CandidateRdpSessions,
	int IpAssignedFromFacts,
	int HistoricalApplied)
{
	/// <summary>True when at least one row received any kind of historical enrichment.</summary>
	public bool AnyApplied => IpAssignedFromFacts > 0 || HistoricalApplied > 0;
}

/// <summary>Pure local-fallback enricher for <see cref="RdpSessionDto"/>.</summary>
public static class LocalSessionEnricher
{
	/// <summary>Session-name prefixes that identify a real RDP client row. Local-only rows like
	/// "console", "services" and the listener entries are deliberately excluded so the
	/// historical fields cannot be misattributed to them.</summary>
	public static readonly IReadOnlyList<string> RdpSessionNamePrefixes = new[]
	{
		"rdp-tcp",
	};

	/// <summary>Enrich every active/disconnected RDP session row in <paramref name="sessions"/>
	/// in place. Non-RDP rows (console / services / listener / SessionName missing) are skipped.</summary>
	/// <param name="sessions">Sessions to enrich. Modified in place.</param>
	/// <param name="correlations">All known SessionIpCorrelation rows for this host.</param>
	/// <param name="facts">All known RdpConnectionFact rows for this host.</param>
	public static LocalSessionEnrichmentResult Enrich(
		IList<RdpSessionDto> sessions,
		IReadOnlyList<SessionIpCorrelation> correlations,
		IReadOnlyList<RdpConnectionFact> facts)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		ArgumentNullException.ThrowIfNull(correlations);
		ArgumentNullException.ThrowIfNull(facts);

		int candidate = 0;
		int ipAssigned = 0;
		int historicalApplied = 0;

		Dictionary<string, FactAggregate> aggregatesByUser = AggregateByUser(facts);

		foreach (RdpSessionDto session in sessions)
		{
			if (!IsRdpClientRow(session))
			{
				continue;
			}

			candidate++;

			string? resolvedIp = ResolveIp(session, correlations, facts);
			if (resolvedIp is not null)
			{
				if (string.IsNullOrWhiteSpace(session.ClientAddress))
				{
					session.ClientAddress = resolvedIp;
					ipAssigned++;
				}
			}

			string? userKey = session.UserName?.Trim();
			if (!string.IsNullOrEmpty(userKey) && aggregatesByUser.TryGetValue(userKey, out FactAggregate agg))
			{
				if (session.HistoricalFirstSeenUtc is null)
				{
					session.HistoricalFirstSeenUtc = agg.FirstSeenUtc;
				}
				if (session.HistoricalLastSeenUtc is null)
				{
					session.HistoricalLastSeenUtc = agg.LastSeenUtc;
				}
				if (session.HistoricalFailedLogons == 0)
				{
					session.HistoricalFailedLogons = agg.FailedLogons;
				}
				if (session.HistoricalSuccessfulLogons == 0)
				{
					session.HistoricalSuccessfulLogons = agg.SuccessfulLogons;
				}
				if (string.IsNullOrEmpty(session.HistoricalUserNamesAttempted))
				{
					session.HistoricalUserNamesAttempted = agg.UserNamesAttempted;
				}
				historicalApplied++;
			}
		}

		return new LocalSessionEnrichmentResult(candidate, ipAssigned, historicalApplied);
	}

	/// <summary>True when <paramref name="session"/> represents a real RDP client row that the
	/// historical enrichment should ever touch. Listener / console / services rows are
	/// deliberately excluded — they are local-only and have no connection facts.</summary>
	public static bool IsRdpClientRow(RdpSessionDto session)
	{
		ArgumentNullException.ThrowIfNull(session);

		// A listener row (SessionId 65536 / 0xFFFFFFFE in older qwinsta output) has no user.
		// SessionName starting with "rdp-tcp" indicates a real RDP client station; everything
		// else (console, services, etc.) is a local-only artefact we must not enrich.
		string? name = session.SessionName?.Trim();
		if (string.IsNullOrEmpty(name))
		{
			return false;
		}

		foreach (string prefix in RdpSessionNamePrefixes)
		{
			if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>Strongest-evidence-first IP resolution. Always returns <c>null</c> rather than
	/// guessing when no unambiguous fact exists.</summary>
	internal static string? ResolveIp(
		RdpSessionDto session,
		IReadOnlyList<SessionIpCorrelation> correlations,
		IReadOnlyList<RdpConnectionFact> facts)
	{
		string? user = string.IsNullOrWhiteSpace(session.UserName) ? null : session.UserName.Trim();

		// 1) SessionIpCorrelation by (WtsSessionId, UserName).
		foreach (SessionIpCorrelation c in correlations)
		{
			if (c.WtsSessionId == session.SessionId
				&& IsValidIp(c.Ip)
				&& UserMatches(c.UserName, user))
			{
				return c.Ip;
			}
		}

		// 2) RdpConnectionFact by (WtsSessionId, UserName).
		foreach (RdpConnectionFact f in facts)
		{
			if (f.WtsSessionId == session.SessionId
				&& IsValidIp(f.Ip)
				&& UserMatches(f.UserName, user))
			{
				return f.Ip;
			}
		}

		// 3) Unambiguous recent RdpConnectionFact by UserName alone — only when one IP exists.
		if (!string.IsNullOrEmpty(user))
		{
			HashSet<string> uniqueIps = new(StringComparer.OrdinalIgnoreCase);
			DateTime mostRecent = DateTime.MinValue;
			string? candidate = null;
			foreach (RdpConnectionFact f in facts)
			{
				if (!IsValidIp(f.Ip) || !UserMatches(f.UserName, user))
				{
					continue;
				}

				uniqueIps.Add(f.Ip);
				if (f.LastSeenUtc > mostRecent)
				{
					mostRecent = f.LastSeenUtc;
					candidate = f.Ip;
				}
			}

			if (uniqueIps.Count == 1 && candidate is not null)
			{
				return candidate;
			}
		}

		return null;
	}

	private static bool UserMatches(string? factUser, string? sessionUser)
	{
		if (string.IsNullOrEmpty(factUser) || string.IsNullOrEmpty(sessionUser))
		{
			return false;
		}

		return string.Equals(factUser.Trim(), sessionUser, StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsValidIp(string? candidate) =>
		!string.IsNullOrWhiteSpace(candidate) && System.Net.IPAddress.TryParse(candidate, out _);

	internal readonly record struct FactAggregate(
		DateTime FirstSeenUtc,
		DateTime LastSeenUtc,
		long FailedLogons,
		long SuccessfulLogons,
		string? UserNamesAttempted);

	private static Dictionary<string, FactAggregate> AggregateByUser(IReadOnlyList<RdpConnectionFact> facts)
	{
		Dictionary<string, FactAggregate> result = new(StringComparer.OrdinalIgnoreCase);
		Dictionary<string, string?> attemptedByUser = new(StringComparer.OrdinalIgnoreCase);

		foreach (RdpConnectionFact f in facts)
		{
			if (string.IsNullOrWhiteSpace(f.UserName))
			{
				continue;
			}

			string user = f.UserName.Trim();
			if (result.TryGetValue(user, out FactAggregate agg))
			{
				result[user] = new FactAggregate(
					FirstSeenUtc: f.FirstSeenUtc < agg.FirstSeenUtc ? f.FirstSeenUtc : agg.FirstSeenUtc,
					LastSeenUtc: f.LastSeenUtc > agg.LastSeenUtc ? f.LastSeenUtc : agg.LastSeenUtc,
					FailedLogons: agg.FailedLogons + f.FailedLogons,
					SuccessfulLogons: agg.SuccessfulLogons + f.SuccessfulLogons,
					UserNamesAttempted: agg.UserNamesAttempted);
			}
			else
			{
				result[user] = new FactAggregate(
					FirstSeenUtc: f.FirstSeenUtc,
					LastSeenUtc: f.LastSeenUtc,
					FailedLogons: f.FailedLogons,
					SuccessfulLogons: f.SuccessfulLogons,
					UserNamesAttempted: f.UserNamesAttempted);
			}

			// Prefer the most-recent fact's UserNamesAttempted summary.
			if (!attemptedByUser.TryGetValue(user, out string? existing) || string.IsNullOrEmpty(existing))
			{
				attemptedByUser[user] = f.UserNamesAttempted;
			}
		}

		foreach (KeyValuePair<string, string?> kvp in attemptedByUser)
		{
			if (!string.IsNullOrEmpty(kvp.Value) && result.TryGetValue(kvp.Key, out FactAggregate agg))
			{
				result[kvp.Key] = agg with { UserNamesAttempted = kvp.Value };
			}
		}

		return result;
	}
}
