// File:    src/RdpAudit.Core/Util/CurrentRdpSessionMatcher.cs
// Module:  RdpAudit.Core.Util
// Purpose: v1.3.8 — decide which RDP session row is the operator-visible "Current" session, i.e.
//          the session that belongs to the user running the Configurator. The prior implementation
//          set RdpSessionDto.IsCurrent purely from ActiveRdpSessionClassifier, so EVERY active
//          rdp-tcp# session (any logged-in remote user, even other people's) was flagged Current.
//          On a host with several concurrent RDP users (e.g. md / pk / af) that mislabels every
//          active session. This matcher scopes Current to the operator by two correlated signals:
//              1. the running process SessionId (Process.GetCurrentProcess().SessionId), when known
//                 and plausible (1 < id < 65536); and
//              2. the normalized current Windows identity — both the domain-qualified form
//                 (e.g. "XEON\md") and the bare leaf username (e.g. "md" / $env:USERNAME).
//          A session must additionally be an active RDP session (rdp-tcp# + Active + non-empty
//          user) to qualify, so disconnected rows never become Current. The matcher is pure /
//          side-effect-free and is consumed by the Configurator (which alone runs inside the
//          operator's interactive session — the LocalSystem service cannot know which session the
//          operator is using).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>The operator's runtime identity context, captured in the interactive Configurator
/// process. <paramref name="ProcessSessionId"/> is the WTS session the Configurator runs in
/// (negative or zero when unknown). <paramref name="IdentityName"/> is the raw
/// <c>WindowsIdentity.GetCurrent().Name</c> (e.g. "XEON\md"); <paramref name="UserName"/> is the
/// raw <c>$env:USERNAME</c> / <c>Environment.UserName</c> (e.g. "md"). Both are normalized
/// internally so a domain-qualified identity matches the bare username qwinsta reports.</summary>
public sealed record OperatorSessionContext(int ProcessSessionId, string? IdentityName, string? UserName);

/// <summary>Which rule decided a session was (or was not) the operator's Current session. Surfaced
/// on the RDP Clients diagnostics line so an operator can see exactly why a row was flagged.</summary>
public enum CurrentMatchRule
{
	/// <summary>No session matched the operator context.</summary>
	None = 0,

	/// <summary>Matched because the session id equals the operator's process session id (strongest).</summary>
	SessionId = 1,

	/// <summary>Matched because the normalized username equals the operator's identity / username
	/// (used when the process session id is unknown or did not line up with a listed session).</summary>
	Identity = 2,
}

/// <summary>Per-session verdict produced by <see cref="CurrentRdpSessionMatcher"/>.</summary>
public sealed record CurrentSessionVerdict(int SessionId, bool IsCurrent, CurrentMatchRule Rule);

/// <summary>Aggregate result of matching an operator context against a session list. Carries the
/// per-session verdicts plus a human-readable description of the normalized operator context and
/// the rule that fired, for the diagnostics panel.</summary>
public sealed record CurrentRdpMatchResult(
	IReadOnlyList<CurrentSessionVerdict> Verdicts,
	int CurrentCount,
	CurrentMatchRule RuleUsed,
	string NormalizedIdentity,
	string NormalizedUserName,
	int OperatorSessionId)
{
	/// <summary>One-line operator-facing summary for the RDP Clients diagnostics label.</summary>
	public string Describe()
	{
		string session = OperatorSessionId > 0
			? OperatorSessionId.ToString(CultureInfo.InvariantCulture)
			: "(unknown)";
		string identity = string.IsNullOrEmpty(NormalizedIdentity) ? "(unknown)" : NormalizedIdentity;
		string user = string.IsNullOrEmpty(NormalizedUserName) ? "(unknown)" : NormalizedUserName;
		return string.Format(
			CultureInfo.InvariantCulture,
			"Current match: process SessionId={0}; identity={1}; username={2}; rule={3}; matched={4}.",
			session,
			identity,
			user,
			RuleUsed,
			CurrentCount);
	}
}

/// <summary>Pure matcher that scopes the operator-visible "Current" flag to the session owned by
/// the user running the Configurator.</summary>
public static class CurrentRdpSessionMatcher
{
	/// <summary>Lowest WTS session id treated as a real interactive RDP session. Shared with
	/// <see cref="ActiveRdpSessionClassifier.MinSessionId"/>.</summary>
	public const int MinSessionId = ActiveRdpSessionClassifier.MinSessionId;

	/// <summary>Exclusive upper bound on a real session id (the WTS_LISTEN sentinel). Shared with
	/// <see cref="ActiveRdpSessionClassifier.MaxSessionIdExclusive"/>.</summary>
	public const int MaxSessionIdExclusive = ActiveRdpSessionClassifier.MaxSessionIdExclusive;

	/// <summary>Match <paramref name="sessions"/> against <paramref name="context"/> and return the
	/// per-session Current verdicts. Only active RDP sessions (rdp-tcp# + Active + non-empty user)
	/// are eligible; among those the matcher prefers an exact process-SessionId match and falls back
	/// to a normalized-username match when the process session id is unknown or absent from the list.
	/// Disconnected and foreign-user sessions are never flagged Current.</summary>
	public static CurrentRdpMatchResult Match(
		IReadOnlyList<RdpSessionDto> sessions,
		OperatorSessionContext context)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		ArgumentNullException.ThrowIfNull(context);

		string normalizedIdentity = NormalizeIdentity(context.IdentityName);
		string identityLeaf = LeafUserName(context.IdentityName);
		string userLeaf = LeafUserName(context.UserName);
		// The operator's effective leaf username: prefer the explicit $env:USERNAME, fall back to
		// the leaf of the qualified Windows identity. Both "md" and "XEON\md" collapse to "md".
		string operatorLeaf = !string.IsNullOrEmpty(userLeaf) ? userLeaf : identityLeaf;

		int operatorSessionId = context.ProcessSessionId;
		bool sessionIdUsable = IsPlausibleSessionId(operatorSessionId);

		// First pass: identify eligible active-RDP rows.
		List<RdpSessionDto> eligible = new(sessions.Count);
		foreach (RdpSessionDto session in sessions)
		{
			if (IsEligible(session))
			{
				eligible.Add(session);
			}
		}

		// Decide which rule wins. SessionId is the strongest signal: if the operator's process
		// session id matches an eligible row, use SessionId matching exclusively (so we never also
		// flag a same-username row in a different session). Otherwise fall back to identity.
		bool sessionIdMatchesAnEligibleRow = sessionIdUsable
			&& eligible.Exists(s => s.SessionId == operatorSessionId);

		CurrentMatchRule ruleUsed = sessionIdMatchesAnEligibleRow
			? CurrentMatchRule.SessionId
			: (!string.IsNullOrEmpty(operatorLeaf) || !string.IsNullOrEmpty(normalizedIdentity)
				? CurrentMatchRule.Identity
				: CurrentMatchRule.None);

		List<CurrentSessionVerdict> verdicts = new(sessions.Count);
		int currentCount = 0;
		foreach (RdpSessionDto session in sessions)
		{
			bool eligibleRow = IsEligible(session);
			bool isCurrent = false;
			CurrentMatchRule rowRule = CurrentMatchRule.None;

			if (eligibleRow)
			{
				switch (ruleUsed)
				{
					case CurrentMatchRule.SessionId:
						if (session.SessionId == operatorSessionId)
						{
							isCurrent = true;
							rowRule = CurrentMatchRule.SessionId;
						}

						break;
					case CurrentMatchRule.Identity:
						if (UserMatches(session.UserName, operatorLeaf, normalizedIdentity))
						{
							isCurrent = true;
							rowRule = CurrentMatchRule.Identity;
						}

						break;
					case CurrentMatchRule.None:
					default:
						break;
				}
			}

			if (isCurrent)
			{
				currentCount++;
			}

			verdicts.Add(new CurrentSessionVerdict(session.SessionId, isCurrent, rowRule));
		}

		return new CurrentRdpMatchResult(
			verdicts,
			currentCount,
			ruleUsed,
			normalizedIdentity,
			operatorLeaf,
			operatorSessionId);
	}

	/// <summary>Apply <see cref="Match"/> and write the resulting Current verdicts back onto the
	/// supplied DTOs (<see cref="RdpSessionDto.IsCurrent"/>). <see cref="RdpSessionDto.IsActiveRdp"/>
	/// is left untouched — it remains the "is this an active RDP session at all" flag. Returns the
	/// match result so callers can surface the diagnostics line.</summary>
	public static CurrentRdpMatchResult ApplyTo(
		IReadOnlyList<RdpSessionDto> sessions,
		OperatorSessionContext context)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		CurrentRdpMatchResult result = Match(sessions, context);
		Dictionary<int, bool> bySession = new(result.Verdicts.Count);
		foreach (CurrentSessionVerdict verdict in result.Verdicts)
		{
			bySession[verdict.SessionId] = verdict.IsCurrent;
		}

		foreach (RdpSessionDto session in sessions)
		{
			session.IsCurrent = bySession.TryGetValue(session.SessionId, out bool current) && current;
		}

		return result;
	}

	private static bool IsEligible(RdpSessionDto session)
	{
		// Reuse the validated active-RDP gate so eligibility stays consistent with IsActiveRdp.
		ActiveRdpClassification classification = ActiveRdpSessionClassifier.Classify(
			sessionId: session.SessionId,
			sessionName: session.SessionName,
			userName: session.UserName,
			normalizedState: session.State);
		return classification.IsActiveRdp;
	}

	private static bool IsPlausibleSessionId(int sessionId)
		=> sessionId >= MinSessionId && sessionId < MaxSessionIdExclusive;

	private static bool UserMatches(string? sessionUser, string operatorLeaf, string normalizedIdentity)
	{
		string sessionLeaf = LeafUserName(sessionUser);
		if (sessionLeaf.Length == 0)
		{
			return false;
		}

		if (operatorLeaf.Length > 0
			&& string.Equals(sessionLeaf, operatorLeaf, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Also accept an exact match against the fully-qualified identity, in case a future session
		// source reports "DOMAIN\user" rather than the bare leaf.
		string sessionNormalized = NormalizeIdentity(sessionUser);
		return normalizedIdentity.Length > 0
			&& string.Equals(sessionNormalized, normalizedIdentity, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Normalize a raw identity to a stable comparable form: trims, drops a UPN suffix
	/// ("user@domain" → "user"), and lower-cases nothing (comparison is OrdinalIgnoreCase). A
	/// domain-qualified "DOMAIN\user" is preserved verbatim (trimmed) so it can be compared as the
	/// fully-qualified form; <see cref="LeafUserName"/> extracts the bare leaf separately.</summary>
	internal static string NormalizeIdentity(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}

		string trimmed = raw.Trim();
		int at = trimmed.IndexOf('@', StringComparison.Ordinal);
		if (at > 0)
		{
			trimmed = trimmed[..at];
		}

		return trimmed;
	}

	/// <summary>Extract the bare leaf username from a raw identity: "XEON\md" → "md",
	/// "md@xeon.local" → "md", "md" → "md".</summary>
	internal static string LeafUserName(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}

		string trimmed = raw.Trim();
		int slash = trimmed.LastIndexOf('\\');
		if (slash >= 0 && slash < trimmed.Length - 1)
		{
			trimmed = trimmed[(slash + 1)..];
		}

		int at = trimmed.IndexOf('@', StringComparison.Ordinal);
		if (at > 0)
		{
			trimmed = trimmed[..at];
		}

		return trimmed;
	}
}
