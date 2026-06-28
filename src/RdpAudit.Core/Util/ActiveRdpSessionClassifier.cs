// File:    src/RdpAudit.Core/Util/ActiveRdpSessionClassifier.cs
// Module:  RdpAudit.Core.Util
// Purpose: v1.2.2 — pure classifier deciding whether a parsed qwinsta / quser row should be
//          treated as the operator-visible "current / active RDP" session. The previous
//          implementation propagated the raw qwinsta ">" marker straight into the DTO's
//          IsCurrent field, which under LocalSystem (the Service runs as) points at
//          session 0 ("services") — so the Remote RDP Clients tab attributed Current? to a
//          system row while the real RDP session went unflagged. The validated semantics:
//              State == Active
//              AND SessionName starts with "rdp-tcp#" (OrdinalIgnoreCase)
//              AND UserName non-empty
//              AND 1 < SessionId < 65536
//          The classifier is intentionally side-effect-free; the Configurator-side and
//          Service-side enumeration paths both consume it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Outcome of a single classifier call. Carries the boolean verdict plus a stable
/// rejection-reason token used by the diagnostic support bundle so operators can see why a
/// row was excluded from the operator-visible current-RDP set.</summary>
public sealed record ActiveRdpClassification(bool IsActiveRdp, string? RejectionReason);

/// <summary>v1.2.2 pure classifier deciding whether a parsed qwinsta / merged row should be
/// surfaced as the operator-visible active RDP session.</summary>
public static class ActiveRdpSessionClassifier
{
	/// <summary>Minimum session id considered for the active-RDP set. Session 0 is
	/// "services" and session 1 is "console" — neither can be the live remote RDP session.</summary>
	public const int MinSessionId = 2;

	/// <summary>Strictly upper-bounds the session id at the WTS_LISTEN sentinel (65536).
	/// 65536 and 65537 in qwinsta output are listener rows, never real sessions.</summary>
	public const int MaxSessionIdExclusive = 65536;

	private const string ActiveStateToken = "Active";
	private const string RdpTcpStationPrefix = "rdp-tcp#";

	/// <summary>Classify a single parsed qwinsta row. Returns
	/// <c>(IsActiveRdp=true, RejectionReason=null)</c> when the row passes every gate;
	/// otherwise the first failing gate is captured in the rejection reason.</summary>
	public static ActiveRdpClassification Classify(QwinstaSessionRow row)
	{
		ArgumentNullException.ThrowIfNull(row);
		string state = QwinstaParser.NormalizeState(row.State);
		return Classify(
			sessionId: row.SessionId,
			sessionName: row.SessionName,
			userName: row.UserName,
			normalizedState: state);
	}

	/// <summary>Classify a session by its raw fields. Used by callers that have already
	/// normalized the state token (e.g. <see cref="QwinstaSessionMapper"/>).</summary>
	public static ActiveRdpClassification Classify(
		int sessionId,
		string? sessionName,
		string? userName,
		string? normalizedState)
	{
		if (sessionId < MinSessionId)
		{
			return new ActiveRdpClassification(false, "SessionId<2 (services/console)");
		}

		if (sessionId >= MaxSessionIdExclusive)
		{
			return new ActiveRdpClassification(false, "SessionId>=65536 (listener)");
		}

		if (!string.Equals(normalizedState, ActiveStateToken, StringComparison.OrdinalIgnoreCase))
		{
			return new ActiveRdpClassification(false, "State!=Active");
		}

		if (string.IsNullOrWhiteSpace(sessionName)
			|| !sessionName.StartsWith(RdpTcpStationPrefix, StringComparison.OrdinalIgnoreCase))
		{
			return new ActiveRdpClassification(false, "SessionName not rdp-tcp#");
		}

		if (string.IsNullOrWhiteSpace(userName))
		{
			return new ActiveRdpClassification(false, "UserName empty");
		}

		return new ActiveRdpClassification(true, null);
	}
}
