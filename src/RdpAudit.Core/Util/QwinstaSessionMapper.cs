// File:    src/RdpAudit.Core/Util/QwinstaSessionMapper.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure mapping from <see cref="QwinstaSessionRow"/> rows produced by
//          <see cref="QwinstaParser"/> to <see cref="RdpSessionDto"/> instances used by the
//          ListRdpSessions IPC contract. Used by the service-side <c>RdpSessionManager</c>
//          and by the Configurator-side <c>LocalRdpSessionProvider</c> so both paths emit
//          structurally identical rows when the parser sees the same qwinsta output.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure mapper that converts parsed qwinsta rows into <see cref="RdpSessionDto"/>.</summary>
public static class QwinstaSessionMapper
{
	/// <summary>Map a single parsed row.</summary>
	public static RdpSessionDto Map(QwinstaSessionRow row)
	{
		ArgumentNullException.ThrowIfNull(row);
		string state = QwinstaParser.NormalizeState(row.State);
		// v1.2.2 — IsActiveRdp reflects the validated active-RDP semantics, not the raw qwinsta
		// ">" marker (which under LocalSystem can point at session 0 / services). The raw marker
		// is preserved on IsQueryCurrent for the diagnostic support bundle only.
		// v1.3.8 — the mapper no longer owns the operator-visible IsCurrent flag. "Current" means
		// "this session belongs to the user running the Configurator", which depends on the caller's
		// process SessionId / Windows identity and so cannot be decided from a qwinsta row alone.
		// CurrentRdpSessionMatcher (applied by the Configurator in the operator's interactive
		// session) sets IsCurrent; the mapper leaves it false. This stops every active rdp-tcp#
		// session of every logged-in user being mislabelled Current on a multi-session host.
		ActiveRdpClassification classification = ActiveRdpSessionClassifier.Classify(
			sessionId: row.SessionId,
			sessionName: row.SessionName,
			userName: row.UserName,
			normalizedState: state);
		return new RdpSessionDto
		{
			SessionId = row.SessionId,
			UserName = row.UserName,
			SessionName = row.SessionName,
			State = state,
			IsCurrent = false,
			IsQueryCurrent = row.IsCurrent,
			IsActiveRdp = classification.IsActiveRdp,
			IsActive = string.Equals(state, "Active", StringComparison.OrdinalIgnoreCase),
			IsDisconnected = string.Equals(state, "Disconnected", StringComparison.OrdinalIgnoreCase),
		};
	}

	/// <summary>Map every row in the supplied parsed sequence.</summary>
	public static IReadOnlyList<RdpSessionDto> MapAll(IReadOnlyList<QwinstaSessionRow> rows)
	{
		ArgumentNullException.ThrowIfNull(rows);
		List<RdpSessionDto> dtos = new(rows.Count);
		foreach (QwinstaSessionRow row in rows)
		{
			dtos.Add(Map(row));
		}

		return dtos;
	}
}
