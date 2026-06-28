// File:    src/RdpAudit.Core/Util/ActiveSessionCounter.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure counter that derives the "Active RDP sessions" KPI from the same
//          RdpSessionDto stream the Remote RDP Clients tab consumes. Centralizing the
//          rule prevents the Overview dashboard and the Sessions tab from disagreeing
//          (e.g. Overview showing 0 while the Sessions tab lists two active rows). A
//          session is counted when it is in the Active state AND attached to a real
//          user (Listener / Services / Console rows are excluded so the KPI reflects
//          actual logged-on remote clients).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure helpers that compute the Overview "Active sessions" KPI from a session list.</summary>
public static class ActiveSessionCounter
{
	/// <summary>Counts sessions that are <see cref="RdpSessionDto.IsActive"/> AND have a
	/// non-empty <see cref="RdpSessionDto.UserName"/>. Listener / Services / Console rows
	/// (no user attached) are excluded so the KPI matches what the Remote RDP Clients tab
	/// displays as active user sessions.</summary>
	public static int CountActiveUserSessions(IReadOnlyList<RdpSessionDto> sessions)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		int count = 0;
		foreach (RdpSessionDto session in sessions)
		{
			if (session.IsActive && !string.IsNullOrWhiteSpace(session.UserName))
			{
				count++;
			}
		}

		return count;
	}
}
