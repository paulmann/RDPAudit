// File:    src/RdpAudit.Core/Sessions/SessionTimelineEventClassifier.cs
// Module:  RdpAudit.Core.Sessions
// Purpose: Pure constant mapping from Windows event ids to timeline kinds for the Session Map
//          feature (Backlog #6). 4688/4689 are process activity, 4656/4657/4658/4663/5140/5145
//          are file/object activity, everything else falls through to Other. The mapping is a
//          single tested table so the builder and the Gantt legend can never disagree.
// Extends: System.Object
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

using System.Collections.Frozen;

namespace RdpAudit.Core.Sessions;

/// <summary>Event-id to timeline-kind classification for RawEvent activity nodes.</summary>
public static class SessionTimelineEventClassifier
{
	/// <summary>Security event ids that represent process activity (4688 created, 4689 exited).</summary>
	public static readonly FrozenSet<int> ProcessEventIds =
		new[] { 4688, 4689 }.ToFrozenSet();

	/// <summary>Security event ids that represent file/object access activity: 4656 handle
	/// requested, 4657 registry value modified, 4658 handle closed, 4663 object accessed,
	/// 5140 share accessed, 5145 share object checked.</summary>
	public static readonly FrozenSet<int> FileEventIds =
		new[] { 4656, 4657, 4658, 4663, 5140, 5145 }.ToFrozenSet();

	/// <summary>
	/// Classifies one event id into a timeline kind. Unknown ids resolve to
	/// <see cref="SessionTimelineEventKind.Other"/> - the classifier never throws.
	/// </summary>
	public static SessionTimelineEventKind Classify(int eventId)
	{
		if (ProcessEventIds.Contains(eventId))
		{
			return SessionTimelineEventKind.Process;
		}

		if (FileEventIds.Contains(eventId))
		{
			return SessionTimelineEventKind.File;
		}

		return SessionTimelineEventKind.Other;
	}

	/// <summary>True when the event id maps to Process or File (activity worth showing by default).</summary>
	public static bool IsProcessOrFile(int eventId)
	{
		SessionTimelineEventKind kind = Classify(eventId);
		return kind is SessionTimelineEventKind.Process or SessionTimelineEventKind.File;
	}
}
