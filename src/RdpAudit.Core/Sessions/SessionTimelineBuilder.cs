// File:    src/RdpAudit.Core/Sessions/SessionTimelineBuilder.cs
// Module:  RdpAudit.Core.Sessions
// Purpose: Pure assembly function for the per-session timeline (Backlog #6). Takes one
//          RdpConnectionFact (the lifecycle source of truth) plus the bounded, pre-correlated
//          RawEvent slices supplied by the service query layer and produces the ordered
//          SessionTimeline: lifecycle nodes, classified activity nodes with explicit
//          correlation-method labels, session-window metadata and truncation counters.
//          No EF, no I/O - fully deterministic for a fixed input set.
// Extends: System.Object
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

using System;
using System.Linq;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Sessions;

/// <summary>
/// Pure builder for <see cref="SessionTimeline"/>. All correlation decisions are explicit:
/// activity rows correlate by LogonId (strongest), then WtsSessionId, then UserName+Domain
/// inside the fact's observation window (weakest, labeled UserWindow). Rows that cannot be
/// correlated are dropped silently so out-of-window noise never pollutes the map.
/// </summary>
public static class SessionTimelineBuilder
{
	/// <summary>Default activity cap applied by the service when the request carries no limit.</summary>
	public const int DefaultActivityCap = 500;

	/// <summary>Minimum activity cap the service accepts.</summary>
	public const int MinActivityCap = 50;

	/// <summary>Hard ceiling for the activity cap, enforced server-side.</summary>
	public const int MaxActivityCap = 2000;

	/// <summary>
	/// Builds the timeline. <paramref name="activitySlices"/> are the service's bounded,
	/// already-window-filtered RawEvent projections (ORDER BY TimeUtc, Take(cap)); the builder
	/// re-derives each node's correlation method, classifies the kind and sorts the final list
	/// chronologically. <paramref name="totalMatching"/> is the service-side count of rows that
	/// matched the correlation filter BEFORE the cap; <paramref name="appliedCap"/> is the cap
	/// the service actually applied, used to set <see cref="SessionTimeline.Truncated"/>.
	/// </summary>
	public static SessionTimeline Build(
		RdpConnectionFact fact,
		IReadOnlyList<SessionTimelineRawEventSlice> activitySlices,
		int totalMatching,
		int appliedCap,
		bool includeOtherEvents,
		DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(fact);
		ArgumentNullException.ThrowIfNull(activitySlices);

		DateTime start = fact.AuthenticatedUtc ?? fact.ConnectedUtc ?? fact.FirstSeenUtc;
		DateTime? end = fact.LoggedOffUtc;
		DateTime windowEnd = fact.LoggedOffUtc.HasValue && fact.LoggedOffUtc.Value > fact.LastSeenUtc
			? fact.LoggedOffUtc.Value
			: fact.LastSeenUtc;

		int total = Math.Max(0, totalMatching);
		int cap = Math.Max(1, appliedCap);

		SessionTimeline timeline = new()
		{
			StartUtc = start,
			EndUtc = end,
			IsActive = fact.IsActive,
			DurationSeconds = end.HasValue
				? (long)Math.Max(0.0, (end.Value - start).TotalSeconds)
				: (long)Math.Max(0.0, (nowUtc - start).TotalSeconds),
			TotalMatching = total,
			Truncated = total > cap,
		};

		AddLifecycle(timeline, SessionTimelineEventKind.LogonStart, fact.AuthenticatedUtc);
		AddLifecycle(timeline, SessionTimelineEventKind.Connected, fact.ConnectedUtc);
		AddLifecycle(timeline, SessionTimelineEventKind.Reconnected, fact.ReconnectedUtc);
		AddLifecycle(timeline, SessionTimelineEventKind.Disconnected, fact.DisconnectedUtc);
		AddLifecycle(timeline, SessionTimelineEventKind.Logoff, fact.LoggedOffUtc);

		foreach (SessionTimelineRawEventSlice slice in activitySlices)
		{
			if (!TryCorrelate(fact, slice, windowEnd, out SessionTimelineCorrelationMethod method))
			{
				continue;
			}

			SessionTimelineEventKind kind = SessionTimelineEventClassifier.Classify(slice.EventId);
			if (kind == SessionTimelineEventKind.Other && !includeOtherEvents)
			{
				continue;
			}

			timeline.Events.Add(new SessionTimelineEvent
			{
				TimeUtc = slice.TimeUtc,
				Kind = kind,
				EventId = slice.EventId,
				Channel = slice.Channel,
				CorrelationMethod = method,
				ProcessName = slice.ProcessName,
				CommandLine = slice.CommandLine,
				ObjectName = slice.ObjectName,
				AccessMask = slice.AccessMask,
				Status = slice.Status,
				Details = slice.Details,
			});
		}

		// LINQ OrderBy is stable, so same-timestamp nodes keep insertion order (lifecycle
		// phases first, then activity in service order).
		timeline.Events = timeline.Events.OrderBy(e => e.TimeUtc).ToList();
		return timeline;
	}

	private static void AddLifecycle(SessionTimeline timeline, SessionTimelineEventKind kind, DateTime? utc)
	{
		if (!utc.HasValue)
		{
			return;
		}

		timeline.Events.Add(new SessionTimelineEvent
		{
			TimeUtc = utc.Value,
			Kind = kind,
			EventId = 0,
			Channel = string.Empty,
			CorrelationMethod = SessionTimelineCorrelationMethod.Lifecycle,
		});
	}

	private static bool TryCorrelate(
		RdpConnectionFact fact,
		SessionTimelineRawEventSlice slice,
		DateTime windowEnd,
		out SessionTimelineCorrelationMethod method)
	{
		method = SessionTimelineCorrelationMethod.UserWindow;

		// Global window gate: activity evidence must sit inside the fact's observation window
		// [FirstSeenUtc, max(LastSeenUtc, LoggedOffUtc)]. This also drops default(DateTime)
		// rows and out-of-band noise that merely shares a correlation key.
		if (slice.TimeUtc < fact.FirstSeenUtc || slice.TimeUtc > windowEnd)
		{
			return false;
		}

		// Priority 1: exact LogonId match (hex/case tolerant) - the strongest forensic key.
		if (!string.IsNullOrEmpty(fact.LogonId)
			&& !string.IsNullOrEmpty(slice.LogonId)
			&& string.Equals(fact.LogonId, slice.LogonId, StringComparison.OrdinalIgnoreCase))
		{
			method = SessionTimelineCorrelationMethod.LogonId;
			return true;
		}

		// Priority 2: WtsSessionId match when both sides carry one.
		if (fact.WtsSessionId.HasValue
			&& slice.SessionId.HasValue
			&& fact.WtsSessionId.Value == slice.SessionId.Value)
		{
			method = SessionTimelineCorrelationMethod.SessionId;
			return true;
		}

		// Priority 3 fallback: UserName+Domain equality inside the window. Requires a real
		// fact user so a nameless fact never attracts arbitrary user-less noise.
		if (!string.IsNullOrWhiteSpace(fact.UserName)
			&& !string.IsNullOrWhiteSpace(fact.Domain)
			&& string.Equals(fact.UserName, slice.UserName, StringComparison.OrdinalIgnoreCase)
			&& string.Equals(fact.Domain, slice.Domain, StringComparison.OrdinalIgnoreCase))
		{
			method = SessionTimelineCorrelationMethod.UserWindow;
			return true;
		}

		return false;
	}
}
