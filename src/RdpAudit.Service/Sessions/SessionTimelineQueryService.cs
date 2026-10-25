// File:    src/RdpAudit.Service/Sessions/SessionTimelineQueryService.cs
// Module:  RdpAudit.Service.Sessions
// Purpose: Read-only SQLite queries for the Session Map timeline (Backlog #6). Loads one
//          RdpConnectionFact by id, then selects the bounded, chronologically ordered candidate
//          RawEvents inside the fact's observation window that correlate by LogonId (exact,
//          index-backed), WtsSessionId, or UserName+Domain. Process/file event ids are filtered
//          server-side unless IncludeOtherEvents is requested. Correlation is finalized by the
//          pure SessionTimelineBuilder; this service only narrows the candidate set.
// Extends: System.Object
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Sessions;

namespace RdpAudit.Service.Sessions;

/// <summary>Result of a timeline query: the fact (null when unknown), the bounded candidate
/// slices, the pre-cap matching count and the cap that was actually applied.</summary>
public sealed class SessionTimelineQueryResult
{
	public RdpConnectionFact? Fact { get; set; }
	public List<SessionTimelineRawEventSlice> Slices { get; set; } = new();
	public int TotalMatching { get; set; }
	public int AppliedCap { get; set; }
}

/// <summary>Read-only query service backing the GetSessionTimeline IPC command.</summary>
public sealed class SessionTimelineQueryService
{
	private readonly IDbContextFactory<AuditDbContext> _factory;

	public SessionTimelineQueryService(IDbContextFactory<AuditDbContext> factory)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
	}

	/// <summary>Resolves the activity cap: 0 or negative falls back to the default 500;
	/// smaller values clamp up to 50, larger values clamp down to 2000.</summary>
	public static int ResolveCap(int requested)
	{
		if (requested <= 0)
		{
			return SessionTimelineBuilder.DefaultActivityCap;
		}

		if (requested < SessionTimelineBuilder.MinActivityCap)
		{
			return SessionTimelineBuilder.MinActivityCap;
		}

		if (requested > SessionTimelineBuilder.MaxActivityCap)
		{
			return SessionTimelineBuilder.MaxActivityCap;
		}

		return requested;
	}

	/// <summary>Loads the fact plus its bounded candidate activity rows. When the fact id is
	/// unknown the result carries Fact=null and no slices; the caller maps that to a typed status.</summary>
	public async Task<SessionTimelineQueryResult> LoadAsync(
		long factId,
		int requestedCap,
		bool includeOtherEvents,
		bool debugMode,
		CancellationToken ct)
	{
		int cap = ResolveCap(requestedCap);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		RdpConnectionFact? fact = await db.RdpConnectionFacts
			.AsNoTracking()
			.FirstOrDefaultAsync(f => f.Id == factId, ct)
			.ConfigureAwait(false);

		if (fact is null)
		{
			return new SessionTimelineQueryResult { Fact = null, AppliedCap = cap };
		}

		DateTime windowEnd = fact.LoggedOffUtc.HasValue && fact.LoggedOffUtc.Value > fact.LastSeenUtc
			? fact.LoggedOffUtc.Value
			: fact.LastSeenUtc;

		IQueryable<RawEvent> candidates = BuildCandidateQuery(db, fact, windowEnd, includeOtherEvents);

		int totalMatching = await candidates.CountAsync(ct).ConfigureAwait(false);

		List<SessionTimelineRawEventSlice> slices = await candidates
			.OrderBy(r => r.TimeUtc)
			.ThenBy(r => r.Id)
			.Take(cap)
			.Select(r => new SessionTimelineRawEventSlice
			{
				EventId = r.EventId,
				Channel = r.Channel,
				TimeUtc = r.TimeUtc,
				LogonId = r.LogonId,
				SessionId = r.SessionId,
				UserName = r.UserName,
				Domain = r.Domain,
				ProcessName = r.ProcessName,
				CommandLine = r.CommandLine,
				ObjectName = r.ObjectName,
				AccessMask = r.AccessMask,
				Status = r.Status,
				Details = debugMode ? r.Details : null,
			})
			.ToListAsync(ct)
			.ConfigureAwait(false);

		return new SessionTimelineQueryResult
		{
			Fact = fact,
			Slices = slices,
			TotalMatching = totalMatching,
			AppliedCap = cap,
		};
	}

	private static IQueryable<RawEvent> BuildCandidateQuery(
		AuditDbContext db,
		RdpConnectionFact fact,
		DateTime windowEnd,
		bool includeOtherEvents)
	{
		DateTime first = fact.FirstSeenUtc;

		// Window gate first: candidates outside the fact's observation span are never relevant
		// even when they share a correlation key.
		IQueryable<RawEvent> q = db.RawEvents
			.AsNoTracking()
			.Where(r => r.TimeUtc >= first && r.TimeUtc <= windowEnd);

		bool hasLogon = !string.IsNullOrEmpty(fact.LogonId);
		bool hasSession = fact.WtsSessionId.HasValue;
		bool hasUser = !string.IsNullOrWhiteSpace(fact.UserName) && !string.IsNullOrWhiteSpace(fact.Domain);

		string logonId = fact.LogonId ?? string.Empty;
		int wtsSessionId = fact.WtsSessionId ?? 0;
		string userName = fact.UserName ?? string.Empty;
		string domain = fact.Domain ?? string.Empty;

		// Correlation pre-filter uses index-friendly exact equality. When the fact carries a
		// strong key (LogonId / WtsSessionId) the predicate targets the (LogonId, TimeUtc) /
		// (SessionId, TimeUtc) indexes; the weaker UserName+Domain fallback applies only when
		// the fact has neither. The pure builder re-derives the precise correlation method.
		if (hasLogon || hasSession)
		{
			q = q.Where(r =>
				(hasLogon && r.LogonId != null && r.LogonId == logonId)
				|| (hasSession && r.SessionId != null && r.SessionId == wtsSessionId));
		}
		else if (hasUser)
		{
			q = q.Where(r =>
				r.UserName != null && r.Domain != null
				&& r.UserName == userName && r.Domain == domain);
		}
		else
		{
			// No correlation key at all: no candidate can ever attach to this fact.
			return q.Where(r => false);
		}

		if (!includeOtherEvents)
		{
			// Only process/file activity counts toward the cap by default, so a flood of
			// correlated security noise cannot starve the timeline of real activity nodes.
			int[] activityIds = SessionTimelineEventClassifier.ProcessEventIds
				.Concat(SessionTimelineEventClassifier.FileEventIds)
				.ToArray();
			q = q.Where(r => activityIds.Contains(r.EventId));
		}

		return q;
	}
}
