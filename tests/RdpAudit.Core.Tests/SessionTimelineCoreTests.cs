// File:    tests/RdpAudit.Core.Tests/SessionTimelineCoreTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit coverage for the Backlog #6 session-map core building blocks: the event-id
//          classifier (4688/4689 -> Process, 4656/4657/4658/4663/5140/5145 -> File, fallback
//          Other) and the pure SessionTimelineBuilder (lifecycle node emission, correlation
//          priority LogonId > SessionId > UserWindow, window gating, Other-events filtering,
//          truncation metadata and stable chronological ordering).
// Depends: SessionTimelineModels, SessionTimelineEventClassifier, SessionTimelineBuilder,
//          RdpConnectionFact, xunit
// Extends: Add a test here whenever the classifier table or the correlation rules change.

using RdpAudit.Core.Models;
using RdpAudit.Core.Sessions;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class SessionTimelineCoreTests
{
	private static readonly DateTime T0 = new(2026, 1, 10, 9, 0, 0, DateTimeKind.Utc);

	private static RdpConnectionFact MakeFact() => new()
	{
		Id = 1,
		Ip = "203.0.113.9",
		UserName = "alice",
		Domain = "ACME",
		LogonId = "0x1A2B",
		WtsSessionId = 3,
		FirstSeenUtc = T0.AddMinutes(0),
		LastSeenUtc = T0.AddMinutes(30),
		AuthenticatedUtc = T0.AddMinutes(2),
		ConnectedUtc = T0.AddMinutes(5),
		DisconnectedUtc = T0.AddMinutes(25),
		LoggedOffUtc = T0.AddMinutes(30),
		IsActive = false,
	};

	private static SessionTimelineRawEventSlice MakeSlice(
		int eventId = 4688,
		int minutes = 10,
		string? logonId = "0x1A2B",
		int? sessionId = null,
		string? user = "alice",
		string? domain = "ACME") => new()
	{
		EventId = eventId,
		Channel = "Security",
		TimeUtc = T0.AddMinutes(minutes),
		LogonId = logonId,
		SessionId = sessionId,
		UserName = user,
		Domain = domain,
		ProcessName = eventId is 4688 or 4689 ? "cmd.exe" : null,
		CommandLine = eventId == 4688 ? "cmd.exe /c whoami" : null,
		ObjectName = "C:\\temp\\x.txt",
		AccessMask = "0x100080",
		Status = "0x0",
		Details = "<Event/>",
	};

	// ── Classifier ───────────────────────────────────────────────────────────────

	[Theory]
	[InlineData(4688)]
	[InlineData(4689)]
	public void Classify_ProcessEventIds_ReturnProcess(int eventId)
		=> Assert.Equal(SessionTimelineEventKind.Process, SessionTimelineEventClassifier.Classify(eventId));

	[Theory]
	[InlineData(4656)]
	[InlineData(4657)]
	[InlineData(4658)]
	[InlineData(4663)]
	[InlineData(5140)]
	[InlineData(5145)]
	public void Classify_FileEventIds_ReturnFile(int eventId)
		=> Assert.Equal(SessionTimelineEventKind.File, SessionTimelineEventClassifier.Classify(eventId));

	[Theory]
	[InlineData(4624)]
	[InlineData(4634)]
	[InlineData(1102)]
	[InlineData(0)]
	public void Classify_UnknownEventIds_ReturnOther(int eventId)
		=> Assert.Equal(SessionTimelineEventKind.Other, SessionTimelineEventClassifier.Classify(eventId));

	[Fact]
	public void IsProcessOrFile_FlagMatchesKind()
	{
		Assert.True(SessionTimelineEventClassifier.IsProcessOrFile(4688));
		Assert.True(SessionTimelineEventClassifier.IsProcessOrFile(5145));
		Assert.False(SessionTimelineEventClassifier.IsProcessOrFile(4624));
	}

	// ── Builder: lifecycle ────────────────────────────────────────────────────────

	[Fact]
	public void Build_FullLifecycle_EmitsAllPhasesInOrder()
	{
		RdpConnectionFact fact = MakeFact();

		SessionTimeline timeline = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 0, 500, false, T0);

		Assert.Equal(new[]
		{
			SessionTimelineEventKind.LogonStart,
			SessionTimelineEventKind.Connected,
			SessionTimelineEventKind.Disconnected,
			SessionTimelineEventKind.Logoff,
		}, timeline.Events.Select(e => e.Kind).ToArray());
		Assert.All(timeline.Events, e => Assert.Equal(SessionTimelineCorrelationMethod.Lifecycle, e.CorrelationMethod));
		Assert.All(timeline.Events, e => Assert.Equal(0, e.EventId));
	}

	[Fact]
	public void Build_NullLifecyclePhases_AreSkipped()
	{
		RdpConnectionFact fact = MakeFact();
		fact.ReconnectedUtc = null;
		fact.DisconnectedUtc = null;

		SessionTimeline timeline = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 0, 500, false, T0);

		Assert.DoesNotContain(timeline.Events, e => e.Kind is SessionTimelineEventKind.Reconnected or SessionTimelineEventKind.Disconnected);
	}

	[Fact]
	public void Build_SessionMetadata_ComputedFromFact()
	{
		RdpConnectionFact fact = MakeFact();

		SessionTimeline timeline = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 0, 500, false, T0);

		Assert.Equal(fact.AuthenticatedUtc!.Value, timeline.StartUtc);
		Assert.Equal(fact.LoggedOffUtc, timeline.EndUtc);
		Assert.False(timeline.IsActive);
		Assert.Equal(28 * 60, timeline.DurationSeconds); // 30m - 2m
	}

	[Fact]
	public void Build_ActiveFactWithoutLogoff_UsesNowForDuration()
	{
		RdpConnectionFact fact = MakeFact();
		fact.LoggedOffUtc = null;
		fact.IsActive = true;
		DateTime now = T0.AddMinutes(45);

		SessionTimeline timeline = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 0, 500, false, now);

		Assert.Null(timeline.EndUtc);
		Assert.True(timeline.IsActive);
		Assert.Equal(43 * 60, timeline.DurationSeconds); // now - AuthenticatedUtc
	}

	// ── Builder: correlation ──────────────────────────────────────────────────────

	[Fact]
	public void Build_LogonIdMatch_CorrelatesAsLogonId()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(logonId: "0x1a2b", sessionId: 99, user: "other", domain: "OTHER");

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		SessionTimelineEvent node = Assert.Single(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
		Assert.Equal(SessionTimelineCorrelationMethod.LogonId, node.CorrelationMethod);
	}

	[Fact]
	public void Build_SessionIdMatch_CorrelatesAsSessionId()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(logonId: null, sessionId: 3, user: "other", domain: "OTHER");

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		SessionTimelineEvent node = Assert.Single(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
		Assert.Equal(SessionTimelineCorrelationMethod.SessionId, node.CorrelationMethod);
	}

	[Fact]
	public void Build_UserDomainMatch_CorrelatesAsUserWindow()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(logonId: null, sessionId: null);

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		SessionTimelineEvent node = Assert.Single(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
		Assert.Equal(SessionTimelineCorrelationMethod.UserWindow, node.CorrelationMethod);
	}

	[Fact]
	public void Build_NoCorrelationKey_DropsRow()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(logonId: null, sessionId: null, user: "bob");

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		Assert.DoesNotContain(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
	}

	[Fact]
	public void Build_OutOfWindowEvidence_Dropped()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(minutes: 60); // after LastSeenUtc

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		Assert.DoesNotContain(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
	}

	// ── Builder: content filtering / truncation ───────────────────────────────────

	[Fact]
	public void Build_OtherEvents_HiddenUnlessRequested()
	{
		RdpConnectionFact fact = MakeFact();
		SessionTimelineRawEventSlice other = MakeSlice(eventId: 4624, minutes: 12);

		SessionTimeline hidden = SessionTimelineBuilder.Build(fact, new[] { other }, 1, 500, includeOtherEvents: false, T0);
		SessionTimeline shown = SessionTimelineBuilder.Build(fact, new[] { other }, 1, 500, includeOtherEvents: true, T0);

		Assert.DoesNotContain(hidden.Events, e => e.Kind == SessionTimelineEventKind.Other);
		Assert.Contains(shown.Events, e => e.Kind == SessionTimelineEventKind.Other);
	}

	[Fact]
	public void Build_ProcessFields_AreProjectedToNode()
	{
		SessionTimelineRawEventSlice slice = MakeSlice(eventId: 4688);

		SessionTimeline timeline = BuildOne(MakeFact(), slice);

		SessionTimelineEvent node = Assert.Single(timeline.Events, e => e.Kind == SessionTimelineEventKind.Process);
		Assert.Equal(4688, node.EventId);
		Assert.Equal("Security", node.Channel);
		Assert.Equal("cmd.exe", node.ProcessName);
		Assert.Equal("cmd.exe /c whoami", node.CommandLine);
		Assert.Equal("C:\\temp\\x.txt", node.ObjectName);
		Assert.Equal("0x100080", node.AccessMask);
		Assert.Equal("0x0", node.Status);
		Assert.Equal("<Event/>", node.Details);
	}

	[Fact]
	public void Build_TruncationMetadata_ReflectsCapVsTotal()
	{
		RdpConnectionFact fact = MakeFact();

		SessionTimeline truncated = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 900, 500, false, T0);
		SessionTimeline exact = SessionTimelineBuilder.Build(fact, Array.Empty<SessionTimelineRawEventSlice>(), 500, 500, false, T0);

		Assert.True(truncated.Truncated);
		Assert.Equal(900, truncated.TotalMatching);
		Assert.False(exact.Truncated);
	}

	[Fact]
	public void Build_Events_ChronologicallyStable()
	{
		RdpConnectionFact fact = MakeFact();
		SessionTimelineRawEventSlice[] slices =
		[
			MakeSlice(eventId: 4688, minutes: 10),
			MakeSlice(eventId: 5145, minutes: 20),
			MakeSlice(eventId: 4689, minutes: 15),
		];

		SessionTimeline timeline = SessionTimelineBuilder.Build(fact, slices, 3, 500, false, T0);

		DateTime[] times = timeline.Events.Select(e => e.TimeUtc).ToArray();
		Assert.Equal(times.OrderBy(t => t), times);
		Assert.Equal(3, timeline.Events.Count(e => e.CorrelationMethod != SessionTimelineCorrelationMethod.Lifecycle));
	}

	private static SessionTimeline BuildOne(RdpConnectionFact fact, SessionTimelineRawEventSlice slice)
		=> SessionTimelineBuilder.Build(fact, new[] { slice }, 1, 500, false, T0);
}
