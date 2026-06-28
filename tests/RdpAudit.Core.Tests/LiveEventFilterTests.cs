// File:    tests/RdpAudit.Core.Tests/LiveEventFilterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 — covers the LiveEvents grid filter predicate. Each field is exercised in
//          isolation, then combinations check AND semantics. Time-range bounds are validated at
//          and around their boundaries.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage 4 — predicate behaviour of <see cref="LiveEventFilter"/>.</summary>
public class LiveEventFilterTests
{
	private static LiveEventRowView Row(
		string? ip = "203.0.113.5",
		string? user = "alice",
		int eventId = 4625,
		string? channel = "Security",
		DateTime? time = null,
		string? domain = "EXAMPLE",
		string? process = "lsass.exe",
		string? authPackage = "NTLM",
		int? logonType = 3)
		=> new()
		{
			Id = 1,
			EventId = eventId,
			Channel = channel,
			TimeUtc = time ?? new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc),
			SourceIp = ip,
			UserName = user,
			Domain = domain,
			LogonType = logonType,
			AuthPackage = authPackage,
			ProcessName = process,
		};

	[Fact]
	public void EmptyFilter_MatchesEveryRow()
	{
		LiveEventFilter filter = new();
		Assert.True(filter.IsEmpty);
		Assert.True(filter.Matches(Row()));
		Assert.True(filter.Matches(Row(ip: null, user: null, channel: null)));
	}

	[Theory]
	[InlineData("203.0.113.5", true)]
	[InlineData("203.0.113", true)]
	[InlineData("113", true)]
	[InlineData("10.0.0.1", false)]
	public void IpFilter_IsCaseInsensitiveContains(string needle, bool expected)
	{
		LiveEventFilter filter = new() { Ip = needle };
		Assert.Equal(expected, filter.Matches(Row(ip: "203.0.113.5")));
	}

	[Theory]
	[InlineData("alice", true)]
	[InlineData("ALICE", true)]
	[InlineData("bob", false)]
	public void UserFilter_IsCaseInsensitiveContains(string needle, bool expected)
	{
		LiveEventFilter filter = new() { User = needle };
		Assert.Equal(expected, filter.Matches(Row(user: "alice")));
	}

	[Fact]
	public void EventIdFilter_IsExactMatch()
	{
		LiveEventFilter filter = new() { EventId = 4625 };
		Assert.True(filter.Matches(Row(eventId: 4625)));
		Assert.False(filter.Matches(Row(eventId: 4624)));
	}

	[Fact]
	public void ChannelFilter_IsCaseInsensitiveContains()
	{
		LiveEventFilter filter = new() { Channel = "security" };
		Assert.True(filter.Matches(Row(channel: "Security")));
		Assert.False(filter.Matches(Row(channel: "System")));
	}

	[Theory]
	[InlineData("alice", true)]   // user
	[InlineData("203.0", true)]   // ip
	[InlineData("EXAMPLE", true)] // domain
	[InlineData("lsass", true)]   // process
	[InlineData("ntlm", true)]    // auth package (case insensitive)
	[InlineData("4625", true)]    // event id rendered as string
	[InlineData("xyzzy", false)]
	public void TextFilter_ScansAcrossFields(string needle, bool expected)
	{
		LiveEventFilter filter = new() { Text = needle };
		Assert.Equal(expected, filter.Matches(Row()));
	}

	[Fact]
	public void TextFilter_OnRowWithNullFields_StillEvaluatesSafely()
	{
		LiveEventFilter filter = new() { Text = "alice" };
		Assert.False(filter.Matches(Row(ip: null, user: null, channel: null, domain: null, process: null, authPackage: null)));
	}

	[Fact]
	public void TimeRange_SinceBoundaryIsInclusive()
	{
		DateTime t = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		LiveEventFilter filter = new() { SinceUtc = t };
		Assert.True(filter.Matches(Row(time: t)));
		Assert.True(filter.Matches(Row(time: t.AddSeconds(1))));
		Assert.False(filter.Matches(Row(time: t.AddSeconds(-1))));
	}

	[Fact]
	public void TimeRange_UntilBoundaryIsInclusive()
	{
		DateTime t = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		LiveEventFilter filter = new() { UntilUtc = t };
		Assert.True(filter.Matches(Row(time: t)));
		Assert.False(filter.Matches(Row(time: t.AddSeconds(1))));
		Assert.True(filter.Matches(Row(time: t.AddSeconds(-1))));
	}

	[Fact]
	public void Combined_FieldsUseAndSemantics()
	{
		LiveEventFilter filter = new()
		{
			Ip = "203.0.113",
			User = "alice",
			EventId = 4625,
			Channel = "Security",
		};
		Assert.True(filter.Matches(Row()));
		Assert.False(filter.Matches(Row(ip: "10.0.0.1")));
		Assert.False(filter.Matches(Row(user: "bob")));
		Assert.False(filter.Matches(Row(eventId: 4624)));
		Assert.False(filter.Matches(Row(channel: "System")));
	}

	[Fact]
	public void Matches_ThrowsOnNullRow()
	{
		LiveEventFilter filter = new() { Ip = "1" };
		Assert.Throws<ArgumentNullException>(() => filter.Matches(null!));
	}
}
