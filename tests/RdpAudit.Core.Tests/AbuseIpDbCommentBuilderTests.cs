// File:    tests/RdpAudit.Core.Tests/AbuseIpDbCommentBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for the Stage 8 AbuseIPDB report comment builder. Verifies sanitisation,
//          length capping, attribution footer, and that local credentials / control characters
//          never leak into the submitted comment.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.AbuseIpDb;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="AbuseIpDbCommentBuilder"/>.</summary>
public class AbuseIpDbCommentBuilderTests
{
	[Fact]
	public void Build_IncludesIpHostnameCountsAndAttribution()
	{
		AbuseIpDbEvidence evidence = new()
		{
			Ip = "203.0.113.7",
			Hostname = "scanner.example",
			FailedAttempts = 47,
			SuccessfulLogins = 0,
			FirstSeenUtc = new DateTime(2026, 5, 1, 12, 0, 0, DateTimeKind.Utc),
			LastSeenUtc = new DateTime(2026, 5, 1, 12, 30, 0, DateTimeKind.Utc),
			UsernamesAttempted = new[] { "admin", "root", "test" },
		};

		string comment = AbuseIpDbCommentBuilder.Build(evidence);

		Assert.Contains("IP Address: 203.0.113.7", comment, StringComparison.Ordinal);
		Assert.Contains("Hostname: scanner.example", comment, StringComparison.Ordinal);
		Assert.Contains("Connection Type: RDP Attack", comment, StringComparison.Ordinal);
		Assert.Contains("Failed Attempts: 47", comment, StringComparison.Ordinal);
		Assert.Contains("Successful Logins: 0", comment, StringComparison.Ordinal);
		Assert.Contains("Usernames Attempted: admin, root, test", comment, StringComparison.Ordinal);
		Assert.Contains("Duration: 30m", comment, StringComparison.Ordinal);
		Assert.Contains(AbuseIpDbCommentBuilder.AttributionFooter, comment, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_HostnameNotResolved_WhenEmpty()
	{
		AbuseIpDbEvidence evidence = new()
		{
			Ip = "198.51.100.1",
			Hostname = string.Empty,
			FailedAttempts = 1,
			SuccessfulLogins = 0,
			FirstSeenUtc = DateTime.UtcNow,
			LastSeenUtc = DateTime.UtcNow,
			UsernamesAttempted = Array.Empty<string>(),
		};

		string comment = AbuseIpDbCommentBuilder.Build(evidence);
		Assert.Contains("Hostname: Not resolved", comment, StringComparison.Ordinal);
		Assert.Contains("Usernames Attempted: n/a", comment, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_CapsLengthBelowLimit()
	{
		string[] usernames = new string[64];
		for (int i = 0; i < usernames.Length; i++)
		{
			usernames[i] = new string('A', 100) + i.ToString();
		}

		AbuseIpDbEvidence evidence = new()
		{
			Ip = "203.0.113.99",
			Hostname = new string('h', 1024),
			FailedAttempts = long.MaxValue,
			SuccessfulLogins = long.MaxValue,
			FirstSeenUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
			LastSeenUtc = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc),
			UsernamesAttempted = usernames,
		};

		string comment = AbuseIpDbCommentBuilder.Build(evidence);
		Assert.True(comment.Length <= AbuseIpDbCommentBuilder.MaxCommentLength,
			"comment exceeded MaxCommentLength: " + comment.Length);
	}

	[Theory]
	[InlineData("with\r\nnewline", "withnewline")]
	[InlineData("comma,inside", "commainside")]
	[InlineData("a;b;c", "abc")]
	[InlineData("ok-name", "ok-name")]
	[InlineData("", "")]
	[InlineData("    ", "")]
	public void SanitizeUsername_StripsControlAndDelimiters(string input, string expected)
	{
		string actual = AbuseIpDbCommentBuilder.SanitizeUsername(input);
		Assert.Equal(expected, actual);
	}

	[Fact]
	public void SanitizeUsername_TruncatesLongValues()
	{
		string longName = new('x', 200);
		string sanitised = AbuseIpDbCommentBuilder.SanitizeUsername(longName);
		Assert.True(sanitised.Length <= AbuseIpDbCommentBuilder.MaxUsernameLength);
		Assert.EndsWith("…", sanitised, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildUsernameList_DedupesAndCaps()
	{
		string[] usernames = { "alice", "alice", "ALICE", "bob", "carol", "dave", "eve", "frank" };
		string list = AbuseIpDbCommentBuilder.BuildUsernameList(usernames);

		string[] parts = list.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
		Assert.True(parts.Length <= AbuseIpDbCommentBuilder.MaxUsernamesIncluded);
		Assert.Contains("alice", parts);
		Assert.Contains("bob", parts);
	}

	[Fact]
	public void SanitizeIp_RejectsControlChars()
	{
		Assert.Equal("invalid-ip", AbuseIpDbCommentBuilder.SanitizeIp(""));
		Assert.Equal("invalid-ip", AbuseIpDbCommentBuilder.SanitizeIp("1.1.1.1 OR 1=1"));
		Assert.Equal("1.2.3.4", AbuseIpDbCommentBuilder.SanitizeIp("1.2.3.4"));
	}

	[Fact]
	public void Build_IncludesIntensityAndEvidenceEventIds()
	{
		AbuseIpDbEvidence evidence = new()
		{
			Ip = "203.0.113.7",
			Hostname = string.Empty,
			FailedAttempts = 120,
			SuccessfulLogins = 1,
			FirstSeenUtc = new DateTime(2026, 5, 1, 12, 0, 0, DateTimeKind.Utc),
			LastSeenUtc = new DateTime(2026, 5, 1, 14, 0, 0, DateTimeKind.Utc),
			UsernamesAttempted = new[] { "admin" },
			EvidenceEventIds = new[] { 4625, 4776, 4624, 4648 },
		};

		string comment = AbuseIpDbCommentBuilder.Build(evidence);

		Assert.Contains("Intensity:", comment, StringComparison.Ordinal);
		Assert.Contains("attempts/hour", comment, StringComparison.Ordinal);
		Assert.Contains("Evidence Event IDs: 4625,4776,4624,4648", comment, StringComparison.Ordinal);
		Assert.EndsWith(AbuseIpDbCommentBuilder.AttributionFooter, comment, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_OmitsEvidenceEventIds_WhenNonePresent()
	{
		AbuseIpDbEvidence evidence = new()
		{
			Ip = "203.0.113.7",
			FailedAttempts = 1,
			SuccessfulLogins = 0,
			FirstSeenUtc = DateTime.UtcNow,
			LastSeenUtc = DateTime.UtcNow,
			UsernamesAttempted = Array.Empty<string>(),
			EvidenceEventIds = Array.Empty<int>(),
		};

		string comment = AbuseIpDbCommentBuilder.Build(evidence);
		Assert.DoesNotContain("Evidence Event IDs:", comment, StringComparison.Ordinal);
	}

	[Fact]
	public void FormatEventIds_DedupesAndDropsNonPositive()
	{
		Assert.Equal("4625,4624", AbuseIpDbCommentBuilder.FormatEventIds(new[] { 4625, 4625, 0, -1, 4624 }));
		Assert.Equal(string.Empty, AbuseIpDbCommentBuilder.FormatEventIds(null));
		Assert.Equal(string.Empty, AbuseIpDbCommentBuilder.FormatEventIds(Array.Empty<int>()));
	}

	[Fact]
	public void FormatIntensity_SubHourWindow_ReportsBurst()
	{
		Assert.Equal("50 attempts (burst)", AbuseIpDbCommentBuilder.FormatIntensity(50, TimeSpan.Zero));
		Assert.Equal("0 attempts", AbuseIpDbCommentBuilder.FormatIntensity(0, TimeSpan.FromHours(2)));
	}

	[Fact]
	public void BuildUsernameList_CapIsTen()
	{
		Assert.Equal(10, AbuseIpDbCommentBuilder.MaxUsernamesIncluded);
		string[] usernames = Enumerable.Range(0, 20).Select(i => "user" + i).ToArray();
		string list = AbuseIpDbCommentBuilder.BuildUsernameList(usernames);
		string[] parts = list.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
		Assert.Equal(10, parts.Length);
	}
}
