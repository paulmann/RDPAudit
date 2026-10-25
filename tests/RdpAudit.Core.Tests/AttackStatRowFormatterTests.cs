// File:    tests/RdpAudit.Core.Tests/AttackStatRowFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 6B — locks the AttackStat clipboard formatters and the duration / top-logins
//          UI helpers consumed by the Configurator Attack Statistics tab. Multiline output is
//          assertable line-by-line; TSV output stays on a single record with a stable header.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage 6B — formatter for Copy Row Details + grid helpers.</summary>
public class AttackStatRowFormatterTests
{
	private static AttackStatEntryDto SampleEntry() => new()
	{
		Ip = "203.0.113.5",
		TotalAttempts = 42,
		Failed = 40,
		Successful = 2,
		FirstSeenUtc = new DateTime(2026, 5, 19, 7, 0, 0, DateTimeKind.Utc),
		LastSeenUtc = new DateTime(2026, 5, 19, 8, 15, 30, DateTimeKind.Utc),
		DurationSeconds = 4_530,
		Top10AttemptedLogins = AttackStatProjection.SerializeTopLogins(new[] { "administrator", "root", "sa" }),
		LastLoginType = 3,
		ThreatScore = 78.3,
		ThreatLevel = AttackThreatLevel.Red,
		IsBlocked = true,
		LastUpdatedUtc = new DateTime(2026, 5, 19, 8, 16, 0, DateTimeKind.Utc),
	};

	[Fact]
	public void Multiline_ContainsEveryLabelledField()
	{
		string text = AttackStatRowFormatter.FormatMultiline(SampleEntry());

		Assert.Contains("Ip: 203.0.113.5", text, StringComparison.Ordinal);
		Assert.Contains("ThreatScore: 78.3", text, StringComparison.Ordinal);
		Assert.Contains("ThreatLevel: Red", text, StringComparison.Ordinal);
		Assert.Contains("TotalAttempts: 42", text, StringComparison.Ordinal);
		Assert.Contains("Failed: 40", text, StringComparison.Ordinal);
		Assert.Contains("Successful: 2", text, StringComparison.Ordinal);
		Assert.Contains("FirstSeenUtc: 2026-05-19 07:00:00", text, StringComparison.Ordinal);
		Assert.Contains("LastSeenUtc: 2026-05-19 08:15:30", text, StringComparison.Ordinal);
		Assert.Contains("DurationSeconds: 4530", text, StringComparison.Ordinal);
		Assert.Contains("Top10AttemptedLogins: administrator, root, sa", text, StringComparison.Ordinal);
		Assert.Contains("LastLoginType: 3", text, StringComparison.Ordinal);
		Assert.Contains("IsBlocked: yes", text, StringComparison.Ordinal);
		Assert.Contains("LastUpdatedUtc: 2026-05-19 08:16:00", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Multiline_RendersMissingValuesAsDash()
	{
		AttackStatEntryDto entry = new()
		{
			Ip = "203.0.113.5",
			LastLoginType = null,
			Top10AttemptedLogins = "[]",
		};

		string text = AttackStatRowFormatter.FormatMultiline(entry);

		Assert.Contains("LastLoginType: -", text, StringComparison.Ordinal);
		Assert.Contains("Top10AttemptedLogins: -", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Tsv_StartsWithStableHeaderRowAndOneDataRow()
	{
		string text = AttackStatRowFormatter.FormatTsv(SampleEntry());
		string[] lines = text.Split('\n');

		Assert.True(lines.Length >= 2);
		string header = lines[0].TrimEnd('\r');
		string row = lines[1].TrimEnd('\r');

		// Header: stable column order.
		Assert.Equal(
			"Ip\tThreatScore\tThreatLevel\tTotalAttempts\tFailed\tSuccessful\tFirstSeenUtc\tLastSeenUtc\tDurationSeconds\tTop10AttemptedLogins\tLastLoginType\tIsBlocked\tLastUpdatedUtc",
			header);

		// Row: 13 fields → 12 tab separators.
		Assert.Equal(12, row.Count(c => c == '\t'));
		Assert.Contains("203.0.113.5", row, StringComparison.Ordinal);
		Assert.Contains("78.3", row, StringComparison.Ordinal);
		Assert.Contains("Red", row, StringComparison.Ordinal);
		Assert.Contains("yes", row, StringComparison.Ordinal);
	}

	[Fact]
	public void Tsv_WithoutHeader_YieldsSingleLine()
	{
		string text = AttackStatRowFormatter.FormatTsv(SampleEntry(), includeHeader: false);
		Assert.DoesNotContain('\n', text);
		Assert.Contains("203.0.113.5", text, StringComparison.Ordinal);
	}

	[Theory]
	[InlineData(null, "")]
	[InlineData("", "")]
	[InlineData("   ", "")]
	[InlineData("not-json", "")]
	[InlineData("[]", "")]
	public void FormatTopLogins_NullOrEmptyOrMalformed_ReturnsEmpty(string? input, string expected)
	{
		Assert.Equal(expected, AttackStatRowFormatter.FormatTopLogins(input));
	}

	[Fact]
	public void FormatTopLogins_JoinsWithCommaAndSpace()
	{
		string json = AttackStatProjection.SerializeTopLogins(new[] { "admin", "root", "sa" });

		Assert.Equal("admin, root, sa", AttackStatRowFormatter.FormatTopLogins(json));
	}

	[Theory]
	[InlineData(0L, "00:00:00")]
	[InlineData(-5L, "00:00:00")]
	[InlineData(59L, "00:00:59")]
	[InlineData(60L, "00:01:00")]
	[InlineData(3_600L, "01:00:00")]
	[InlineData(86_399L, "23:59:59")]
	[InlineData(86_400L, "1d 00:00:00")]
	[InlineData(90_061L, "1d 01:01:01")]
	public void FormatDuration_ProducesCompactHhMmSs(long seconds, string expected)
	{
		Assert.Equal(expected, AttackStatRowFormatter.FormatDuration(seconds));
	}

	[Fact]
	public void Tsv_SanitisesTabsAndNewlinesInLoginPayload()
	{
		AttackStatEntryDto entry = SampleEntry();
		entry.Top10AttemptedLogins = AttackStatProjection.SerializeTopLogins(new[] { "a\tb", "c\nd" });

		string text = AttackStatRowFormatter.FormatTsv(entry, includeHeader: false);

		// One TSV record — must remain on a single line.
		Assert.DoesNotContain('\n', text);
		Assert.DoesNotContain('\r', text);

		// 13 fields → 12 separators exactly. Any unsanitised tab inside the value would inflate the count.
		Assert.Equal(12, text.Count(c => c == '\t'));
	}
}
