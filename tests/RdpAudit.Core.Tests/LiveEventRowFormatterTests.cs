// File:    tests/RdpAudit.Core.Tests/LiveEventRowFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 — locks the LiveEvents copy-to-clipboard serialisation. Multiline output is
//          assertable line-by-line; TSV output stays on a single row with a stable header.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage 4 — formatter for "Copy Event Details".</summary>
public class LiveEventRowFormatterTests
{
	private static LiveEventRowView SampleRow() => new()
	{
		Id = 42,
		EventId = 4625,
		Channel = "Security",
		TimeUtc = new DateTime(2026, 5, 19, 8, 15, 30, DateTimeKind.Utc),
		SourceIp = "203.0.113.5",
		UserName = "alice",
		Domain = "EXAMPLE",
		LogonType = 3,
		AuthPackage = "NTLM",
		ProcessName = "lsass.exe",
	};

	[Fact]
	public void Multiline_ContainsEveryLabelledField()
	{
		string text = LiveEventRowFormatter.FormatMultiline(SampleRow());

		Assert.Contains("Id: 42", text, StringComparison.Ordinal);
		Assert.Contains("TimeUtc: 2026-05-19 08:15:30", text, StringComparison.Ordinal);
		Assert.Contains("EventId: 4625", text, StringComparison.Ordinal);
		Assert.Contains("Channel: Security", text, StringComparison.Ordinal);
		Assert.Contains("User: alice", text, StringComparison.Ordinal);
		Assert.Contains("Domain: EXAMPLE", text, StringComparison.Ordinal);
		Assert.Contains("SourceIp: 203.0.113.5", text, StringComparison.Ordinal);
		Assert.Contains("LogonType: 3", text, StringComparison.Ordinal);
		Assert.Contains("AuthPackage: NTLM", text, StringComparison.Ordinal);
		Assert.Contains("Process: lsass.exe", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Multiline_RendersMissingValuesAsDash()
	{
		LiveEventRowView row = new()
		{
			Id = 1,
			EventId = 7,
			Channel = null,
			TimeUtc = DateTime.UtcNow,
			SourceIp = null,
			UserName = null,
			Domain = string.Empty,
			LogonType = null,
			AuthPackage = "   ",
			ProcessName = null,
		};

		string text = LiveEventRowFormatter.FormatMultiline(row);
		Assert.Contains("Channel: -", text, StringComparison.Ordinal);
		Assert.Contains("User: -", text, StringComparison.Ordinal);
		Assert.Contains("Domain: -", text, StringComparison.Ordinal);
		Assert.Contains("SourceIp: -", text, StringComparison.Ordinal);
		Assert.Contains("LogonType: -", text, StringComparison.Ordinal);
		Assert.Contains("AuthPackage: -", text, StringComparison.Ordinal);
		Assert.Contains("Process: -", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Tsv_HasHeaderAndSingleDataLine()
	{
		string tsv = LiveEventRowFormatter.FormatTsv(SampleRow(), includeHeader: true);
		string[] lines = tsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		Assert.Equal(2, lines.Length);

		string header = lines[0].TrimEnd('\r');
		Assert.Equal("Id\tTimeUtc\tEventId\tChannel\tUser\tDomain\tSourceIp\tLogonType\tAuthPackage\tProcess", header);

		string data = lines[1].TrimEnd('\r');
		string[] cols = data.Split('\t');
		Assert.Equal(10, cols.Length);
		Assert.Equal("42", cols[0]);
		Assert.Equal("2026-05-19 08:15:30", cols[1]);
		Assert.Equal("4625", cols[2]);
		Assert.Equal("Security", cols[3]);
		Assert.Equal("alice", cols[4]);
		Assert.Equal("EXAMPLE", cols[5]);
		Assert.Equal("203.0.113.5", cols[6]);
		Assert.Equal("3", cols[7]);
		Assert.Equal("NTLM", cols[8]);
		Assert.Equal("lsass.exe", cols[9]);
	}

	[Fact]
	public void Tsv_OmitsHeaderWhenRequested()
	{
		string tsv = LiveEventRowFormatter.FormatTsv(SampleRow(), includeHeader: false);
		Assert.DoesNotContain("Id\tTimeUtc", tsv, StringComparison.Ordinal);
	}

	[Fact]
	public void Tsv_NeutralisesTabAndNewlinesInValues()
	{
		LiveEventRowView row = new()
		{
			Id = 9,
			EventId = 1,
			Channel = "Custom\tChannel",
			TimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
			SourceIp = "1.2.3.4",
			UserName = "alice\nadmin",
			Domain = "EX\rAMPLE",
			LogonType = null,
			AuthPackage = "Negotiate",
			ProcessName = "svc.exe",
		};

		string tsv = LiveEventRowFormatter.FormatTsv(row, includeHeader: false);

		// One data line — no embedded LF/CR/TAB inside cells should break the row count.
		string[] lines = tsv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		Assert.Single(lines);
		string[] cols = lines[0].TrimEnd('\r').Split('\t');
		Assert.Equal(10, cols.Length);
		Assert.Equal("Custom Channel", cols[3]);
		Assert.Equal("alice admin", cols[4]);
		Assert.Equal("EX AMPLE", cols[5]);
	}

	[Fact]
	public void Multiline_ThrowsOnNullRow()
	{
		Assert.Throws<ArgumentNullException>(() => LiveEventRowFormatter.FormatMultiline(null!));
	}

	[Fact]
	public void Tsv_ThrowsOnNullRow()
	{
		Assert.Throws<ArgumentNullException>(() => LiveEventRowFormatter.FormatTsv(null!));
	}
}
