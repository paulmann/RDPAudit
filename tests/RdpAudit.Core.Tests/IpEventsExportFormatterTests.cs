// File:    tests/RdpAudit.Core.Tests/IpEventsExportFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage A — locks the Export-All-IP-Events formatter contracts in JSON / TXT / Markdown
//          / CSV. JSON/TXT/Markdown carry the summary header; CSV stays a clean tabular event
//          stream. Embedded tabs / CR / LF must never break the structure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage A — IP events export formatter coverage.</summary>
public class IpEventsExportFormatterTests
{
	private static EventsForIpDto SampleDto() => new()
	{
		Status = IpcResultStatus.Success,
		Ip = "203.0.113.7",
		FirstSeenUtc = new DateTime(2026, 5, 19, 7, 0, 0, DateTimeKind.Utc),
		LastSeenUtc = new DateTime(2026, 5, 19, 8, 15, 30, DateTimeKind.Utc),
		FailedCount = 40,
		SuccessCount = 2,
		TotalEvents = 42,
		DurationSeconds = 4_530,
		AttemptedUserNames = new List<string> { "administrator", "root" },
		AttackType = "BruteForce",
		ThreatLevel = "Red",
		IsBlocked = true,
		QueriedUtc = new DateTime(2026, 5, 19, 8, 16, 0, DateTimeKind.Utc),
		Events = new List<IpEventEntryDto>
		{
			new()
			{
				Id = 101,
				TimeUtc = new DateTime(2026, 5, 19, 8, 15, 30, DateTimeKind.Utc),
				EventId = 4625,
				Channel = "Security",
				UserName = "administrator",
				Domain = "WORKSTATION",
				LogonType = 3,
				AuthPackage = "NTLM",
				ProcessName = "C:\\Windows\\System32\\svchost.exe",
				Status = "0xC000006A",
			},
			new()
			{
				Id = 100,
				TimeUtc = new DateTime(2026, 5, 19, 7, 0, 0, DateTimeKind.Utc),
				EventId = 4625,
				Channel = "Security",
				UserName = "root",
				Domain = null,
				LogonType = 10,
				AuthPackage = "NTLM",
				ProcessName = null,
				Status = "0xC000006D",
			},
		},
	};

	[Fact]
	public void Json_RoundTripsThroughSerializer()
	{
		EventsForIpDto dto = SampleDto();
		string json = IpEventsExportFormatter.Format(dto, IpEventsExportFormat.Json);

		using JsonDocument doc = JsonDocument.Parse(json);
		Assert.Equal(dto.Ip, doc.RootElement.GetProperty("Ip").GetString());
		Assert.Equal(dto.FailedCount, doc.RootElement.GetProperty("FailedCount").GetInt64());
		Assert.Equal(2, doc.RootElement.GetProperty("Events").GetArrayLength());
	}

	[Fact]
	public void Txt_ContainsSummaryHeaderAndEventRows()
	{
		string text = IpEventsExportFormatter.Format(SampleDto(), IpEventsExportFormat.Txt);

		Assert.Contains("IP: 203.0.113.7", text, StringComparison.Ordinal);
		Assert.Contains("Attack type: BruteForce", text, StringComparison.Ordinal);
		Assert.Contains("Threat level: Red", text, StringComparison.Ordinal);
		Assert.Contains("Currently blocked: yes", text, StringComparison.Ordinal);
		Assert.Contains("Failed logons: 40", text, StringComparison.Ordinal);
		Assert.Contains("Successful logons: 2", text, StringComparison.Ordinal);
		Assert.Contains("Active-window duration (seconds): 4530", text, StringComparison.Ordinal);
		Assert.Contains("Attempted user names: administrator, root", text, StringComparison.Ordinal);
		Assert.Contains("event=4625", text, StringComparison.Ordinal);
		Assert.Contains("user=administrator", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Markdown_RendersSummaryAndTable()
	{
		string md = IpEventsExportFormatter.Format(SampleDto(), IpEventsExportFormat.Markdown);

		Assert.Contains("# RdpAudit — IP events export", md, StringComparison.Ordinal);
		Assert.Contains("- IP: 203.0.113.7", md, StringComparison.Ordinal);
		Assert.Contains("| Time (UTC) | Id | Event |", md, StringComparison.Ordinal);
		Assert.Contains("| 2026-05-19 08:15:30 | 101 | 4625 | Security | administrator | WORKSTATION | 3 |", md, StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_HasNoSummary_AndStableHeader()
	{
		string csv = IpEventsExportFormatter.Format(SampleDto(), IpEventsExportFormat.Csv);
		string[] lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

		Assert.StartsWith("Id,TimeUtc,EventId,Channel,User,Domain,LogonType,AuthPackage,Process,Status", lines[0], StringComparison.Ordinal);
		Assert.DoesNotContain("Attack type", csv);
		Assert.DoesNotContain("# RdpAudit", csv);
		// First data row corresponds to the first event in the list.
		Assert.Contains("101,2026-05-19 08:15:30,4625,Security,administrator,WORKSTATION,3,NTLM,", lines[1].TrimEnd('\r'), StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_QuotesCellsWithCommasNewlinesAndDoubleQuotes()
	{
		EventsForIpDto dto = SampleDto();
		dto.Events[0].Channel = "Security,Audit\r\nDouble \"Quotes\"";
		string csv = IpEventsExportFormatter.Format(dto, IpEventsExportFormat.Csv);

		// CR / LF are replaced by spaces inside the quoted cell, internal quotes are doubled.
		Assert.Contains("\"Security,Audit  Double \"\"Quotes\"\"\"", csv, StringComparison.Ordinal);
	}

	[Fact]
	public void Txt_NeutralisesTabsAndNewlines_InsideEventFields()
	{
		EventsForIpDto dto = SampleDto();
		dto.Events[0].UserName = "evil\tname\r\nnext-line";
		string text = IpEventsExportFormatter.Format(dto, IpEventsExportFormat.Txt);

		Assert.DoesNotContain("\tname", text, StringComparison.Ordinal);
		Assert.DoesNotContain("name\r\nnext-line", text, StringComparison.Ordinal);
		Assert.Contains("evil name  next-line", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Txt_NeutralisesNewlines_InAttemptedUserNames()
	{
		EventsForIpDto dto = SampleDto();
		// A malicious login containing CR/LF must not be able to inject a forged summary line.
		dto.AttemptedUserNames = new List<string> { "administrator", "evil\r\nFailed logons: 0" };
		string text = IpEventsExportFormatter.Format(dto, IpEventsExportFormat.Txt);

		Assert.DoesNotContain("evil\r\nFailed logons: 0", text, StringComparison.Ordinal);
		Assert.Contains("Attempted user names: administrator, evil  Failed logons: 0", text, StringComparison.Ordinal);
		// The genuine summary line still reports the real failed count, not the injected one.
		Assert.Contains("Failed logons: 40", text, StringComparison.Ordinal);
	}

	[Theory]
	[InlineData(IpEventsExportFormat.Json, ".json")]
	[InlineData(IpEventsExportFormat.Txt, ".txt")]
	[InlineData(IpEventsExportFormat.Markdown, ".md")]
	[InlineData(IpEventsExportFormat.Csv, ".csv")]
	public void GetFileExtension_MatchesFormat(IpEventsExportFormat format, string expected)
	{
		Assert.Equal(expected, IpEventsExportFormatter.GetFileExtension(format));
	}

	[Fact]
	public void GetDefaultFileName_StampsIpAndUtc()
	{
		EventsForIpDto dto = SampleDto();
		DateTime now = new(2026, 5, 19, 8, 16, 0, DateTimeKind.Utc);
		string name = IpEventsExportFormatter.GetDefaultFileName(dto, IpEventsExportFormat.Json, now);

		Assert.Equal("rdpaudit-events-203.0.113.7-20260519-081600.json", name);
	}

	[Fact]
	public void GetDefaultFileName_SanitisesNonFilesystemSafeChars()
	{
		EventsForIpDto dto = SampleDto();
		dto.Ip = "fe80::1%eth0";
		DateTime now = new(2026, 5, 19, 8, 16, 0, DateTimeKind.Utc);
		string name = IpEventsExportFormatter.GetDefaultFileName(dto, IpEventsExportFormat.Csv, now);

		Assert.Equal("rdpaudit-events-fe80__1_eth0-20260519-081600.csv", name);
	}

	[Fact]
	public void Format_Throws_WhenDtoIsNull()
	{
		Assert.Throws<ArgumentNullException>(() => IpEventsExportFormatter.Format(null!, IpEventsExportFormat.Json));
	}

	[Fact]
	public void Format_Throws_OnUnknownFormat()
	{
		EventsForIpDto dto = SampleDto();
		Assert.Throws<ArgumentOutOfRangeException>(() => IpEventsExportFormatter.Format(dto, (IpEventsExportFormat)99));
	}
}
