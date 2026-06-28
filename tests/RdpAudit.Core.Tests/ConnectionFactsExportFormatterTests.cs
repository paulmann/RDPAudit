// File:    tests/RdpAudit.Core.Tests/ConnectionFactsExportFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage IP-E — locks the Export-Connection-Facts formatter contracts in JSON / TXT /
//          Markdown / CSV. JSON/TXT/Markdown carry the per-IP summary header; CSV stays a clean
//          tabular fact stream with only a header row and machine-friendly cells. Embedded
//          quotes / commas / CR / LF / pipes must never break the structure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage IP-E — Connection facts export formatter coverage.</summary>
public class ConnectionFactsExportFormatterTests
{
	private static ConnectionFactsForIpDto SampleDto() => new()
	{
		Status = IpcResultStatus.Success,
		Ip = "203.0.113.42",
		QueriedUtc = new DateTime(2026, 5, 20, 10, 30, 0, DateTimeKind.Utc),
		TotalMatching = 3,
		AppliedLimit = 500,
		FirstSeenUtc = new DateTime(2026, 5, 19, 9, 0, 0, DateTimeKind.Utc),
		LastSeenUtc = new DateTime(2026, 5, 20, 10, 25, 0, DateTimeKind.Utc),
		FailedLogons = 17,
		SuccessfulLogons = 1,
		HasActiveFact = true,
		Facts = new List<ConnectionFactDto>
		{
			new()
			{
				Id = 1001,
				Ip = "203.0.113.42",
				UserName = "administrator",
				Domain = "CORP",
				WtsSessionId = 4,
				LogonId = "0x1234ABCD",
				FirstSeenUtc = new DateTime(2026, 5, 19, 9, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 20, 10, 25, 0, DateTimeKind.Utc),
				ConnectedUtc = new DateTime(2026, 5, 19, 9, 0, 5, DateTimeKind.Utc),
				AuthenticatedUtc = new DateTime(2026, 5, 19, 9, 0, 30, DateTimeKind.Utc),
				DisconnectedUtc = null,
				ReconnectedUtc = null,
				LoggedOffUtc = null,
				FailedLogons = 10,
				SuccessfulLogons = 1,
				ObservedEventIds = "4624,4625,1149",
				UserNamesAttempted = "administrator,admin",
				IsActive = true,
			},
			new()
			{
				Id = 1002,
				Ip = "203.0.113.42",
				UserName = "guest, with comma",
				Domain = "WK1",
				WtsSessionId = null,
				LogonId = null,
				FirstSeenUtc = new DateTime(2026, 5, 19, 11, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc),
				ConnectedUtc = null,
				AuthenticatedUtc = null,
				DisconnectedUtc = new DateTime(2026, 5, 19, 11, 59, 0, DateTimeKind.Utc),
				ReconnectedUtc = null,
				LoggedOffUtc = new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc),
				FailedLogons = 7,
				SuccessfulLogons = 0,
				ObservedEventIds = "4625",
				UserNamesAttempted = "guest,\"weird\"",
				IsActive = false,
			},
		},
	};

	[Fact]
	public void Format_NullDto_Throws()
	{
		Assert.Throws<ArgumentNullException>(() =>
			ConnectionFactsExportFormatter.Format(null!, ConnectionFactsExportFormat.Json));
	}

	[Fact]
	public void Format_UnknownFormat_Throws()
	{
		ConnectionFactsForIpDto dto = SampleDto();
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			ConnectionFactsExportFormatter.Format(dto, (ConnectionFactsExportFormat)999));
	}

	[Fact]
	public void Json_RoundTrips()
	{
		string body = ConnectionFactsExportFormatter.Format(SampleDto(), ConnectionFactsExportFormat.Json);

		using JsonDocument doc = JsonDocument.Parse(body);
		JsonElement root = doc.RootElement;
		Assert.Equal("203.0.113.42", root.GetProperty("Ip").GetString());
		Assert.Equal(17, root.GetProperty("FailedLogons").GetInt64());
		Assert.Equal(1, root.GetProperty("SuccessfulLogons").GetInt64());
		Assert.True(root.GetProperty("HasActiveFact").GetBoolean());
		Assert.Equal(2, root.GetProperty("Facts").GetArrayLength());
	}

	[Fact]
	public void Txt_IncludesSummaryHeader()
	{
		string body = ConnectionFactsExportFormatter.Format(SampleDto(), ConnectionFactsExportFormat.Txt);
		Assert.StartsWith("=== RdpAudit — Connection facts export ===", body, StringComparison.Ordinal);
		Assert.Contains("IP: 203.0.113.42", body, StringComparison.Ordinal);
		Assert.Contains("Failed logons: 17", body, StringComparison.Ordinal);
		Assert.Contains("Successful logons: 1", body, StringComparison.Ordinal);
		Assert.Contains("Has active fact: yes", body, StringComparison.Ordinal);
		Assert.Contains("Fact count (returned): 2", body, StringComparison.Ordinal);
		Assert.Contains("Total matching: 3", body, StringComparison.Ordinal);
		Assert.Contains("Generated (UTC): 2026-05-20 10:30:00", body, StringComparison.Ordinal);
		// Per-fact lines must appear.
		Assert.Contains("id=1001", body, StringComparison.Ordinal);
		Assert.Contains("id=1002", body, StringComparison.Ordinal);
		Assert.Contains("active=yes", body, StringComparison.Ordinal);
		Assert.Contains("active=no", body, StringComparison.Ordinal);
	}

	[Fact]
	public void Markdown_IncludesSummarySectionAndTableHeader()
	{
		string body = ConnectionFactsExportFormatter.Format(SampleDto(), ConnectionFactsExportFormat.Markdown);
		Assert.StartsWith("# RdpAudit — Connection facts export", body, StringComparison.Ordinal);
		Assert.Contains("## Summary", body, StringComparison.Ordinal);
		Assert.Contains("- IP: 203.0.113.42", body, StringComparison.Ordinal);
		Assert.Contains("- Has active fact: yes", body, StringComparison.Ordinal);
		Assert.Contains("## Facts (LastSeenUtc desc)", body, StringComparison.Ordinal);
		Assert.Contains("| First (UTC) | Last (UTC) | Id | IP | User |", body, StringComparison.Ordinal);
		Assert.Contains("| 1001 |", body, StringComparison.Ordinal);
		Assert.Contains("| 1002 |", body, StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_HasHeaderOnlyAsFirstLineAndNoProsePreamble()
	{
		string body = ConnectionFactsExportFormatter.Format(SampleDto(), ConnectionFactsExportFormat.Csv);

		string[] lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		// First line is the CSV header row, not prose.
		Assert.StartsWith("Id,Ip,UserName,Domain,WtsSessionId,LogonId,FirstSeenUtc,LastSeenUtc,ConnectedUtc,AuthenticatedUtc,DisconnectedUtc,ReconnectedUtc,LoggedOffUtc,FailedLogons,SuccessfulLogons,ObservedEventIds,UserNamesAttempted,IsActive", lines[0], StringComparison.Ordinal);
		Assert.DoesNotContain("RdpAudit", lines[0], StringComparison.Ordinal);
		Assert.DoesNotContain("Summary", body, StringComparison.Ordinal);
		Assert.DoesNotContain("===", body, StringComparison.Ordinal);

		// 2 fact rows + 1 header.
		Assert.Equal(3, lines.Length);
	}

	[Fact]
	public void Csv_HeaderCarriesReportabilityColumns()
	{
		ConnectionFactsForIpDto dto = SampleDto();
		dto.Facts[0].Classification = "Public";
		dto.Facts[0].IsPublic = true;
		dto.Facts[0].IsWhitelisted = false;
		dto.Facts[0].IsReportableToAbuseIPDB = true;
		dto.Facts[0].IsEligibleForAutoBlock = true;

		string body = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Csv);
		string[] lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		string header = lines[0].TrimEnd('\r', '\n');

		Assert.EndsWith("IsActive,Classification,IsPublic,IsWhitelisted,IsReportableToAbuseIPDB,IsEligibleForAutoBlock",
			header, StringComparison.Ordinal);
		// First fact row reflects the reportability cells (…,yes,Public,yes,no,yes,yes).
		Assert.Contains(",Public,yes,no,yes,yes", body, StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_EscapesCommasAndQuotes()
	{
		string body = ConnectionFactsExportFormatter.Format(SampleDto(), ConnectionFactsExportFormat.Csv);

		// "guest, with comma" must be quoted; embedded double-quotes in attempted user names must be doubled.
		Assert.Contains("\"guest, with comma\"", body, StringComparison.Ordinal);
		Assert.Contains("\"guest,\"\"weird\"\"\"", body, StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_NeutralisesEmbeddedNewlines()
	{
		ConnectionFactsForIpDto dto = SampleDto();
		dto.Facts[0].UserNamesAttempted = "line1\nline2\rback";

		string body = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Csv);
		// No bare CR/LF inside a quoted cell — the formatter replaces them with spaces.
		Assert.Contains("\"line1 line2 back\"", body, StringComparison.Ordinal);
		Assert.DoesNotContain("line1\nline2", body, StringComparison.Ordinal);
	}

	[Fact]
	public void Markdown_EscapesPipesInUserNames()
	{
		ConnectionFactsForIpDto dto = SampleDto();
		dto.Facts[0].UserName = "weird|pipe";

		string body = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Markdown);
		Assert.Contains("weird\\|pipe", body, StringComparison.Ordinal);
	}

	[Fact]
	public void EmptyFacts_StillProducesSummaryHeaderForNonCsv()
	{
		ConnectionFactsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = "198.51.100.7",
			QueriedUtc = new DateTime(2026, 5, 20, 11, 0, 0, DateTimeKind.Utc),
			Facts = new List<ConnectionFactDto>(),
		};

		string txt = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Txt);
		Assert.Contains("IP: 198.51.100.7", txt, StringComparison.Ordinal);
		Assert.Contains("(no recorded facts)", txt, StringComparison.Ordinal);

		string md = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Markdown);
		Assert.Contains("## Summary", md, StringComparison.Ordinal);
		Assert.Contains("(no facts)", md, StringComparison.Ordinal);

		string csv = ConnectionFactsExportFormatter.Format(dto, ConnectionFactsExportFormat.Csv);
		string[] lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		Assert.Single(lines);
		Assert.StartsWith("Id,Ip,UserName,", lines[0], StringComparison.Ordinal);
	}

	[Fact]
	public void DefaultFileName_SanitisesIpSegment()
	{
		ConnectionFactsForIpDto dto = new() { Ip = "203.0.113.42" };
		DateTime now = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		string name = ConnectionFactsExportFormatter.GetDefaultFileName(dto, ConnectionFactsExportFormat.Json, now);
		Assert.Equal("rdpaudit-facts-203.0.113.42-20260520-120000.json", name);

		ConnectionFactsForIpDto v6 = new() { Ip = "2001:db8::1" };
		string v6name = ConnectionFactsExportFormatter.GetDefaultFileName(v6, ConnectionFactsExportFormat.Csv, now);
		Assert.Equal("rdpaudit-facts-2001_db8__1-20260520-120000.csv", v6name);
	}

	[Fact]
	public void GetFileExtension_ReturnsExpected()
	{
		Assert.Equal(".json", ConnectionFactsExportFormatter.GetFileExtension(ConnectionFactsExportFormat.Json));
		Assert.Equal(".txt", ConnectionFactsExportFormatter.GetFileExtension(ConnectionFactsExportFormat.Txt));
		Assert.Equal(".md", ConnectionFactsExportFormatter.GetFileExtension(ConnectionFactsExportFormat.Markdown));
		Assert.Equal(".csv", ConnectionFactsExportFormatter.GetFileExtension(ConnectionFactsExportFormat.Csv));
	}

	[Fact]
	public void GetSaveFileFilter_ReturnsExpected()
	{
		Assert.Equal("JSON (*.json)|*.json", ConnectionFactsExportFormatter.GetSaveFileFilter(ConnectionFactsExportFormat.Json));
		Assert.Equal("Text (*.txt)|*.txt", ConnectionFactsExportFormatter.GetSaveFileFilter(ConnectionFactsExportFormat.Txt));
		Assert.Equal("Markdown (*.md)|*.md", ConnectionFactsExportFormatter.GetSaveFileFilter(ConnectionFactsExportFormat.Markdown));
		Assert.Equal("CSV (*.csv)|*.csv", ConnectionFactsExportFormatter.GetSaveFileFilter(ConnectionFactsExportFormat.Csv));
	}
}
