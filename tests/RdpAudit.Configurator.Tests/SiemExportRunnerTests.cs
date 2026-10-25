// File:    tests/RdpAudit.Configurator.Tests/SiemExportRunnerTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Backlog #4 tests for the pure composition (BuildText) and file output
//          (WriteExportFileAsync) of SiemExportRunner: golden CEF / LEEF / NDJSON field shapes,
//          event-then-alert ordering, non-success projections skipped, deviceVersion propagated
//          into every header and UTF-8 without BOM writing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Xunit;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Siem;

namespace RdpAudit.Configurator.Tests;

public sealed class SiemExportRunnerTests
{
	private const string Version = "2.1.0";

	private static readonly DateTime Time = new(2026, 9, 10, 12, 30, 0, DateTimeKind.Utc);

	[Fact]
	public async Task WriteExportFileAsync_WritesUtf8WithoutBom()
	{
		string dir = Path.Combine(Path.GetTempPath(), "rdpaudit-siem-tests", Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(dir);
		try
		{
			string path = Path.Combine(dir, "out.cef");
			string body = "CEF:0|RdpAudit|RdpAudit|2.1.0|event:4625|Test\u00e9";

			await SiemExportRunner.WriteExportFileAsync(path, body);

			byte[] bytes = await File.ReadAllBytesAsync(path);
			Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
				"Export file must not start with a UTF-8 BOM.");
			Assert.Equal(body, await File.ReadAllTextAsync(path));
		}
		finally
		{
			Directory.Delete(dir, recursive: true);
		}
	}

	[Fact]
	public void BuildText_Cef_RendersEventsThenAlertsWithVersionInEveryHeader()
	{
		(EventsForIpDto events, AlertsForIpDto alerts) = Fixture();

		string text = SiemExportRunner.BuildText(events, alerts, SiemFormat.Cef, Version);

		string[] lines = text.Split('\n');
		Assert.Equal(2, lines.Length);
		Assert.StartsWith("CEF:0|RdpAudit|RdpAudit|2.1.0|event:4625|", lines[0]);
		Assert.Contains(" cs8=event", lines[0]);
		Assert.Contains(" src=203.0.113.7", lines[0]);
		Assert.Contains(" cn1=3", lines[0]);
		Assert.Contains("deviceCustomDate1=Sep 10 2026 12:30:00 +00:00", lines[0]);
		Assert.StartsWith("CEF:0|RdpAudit|RdpAudit|2.1.0|BRUTE-FORCE|", lines[1]);
		Assert.Contains(" cs8=alert", lines[1]);
		Assert.Contains(" msg=Brute force attempt", lines[1]);
		Assert.DoesNotContain("\n\n", text);
	}

	[Fact]
	public void BuildText_Leef_RendersTabSeparatedAttributes()
	{
		(EventsForIpDto events, AlertsForIpDto alerts) = Fixture();

		string text = SiemExportRunner.BuildText(events, alerts, SiemFormat.Leef, Version);

		string[] lines = text.Split('\n');
		Assert.Equal(2, lines.Length);
		Assert.StartsWith("LEEF:2.0|RdpAudit|RdpAudit|2.1.0|event:4625\t", lines[0]);
		Assert.Contains("\tdevTime=2026-09-10T12:30:00.000Z", lines[0]);
		Assert.Contains("\tsrc=203.0.113.7", lines[0]);
		Assert.Contains("\tsev=5", lines[0]);
		Assert.StartsWith("LEEF:2.0|RdpAudit|RdpAudit|2.1.0|BRUTE-FORCE\t", lines[1]);
		Assert.Contains("\tsev=5", lines[1]);
		Assert.Contains("\trecordType=alert", lines[1]);
	}

	[Fact]
	public void BuildText_JsonNdjson_RendersCamelCaseRecords()
	{
		(EventsForIpDto events, AlertsForIpDto alerts) = Fixture();

		string text = SiemExportRunner.BuildText(events, alerts, SiemFormat.JsonNdjson, Version);

		string[] lines = text.Split('\n');
		Assert.Equal(2, lines.Length);
		Assert.Contains("\"deviceVersion\":\"2.1.0\"", lines[0]);
		Assert.Contains("\"type\":\"event\"", lines[0]);
		Assert.Contains("\"sourceIp\":\"203.0.113.7\"", lines[0]);
		Assert.Contains("\"type\":\"alert\"", lines[1]);
		Assert.Contains("\"signatureId\":\"BRUTE-FORCE\"", lines[1]);
		Assert.DoesNotContain("\n\n", text);

		// Every line is a standalone JSON object.
		foreach (string line in lines)
		{
			using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(line);
			Assert.Equal(System.Text.Json.JsonValueKind.Object, doc.RootElement.ValueKind);
		}
	}

	[Fact]
	public void BuildText_SkipsNonSuccessProjections()
	{
		(EventsForIpDto events, AlertsForIpDto alerts) = Fixture();
		events.Status = IpcResultStatus.Unavailable;
		alerts.Status = IpcResultStatus.Refused;

		string text = SiemExportRunner.BuildText(events, alerts, SiemFormat.Cef, Version);

		Assert.Equal(string.Empty, text);
	}

	[Fact]
	public void BuildText_EmptyProjections_ReturnsEmpty()
	{
		EventsForIpDto events = new() { Ip = "203.0.113.7", Status = IpcResultStatus.Success };
		AlertsForIpDto alerts = new() { Ip = "203.0.113.7", Status = IpcResultStatus.Success };

		string text = SiemExportRunner.BuildText(events, alerts, SiemFormat.Cef, Version);

		Assert.Equal(string.Empty, text);
	}

	private static (EventsForIpDto Events, AlertsForIpDto Alerts) Fixture()
	{
		EventsForIpDto events = new()
		{
			Ip = "203.0.113.7",
			Status = IpcResultStatus.Success,
			FirstSeenUtc = Time,
			LastSeenUtc = Time,
			FailedCount = 3,
			TotalEvents = 4,
			Events =
			{
				new IpEventEntryDto
				{
					Id = 11,
					TimeUtc = Time,
					EventId = 4625,
					Channel = "Security",
					UserName = "Administrator",
					Domain = "CORP",
					LogonType = 10,
				},
			},
		};

		AlertsForIpDto alerts = new()
		{
			Ip = "203.0.113.7",
			Status = IpcResultStatus.Success,
			TotalAlerts = 1,
			Alerts =
			{
				new AlertEntryDto
				{
					Id = 5,
					RuleId = "BRUTE-FORCE",
					Severity = Core.Models.AlertSeverity.Medium,
					TimeUtc = Time,
					SourceIp = "203.0.113.7",
					UserName = "Administrator",
					Message = "Brute force attempt",
				},
			},
		};

		return (events, alerts);
	}
}
