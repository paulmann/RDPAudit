// File:    tests/RdpAudit.Service.Tests/ApiEventDtoSerializationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Lock the JSON wire shape of the REST API DTOs: camelCase property names, enums as
//          strings (JsonStringEnumConverter), TimeSpan-backed uptime as a string, omitted nulls
//          and the plain "error":"..." envelope. These contracts are what the committed OpenAPI
//          descriptor promises; the integration tests then consume the same shapes over HTTP.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.RestApi;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ApiEventDtoSerializationTests
{
	[Fact]
	public void PagedEventPage_UsesCamelCaseKeys_AndOmitsNullDetails()
	{
		PagedEventPage page = new()
		{
			Offset = 10,
			Limit = 20,
			Total = 30,
			Events =
			[
				new PagedEventRow
				{
					Id = 42,
					EventId = 4625,
					Channel = "Security",
					TimeUtc = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc),
					SourceIp = "198.51.100.7",
					Details = null,
				},
			],
		};

		string json = JsonSerializer.Serialize(page, JsonOptions.Default);

		Assert.Contains("\"offset\":10", json, StringComparison.Ordinal);
		Assert.Contains("\"limit\":20", json, StringComparison.Ordinal);
		Assert.Contains("\"total\":30", json, StringComparison.Ordinal);
		Assert.Contains("\"eventId\":4625", json, StringComparison.Ordinal);
		Assert.Contains("\"sourceIp\":\"198.51.100.7\"", json, StringComparison.Ordinal);
		Assert.DoesNotContain("details", json, StringComparison.Ordinal);
		Assert.DoesNotContain("\"TimeUtc\"", json, StringComparison.Ordinal);
		Assert.DoesNotContain("\"EventId\"", json, StringComparison.Ordinal);
	}

	[Fact]
	public void PagedEventPage_RoundTrips()
	{
		PagedEventPage page = new()
		{
			Offset = 0,
			Limit = 2,
			Total = 2,
			ExplainPlan = ["SCAN RawEvents"],
			Events =
			[
				new PagedEventRow
				{
					Id = 1,
					EventId = 4625,
					Channel = "Security",
					TimeUtc = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc),
					IngestionSequence = 100,
					EventLayer = 3,
					SessionId = 7,
					LogonType = 10,
					LogonId = "0xABC",
					Details = "raw xml",
				},
				new PagedEventRow
				{
					Id = 2,
					EventId = 2000,
					Channel = "System",
					TimeUtc = new DateTime(2026, 9, 1, 11, 59, 0, DateTimeKind.Utc),
				},
			],
		};

		string json = JsonSerializer.Serialize(page, JsonOptions.Default);
		PagedEventPage? round = JsonSerializer.Deserialize<PagedEventPage>(json, JsonOptions.Default);

		Assert.NotNull(round);
		Assert.Equal(2, round!.Events.Count);
		Assert.Equal(1L, round.Events[0].Id);
		Assert.Equal("0xABC", round.Events[0].LogonId);
		Assert.Equal("raw xml", round.Events[0].Details);
		Assert.Null(round.Events[1].Details);
		Assert.Equal(["SCAN RawEvents"], round.ExplainPlan);
	}

	[Fact]
	public void ServiceStatus_Uptime_SerializesAsString()
	{
		ServiceStatus status = new()
		{
			Version = "2.0.2",
			StartedUtc = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc),
			Uptime = TimeSpan.FromHours(2) + TimeSpan.FromMinutes(3),
			ProcessId = 1234,
			EventsCaptured = 5,
		};

		string json = JsonSerializer.Serialize(status, JsonOptions.Default);

		Assert.Contains("\"version\":\"2.0.2\"", json, StringComparison.Ordinal);
		Assert.Contains("\"processId\":1234", json, StringComparison.Ordinal);
		using JsonDocument doc = JsonDocument.Parse(json);
		Assert.Equal(
			JsonValueKind.String,
			doc.RootElement.GetProperty("uptime").ValueKind);
	}

	[Fact]
	public void Enums_AreSerializedAsStrings()
	{
		object payload = new
		{
			severity = RdpAudit.Core.Models.AlertSeverity.High,
			status = RdpAudit.Core.Models.SessionStatus.Disconnected,
		};

		string json = JsonSerializer.Serialize(payload, JsonOptions.Default);

		Assert.Contains("\"severity\":\"High\"", json, StringComparison.Ordinal);
		Assert.Contains("\"status\":\"Disconnected\"", json, StringComparison.Ordinal);
	}

	[Fact]
	public void ProblemEnvelope_SerializesWithCamelCaseProperties()
	{
		object envelope = new
		{
			type = "about:blank",
			title = "Bad Request",
			status = 400,
			detail = "Parameter 'sourceIp' must be a valid IP address literal.",
		};

		string json = JsonSerializer.Serialize(envelope, JsonOptions.Default);

		using JsonDocument doc = JsonDocument.Parse(json);
		Assert.Equal("about:blank", doc.RootElement.GetProperty("type").GetString());
		Assert.Equal("Bad Request", doc.RootElement.GetProperty("title").GetString());
		Assert.Equal(400, doc.RootElement.GetProperty("status").GetInt32());
		Assert.Equal(
			"Parameter 'sourceIp' must be a valid IP address literal.",
			doc.RootElement.GetProperty("detail").GetString());
	}
}
