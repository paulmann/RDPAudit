// File:    tests/RdpAudit.Service.Tests/Scenarios/RestApiScenarioTests.cs
// Module:  RdpAudit.Service.Tests.Scenarios
// Purpose: Tier-3 user-level scenarios for the read-only REST API, driven through the real HTTP
//          pipeline (TestServer) exactly as an operator or a monitoring agent would use it:
//          1. Happy path - the full read-only reporting walk: healthz -> config (masked secrets)
//             -> status -> alerts -> sessions -> paged events.
//          2. Edge case - extreme /api/events pagination bounds are clamped server-side and the
//             includeDetails toggle behaves as documented.
//          3. Edge case - malformed query parameters are rejected with 400 problem+json instead
//             of a silent default.
//          4. Error state - unknown paths return 404 and non-GET/HEAD methods return 405, both as
//             RFC 9457 problem bodies.
//          5. Security boundary - a wrong token gets a 401 challenge while /healthz stays
//             anonymous.
//          6. Rate limiting - an exhausted per-minute budget returns 429 with Retry-After.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Text.Json;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>Operator-level REST API scenarios against the real HTTP pipeline.</summary>
public sealed class RestApiScenarioTests
{
	private static readonly DateTime BaseUtc = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);

	[Fact]
	public async Task OperatorReadOnlyWalk_ReportsConfigStatusAlertsSessionsAndEvents()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync(
			seed: SeedReportingFixtures,
			configure: static opts =>
			{
				opts.AbuseIpDb.ApiKey = "abuse-secret";
				opts.MikroTik.Password = "mikrotik-secret";
				opts.Api.Token = "api-secret";
			});

		// /healthz is anonymous and outside the bearer perimeter.
		using (HttpResponseMessage health = await api.Client.GetAsync(new Uri("/healthz", UriKind.Relative)))
		{
			Assert.Equal(HttpStatusCode.OK, health.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await health.Content.ReadAsStringAsync());
			Assert.Equal("ok", body.RootElement.GetProperty("status").GetString());
		}

		// /api/config must never leak the configured secrets, only the masked view.
		using (HttpResponseMessage config = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/config")))
		{
			Assert.Equal(HttpStatusCode.OK, config.StatusCode);
			string payload = await config.Content.ReadAsStringAsync();
			Assert.DoesNotContain("abuse-secret", payload, StringComparison.Ordinal);
			Assert.DoesNotContain("mikrotik-secret", payload, StringComparison.Ordinal);
			Assert.DoesNotContain("api-secret", payload, StringComparison.Ordinal);
			using JsonDocument body = JsonDocument.Parse(payload);
			Assert.Equal(
				"***configured***",
				body.RootElement.GetProperty("api").GetProperty("token").GetString());
		}

		// /api/status mirrors the runtime snapshot produced by the GetStatus IPC command.
		using (HttpResponseMessage status = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/status")))
		{
			Assert.Equal(HttpStatusCode.OK, status.StatusCode);
			Assert.Equal("application/json", status.Content.Headers.ContentType?.MediaType);
			using JsonDocument body = JsonDocument.Parse(await status.Content.ReadAsStringAsync());
			JsonElement root = body.RootElement;
			Assert.Equal(JsonValueKind.String, root.GetProperty("version").ValueKind);
			Assert.Equal(JsonValueKind.String, root.GetProperty("startedUtc").ValueKind);
			Assert.Equal(JsonValueKind.String, root.GetProperty("uptime").ValueKind);
			Assert.Equal(JsonValueKind.Object, root.GetProperty("channelStatus").ValueKind);
		}

		// /api/alerts returns the seeded alert.
		using (HttpResponseMessage alerts = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/alerts")))
		{
			Assert.Equal(HttpStatusCode.OK, alerts.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await alerts.Content.ReadAsStringAsync());
			JsonElement first = body.RootElement.EnumerateArray().First();
			Assert.Equal("BruteForce", first.GetProperty("ruleId").GetString());
			Assert.Equal("Brute force suspected", first.GetProperty("message").GetString());
		}

		// /api/sessions returns the seeded session.
		using (HttpResponseMessage sessions = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/sessions")))
		{
			Assert.Equal(HttpStatusCode.OK, sessions.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await sessions.Content.ReadAsStringAsync());
			JsonElement first = body.RootElement.EnumerateArray().First();
			Assert.Equal(2, first.GetProperty("wtsSessionId").GetInt32());
			Assert.Equal("alice", first.GetProperty("userName").GetString());
		}

		// /api/addresses returns the seeded address aggregates, newest activity first.
		using (HttpResponseMessage addresses = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/addresses")))
		{
			Assert.Equal(HttpStatusCode.OK, addresses.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await addresses.Content.ReadAsStringAsync());
			JsonElement first = body.RootElement.EnumerateArray().First();
			Assert.Equal("198.51.100.77", first.GetProperty("ip").GetString());
			Assert.Equal(12, first.GetProperty("successCount").GetInt32());
			Assert.Equal(JsonValueKind.String, first.GetProperty("lastSeen").ValueKind);
		}

		// /api/attacks returns the seeded attack-statistics snapshot with the per-IP rows.
		using (HttpResponseMessage attacks = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/attacks")))
		{
			Assert.Equal(HttpStatusCode.OK, attacks.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await attacks.Content.ReadAsStringAsync());
			JsonElement root = body.RootElement;
			Assert.Equal("Success", root.GetProperty("status").GetString());
			Assert.Equal(1, root.GetProperty("totalMatching").GetInt32());
			JsonElement first = root.GetProperty("entries").EnumerateArray().First();
			Assert.Equal("203.0.113.9", first.GetProperty("ip").GetString());
			Assert.Equal(95, first.GetProperty("threatScore").GetDouble());
			Assert.True(first.GetProperty("isBlocked").GetBoolean());
			Assert.Equal(JsonValueKind.String, first.GetProperty("threatLevel").ValueKind);
		}

		// /api/events pages newest-first and keeps details out of the default projection.
		using (HttpResponseMessage events = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/events?limit=2")))
		{
			Assert.Equal(HttpStatusCode.OK, events.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await events.Content.ReadAsStringAsync());
			JsonElement page = body.RootElement;
			Assert.Equal(2, page.GetProperty("limit").GetInt32());
			Assert.Equal(3, page.GetProperty("total").GetInt32());
			Assert.Equal(2, page.GetProperty("events").GetArrayLength());
			JsonElement first = page.GetProperty("events").EnumerateArray().First();
			Assert.Equal(2000, first.GetProperty("eventId").GetInt32());
			Assert.False(first.TryGetProperty("details", out _));
		}
	}

	[Fact]
	public async Task EventsPagination_ExtremeBounds_AreClampedAndDetailsToggleWorks()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync(seed: SeedReportingFixtures);

		// An oversized page size clamps to the documented maximum and details arrive on request.
		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/events?limit=9999&includeDetails=true")))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			JsonElement page = body.RootElement;
			Assert.Equal(500, page.GetProperty("limit").GetInt32());
			Assert.Equal(3, page.GetProperty("total").GetInt32());
			JsonElement first = page.GetProperty("events").EnumerateArray().First();
			Assert.Equal("details-1", first.GetProperty("details").GetString());
		}

		// An offset beyond the whole table yields an empty page but the same total.
		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/events?offset=999999")))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			JsonElement page = body.RootElement;
			Assert.Equal(999999, page.GetProperty("offset").GetInt32());
			Assert.Equal(3, page.GetProperty("total").GetInt32());
			Assert.Equal(0, page.GetProperty("events").GetArrayLength());
		}
	}

	[Fact]
	public async Task EventsQuery_MalformedParameters_Return400ProblemBodies()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync();

		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/events?sinceUtc=not-a-time")))
		{
			Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
			Assert.Contains(
				"sinceUtc",
				body.RootElement.GetProperty("detail").GetString(),
				StringComparison.Ordinal);
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/events?sourceIp=not-an-ip")))
		{
			Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
			Assert.Contains(
				"sourceIp",
				body.RootElement.GetProperty("detail").GetString(),
				StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task AttackStatsFilters_AndMalformedQuery_BehaveAsDocumented()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync(seed: SeedReportingFixtures);

		// onlyBlocked narrows the page to the blocked attacker row.
		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/attacks?onlyBlocked=true")))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(1, body.RootElement.GetProperty("totalMatching").GetInt32());
			JsonElement entry = body.RootElement.GetProperty("entries").EnumerateArray().Single();
			Assert.Equal("203.0.113.9", entry.GetProperty("ip").GetString());
		}

		// minThreatScore below all rows yields an empty page but keeps the totals.
		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/attacks?minThreatScore=99")))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(0, body.RootElement.GetProperty("totalMatching").GetInt32());
			Assert.Equal(0, body.RootElement.GetProperty("entries").GetArrayLength());
		}

		// Malformed filters are rejected with 400 problem+json, never a silent default.
		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/attacks?minThreatScore=abc")))
		{
			Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
			Assert.Contains(
				"minThreatScore",
				body.RootElement.GetProperty("detail").GetString(),
				StringComparison.Ordinal);
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/attacks?sinceUtc=not-a-time")))
		{
			Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
			Assert.Contains(
				"sinceUtc",
				body.RootElement.GetProperty("detail").GetString(),
				StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task UnknownPathAndUnsupportedMethod_ReturnProblemBodies()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync();

		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/unknown")))
		{
			Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal("Not Found", body.RootElement.GetProperty("title").GetString());
			Assert.Equal(404, body.RootElement.GetProperty("status").GetInt32());
			Assert.Equal("/api/unknown", body.RootElement.GetProperty("instance").GetString());
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Post, "/api/status")))
		{
			Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal("Method Not Allowed", body.RootElement.GetProperty("title").GetString());
			Assert.Equal(405, body.RootElement.GetProperty("status").GetInt32());
			Assert.Contains(
				"POST",
				body.RootElement.GetProperty("detail").GetString(),
				StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task WrongToken_IsRejectedWith401Challenge_WhileHealthzStaysAnonymous()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync();

		using HttpRequestMessage wrongToken = new(HttpMethod.Get, "/api/status");
		wrongToken.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
			"Bearer",
			"wrong-token");
		using (HttpResponseMessage response = await api.Client.SendAsync(wrongToken))
		{
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Equal("Bearer realm=\"rdpaudit\"", response.Headers.WwwAuthenticate.ToString());
			Assert.Equal(RestApiProblem.MediaType, response.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal("Unauthorized", body.RootElement.GetProperty("title").GetString());
			Assert.Equal(401, body.RootElement.GetProperty("status").GetInt32());
		}

		using (HttpResponseMessage response = await api.Client.GetAsync(new Uri("/healthz", UriKind.Relative)))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}
	}

	[Fact]
	public async Task RateBudgetExhaustion_Returns429WithRetryAfterAndProblemBody()
	{
		await using RestApiTestApp api = await RestApiTestApp.CreateAsync(rateLimitPerMinute: 2);

		using (HttpResponseMessage first = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/status")))
		{
			Assert.Equal(HttpStatusCode.OK, first.StatusCode);
		}

		using (HttpResponseMessage second = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/status")))
		{
			Assert.Equal(HttpStatusCode.OK, second.StatusCode);
		}

		using (HttpResponseMessage blocked = await api.Client.SendAsync(
			api.CreateAuthedRequest(HttpMethod.Get, "/api/status")))
		{
			Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
			Assert.NotNull(blocked.Headers.RetryAfter?.Delta);
			Assert.InRange(blocked.Headers.RetryAfter.Delta.Value.TotalSeconds, 1, 60);
			Assert.Equal(RestApiProblem.MediaType, blocked.Content.Headers.ContentType?.ToString());
			using JsonDocument body = JsonDocument.Parse(await blocked.Content.ReadAsStringAsync());
			Assert.Equal("Too Many Requests", body.RootElement.GetProperty("title").GetString());
			Assert.Equal(429, body.RootElement.GetProperty("status").GetInt32());
		}
	}

	private static void SeedReportingFixtures(AuditDbContext db)
	{
		db.Alerts.Add(new Alert
		{
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			TimeUtc = BaseUtc.AddMinutes(-1),
			SourceIp = "203.0.113.9",
			UserName = "attacker",
			Message = "Brute force suspected",
		});

		db.Sessions.Add(new Session
		{
			WtsSessionId = 2,
			UserName = "alice",
			Domain = "CONTOSO",
			SourceIp = "198.51.100.4",
			ConnectUtc = BaseUtc.AddMinutes(-2),
			Status = SessionStatus.Active,
		});

		db.Addresses.Add(new Address
		{
			Ip = "198.51.100.77",
			FailCount = 2,
			SuccessCount = 12,
			FirstSeen = BaseUtc.AddMinutes(-30),
			LastSeen = BaseUtc.AddMinutes(-2),
			ThreatScore = 3.5,
			IsBlocked = false,
			IsPublicIp = true,
		});

		db.AttackStats.Add(new AttackStat
		{
			Ip = "203.0.113.9",
			TotalAttempts = 60,
			Successful = 0,
			Failed = 60,
			FirstSeenUtc = BaseUtc.AddMinutes(-40),
			LastSeenUtc = BaseUtc.AddMinutes(-1),
			DurationSeconds = 2340,
			Top10AttemptedLogins = "[]",
			ThreatScore = 95,
			IsBlocked = true,
			LastUpdatedUtc = BaseUtc.AddMinutes(-1),
		});

		for (int i = 1; i <= 3; i++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = i == 1 ? 2000 : 4625,
				Channel = i % 2 == 0 ? "System" : "Security",
				TimeUtc = BaseUtc.AddMinutes(-i),
				IngestionSequence = i,
				EventLayer = 3,
				SourceIp = "10.0.0." + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
				SourceIpDerived = false,
				SourceIpUnresolved = false,
				UserName = "user" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
				Domain = "CONTOSO",
				Details = "details-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
				Processed = false,
			});
		}
	}
}
