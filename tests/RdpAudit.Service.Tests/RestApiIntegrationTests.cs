// File:    tests/RdpAudit.Service.Tests/RestApiIntegrationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end contract tests for the read-only REST API. Each test boots the real
//          RestApiHostedService.CreateApiApplication pipeline (security-headers middleware,
//          bearer auth, the service-scope bridge and the endpoint map) on an ASP.NET Core
//          TestServer and asserts the full HTTP contract: 200 shapes, 401 on missing/invalid
//          tokens, 400 on invalid /api/events query parameters, 405 on non-GET/HEAD methods,
//          the anonymous /healthz exemption and the embedded OpenAPI descriptor.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Models;
using RdpAudit.Core.RestApi;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.RestApi;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RestApiIntegrationTests
{
	private const string BearerToken = "test-secret-token";

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
		{
			cancellationToken.ThrowIfCancellationRequested();
			return Task.FromResult(new AuditDbContext(_options));
		}
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
		where T : class
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;

		public T CurrentValue { get; }

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class EngineScopeFactory : IServiceScopeFactory
	{
		private readonly IServiceProvider _root;

		public EngineScopeFactory(IServiceProvider root) => _root = root;

		public IServiceScope CreateScope() => _root.CreateScope();
	}

	private sealed class ApiHarness : IAsyncDisposable
	{
		private readonly WebApplication _app;
		private readonly TestServer _server;
		private readonly ServiceProvider _root;
		private readonly string _dbPath;

		public ApiHarness(WebApplication app, TestServer server, ServiceProvider root, string dbPath)
		{
			_app = app;
			_server = server;
			_root = root;
			_dbPath = dbPath;
			Client = server.CreateClient();
		}

		public HttpClient Client { get; }

		public async ValueTask DisposeAsync()
		{
			Client.Dispose();
			await _app.StopAsync(default);
			await _app.DisposeAsync();
			_server.Dispose();
			_root.Dispose();
			TryDeleteDatabase(_dbPath);
		}
	}

	private static async Task<string> CreateDbAsync()
	{
		string dbPath = Path.Combine(
			Path.GetTempPath(),
			"rdpaudit-rest-api-" + Guid.NewGuid().ToString("N") + ".db");
		{
			await using SqliteConnection conn = new(AuditDbContextOptionsFactory.BuildConnectionString(dbPath));
			await conn.OpenAsync();
		}

		await using (AuditDbContext init = new(AuditDbContextOptionsFactory.Create(dbPath)))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return dbPath;
	}

	private static IpcDispatcher CreateDispatcher(RdpAuditOptions opts, string dbPath)
	{
		IDbContextFactory<AuditDbContext> factory = new TestDbContextFactory(
			AuditDbContextOptionsFactory.Create(dbPath));
		ServiceMetrics metrics = new();
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(opts);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(
			factory,
			metrics,
			monitor,
			settings,
			firewall,
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance);
	}

	private static ApiHarness CreateApi(
		string dbPath,
		Action<RdpAuditOptions>? configure = null,
		Action<AuditDbContext>? seed = null,
		int rateLimitPerMinute = 60)
	{
		if (seed is not null)
		{
			using AuditDbContext seeder = new(AuditDbContextOptionsFactory.Create(dbPath));
			seed(seeder);
			seeder.SaveChanges();
		}

		RdpAuditOptions opts = new();
		opts.Storage.DatabasePath = dbPath;
		configure?.Invoke(opts);

		ServiceCollection services = new();
		services.AddSingleton(CreateDispatcher(opts, dbPath));
		services.AddSingleton<IPagedEventReader>(new PagedEventReader(
			new ReadOnlyAuditDbContextFactory(new StaticOptionsMonitor<RdpAuditOptions>(opts))));
		ServiceProvider root = services.BuildServiceProvider();

		RestApiPlan plan = RestApiPlan.Listening(
			"127.0.0.1",
			8443,
			100,
			rateLimitPerMinute,
			RestApiTestCertificateFactory.CreateSelfSigned(),
			warnNonLoopback: false,
			acceptedSelfSigned: false);
		WebApplication app = RestApiHostedService.CreateApiApplication(
			plan,
			BearerToken,
			new EngineScopeFactory(root),
			NullLoggerFactory.Instance,
			static builder => builder.WebHost.UseTestServer());
		app.StartAsync().GetAwaiter().GetResult();
		TestServer server = app.GetTestServer();
		return new ApiHarness(app, server, root, dbPath);
	}

	private static HttpRequestMessage CreateAuthedRequest(HttpMethod method, string path)
	{
		HttpRequestMessage request = new(method, path);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", BearerToken);
		return request;
	}

	private static void TryDeleteDatabase(string dbPath)
	{
		try
		{
			if (File.Exists(dbPath))
			{
				File.Delete(dbPath);
			}

			if (File.Exists(dbPath + "-wal"))
			{
				File.Delete(dbPath + "-wal");
			}

			if (File.Exists(dbPath + "-shm"))
			{
				File.Delete(dbPath + "-shm");
			}
		}
		catch
		{
			// Best-effort temp cleanup.
		}
	}

	[Fact]
	public async Task Healthz_WithoutToken_Returns200Anonymous()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		HttpResponseMessage response = await api.Client.GetAsync(new Uri("/healthz", UriKind.Relative));

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal("ok", body.RootElement.GetProperty("status").GetString());
		JsonElement bindings = body.RootElement.GetProperty("bindings");
		Assert.Contains(
			bindings.EnumerateArray().Select(static b => b.GetString()),
			static value => value == "https://127.0.0.1:8443");
	}

	[Fact]
	public async Task ApiStatus_WithValidToken_Returns200CamelCaseShape()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/status");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		JsonElement root = body.RootElement;
		Assert.Equal(JsonValueKind.String, root.GetProperty("version").ValueKind);
		Assert.Equal(JsonValueKind.String, root.GetProperty("startedUtc").ValueKind);
		// TimeSpan-backed Uptime must reach the wire as a string, never as an object or number.
		Assert.Equal(JsonValueKind.String, root.GetProperty("uptime").ValueKind);
		Assert.Equal(JsonValueKind.Number, root.GetProperty("processId").ValueKind);
		Assert.Equal(JsonValueKind.Object, root.GetProperty("channelStatus").ValueKind);
	}

	[Fact]
	public async Task ApiStatus_HeadRequest_Returns200()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Head, "/api/status");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
	}

	[Fact]
	public async Task ApiStatus_WithoutToken_Returns401WithChallenge()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		HttpResponseMessage response = await api.Client.GetAsync(new Uri("/api/status", UriKind.Relative));

		Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		Assert.Equal("Bearer realm=\"rdpaudit\"", response.Headers.WwwAuthenticate.ToString());
		Assert.Contains("application/problem+json", response.Content.Headers.ContentType?.ToString(), StringComparison.Ordinal);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal("Unauthorized", body.RootElement.GetProperty("title").GetString());
	}

	[Fact]
	public async Task ApiStatus_WithInvalidToken_Returns401()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = new(HttpMethod.Get, "/api/status");
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-token");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
	}

	[Fact]
	public async Task ApiAlerts_WithValidToken_ReturnsSeededAlerts()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, seed: db =>
		{
			db.Alerts.Add(new Alert
			{
				RuleId = "BruteForce",
				Severity = AlertSeverity.High,
				TimeUtc = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc),
				SourceIp = "203.0.113.9",
				UserName = "attacker",
				Message = "Brute force suspected",
			});
		});

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/alerts");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		JsonElement first = body.RootElement.EnumerateArray().First();
		Assert.Equal("BruteForce", first.GetProperty("ruleId").GetString());
		Assert.Equal("High", first.GetProperty("severity").GetString());
		Assert.Equal("Brute force suspected", first.GetProperty("message").GetString());
	}

	[Fact]
	public async Task ApiSessions_WithValidToken_ReturnsSeededSessions()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, seed: db =>
		{
			db.Sessions.Add(new Session
			{
				WtsSessionId = 3,
				UserName = "alice",
				Domain = "CONTOSO",
				SourceIp = "198.51.100.4",
				ConnectUtc = new DateTime(2026, 9, 1, 9, 30, 0, DateTimeKind.Utc),
				Status = SessionStatus.Active,
			});
		});

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/sessions");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		JsonElement first = body.RootElement.EnumerateArray().First();
		Assert.Equal(3, first.GetProperty("wtsSessionId").GetInt32());
		Assert.Equal("alice", first.GetProperty("userName").GetString());
		Assert.NotNull(first.GetProperty("connectUtc").GetString());
	}

	[Fact]
	public async Task ApiAddresses_WithValidToken_ReturnsSeededAddressesNewestFirst()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, seed: db =>
		{
			db.Addresses.Add(new Address
			{
				Ip = "203.0.113.20",
				FailCount = 14,
				SuccessCount = 2,
				FirstSeen = new DateTime(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc),
				LastSeen = new DateTime(2026, 9, 1, 8, 30, 0, DateTimeKind.Utc),
				ThreatScore = 82.5,
				IsBlocked = true,
				BlockReason = "Auto block",
				IsPublicIp = true,
			});
			db.Addresses.Add(new Address
			{
				Ip = "198.51.100.12",
				FailCount = 3,
				SuccessCount = 9,
				FirstSeen = new DateTime(2026, 9, 1, 9, 0, 0, DateTimeKind.Utc),
				LastSeen = new DateTime(2026, 9, 1, 9, 15, 0, DateTimeKind.Utc),
				ThreatScore = 4.0,
				IsBlocked = false,
				IsPublicIp = true,
			});
		});

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/addresses");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(2, body.RootElement.GetArrayLength());
		JsonElement first = body.RootElement.EnumerateArray().First();
		Assert.Equal("198.51.100.12", first.GetProperty("ip").GetString());
		Assert.Equal(9, first.GetProperty("successCount").GetInt32());
		Assert.Equal(JsonValueKind.String, first.GetProperty("lastSeen").ValueKind);
	}

	[Fact]
	public async Task ApiAttacks_WithValidToken_MapsFiltersAndShape()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, seed: db =>
		{
			db.AttackStats.Add(new AttackStat
			{
				Ip = "203.0.113.7",
				TotalAttempts = 45,
				Successful = 0,
				Failed = 45,
				FirstSeenUtc = new DateTime(2026, 9, 1, 10, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 9, 1, 11, 0, 0, DateTimeKind.Utc),
				DurationSeconds = 3600,
				Top10AttemptedLogins = "[]",
				ThreatScore = 91,
				IsBlocked = true,
				LastUpdatedUtc = new DateTime(2026, 9, 1, 11, 5, 0, DateTimeKind.Utc),
			});
			db.AttackStats.Add(new AttackStat
			{
				Ip = "198.51.100.44",
				TotalAttempts = 7,
				Successful = 6,
				Failed = 1,
				FirstSeenUtc = new DateTime(2026, 9, 1, 9, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 9, 1, 9, 30, 0, DateTimeKind.Utc),
				DurationSeconds = 1800,
				Top10AttemptedLogins = "[]",
				ThreatScore = 18,
				IsBlocked = false,
				LastUpdatedUtc = new DateTime(2026, 9, 1, 9, 35, 0, DateTimeKind.Utc),
			});
		});

		using (HttpResponseMessage response = await api.Client.SendAsync(
			CreateAuthedRequest(HttpMethod.Get, "/api/attacks")))
		{
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			JsonElement root = body.RootElement;
			Assert.Equal("Success", root.GetProperty("status").GetString());
			Assert.Equal(2, root.GetProperty("totalMatching").GetInt32());
			Assert.Equal(500, root.GetProperty("appliedLimit").GetInt32());
			Assert.Equal(0, root.GetProperty("failedLogons").GetInt64());
			Assert.Equal(JsonValueKind.String, root.GetProperty("windowStartUtc").ValueKind);
			JsonElement first = root.GetProperty("entries").EnumerateArray().First();
			Assert.Equal("203.0.113.7", first.GetProperty("ip").GetString());
			Assert.Equal(91, first.GetProperty("threatScore").GetDouble());
			Assert.True(first.GetProperty("isBlocked").GetBoolean());
			Assert.Equal(JsonValueKind.String, first.GetProperty("threatLevel").ValueKind);
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			CreateAuthedRequest(HttpMethod.Get, "/api/attacks?onlyBlocked=true")))
		{
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(1, body.RootElement.GetProperty("totalMatching").GetInt32());
			JsonElement entry = body.RootElement.GetProperty("entries").EnumerateArray().Single();
			Assert.Equal("203.0.113.7", entry.GetProperty("ip").GetString());
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			CreateAuthedRequest(HttpMethod.Get, "/api/attacks?minThreatScore=50")))
		{
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(1, body.RootElement.GetProperty("totalMatching").GetInt32());
			JsonElement entry = body.RootElement.GetProperty("entries").EnumerateArray().Single();
			Assert.Equal("203.0.113.7", entry.GetProperty("ip").GetString());
		}

		using (HttpResponseMessage response = await api.Client.SendAsync(
			CreateAuthedRequest(HttpMethod.Get, "/api/attacks?limit=1")))
		{
			using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
			Assert.Equal(2, body.RootElement.GetProperty("totalMatching").GetInt32());
			Assert.Equal(1, body.RootElement.GetProperty("appliedLimit").GetInt32());
			Assert.Equal(1, body.RootElement.GetProperty("entries").GetArrayLength());
		}
	}

	[Theory]
	[InlineData("/api/attacks?minThreatScore=abc")]
	[InlineData("/api/attacks?minThreatScore=-1")]
	[InlineData("/api/attacks?sinceUtc=not-a-time")]
	[InlineData("/api/attacks?untilUtc=not-a-time")]
	[InlineData("/api/attacks?limit=-3")]
	[InlineData("/api/attacks?minThreatScore=NaN")]
	[InlineData("/api/attacks?minThreatScore=Infinity")]
	[InlineData("/api/attacks?minThreatScore=-Infinity")]
	[InlineData("/api/attacks?minThreatScore=101")]
	[InlineData("/api/attacks?untilUtc=0001-01-01")]
	[InlineData("/api/attacks?sinceUtc=1900-01-01")]
	[InlineData("/api/attacks?sinceUtc=2000-01-01&untilUtc=2010-01-01")]
	public async Task ApiAttacks_MalformedQuery_Returns400Problem(string path)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, path);
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
		Assert.Contains("application/problem+json", response.Content.Headers.ContentType?.ToString(), StringComparison.Ordinal);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
	}

	[Fact]
	public async Task ApiConfig_WithValidToken_MasksAllSecrets()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, configure: opts =>
		{
			opts.AbuseIpDb.ApiKey = "abuse-secret";
			opts.MikroTik.Password = "mikrotik-secret";
			opts.Api.Token = "api-secret";
		});

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/config");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		string payload = await response.Content.ReadAsStringAsync();
		Assert.DoesNotContain("abuse-secret", payload, StringComparison.Ordinal);
		Assert.DoesNotContain("mikrotik-secret", payload, StringComparison.Ordinal);
		Assert.DoesNotContain("api-secret", payload, StringComparison.Ordinal);
		using JsonDocument body = JsonDocument.Parse(payload);
		Assert.Equal(
			"***configured***",
			body.RootElement.GetProperty("api").GetProperty("token").GetString());
	}

	[Fact]
	public async Task ApiEvents_WithValidToken_ReturnsBoundedPage()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, seed: db =>
		{
			DateTime start = new(2026, 9, 1, 10, 0, 0, DateTimeKind.Utc);
			for (int i = 1; i <= 5; i++)
			{
				db.RawEvents.Add(new RawEvent
				{
					EventId = i == 5 ? 2000 : 4625,
					Channel = i % 2 == 0 ? "System" : "Security",
					TimeUtc = start.AddMinutes(-i),
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
		});

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/api/events?limit=2");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		JsonElement page = body.RootElement;
		Assert.Equal(0, page.GetProperty("offset").GetInt32());
		Assert.Equal(2, page.GetProperty("limit").GetInt32());
		Assert.Equal(5, page.GetProperty("total").GetInt32());
		Assert.Equal(2, page.GetProperty("events").GetArrayLength());

		// Details must stay omitted unless includeDetails is requested.
		foreach (JsonElement row in page.GetProperty("events").EnumerateArray())
		{
			Assert.False(row.TryGetProperty("details", out _));
			Assert.Equal(JsonValueKind.String, row.GetProperty("timeUtc").ValueKind);
		}
	}

	[Theory]
	[InlineData("a%0Ab")]
	[InlineData("a%0Db")]
	[InlineData("a%09b")]
	[InlineData("a%00b")]
	[InlineData("%0A%3D%3D")]
	public async Task ApiEvents_ControlCharactersInFilter_StillAnswersAPage(string encodedValue)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		// includeExplain is part of the request on purpose: it is the code path that renders the
		// generated SQL text and hands it to EXPLAIN QUERY PLAN, where a line break used to survive
		// normalisation, corrupt the statement and turn the request into a 500.
		using HttpRequestMessage request = CreateAuthedRequest(
			HttpMethod.Get,
			"/api/events?includeExplain=true&userName=" + encodedValue);
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(0, body.RootElement.GetProperty("total").GetInt32());
		Assert.Equal(JsonValueKind.Array, body.RootElement.GetProperty("explainPlan").ValueKind);
	}

	[Fact]
	public async Task ApiEvents_InvalidSourceIp_Returns400()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(
			HttpMethod.Get,
			"/api/events?sourceIp=not-an-ip");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
		Assert.Contains("application/problem+json", response.Content.Headers.ContentType?.ToString(), StringComparison.Ordinal);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(400, body.RootElement.GetProperty("status").GetInt32());
		Assert.Contains(
			"sourceIp",
			body.RootElement.GetProperty("detail").GetString(),
			StringComparison.Ordinal);
	}

	[Fact]
	public async Task ApiEvents_OverLongChannel_Returns400()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		string channel = new('x', PagedEventsQuery.MaxChannelLength + 1);
		using HttpRequestMessage request = CreateAuthedRequest(
			HttpMethod.Get,
			"/api/events?channel=" + channel);
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
	}

	[Fact]
	public async Task ApiEndpoints_RejectPost_With405()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Post, "/api/status");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
	}

	[Fact]
	public async Task OpenApi_WithValidToken_ReturnsEmbeddedDescriptor()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Get, "/openapi/v1.json");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
		string payload = await response.Content.ReadAsStringAsync();
		Assert.Equal(RestApiOpenApiDocument.Content, payload);
		using JsonDocument body = JsonDocument.Parse(payload);
		Assert.Equal("3.0.3", body.RootElement.GetProperty("openapi").GetString());
		Assert.True(body.RootElement.GetProperty("paths").TryGetProperty("/api/status", out _));
	}

	[Fact]
	public async Task OpenApi_WithoutToken_Returns401()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		HttpResponseMessage response = await api.Client.GetAsync(new Uri("/openapi/v1.json", UriKind.Relative));

		Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
	}

	[Theory]
	[InlineData("/api/status")]
	[InlineData("/api/alerts")]
	[InlineData("/api/sessions")]
	[InlineData("/api/addresses")]
	[InlineData("/api/attacks")]
	[InlineData("/api/config")]
	[InlineData("/api/events")]
	[InlineData("/openapi/v1.json")]
	public async Task EveryProtectedEndpoint_WithoutToken_Returns401(string path)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		HttpResponseMessage response = await api.Client.GetAsync(new Uri(path, UriKind.Relative));

		Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		Assert.Equal("Bearer realm=\"rdpaudit\"", response.Headers.WwwAuthenticate.ToString());
	}

	[Theory]
	[InlineData("/api/status")]
	[InlineData("/api/alerts")]
	[InlineData("/api/sessions")]
	[InlineData("/api/addresses")]
	[InlineData("/api/attacks")]
	[InlineData("/api/config")]
	[InlineData("/api/events")]
	[InlineData("/openapi/v1.json")]
	public async Task EveryProtectedEndpoint_WithInvalidToken_Returns401(string path)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = new(HttpMethod.Get, path);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-token");
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
	}

	[Theory]
	[InlineData("/api/status")]
	[InlineData("/api/alerts")]
	[InlineData("/api/sessions")]
	[InlineData("/api/addresses")]
	[InlineData("/api/attacks")]
	[InlineData("/api/config")]
	[InlineData("/api/events")]
	[InlineData("/openapi/v1.json")]
	public async Task EveryProtectedEndpoint_RejectsPost_With405(string path)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Post, path);
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
	}

	[Theory]
	[InlineData("/api/status")]
	[InlineData("/api/alerts")]
	[InlineData("/api/sessions")]
	[InlineData("/api/addresses")]
	[InlineData("/api/attacks")]
	[InlineData("/api/config")]
	[InlineData("/api/events")]
	[InlineData("/openapi/v1.json")]
	public async Task EveryProtectedEndpoint_HeadRequest_Returns200(string path)
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath);

		using HttpRequestMessage request = CreateAuthedRequest(HttpMethod.Head, path);
		HttpResponseMessage response = await api.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
	}

	[Fact]
	public async Task RateLimit_ExhaustsBudget_Returns429WithProblemAndRetryAfter()
	{
		string dbPath = await CreateDbAsync();
		await using ApiHarness api = CreateApi(dbPath, rateLimitPerMinute: 2);

		using HttpRequestMessage first = CreateAuthedRequest(HttpMethod.Get, "/api/status");
		using HttpResponseMessage firstResponse = await api.Client.SendAsync(first);
		Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

		using HttpRequestMessage second = CreateAuthedRequest(HttpMethod.Get, "/api/status");
		using HttpResponseMessage secondResponse = await api.Client.SendAsync(second);
		Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);

		using HttpRequestMessage third = CreateAuthedRequest(HttpMethod.Get, "/api/status");
		HttpResponseMessage blocked = await api.Client.SendAsync(third);

		Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
		Assert.NotNull(blocked.Headers.RetryAfter);
		Assert.Contains("application/problem+json", blocked.Content.Headers.ContentType?.ToString(), StringComparison.Ordinal);
		using JsonDocument body = JsonDocument.Parse(await blocked.Content.ReadAsStringAsync());
		Assert.Equal("Too Many Requests", body.RootElement.GetProperty("title").GetString());
		Assert.Equal(429, body.RootElement.GetProperty("status").GetInt32());
	}
}