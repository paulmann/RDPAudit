// File:    tests/RdpAudit.Service.Tests/Scenarios/RestApiTestApp.cs
// Module:  RdpAudit.Service.Tests.Scenarios
// Purpose: Shared harness for the tier-3 REST API scenario tests. Boots the real
//          RestApiHostedService.CreateApiApplication pipeline (service-scope bridge, status-code
//          pages, security headers, rate limiter, bearer auth and endpoints) on an ASP.NET Core
//          TestServer against a temporary SQLite database, exposes the HTTP client plus the
//          runtime route table, and disposes everything at the end of the test.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.RestApi;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.RestApi;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>TestServer-backed read-only REST API with the outer-container scope bridge.</summary>
internal sealed class RestApiTestApp : IAsyncDisposable
{
	public const string BearerToken = "test-secret-token";

	private readonly WebApplication _app;
	private readonly TestServer _server;
	private readonly ServiceProvider _root;
	private readonly string _dbPath;

	private RestApiTestApp(WebApplication app, TestServer server, ServiceProvider root, string dbPath)
	{
		_app = app;
		_server = server;
		_root = root;
		_dbPath = dbPath;
		Client = server.CreateClient();

		Dictionary<string, List<string>> methodsByPath = new(StringComparer.Ordinal);
		foreach (EndpointDataSource dataSource in ((IEndpointRouteBuilder)app).DataSources)
		{
			foreach (Endpoint endpoint in dataSource.Endpoints)
			{
				if (endpoint is not RouteEndpoint route
					|| route.RoutePattern.RawText is null
					|| endpoint.Metadata.GetMetadata<HttpMethodMetadata>() is not { } methodMetadata)
				{
					continue;
				}

				if (!methodsByPath.TryGetValue(route.RoutePattern.RawText, out List<string>? methods))
				{
					methods = [];
					methodsByPath.Add(route.RoutePattern.RawText, methods);
				}

				foreach (string method in methodMetadata.HttpMethods)
				{
					if (!methods.Contains(method, StringComparer.Ordinal))
					{
						methods.Add(method);
					}
				}
			}
		}

		Paths = methodsByPath.Keys.OrderBy(static path => path, StringComparer.Ordinal).ToArray();
		MethodsByPath = methodsByPath.ToDictionary(
			static pair => pair.Key,
			static pair => (IReadOnlyList<string>)pair.Value.OrderBy(static m => m, StringComparer.Ordinal).ToArray(),
			StringComparer.Ordinal);
	}

	public HttpClient Client { get; }

	/// <summary>Distinct route paths served by the runtime application (e.g. /healthz, /api/status).</summary>
	public IReadOnlyList<string> Paths { get; }

	/// <summary>HTTP methods allowed per path in the runtime route table.</summary>
	public IReadOnlyDictionary<string, IReadOnlyList<string>> MethodsByPath { get; }

	public HttpRequestMessage CreateAuthedRequest(HttpMethod method, string path)
	{
		HttpRequestMessage request = new(method, path);
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", BearerToken);
		return request;
	}

	public static async Task<RestApiTestApp> CreateAsync(
		Action<AuditDbContext>? seed = null,
		int rateLimitPerMinute = 60,
		Action<RdpAuditOptions>? configure = null)
	{
		string dbPath = Path.Combine(
			Path.GetTempPath(),
			"rdpaudit-restapi-scenario-" + Guid.NewGuid().ToString("N") + ".db");
		try
		{
			{
				await using SqliteConnection connection = new(AuditDbContextOptionsFactory.BuildConnectionString(dbPath));
				await connection.OpenAsync();
			}

			await using (AuditDbContext init = new(AuditDbContextOptionsFactory.Create(dbPath)))
			{
				await init.Database.EnsureCreatedAsync();
			}

			if (seed is not null)
			{
				await using (AuditDbContext seeder = new(AuditDbContextOptionsFactory.Create(dbPath)))
				{
					seed(seeder);
					await seeder.SaveChangesAsync();
				}
			}

			RdpAuditOptions options = new();
			options.Storage.DatabasePath = dbPath;
			configure?.Invoke(options);

			ServiceCollection services = new();
			services.AddSingleton(CreateDispatcher(options, dbPath));
			services.AddSingleton<IPagedEventReader>(new PagedEventReader(
				new ReadOnlyAuditDbContextFactory(new StaticOptionsMonitor<RdpAuditOptions>(options))));
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
			await app.StartAsync();
			return new RestApiTestApp(app, app.GetTestServer(), root, dbPath);
		}
		catch
		{
			TryDeleteDatabase(dbPath);
			throw;
		}
	}

	public async ValueTask DisposeAsync()
	{
		Client.Dispose();
		await _app.StopAsync(default);
		await _app.DisposeAsync();
		_server.Dispose();
		_root.Dispose();
		TryDeleteDatabase(_dbPath);
	}

	private static IpcDispatcher CreateDispatcher(RdpAuditOptions options, string dbPath)
	{
		IDbContextFactory<AuditDbContext> factory = new TestDbContextFactory(
			AuditDbContextOptionsFactory.Create(dbPath));
		ServiceMetrics metrics = new();
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(options);
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
}
