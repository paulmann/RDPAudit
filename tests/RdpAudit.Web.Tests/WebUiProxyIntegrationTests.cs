// File:    tests/RdpAudit.Web.Tests/WebUiProxyIntegrationTests.cs
// Module:  RdpAudit.Web.Tests
// Purpose: Verification of plan step 4 (the RdpAudit.Web proxy project). Boots the exact
//          production pipeline via WebUiProxyApp.Build on an ASP.NET Core TestServer with the
//          real wwwroot and a raw-TCP loopback fake backend, then asserts the three contracts
//          the step requires: the server-side bearer header is injected and the browser's own
//          Authorization is dropped; wwwroot statics and security headers are served; backend
//          failures translate to 502 and vault failures to a curated 503 problem response.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RdpAudit.Core.Security;
using RdpAudit.Web.Hosting;
using RdpAudit.Web.Proxy;
using Xunit;

namespace RdpAudit.Web.Tests;

public sealed class WebUiProxyIntegrationTests
{
	private const string VaultToken = "vault-token-0123456789abcdef0123456789abcdef";

	[Fact]
	public async Task Proxy_ForwardsWithServerToken_AndDropsBrowserToken()
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new StubTokenProvider(VaultToken));

		using HttpRequestMessage request = new(HttpMethod.Get, "/api/status");
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "browser-secret-value");
		using HttpResponseMessage response = await harness.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal("Bearer " + VaultToken, body.RootElement.GetProperty("authorization").GetString());
		BackendRequestRecord record = Assert.Single(backend.Requests);
		Assert.Equal("/api/status", record.Path);
		Assert.Equal(HttpMethod.Get.Method, record.Method);
	}

	[Fact]
	public async Task Static_IndexHtml_IsServed_WithSecurityHeaders()
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new StubTokenProvider());

		using HttpResponseMessage response = await harness.Client.GetAsync(new Uri("/", UriKind.Relative));

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		Assert.StartsWith("text/html", response.Content.Headers.ContentType?.MediaType, StringComparison.Ordinal);
		string body = await response.Content.ReadAsStringAsync();
		Assert.Contains("RdpAudit Web Access", body, StringComparison.Ordinal);
		Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
		Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
		Assert.Empty(backend.Requests);
	}

	[Fact]
	public async Task Proxy_UnreachableBackend_Returns502Problem()
	{
		int closedPort = FakeBackendServer.ReserveThenClosePort();
		string backendUrl = "http://127.0.0.1:" + closedPort.ToString(
			System.Globalization.CultureInfo.InvariantCulture);
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backendUrl,
			new StubTokenProvider());

		using HttpResponseMessage response = await harness.Client.GetAsync(new Uri("/api/anything", UriKind.Relative));

		Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
		Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(502, body.RootElement.GetProperty("status").GetInt32());
	}

	[Fact]
	public async Task Proxy_TokenProviderFailure_Returns503_WithoutTouchingBackend()
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new ThrowingTokenProvider());

		using HttpResponseMessage response = await harness.Client.GetAsync(new Uri("/api/status", UriKind.Relative));

		Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
		Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
		using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
		Assert.Equal(503, body.RootElement.GetProperty("status").GetInt32());
		Assert.Contains("token", body.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
		Assert.Empty(backend.Requests);
	}

	[Fact]
	public async Task ForeignHost_ApiRequest_IsRejectedWith400_AndNeverReachesBackend()
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new StubTokenProvider(VaultToken));

		using HttpRequestMessage request = new(HttpMethod.Get, "/api/status");
		request.Headers.Host = "evil.example.com";
		using HttpResponseMessage response = await harness.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
		Assert.Empty(backend.Requests);
	}

	[Fact]
	public async Task ForeignHost_StaticRequest_IsRejectedWith400()
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new StubTokenProvider());

		using HttpRequestMessage request = new(HttpMethod.Get, "/");
		request.Headers.Host = "attacker.test";
		using HttpResponseMessage response = await harness.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
	}

	[Theory]
	[InlineData("127.0.0.1")]
	[InlineData("localhost")]
	[InlineData("localhost.")]
	[InlineData("[::1]")]
	public async Task LoopbackHost_StaticRequest_IsServed(string host)
	{
		await using FakeBackendServer backend = FakeBackendServer.Start();
		await using WebProxyHarness harness = await WebProxyHarness.CreateAsync(
			backend.BaseUrl,
			new StubTokenProvider());

		using HttpRequestMessage request = new(HttpMethod.Get, "/");
		request.Headers.Host = host;
		using HttpResponseMessage response = await harness.Client.SendAsync(request);

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
	}

	private static string FindWebRoot()
	{
		DirectoryInfo? current = new(AppContext.BaseDirectory);
		while (current is not null)
		{
			if (File.Exists(Path.Combine(current.FullName, "RdpAudit.sln")))
			{
				string webRoot = Path.Combine(current.FullName, "src", "RdpAudit.Web", "wwwroot");
				if (Directory.Exists(webRoot))
				{
					return webRoot;
				}
			}

			current = current.Parent;
		}

		throw new InvalidOperationException("The repository root (RdpAudit.sln) could not be located from '"
			+ AppContext.BaseDirectory + "'.");
	}

	/// <summary>TestServer harness around the real WebUiProxyApp.Build pipeline.</summary>
	private sealed class WebProxyHarness : IAsyncDisposable
	{
		private readonly WebApplication _app;

		private WebProxyHarness(WebApplication app)
		{
			_app = app;
			Client = app.GetTestServer().CreateClient();
		}

		public HttpClient Client { get; }

		public static async Task<WebProxyHarness> CreateAsync(
			string backendUrl,
			IWebUiTokenProvider tokenProvider)
		{
			WebApplication app = WebUiProxyApp.Build(
				[],
				new WebApplicationOptions
				{
					WebRootPath = FindWebRoot(),
				},
				builder =>
				{
					builder.WebHost.UseTestServer();
					builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
					{
						["WebUiProxy:BackendBaseUrl"] = backendUrl,
					});
				},
				services => services.AddSingleton(tokenProvider));
			await app.StartAsync();
			return new WebProxyHarness(app);
		}

		public async ValueTask DisposeAsync()
		{
			Client.Dispose();
			await _app.StopAsync();
			await _app.DisposeAsync();
		}
	}

	private sealed class StubTokenProvider : IWebUiTokenProvider
	{
		private readonly string _token;

		public StubTokenProvider(string token = VaultToken) => _token = token;

		public Task<string> GetTokenAsync(CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();
			return Task.FromResult(_token);
		}
	}

	private sealed class ThrowingTokenProvider : IWebUiTokenProvider
	{
		public Task<string> GetTokenAsync(CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();
			throw new SecretProtectionException("The web-UI token vault is unavailable for this test.");
		}
	}
}
