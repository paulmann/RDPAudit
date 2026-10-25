// File:    tests/RdpAudit.Service.Tests/AbuseIpDbClientTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: HttpMessageHandler-driven tests for the Stage 8 AbuseIpDbClient. Verifies that the
//          request is POSTed to the configured endpoint, carries the required Key header and
//          Accept: application/json header, encodes ip / categories / comment as form fields, and
//          classifies 2xx / 4xx / 429 / 5xx responses correctly. The API key never appears in the
//          test-side logging — only in the simulated HTTP request.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using RdpAudit.Service.AbuseIpDb;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AbuseIpDbClientTests
{
	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class StubFactory : IHttpClientFactory
	{
		private readonly HttpMessageHandler _handler;
		public StubFactory(HttpMessageHandler handler) => _handler = handler;
		public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
	}

	private sealed class CapturingHandler : HttpMessageHandler
	{
		public HttpRequestMessage? LastRequest { get; private set; }
		public string? LastBody { get; private set; }

		public HttpResponseMessage NextResponse { get; set; } = new(HttpStatusCode.OK);

		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			LastRequest = request;
			if (request.Content is not null)
			{
				LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
			}
			return NextResponse;
		}
	}

	private static (AbuseIpDbClient Client, CapturingHandler Handler, InMemorySecretProtector Protector) Build(AbuseIpDbOptions opts)
	{
		RdpAuditOptions rd = new();
		rd.AbuseIpDb = opts;

		CapturingHandler handler = new();
		InMemorySecretProtector protector = new();
		AbuseIpDbClient client = new(
			new StubFactory(handler),
			new StaticOptionsMonitorLocal<RdpAuditOptions>(rd),
			protector,
			NullLogger<AbuseIpDbClient>.Instance);

		return (client, handler, protector);
	}

	[Fact]
	public async Task ReportAsync_ReturnsNotConfigured_WhenDisabled()
	{
		AbuseIpDbOptions opts = new() { Enabled = false, ReportAttacks = false };
		(AbuseIpDbClient client, _, _) = Build(opts);

		AbuseIpDbReportResult result = await client.ReportAsync(new AbuseIpDbReportRequest
		{
			Ip = "203.0.113.10",
			Categories = "18,22",
			Comment = "test",
		}, CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.NotConfigured, result.Outcome);
	}

	[Fact]
	public async Task ReportAsync_PostsExpectedBodyAndHeaders_On200()
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			ReportAttacks = true,
			EndpointUrl = "https://api.example.test/api/v2/report",
			TimeoutSeconds = 5,
		};

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('a', 80));

		AbuseIpDbReportResult result = await client.ReportAsync(new AbuseIpDbReportRequest
		{
			Ip = "203.0.113.10",
			Categories = "18,22",
			Comment = "RDP brute force",
		}, CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.Accepted, result.Outcome);
		Assert.Equal(200, result.ResponseCode);

		Assert.NotNull(handler.LastRequest);
		Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
		Assert.Equal("https://api.example.test/api/v2/report", handler.LastRequest.RequestUri!.ToString());
		Assert.True(handler.LastRequest.Headers.TryGetValues("Key", out IEnumerable<string>? key));
		Assert.Equal(new string('a', 80), Assert.Single(key!));
		Assert.Contains(new MediaTypeWithQualityHeaderValue("application/json"), handler.LastRequest.Headers.Accept);

		Assert.NotNull(handler.LastBody);
		Assert.Contains("ip=203.0.113.10", handler.LastBody!, StringComparison.Ordinal);
		Assert.Contains("categories=18%2C22", handler.LastBody, StringComparison.Ordinal);
		Assert.Contains("comment=RDP+brute+force", handler.LastBody, StringComparison.Ordinal);
	}

	[Fact]
	public async Task ReportAsync_Maps429_ToRateLimited_WithRetryAfter()
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			ReportAttacks = true,
		};

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('a', 80));

		HttpResponseMessage resp = new(HttpStatusCode.TooManyRequests);
		resp.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
		handler.NextResponse = resp;

		AbuseIpDbReportResult result = await client.ReportAsync(new AbuseIpDbReportRequest
		{
			Ip = "203.0.113.10",
			Categories = "18",
			Comment = "x",
		}, CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.RateLimited, result.Outcome);
		Assert.Equal(429, result.ResponseCode);
		Assert.NotNull(result.RetryAfter);
		Assert.Equal(TimeSpan.FromSeconds(120), result.RetryAfter);
	}

	[Fact]
	public async Task ReportAsync_Maps401_ToRejected()
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			ReportAttacks = true,
		};

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('a', 80));

		handler.NextResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);

		AbuseIpDbReportResult result = await client.ReportAsync(new AbuseIpDbReportRequest
		{
			Ip = "203.0.113.10",
			Categories = "18",
			Comment = "x",
		}, CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.Rejected, result.Outcome);
		Assert.Equal(401, result.ResponseCode);
	}

	[Fact]
	public async Task ReportAsync_Maps503_ToServerError()
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			ReportAttacks = true,
		};

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('a', 80));

		handler.NextResponse = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

		AbuseIpDbReportResult result = await client.ReportAsync(new AbuseIpDbReportRequest
		{
			Ip = "203.0.113.10",
			Categories = "18",
			Comment = "x",
		}, CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.ServerError, result.Outcome);
		Assert.Equal(503, result.ResponseCode);
	}

	[Fact]
	public async Task ValidateKeyAsync_HitsCheckEndpoint_On200()
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			BaseUrl = "https://api.example.test",
		};

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('b', 80));

		AbuseIpDbReportResult result = await client.ValidateKeyAsync(CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.Accepted, result.Outcome);
		Assert.NotNull(handler.LastRequest);
		Assert.Equal(HttpMethod.Get, handler.LastRequest!.Method);
		Assert.Contains("/api/v2/check", handler.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
		Assert.Contains("127.0.0.1", handler.LastRequest.RequestUri.Query, StringComparison.Ordinal);
	}

	[Fact]
	public async Task ValidateKeyAsync_Returns_Rejected_On401()
	{
		AbuseIpDbOptions opts = new();

		(AbuseIpDbClient client, CapturingHandler handler, InMemorySecretProtector protector) = Build(opts);
		opts.ApiKey = protector.Protect(new string('c', 80));
		handler.NextResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);

		AbuseIpDbReportResult result = await client.ValidateKeyAsync(CancellationToken.None);

		Assert.Equal(AbuseIpDbReportOutcome.Rejected, result.Outcome);
		Assert.Equal(401, result.ResponseCode);
	}
}
