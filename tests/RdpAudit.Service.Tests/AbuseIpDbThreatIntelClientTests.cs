// File:    tests/RdpAudit.Service.Tests/AbuseIpDbThreatIntelClientTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: HttpMessageHandler-driven tests for the Backlog #5 AbuseIpDbThreatIntelClient.
//          Verifies that only public IP literals are sent, the /api/v2/check query carries
//          ipAddress / maxAgeInDays / verbose, the Key header carries the unprotected API key
//          (and never leaks into results), and 2xx / 4xx / 429 / 5xx / malformed-body and
//          transport failures are classified fail-closed into their lookup outcomes.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Service.ThreatIntel;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AbuseIpDbThreatIntelClientTests
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
		private const string CanonicalPayload =
			"{\"data\":{\"abuseConfidenceScore\":75,\"totalReports\":9,\"isWhitelisted\":false,\"isPublic\":true,\"usageType\":\"Data Center\",\"countryCode\":\"US\"}}";

		public HttpRequestMessage? LastRequest { get; private set; }
		public HttpResponseMessage NextResponse { get; set; } = new(HttpStatusCode.OK)
		{
			Content = new StringContent(CanonicalPayload, System.Text.Encoding.UTF8, "application/json"),
		};
		public Exception? NextException { get; set; }

		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			LastRequest = request;
			if (NextException is not null)
			{
				throw NextException;
			}

			return Task.FromResult(NextResponse);
		}
	}

	private sealed record Customized(AbuseIpDbThreatIntelClient Client, CapturingHandler Handler, InMemorySecretProtector Protector);

	private static Customized Build(AbuseIpDbOptions opts)
	{
		RdpAuditOptions rd = new();
		rd.AbuseIpDb = opts;

		CapturingHandler handler = new();
		InMemorySecretProtector protector = new();
		AbuseIpDbThreatIntelClient client = new(
			new StubFactory(handler),
			new StaticOptionsMonitorLocal<RdpAuditOptions>(rd),
			protector,
			NullLogger<AbuseIpDbThreatIntelClient>.Instance);

		return new Customized(client, handler, protector);
	}

	private static Customized BuildDefault(string? plaintextKey = null)
	{
		AbuseIpDbOptions opts = new()
		{
			Enabled = true,
			CheckEnabled = true,
			CacheLookups = true,
			BaseUrl = "https://api.example.test",
		};
		Customized customized = Build(opts);
		if (plaintextKey is not null)
		{
			opts.ApiKey = customized.Protector.Protect(plaintextKey);
		}

		return customized;
	}

	[Fact]
	public async Task LookupAsync_ReturnsNotConfigured_WhenDisabled()
	{
		AbuseIpDbOptions opts = new() { Enabled = false, CheckEnabled = true, CacheLookups = true };
		Customized customized = Build(opts);

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.NotConfigured, result.Outcome);
		Assert.Null(customized.Handler.LastRequest);
	}

	[Fact]
	public async Task LookupAsync_ReturnsNotConfigured_WhenCheckDisabled()
	{
		AbuseIpDbOptions opts = new() { Enabled = true, CheckEnabled = false, CacheLookups = true };
		Customized customized = Build(opts);

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.NotConfigured, result.Outcome);
		Assert.Null(customized.Handler.LastRequest);
	}

	[Fact]
	public async Task LookupAsync_ReturnsNotConfigured_WithoutApiKey()
	{
		Customized customized = BuildDefault();

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.NotConfigured, result.Outcome);
		Assert.Null(customized.Handler.LastRequest);
	}

	[Fact]
	public async Task LookupAsync_RefusesPrivateIp_WithoutHttp()
	{
		Customized customized = BuildDefault(new string('a', 80));

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("192.168.1.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.Rejected, result.Outcome);
		Assert.Null(customized.Handler.LastRequest);
		Assert.DoesNotContain(new string('a', 80), result.Message, StringComparison.Ordinal);
	}

	[Fact]
	public async Task LookupAsync_RefusesLoopback_WithoutHttp()
	{
		Customized customized = BuildDefault(new string('a', 80));

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("127.0.0.1", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.Rejected, result.Outcome);
		Assert.Null(customized.Handler.LastRequest);
	}

	[Fact]
	public async Task LookupAsync_SendsExpectedGetHeadersAndMapsPayload_On200()
	{
		Customized customized = BuildDefault(new string('a', 80));

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.Success, result.Outcome);
		Assert.Equal(75, result.AbuseConfidenceScore);
		Assert.Equal(9, result.TotalReports);
		Assert.False(result.IsWhitelisted);
		Assert.True(result.IsPublic);
		Assert.Equal("Data Center", result.UsageType);
		Assert.Equal("US", result.CountryCode);

		Assert.NotNull(customized.Handler.LastRequest);
		Assert.Equal(HttpMethod.Get, customized.Handler.LastRequest!.Method);
		Assert.Equal("https://api.example.test/api/v2/check",
			customized.Handler.LastRequest.RequestUri!.GetLeftPart(UriPartial.Path));
		Assert.Contains("ipAddress=203.0.113.10", customized.Handler.LastRequest.RequestUri.Query, StringComparison.Ordinal);
		Assert.Contains("maxAgeInDays=30", customized.Handler.LastRequest.RequestUri.Query, StringComparison.Ordinal);
		Assert.Contains("verbose", customized.Handler.LastRequest.RequestUri.Query, StringComparison.Ordinal);
		Assert.True(customized.Handler.LastRequest.Headers.TryGetValues("Key", out IEnumerable<string>? key));
		Assert.Equal(new string('a', 80), Assert.Single(key!));
		Assert.Contains(new MediaTypeWithQualityHeaderValue("application/json"), customized.Handler.LastRequest.Headers.Accept);
	}

	[Fact]
	public async Task LookupAsync_ClampsAbuseConfidenceScore_To100()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent("{\"data\":{\"abuseConfidenceScore\":240}}", System.Text.Encoding.UTF8, "application/json"),
		};

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.Success, result.Outcome);
		Assert.Equal(100, result.AbuseConfidenceScore);
	}

	[Fact]
	public async Task LookupAsync_Maps429_ToRateLimited_WithRetryAfter()
	{
		Customized customized = BuildDefault(new string('a', 80));
		HttpResponseMessage resp = new(HttpStatusCode.TooManyRequests);
		resp.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
		customized.Handler.NextResponse = resp;

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.RateLimited, result.Outcome);
		Assert.Equal(429, result.ResponseCode);
		Assert.NotNull(result.RetryAfter);
		Assert.Equal(TimeSpan.FromSeconds(120), result.RetryAfter);
	}

	[Fact]
	public async Task LookupAsync_Maps401_ToRejected()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized);

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.Rejected, result.Outcome);
		Assert.Equal(401, result.ResponseCode);
	}

	[Fact]
	public async Task LookupAsync_Maps503_ToServerError()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.ServerError, result.Outcome);
		Assert.Equal(503, result.ResponseCode);
	}

	[Fact]
	public async Task LookupAsync_InvalidJson_ToMalformedResponse()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent("{not json}", System.Text.Encoding.UTF8, "application/json"),
		};

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.MalformedResponse, result.Outcome);
		Assert.Null(result.AbuseConfidenceScore);
	}

	[Fact]
	public async Task LookupAsync_MissingDataObject_ToMalformedResponse()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent("{\"errors\":[{\"detail\":\"x\"}]}", System.Text.Encoding.UTF8, "application/json"),
		};

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.MalformedResponse, result.Outcome);
	}

	[Fact]
	public async Task LookupAsync_EmptyBody_ToMalformedResponse()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(string.Empty, System.Text.Encoding.UTF8, "application/json"),
		};

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.MalformedResponse, result.Outcome);
	}

	[Fact]
	public async Task LookupAsync_HttpRequestException_ToTransportError()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextException = new HttpRequestException("network down");

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.TransportError, result.Outcome);
		Assert.Equal(0, result.ResponseCode);
	}

	[Fact]
	public async Task LookupAsync_TaskCanceled_ToTransportError()
	{
		Customized customized = BuildDefault(new string('a', 80));
		customized.Handler.NextException = new TaskCanceledException("timeout");

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.Equal(ThreatIntelLookupOutcome.TransportError, result.Outcome);
	}

	[Fact]
	public async Task LookupAsync_NeverLeaksKey_InResultMessage()
	{
		Customized customized = BuildDefault(new string('x', 80));
		customized.Handler.NextResponse = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

		ThreatIntelLookupResult result = await customized.Client.LookupAsync("203.0.113.10", CancellationToken.None);

		Assert.DoesNotContain(new string('x', 80), result.Message, StringComparison.Ordinal);
	}
}
