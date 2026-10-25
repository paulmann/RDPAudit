// File:    tests/RdpAudit.Service.Tests/RestApiRateLimitTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for RestApiRateLimitMiddleware: per-IP budget consumption, 429 with
//          Retry-After and an RFC 9457 problem+json body, fixed-window reset, per-client
//          isolation and input validation. A mutable clock makes window transitions deterministic.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RestApiRateLimitTests
{
	private sealed class MutableClock : TimeProvider
	{
		public DateTimeOffset UtcNow { get; set; } =
			new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

		public override DateTimeOffset GetUtcNow() => UtcNow;
	}

	private static DefaultHttpContext CreateContext(string? remoteIp = "203.0.113.7")
	{
		DefaultHttpContext context = new();
		context.Response.Body = new MemoryStream();
		if (remoteIp is not null)
		{
			context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
		}

		return context;
	}

	private static (RequestDelegate Next, Func<int> Calls) CountingNext()
	{
		int calls = 0;
		RequestDelegate next = _ =>
		{
			calls++;
			return Task.CompletedTask;
		};
		return (next, () => calls);
	}

	private static async Task<JsonDocument> ReadProblemAsync(DefaultHttpContext context)
	{
		context.Response.Body.Position = 0;
		using StreamReader reader = new(context.Response.Body, leaveOpen: true);
		return JsonDocument.Parse(await reader.ReadToEndAsync());
	}

	[Fact]
	public void GetClientKey_WithRemoteIp_ReturnsLiteral()
	{
		DefaultHttpContext context = CreateContext("203.0.113.7");

		Assert.Equal("203.0.113.7", RestApiRateLimitMiddleware.GetClientKey(context));
	}

	[Fact]
	public void GetClientKey_WithoutRemoteIp_ReturnsUnknown()
	{
		DefaultHttpContext context = new();

		Assert.Equal("unknown", RestApiRateLimitMiddleware.GetClientKey(context));
	}

	[Fact]
	public async Task InvokeAsync_WithinBudget_InvokesNextEveryTime()
	{
		(RequestDelegate next, Func<int> calls) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 2);

		await middleware.InvokeAsync(CreateContext());
		await middleware.InvokeAsync(CreateContext());

		Assert.Equal(2, calls());
	}

	[Fact]
	public async Task InvokeAsync_OverBudget_Returns429WithRetryAfterAndProblem()
	{
		(RequestDelegate next, Func<int> calls) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 2);
		await middleware.InvokeAsync(CreateContext());
		await middleware.InvokeAsync(CreateContext());
		DefaultHttpContext context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.Equal(2, calls());
		Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
		Assert.True(
			int.TryParse(
				context.Response.Headers[HeaderNames.RetryAfter].ToString(),
				System.Globalization.NumberStyles.None,
				System.Globalization.CultureInfo.InvariantCulture,
				out int retryAfter)
			&& retryAfter > 0,
			"Retry-After must be a positive second count.");
		Assert.Equal(RestApiProblem.MediaType, context.Response.ContentType);
		using JsonDocument body = await ReadProblemAsync(context);
		Assert.Equal("Too Many Requests", body.RootElement.GetProperty("title").GetString());
		Assert.Equal(429, body.RootElement.GetProperty("status").GetInt32());
	}

	[Fact]
	public async Task InvokeAsync_WindowReset_AllowsRequestAgain()
	{
		MutableClock clock = new();
		(RequestDelegate next, Func<int> calls) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 1, clock);
		await middleware.InvokeAsync(CreateContext());
		Assert.Equal(1, calls());

		DefaultHttpContext blocked = CreateContext();
		await middleware.InvokeAsync(blocked);
		Assert.Equal(StatusCodes.Status429TooManyRequests, blocked.Response.StatusCode);

		clock.UtcNow = clock.UtcNow.AddMinutes(1);
		DefaultHttpContext allowed = CreateContext();
		await middleware.InvokeAsync(allowed);

		Assert.Equal(2, calls());
	}

	[Fact]
	public async Task InvokeAsync_BudgetsArePerClientIp()
	{
		(RequestDelegate next, Func<int> calls) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 1);

		await middleware.InvokeAsync(CreateContext("203.0.113.7"));
		await middleware.InvokeAsync(CreateContext("203.0.113.8"));

		Assert.Equal(2, calls());
	}

	[Fact]
	public async Task InvokeAsync_ZeroBudget_ClampsToOneRequest()
	{
		(RequestDelegate next, Func<int> calls) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 0);
		await middleware.InvokeAsync(CreateContext());
		DefaultHttpContext context = CreateContext();

		await middleware.InvokeAsync(context);

		Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
		Assert.Equal(1, calls());
	}

	[Fact]
	public async Task InvokeAsync_WithNullContext_Throws()
	{
		(RequestDelegate next, _) = CountingNext();
		RestApiRateLimitMiddleware middleware = new(next, 2);

		await Assert.ThrowsAsync<ArgumentNullException>(() => middleware.InvokeAsync(null!));
	}
}
