// File:    tests/RdpAudit.Service.Tests/RestApiBearerAuthTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for RestApiBearerAuthMiddleware: /healthz bypass, 401 with a generic
//          WWW-Authenticate challenge for missing/invalid tokens, and pass-through for a valid
//          bearer token. The middleware never reveals whether a token exists.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public class RestApiBearerAuthTests
{
	private const string ExpectedToken = "rdp-api-super-secret-token";

	private static RestApiBearerAuthMiddleware CreateMiddleware(RequestDelegate next)
		=> new(next, new ApiTokenResolver(ExpectedToken));

	private static bool _nextInvoked;

	private static RequestDelegate TrackingNext()
	{
		_nextInvoked = false;
		return static inner =>
		{
			_nextInvoked = true;
			inner.Response.StatusCode = StatusCodes.Status200OK;
			return Task.CompletedTask;
		};
	}

	private static async Task<DefaultHttpContext> RunAsync(
		string path,
		string? authorization,
		RequestDelegate? next = null)
	{
		DefaultHttpContext context = new();
		context.Request.Path = path;
		context.Response.Body = new MemoryStream();
		if (authorization is not null)
		{
			context.Request.Headers[HeaderNames.Authorization] = authorization;
		}

		await CreateMiddleware(next ?? TrackingNext()).InvokeAsync(context);
		return context;
	}

	[Theory]
	[InlineData("/healthz")]
	[InlineData("/HEALTHZ")]
	public async Task InvokeAsync_WithHealthPath_ByPassesAuth(string path)
	{
		DefaultHttpContext context = await RunAsync(path, null);

		Assert.True(_nextInvoked);
		Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
	}

	[Fact]
	public async Task InvokeAsync_WithValidToken_InvokesNext()
	{
		DefaultHttpContext context = await RunAsync("/api/events", "Bearer " + ExpectedToken);

		Assert.True(_nextInvoked);
		Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
	}

	[Fact]
	public async Task InvokeAsync_WithValidTokenWithPadding_InvokesNext()
	{
		DefaultHttpContext context = await RunAsync("/api/status", "Bearer  " + ExpectedToken + " ");

		Assert.True(_nextInvoked);
		Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
	}

	[Fact]
	public async Task InvokeAsync_WithoutAuthorization_Returns401WithChallenge()
	{
		DefaultHttpContext context = await RunAsync("/api/events", null);

		Assert.False(_nextInvoked);
		Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
		Assert.Equal("Bearer realm=\"rdpaudit\"", context.Response.Headers[HeaderNames.WWWAuthenticate].ToString());
	}

	[Fact]
	public async Task InvokeAsync_WithInvalidToken_Returns401WithChallenge()
	{
		DefaultHttpContext context = await RunAsync("/api/events", "Bearer wrong-token");

		Assert.False(_nextInvoked);
		Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
		Assert.Equal("Bearer realm=\"rdpaudit\"", context.Response.Headers[HeaderNames.WWWAuthenticate].ToString());
	}

	[Fact]
	public async Task InvokeAsync_WithNonBearerScheme_Returns401()
	{
		DefaultHttpContext context = await RunAsync(
			"/api/events",
			"Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("u:p")));

		Assert.False(_nextInvoked);
		Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
		Assert.Equal("Bearer realm=\"rdpaudit\"", context.Response.Headers[HeaderNames.WWWAuthenticate].ToString());
	}

	[Fact]
	public async Task InvokeAsync_WithBlankBearerToken_Returns401()
	{
		DefaultHttpContext context = await RunAsync("/api/events", "Bearer   ");

		Assert.False(_nextInvoked);
		Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
	}

	[Fact]
	public async Task InvokeAsync_WithOpenApiPath_RequiresToken()
	{
		// The OpenAPI descriptor is part of the guarded surface: it must not be anonymous.
		DefaultHttpContext context = await RunAsync("/openapi/v1.json", null);

		Assert.False(_nextInvoked);
		Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
	}

	[Fact]
	public async Task InvokeAsync_WithNullContext_Throws()
	{
		RestApiBearerAuthMiddleware middleware = CreateMiddleware(static _ => Task.CompletedTask);

		await Assert.ThrowsAsync<ArgumentNullException>(
			() => middleware.InvokeAsync(null!));
	}

	[Fact]
	public void IsHealthPath_MatchesOnlyHealthz()
	{
		Assert.True(RestApiBearerAuthMiddleware.IsHealthPath(new PathString("/healthz")));
		Assert.True(RestApiBearerAuthMiddleware.IsHealthPath(new PathString("/HEALTHZ")));
		Assert.False(RestApiBearerAuthMiddleware.IsHealthPath(new PathString("/healthz/")));
		Assert.False(RestApiBearerAuthMiddleware.IsHealthPath(new PathString("/health")));
		Assert.False(RestApiBearerAuthMiddleware.IsHealthPath(new PathString("/api/healthz")));
	}
}
