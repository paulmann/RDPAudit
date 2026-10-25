// File:    tests/RdpAudit.Service.Tests/RestApiSecurityHeadersTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for RestApiSecurityHeadersMiddleware and its path classifier: hardening
//          headers are attached only to API/OpenAPI paths, the inner pipeline is always invoked,
//          and non-API paths receive no header injection.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.AspNetCore.Http;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public class RestApiSecurityHeadersTests
{
	[Theory]
	[InlineData("/api/events")]
	[InlineData("/api")]
	[InlineData("/API/status")]
	[InlineData("/openapi/v1.json")]
	[InlineData("/OPENAPI/v1.json")]
	public void IsApiPath_ForProtectedPrefixes_ReturnsTrue(string path)
	{
		Assert.True(RestApiSecurityHeadersMiddleware.IsApiPath(new PathString(path)));
	}

	[Theory]
	[InlineData("/api2/events")]
	[InlineData("/openapi2/v1.json")]
	public void IsApiPath_UsesPrefixMatching_SoSimilarPrefixesAreAlsoHardened(string path)
	{
		// The classifier deliberately matches by prefix: paths that merely start with the
		// reserved prefixes get the hardening headers even if no endpoint exists there yet.
		Assert.True(RestApiSecurityHeadersMiddleware.IsApiPath(new PathString(path)));
	}

	[Theory]
	[InlineData("/healthz")]
	[InlineData("/ap")]
	[InlineData("/")]
	[InlineData("/other/api/events")]
	[InlineData("/apx/events")]
	public void IsApiPath_ForOtherPaths_ReturnsFalse(string path)
	{
		Assert.False(RestApiSecurityHeadersMiddleware.IsApiPath(new PathString(path)));
	}

	[Fact]
	public async Task InvokeAsync_WithApiPath_AddsAllHardeningHeaders()
	{
		DefaultHttpContext context = new();
		context.Request.Path = "/api/events";
		context.Response.Body = new MemoryStream();
		RestApiSecurityHeadersMiddleware middleware = new(static inner =>
		{
			inner.Response.StatusCode = StatusCodes.Status200OK;
			return Task.CompletedTask;
		});

		await middleware.InvokeAsync(context);

		Assert.Equal("no-store", context.Response.Headers.CacheControl);
		Assert.Equal("no-cache", context.Response.Headers.Pragma);
		Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"]);
		Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"]);
	}

	[Fact]
	public async Task InvokeAsync_WithOpenApiPath_AddsAllHardeningHeaders()
	{
		DefaultHttpContext context = new();
		context.Request.Path = "/openapi/v1.json";
		context.Response.Body = new MemoryStream();
		RestApiSecurityHeadersMiddleware middleware = new(static inner => Task.CompletedTask);

		await middleware.InvokeAsync(context);

		Assert.Equal("no-store", context.Response.Headers.CacheControl);
		Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"]);
		Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"]);
	}

	[Fact]
	public async Task InvokeAsync_WithNonApiPath_AddsNoHeaders()
	{
		DefaultHttpContext context = new();
		context.Request.Path = "/healthz";
		context.Response.Body = new MemoryStream();
		bool innerInvoked = false;
		RestApiSecurityHeadersMiddleware middleware = new(inner =>
		{
			innerInvoked = true;
			return Task.CompletedTask;
		});

		await middleware.InvokeAsync(context);

		Assert.True(innerInvoked);
		Assert.Equal(0, context.Response.Headers.CacheControl.Count);
		Assert.Equal(string.Empty, context.Response.Headers.Pragma.ToString());
		Assert.False(context.Response.Headers.ContainsKey("X-Content-Type-Options"));
		Assert.False(context.Response.Headers.ContainsKey("X-Frame-Options"));
	}

	[Fact]
	public async Task InvokeAsync_WithErrorResponse_HeadersStillAttached()
	{
		// The security-header middleware is installed BEFORE the auth middleware by design;
		// a 401 produced downstream must still carry the hardening headers.
		DefaultHttpContext context = new();
		context.Request.Path = "/api/events";
		context.Response.Body = new MemoryStream();
		RestApiSecurityHeadersMiddleware middleware = new(inner =>
		{
			inner.Response.StatusCode = StatusCodes.Status401Unauthorized;
			return Task.CompletedTask;
		});

		await middleware.InvokeAsync(context);

		Assert.Equal("no-store", context.Response.Headers.CacheControl);
		Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"]);
		Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"]);
	}
}
