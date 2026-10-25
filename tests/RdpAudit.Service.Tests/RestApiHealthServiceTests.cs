// File:    tests/RdpAudit.Service.Tests/RestApiHealthServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for RestApiHealthService: 200 JSON payload with normalized bindings,
//          constructor guards, and GET+HEAD route mapping.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.AspNetCore.Http;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public class RestApiHealthServiceTests
{
	private static async Task<string> ServeAsync(params string[] bindings)
	{
		RestApiHealthService service = new(bindings);
		DefaultHttpContext context = new();
		context.Response.Body = new MemoryStream();

		await service.ServeAsync(context);

		context.Response.Body.Position = 0;
		using StreamReader reader = new(context.Response.Body);
		return await reader.ReadToEndAsync();
	}

	[Fact]
	public void Constructor_WithNullBindings_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => new RestApiHealthService(null!));
	}

	[Fact]
	public async Task ServeAsync_ReturnsOkWithJson()
	{
		string body = await ServeAsync("https://127.0.0.1:8443");

		using JsonDocument document = JsonDocument.Parse(body);
		Assert.Equal("ok", document.RootElement.GetProperty("status").GetString());
		JsonElement bindings = document.RootElement.GetProperty("bindings");
		Assert.Equal(1, bindings.GetArrayLength());
		Assert.Equal("https://127.0.0.1:8443", bindings[0].GetString());
	}

	[Fact]
	public async Task ServeAsync_WithNoBindings_ReturnsEmptyArray()
	{
		string body = await ServeAsync();

		using JsonDocument document = JsonDocument.Parse(body);
		Assert.Equal("ok", document.RootElement.GetProperty("status").GetString());
		Assert.Equal(0, document.RootElement.GetProperty("bindings").GetArrayLength());
	}

	[Fact]
	public async Task ServeAsync_WithBlankBindings_SkipsAndTrims()
	{
		string body = await ServeAsync("  ", " https://10.0.0.5:8443 ", "");

		using JsonDocument document = JsonDocument.Parse(body);
		JsonElement bindings = document.RootElement.GetProperty("bindings");
		Assert.Equal(1, bindings.GetArrayLength());
		Assert.Equal("https://10.0.0.5:8443", bindings[0].GetString());
	}

	[Fact]
	public async Task ServeAsync_SetsJsonContentTypeAnd200()
	{
		RestApiHealthService service = new(new[] { "https://127.0.0.1:8443" });
		DefaultHttpContext context = new();
		context.Response.Body = new MemoryStream();

		await service.ServeAsync(context);

		Assert.Contains("application/json", context.Response.ContentType);
		Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
	}

	[Fact]
	public async Task ServeAsync_WithNullContext_Throws()
	{
		RestApiHealthService service = new(new[] { "https://127.0.0.1:8443" });

		await Assert.ThrowsAsync<ArgumentNullException>(() => service.ServeAsync(null!));
	}
}
