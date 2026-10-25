/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixApiRequestBodyTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Pins the one request-shape rule that a live server taught us: "params" must be present even
//          when the method takes none. Measured against Zabbix 8.0.0 on 2026-10-25 - omitting it makes
//          apiinfo.version fail with 'the parameter "params" is missing', which the connection test
//          then reports as an unreachable server.
// Extends: System.Object

using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Service.Zabbix;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Tests of the JSON-RPC request body builder.</summary>
public sealed class ZabbixApiRequestBodyTests
{
	[Fact]
	public void BuildRequestBody_AlwaysCarriesParams()
	{
		string body = ZabbixApiClient.BuildRequestBody("apiinfo.version", null, 7);

		using JsonDocument document = JsonDocument.Parse(body);
		Assert.Equal("2.0", document.RootElement.GetProperty("jsonrpc").GetString());
		Assert.Equal("apiinfo.version", document.RootElement.GetProperty("method").GetString());
		Assert.Equal(7, document.RootElement.GetProperty("id").GetInt32());
		Assert.True(document.RootElement.TryGetProperty("params", out JsonElement parameters));
		Assert.Equal(JsonValueKind.Object, parameters.ValueKind);
		Assert.Empty(parameters.EnumerateObject());
	}

	[Fact]
	public void BuildRequestBody_ForwardsTheParametersItWasGiven()
	{
		JsonObject parameters = new() { ["username"] = "md" };

		string body = ZabbixApiClient.BuildRequestBody("user.login", parameters, 1);

		using JsonDocument document = JsonDocument.Parse(body);
		Assert.Equal("md", document.RootElement.GetProperty("params").GetProperty("username").GetString());
	}

	[Fact]
	public void BuildRequestBody_RejectsAnEmptyMethod()
		=> Assert.ThrowsAny<ArgumentException>(() => ZabbixApiClient.BuildRequestBody("  ", null, 1));
}
