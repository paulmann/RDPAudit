// File:    tests/RdpAudit.Service.Tests/Scenarios/RestOpenApiDriftScenarioTests.cs
// Module:  RdpAudit.Service.Tests.Scenarios
// Purpose: Tier-3 drift guards for the committed OpenAPI descriptor. The committed file
//          (src/RdpAudit.Service/RestApi/openapi-v1.json) is the single source of truth served at
//          /openapi/v1.json, so these tests lock three invariants:
//          1. The embedded runtime copy is byte-for-byte identical to the committed file.
//          2. The runtime route table matches the documented paths and methods exactly (no
//             undocumented endpoint can sneak onto the listener, no documented endpoint can
//             silently disappear).
//          3. The descriptor stays an OpenAPI 3.0 document describing GET-only reads with the
//             bearer scheme and an anonymous /healthz probe.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>Keeps the committed OpenAPI descriptor, the embedded copy and the runtime surface in sync.</summary>
public sealed class RestOpenApiDriftScenarioTests
{
	private static readonly string[] AllowedRuntimeMethods =
		["GET", "HEAD"];

	[Fact]
	public void EmbeddedDescriptor_MatchesCommittedFileByteForByte()
	{
		string committed = ReadCommittedDescriptor();

		Assert.Equal(committed, RestApiOpenApiDocument.Content);
	}

	[Fact]
	public async Task RuntimeRouteTable_MatchesCommittedPathsAndMethods()
	{
		using JsonDocument spec = JsonDocument.Parse(ReadCommittedDescriptor());
		JsonElement specPaths = spec.RootElement.GetProperty("paths");

		await using RestApiTestApp api = await RestApiTestApp.CreateAsync();

		HashSet<string> runtimePaths = api.Paths.ToHashSet(StringComparer.Ordinal);
		foreach (JsonProperty specPath in specPaths.EnumerateObject())
		{
			Assert.True(
				runtimePaths.Contains(specPath.Name),
				$"Runtime route table is missing documented path '{specPath.Name}'.");
		}

		foreach (string runtimePath in api.Paths)
		{
			Assert.True(
				specPaths.TryGetProperty(runtimePath, out _),
				$"Runtime path '{runtimePath}' is not documented in openapi-v1.json.");
		}

		foreach (JsonProperty specPath in specPaths.EnumerateObject())
		{
			Assert.Equal(
				AllowedRuntimeMethods, api.MethodsByPath[specPath.Name].OrderBy(static m => m, StringComparer.Ordinal));
		}
	}

	[Fact]
	public void CommittedDescriptor_IsReadOnlyV3DocumentWithAnonymousHealthz()
	{
		using JsonDocument spec = JsonDocument.Parse(ReadCommittedDescriptor());
		JsonElement root = spec.RootElement;

		Assert.Equal("3.0.3", root.GetProperty("openapi").GetString());

		JsonElement security = root.GetProperty("security").EnumerateArray().Single();
		Assert.Equal("bearerAuth", security.EnumerateObject().Single().Name);

		JsonElement scheme = root
			.GetProperty("components")
			.GetProperty("securitySchemes")
			.GetProperty("bearerAuth");
		Assert.Equal("http", scheme.GetProperty("type").GetString());
		Assert.Equal("bearer", scheme.GetProperty("scheme").GetString());

		JsonElement paths = root.GetProperty("paths");
		foreach (JsonProperty path in paths.EnumerateObject())
		{
			// The API is read-only: every path documents exactly one operation, GET.
			Assert.Equal("get", path.Value.EnumerateObject().Single().Name);
		}

		// /healthz is the only anonymous endpoint and must stay outside the bearer perimeter.
		JsonElement healthz = paths.GetProperty("/healthz").GetProperty("get");
		Assert.True(healthz.TryGetProperty("security", out JsonElement healthzSecurity));
		Assert.Equal(0, healthzSecurity.GetArrayLength());
	}

	private static string ReadCommittedDescriptor()
	{
		string committedPath = Path.Combine(
			FindRepoRoot(),
			"src",
			"RdpAudit.Service",
			"RestApi",
			"openapi-v1.json");
		return File.ReadAllText(committedPath);
	}

	private static string FindRepoRoot()
	{
		DirectoryInfo? directory = new(AppContext.BaseDirectory);
		while (directory is not null)
		{
			if (File.Exists(Path.Combine(directory.FullName, "RdpAudit.sln")))
			{
				return directory.FullName;
			}

			directory = directory.Parent;
		}

		throw new InvalidOperationException(
			"RdpAudit.sln not found while walking up from " + AppContext.BaseDirectory + ".");
	}
}
