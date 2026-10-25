// File:    tests/RdpAudit.Service.Tests/Scenarios/DocumentationDriftScenarioTests.cs
// Module:  RdpAudit.Service.Tests.Scenarios
// Purpose: Tier-3 drift guards linking the committed OpenAPI descriptor to its hand-written
//          documentation. docs/51-rest-api.md is the operator-facing contract for the read-only
//          REST API; if the committed descriptor (src/RdpAudit.Service/RestApi/openapi-v1.json)
//          gains, loses or renames a path, the documentation must follow in the same change.
//          These tests fail otherwise so the prose contract and the wire contract cannot drift
//          apart silently.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Xunit;

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>Keeps the operator-facing REST API documentation pinned to the committed descriptor.</summary>
public sealed class DocumentationDriftScenarioTests
{
	[Fact]
	public void RestApiDoc_MentionsEveryCommittedDescriptorPath()
	{
		string doc = ReadRepositoryFile("docs", "51-rest-api.md");
		using JsonDocument spec = JsonDocument.Parse(ReadRepositoryFile(
			"src", "RdpAudit.Service", "RestApi", "openapi-v1.json"));

		JsonElement paths = spec.RootElement.GetProperty("paths");
		foreach (JsonProperty path in paths.EnumerateObject())
		{
			Assert.True(
				doc.Contains("`" + path.Name + "`", StringComparison.Ordinal),
				$"docs/51-rest-api.md does not document committed path '{path.Name}'.");
		}
	}

	[Fact]
	public void RestApiDoc_ReferencesTheCommittedDescriptorPath()
	{
		string doc = ReadRepositoryFile("docs", "51-rest-api.md");

		Assert.Contains(
			"src/RdpAudit.Service/RestApi/openapi-v1.json",
			doc,
			StringComparison.Ordinal);
		Assert.True(File.Exists(Path.Combine(
			FindRepoRoot(), "src", "RdpAudit.Service", "RestApi", "openapi-v1.json")));
	}

	private static string ReadRepositoryFile(params string[] relativeParts)
	{
		string path = relativeParts.Aggregate(FindRepoRoot(), Path.Combine);
		Assert.True(File.Exists(path), $"Repository file not found: {path}");
		return File.ReadAllText(path);
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
