/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupManifestTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks the on-disk manifest contract of a database snapshot: every field survives the JSON
//          round trip under its explicit camelCase name, row counts stay keyed by table name, and a
//          manifest that is empty, malformed, truncated or written by a different manifest schema is
//          refused instead of being partially interpreted. This is the artifact an operator reads with
//          a text editor and the verifier trusts; a silent mis-read here would attach a wrong SHA-256
//          to a snapshot.
// Depends: RdpAudit.Core.Backup, System.Text.Json, xUnit
// Extends: Add an assertion here whenever DatabaseBackupManifest gains a member a restore depends on.

using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Round-trip and robustness tests for the snapshot manifest.</summary>
public sealed class DatabaseBackupManifestTests
{
	private static DatabaseBackupManifest SampleManifest()
	{
		DatabaseBackupManifest manifest = new()
		{
			Kind = DatabaseBackupKind.PreMigration,
			CreatedUtc = new DateTime(2026, 9, 14, 10, 30, 45, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			DatabaseBytes = 123_456,
			DatabaseSha256 = "ABCDEF0123456789",
			LastAppliedMigration = "20260914160902_Stage17EventDeletionLedger",
			AppliedMigrationCount = 17,
			ProductVersion = "2.0.3+abcdef",
			ShardsIncluded = true,
			ShardsDirectory = @"C:\ProgramData\RdpAudit\Backups\20260914-103045\actions",
			ShardFileCount = 3,
			ShardBytes = 4096,
			RowCounts = new Dictionary<string, long>(StringComparer.Ordinal)
			{
				["RawEvents"] = 42,
				["Alerts"] = 0,
			},
		};
		return manifest;
	}

	[Fact]
	public void Serialize_RoundTripsEveryField()
	{
		DatabaseBackupManifest source = SampleManifest();

		string json = DatabaseBackupManifestCodec.Serialize(source);
		DatabaseBackupManifest? parsed = DatabaseBackupManifestCodec.TryDeserialize(json);

		Assert.NotNull(parsed);
		Assert.Equal(DatabaseBackupManifest.CurrentSchemaVersion, parsed!.ManifestVersion);
		Assert.Equal(source.Kind, parsed.Kind);
		Assert.Equal(source.CreatedUtc, parsed.CreatedUtc);
		Assert.Equal(source.DatabasePath, parsed.DatabasePath);
		Assert.Equal(source.DatabaseBytes, parsed.DatabaseBytes);
		Assert.Equal(source.DatabaseSha256, parsed.DatabaseSha256);
		Assert.Equal(source.LastAppliedMigration, parsed.LastAppliedMigration);
		Assert.Equal(source.AppliedMigrationCount, parsed.AppliedMigrationCount);
		Assert.Equal(source.ProductVersion, parsed.ProductVersion);
		Assert.Equal(source.ShardsIncluded, parsed.ShardsIncluded);
		Assert.Equal(source.ShardsDirectory, parsed.ShardsDirectory);
		Assert.Equal(source.ShardFileCount, parsed.ShardFileCount);
		Assert.Equal(source.ShardBytes, parsed.ShardBytes);
		Assert.Equal(42, parsed.RowCounts["RawEvents"]);
		Assert.Equal(0, parsed.RowCounts["Alerts"]);
	}

	[Fact]
	public void Serialize_UsesExplicitCamelCaseNamesAndKeepsAnEmptyCountZero()
	{
		string json = DatabaseBackupManifestCodec.Serialize(SampleManifest());
		JsonNode? node = JsonNode.Parse(json);

		Assert.NotNull(node);
		Assert.Equal(DatabaseBackupManifest.CurrentSchemaVersion, node!["manifestVersion"]!.GetValue<int>());
		Assert.Equal("PreMigration", node["kind"]!.GetValue<string>());
		Assert.True(node["shardsIncluded"]!.GetValue<bool>());

		// A zero row count must survive as a zero: "the table is empty" and "the table was not counted"
		// are different facts and only the second one is allowed to be absent.
		Assert.Equal(0, node["rowCounts"]!["Alerts"]!.GetValue<long>());
	}

	[Fact]
	public void TryDeserialize_RefusesEmptyAndMalformedInput()
	{
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(null));
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(""));
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize("   "));
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize("not json at all"));
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize("{ \"manifestVersion\": "));
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize("{ \"createdUtc\": \"not-a-date\" }"));
	}

	[Theory]
	[InlineData(0)]
	[InlineData(2)]
	[InlineData(99)]
	[InlineData(-1)]
	public void TryDeserialize_RefusesAForeignManifestSchemaVersion(int version)
	{
		string json = DatabaseBackupManifestCodec.Serialize(SampleManifest());
		JsonObject node = JsonNode.Parse(json)!.AsObject();
		node["manifestVersion"] = version;

		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(node.ToJsonString()));
	}

	[Fact]
	public void TryDeserialize_RefusesADocumentWithoutTheFactsAVerificationNeeds()
	{
		// A hand-written or truncated-but-valid document parses as JSON; it must still be refused,
		// because a manifest with no creation instant or no hash would read as "nothing to compare".
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize("{\"kind\":\"Manual\",\"databaseBytes\":1}"));

		string valid = DatabaseBackupManifestCodec.Serialize(SampleManifest());

		JsonObject noHash = JsonNode.Parse(valid)!.AsObject();
		noHash["databaseSha256"] = "";
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(noHash.ToJsonString()));

		JsonObject noTime = JsonNode.Parse(valid)!.AsObject();
		noTime["createdUtc"] = "0001-01-01T00:00:00";
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(noTime.ToJsonString()));

		JsonObject negativeSize = JsonNode.Parse(valid)!.AsObject();
		negativeSize["databaseBytes"] = -1;
		Assert.Null(DatabaseBackupManifestCodec.TryDeserialize(negativeSize.ToJsonString()));
	}

	[Fact]
	public void TryRead_ReportsAMissingFileAndAMalformedFileDistinctly()
	{
		string directory = Path.Combine(Path.GetTempPath(), "rdpaudit-manifest-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(directory);
		try
		{
			string manifestPath = Path.Combine(directory, DatabaseBackupLayout.ManifestFileName);

			Assert.False(DatabaseBackupManifestCodec.TryRead(manifestPath, out DatabaseBackupManifest? missing, out string? missingError));
			Assert.Null(missing);
			Assert.Contains("no manifest.json", missingError!, StringComparison.Ordinal);

			File.WriteAllText(manifestPath, "{ this is not json");
			Assert.False(DatabaseBackupManifestCodec.TryRead(manifestPath, out DatabaseBackupManifest? malformed, out string? malformedError));
			Assert.Null(malformed);
			Assert.Contains("not a readable RdpAudit database manifest", malformedError!, StringComparison.Ordinal);

			DatabaseBackupManifestCodec.WriteAtomic(manifestPath, SampleManifest());
			Assert.True(DatabaseBackupManifestCodec.TryRead(manifestPath, out DatabaseBackupManifest? good, out string? goodError));
			Assert.Null(goodError);
			Assert.Equal(DatabaseBackupKind.PreMigration, good!.Kind);

			// The atomic write must not leave its temporary file behind.
			Assert.False(File.Exists(manifestPath + ".tmp"));
		}
		finally
		{
			Directory.Delete(directory, recursive: true);
		}
	}

	[Fact]
	public void Describe_NamesTheFactsARestoreDependsOn()
	{
		string described = DatabaseBackupManifestCodec.Describe(SampleManifest());

		Assert.Contains("kind=PreMigration", described, StringComparison.Ordinal);
		Assert.Contains("appliedMigrations=17", described, StringComparison.Ordinal);
		Assert.Contains("20260914160902_Stage17EventDeletionLedger", described, StringComparison.Ordinal);
		Assert.Contains("shardsIncluded=True", described, StringComparison.Ordinal);
	}
}
