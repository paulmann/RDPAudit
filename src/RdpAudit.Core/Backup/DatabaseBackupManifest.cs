/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupManifest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Backup)
// Purpose: The serializable record that makes a database snapshot self-describing and verifiable:
//          what was copied, from where, at which UTC instant, with which SHA-256, which EF schema
//          state it carries, whether the shard tree travelled with it, and the row counts of the key
//          evidence tables at the moment of the copy. The manifest is the difference between "a file
//          named rdpaudit.db" and evidence an operator may restore. Written atomically (temp file +
//          File.Move) and read defensively: a manifest that cannot be parsed or that was written by a
//          newer manifest schema is reported as unreadable, never silently interpreted.
// Depends: System.Text.Json, System.Text.Json.Serialization
// Extends: Add a field by appending a [JsonPropertyName] property and bumping
//          DatabaseBackupManifest.CurrentSchemaVersion only when an existing field changes meaning.

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Backup;

/// <summary>Kind of a database snapshot. Values are persisted in the manifest, so they are part of
/// the on-disk contract and must not be renamed without a manifest schema bump.</summary>
public static class DatabaseBackupKind
{
	/// <summary>An operator- or IPC-requested snapshot.</summary>
	public const string Manual = "Manual";

	/// <summary>The mandatory snapshot taken by the schema initializer before applying EF migrations.</summary>
	public const string PreMigration = "PreMigration";
}

/// <summary>Describes one database snapshot. Serialized to <c>manifest.json</c> inside the snapshot
/// directory; every member carries an explicit JSON name so the artifact is readable by tools that
/// do not share the assembly.</summary>
public sealed record DatabaseBackupManifest
{
	/// <summary>Version of the manifest schema this build writes.</summary>
	public const int CurrentSchemaVersion = 1;

	/// <summary>Manifest schema version. A reader refuses a manifest newer than it understands.</summary>
	[JsonPropertyName("manifestVersion")]
	public int ManifestVersion { get; init; } = CurrentSchemaVersion;

	/// <summary>Snapshot origin: <see cref="DatabaseBackupKind.Manual"/> or
	/// <see cref="DatabaseBackupKind.PreMigration"/>.</summary>
	[JsonPropertyName("kind")]
	public string Kind { get; init; } = DatabaseBackupKind.Manual;

	/// <summary>UTC instant the snapshot was taken.</summary>
	[JsonPropertyName("createdUtc")]
	public DateTime CreatedUtc { get; init; }

	/// <summary>Absolute path of the live database the snapshot was copied from.</summary>
	[JsonPropertyName("databasePath")]
	public string DatabasePath { get; init; } = string.Empty;

	/// <summary>Size of the copied database file in bytes.</summary>
	[JsonPropertyName("databaseBytes")]
	public long DatabaseBytes { get; init; }

	/// <summary>Uppercase hexadecimal SHA-256 of the copied database file.</summary>
	[JsonPropertyName("databaseSha256")]
	public string DatabaseSha256 { get; init; } = string.Empty;

	/// <summary>Newest EF migration applied to the copied database, or null when the database has no
	/// migration history at all (a store created before migrations existed, or an empty store).</summary>
	[JsonPropertyName("lastAppliedMigration")]
	public string? LastAppliedMigration { get; init; }

	/// <summary>Number of EF migrations applied to the copied database.</summary>
	[JsonPropertyName("appliedMigrationCount")]
	public int AppliedMigrationCount { get; init; }

	/// <summary>Product version that produced the snapshot; null when it could not be resolved.</summary>
	[JsonPropertyName("productVersion")]
	public string? ProductVersion { get; init; }

	/// <summary>True when the shard tree was copied into the snapshot alongside the database.</summary>
	[JsonPropertyName("shardsIncluded")]
	public bool ShardsIncluded { get; init; }

	/// <summary>Absolute path of the shard tree that was copied; null when shards were not included.</summary>
	[JsonPropertyName("shardsDirectory")]
	public string? ShardsDirectory { get; init; }

	/// <summary>Number of shard files copied; zero when shards were not included.</summary>
	[JsonPropertyName("shardFileCount")]
	public int ShardFileCount { get; init; }

	/// <summary>Bytes of shard data copied; zero when shards were not included.</summary>
	[JsonPropertyName("shardBytes")]
	public long ShardBytes { get; init; }

	/// <summary>Row counts of the key evidence tables inside the snapshot. A table that could not be
	/// counted is absent rather than reported as zero, so "empty" stays distinguishable from "unknown".</summary>
	[JsonPropertyName("rowCounts")]
	public IReadOnlyDictionary<string, long> RowCounts { get; init; } = new Dictionary<string, long>(StringComparer.Ordinal);
}

/// <summary>Serializes and deserializes <see cref="DatabaseBackupManifest"/>, including the atomic
/// write used when a snapshot is completed. The manifest is written last, so a snapshot without a
/// readable manifest is by construction an incomplete snapshot.</summary>
public static class DatabaseBackupManifestCodec
{
	private static readonly JsonSerializerOptions SerializerOptions = new()
	{
		WriteIndented = true,
		PropertyNameCaseInsensitive = true,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	};

	/// <summary>Serializes the manifest to indented JSON with camelCase-free explicit names.</summary>
	public static string Serialize(DatabaseBackupManifest manifest)
	{
		ArgumentNullException.ThrowIfNull(manifest);
		return JsonSerializer.Serialize(manifest, SerializerOptions);
	}

	/// <summary>
	/// Parses a manifest from JSON. Returns null for empty, malformed, incomplete or future-schema
	/// input instead of throwing, so a corrupt artifact degrades to "manifest unreadable" at the call
	/// site. A manifest whose schema version is not the one this build writes is refused, and so is a
	/// document that omits the facts a verification depends on - the creation instant and the SHA-256.
	/// Accepting a partial document would attach an empty hash to a snapshot and read as "nothing to
	/// compare", which is precisely the silent mis-read this artifact exists to prevent.
	/// </summary>
	public static DatabaseBackupManifest? TryDeserialize(string? json)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			return null;
		}

		try
		{
			DatabaseBackupManifest? manifest = JsonSerializer.Deserialize<DatabaseBackupManifest>(json, SerializerOptions);
			if (manifest is null || manifest.ManifestVersion != DatabaseBackupManifest.CurrentSchemaVersion)
			{
				return null;
			}

			if (manifest.CreatedUtc == default
				|| string.IsNullOrWhiteSpace(manifest.DatabaseSha256)
				|| manifest.DatabaseBytes < 0)
			{
				return null;
			}

			return manifest;
		}
		catch (JsonException)
		{
			return null;
		}
		catch (NotSupportedException)
		{
			return null;
		}
		catch (ArgumentException)
		{
			return null;
		}
	}

	/// <summary>Reads and parses the manifest at <paramref name="manifestPath"/>. Never throws: a
	/// missing, unreadable or malformed manifest yields null plus an English reason.</summary>
	public static bool TryRead(string manifestPath, out DatabaseBackupManifest? manifest, out string? error)
	{
		manifest = null;
		error = null;
		if (string.IsNullOrWhiteSpace(manifestPath))
		{
			error = "No manifest path was supplied.";
			return false;
		}

		string json;
		try
		{
			if (!File.Exists(manifestPath))
			{
				error = "The snapshot has no manifest.json.";
				return false;
			}

			json = File.ReadAllText(manifestPath);
		}
		catch (IOException ex)
		{
			error = "The snapshot manifest could not be read: " + ex.Message;
			return false;
		}
		catch (UnauthorizedAccessException ex)
		{
			error = "The snapshot manifest could not be read: " + ex.Message;
			return false;
		}

		manifest = TryDeserialize(json);
		if (manifest is null)
		{
			error = "The snapshot manifest is not a readable RdpAudit database manifest (malformed JSON or an unsupported manifest version).";
			return false;
		}

		return true;
	}

	/// <summary>
	/// Writes the manifest atomically: the JSON goes to a sibling temp file which is then moved over
	/// the target, so a reader either sees the previous manifest or the complete new one. Creates the
	/// containing directory when it does not exist.
	/// </summary>
	public static void WriteAtomic(string manifestPath, DatabaseBackupManifest manifest)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
		ArgumentNullException.ThrowIfNull(manifest);

		string? directory = Path.GetDirectoryName(manifestPath);
		if (!string.IsNullOrEmpty(directory))
		{
			Directory.CreateDirectory(directory);
		}

		string tempPath = manifestPath + ".tmp";
		File.WriteAllText(tempPath, Serialize(manifest));
		File.Move(tempPath, manifestPath, overwrite: true);
	}

	/// <summary>Renders the manifest as one operator-facing line for logs and reports.</summary>
	public static string Describe(DatabaseBackupManifest manifest)
	{
		ArgumentNullException.ThrowIfNull(manifest);
		return string.Format(
			CultureInfo.InvariantCulture,
			"kind={0} createdUtc={1:o} databaseBytes={2} sha256={3} appliedMigrations={4} lastAppliedMigration={5} shardsIncluded={6} shardFiles={7} shardBytes={8} countedTables={9}",
			manifest.Kind,
			manifest.CreatedUtc,
			manifest.DatabaseBytes,
			manifest.DatabaseSha256,
			manifest.AppliedMigrationCount,
			manifest.LastAppliedMigration ?? "(none)",
			manifest.ShardsIncluded,
			manifest.ShardFileCount,
			manifest.ShardBytes,
			manifest.RowCounts.Count);
	}
}
