/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseMigrationFailureMarker.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data)
// Purpose: Persists a machine readable marker describing a fatal EF Core migration failure so the
//          Configurator can detect the condition on the next launch and offer the operator a
//          guided recovery (back up the incompatible database, drop it, and let the service create
//          a fresh one). The marker is written atomically (temp file + File.Move) into ProgramData
//          so it survives service crashes and SCM restart loops without corrupting itself.
// Depends: System.Text.Json, System.IO, ServiceLayout
// Extends: If additional recovery paths are added, extend MigrationFailureMarkerPayload and bump
//          the schema Version field so old Configurator builds refuse to parse forward-compat data.

using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Data;

/// <summary>Serializable payload describing a fatal EF migration failure.</summary>
public sealed record MigrationFailureMarkerPayload
{
	/// <summary>Marker schema version. Bump on breaking payload changes.</summary>
	[JsonPropertyName("version")]
	public int Version { get; init; } = 1;

	/// <summary>UTC timestamp of the failure (ISO 8601 round-trip).</summary>
	[JsonPropertyName("timestampUtc")]
	public DateTime TimestampUtc { get; init; }

	/// <summary>Absolute path of the SQLite database file the service attempted to migrate.</summary>
	[JsonPropertyName("databasePath")]
	public string DatabasePath { get; init; } = string.Empty;

	/// <summary>Ordered list of migrations that were pending at the time of the failure.</summary>
	[JsonPropertyName("pendingMigrations")]
	public IReadOnlyList<string> PendingMigrations { get; init; } = Array.Empty<string>();

	/// <summary>Optional exception type name (e.g. Microsoft.Data.Sqlite.SqliteException).</summary>
	[JsonPropertyName("exceptionType")]
	public string? ExceptionType { get; init; }

	/// <summary>Optional exception message (single line, English).</summary>
	[JsonPropertyName("exceptionMessage")]
	public string? ExceptionMessage { get; init; }

	/// <summary>Optional full stack trace of the failure.</summary>
	[JsonPropertyName("exceptionStack")]
	public string? ExceptionStack { get; init; }

	/// <summary>Optional last executed SQL command text, if the caller could capture it.</summary>
	[JsonPropertyName("failedSql")]
	public string? FailedSql { get; init; }

	/// <summary>Optional service assembly version at the time of failure.</summary>
	[JsonPropertyName("serviceVersion")]
	public string? ServiceVersion { get; init; }
}

/// <summary>Reads and writes the migration failure marker file under ProgramData\RdpAudit.</summary>
public static class DatabaseMigrationFailureMarker
{
	/// <summary>Marker file name kept next to appsettings.json.</summary>
	public const string FileName = "migration-failure.marker.json";

	private static readonly JsonSerializerOptions SerializerOptions = new()
	{
		WriteIndented = true,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	};

	/// <summary>Returns the absolute path of the marker file inside the given ProgramData directory.</summary>
	public static string GetMarkerPath(string programDataDirectory)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataDirectory);
		return Path.Combine(programDataDirectory, FileName);
	}

	/// <summary>Writes the marker atomically (temp + File.Move). Never throws to the caller; a failure
	/// to write the marker must not mask the underlying migration exception.</summary>
	public static void Write(string programDataDirectory, MigrationFailureMarkerPayload payload)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataDirectory);
		ArgumentNullException.ThrowIfNull(payload);

		try
		{
			Directory.CreateDirectory(programDataDirectory);
			string finalPath = GetMarkerPath(programDataDirectory);
			string tempPath = finalPath + ".tmp";

			string json = JsonSerializer.Serialize(payload, SerializerOptions);
			File.WriteAllText(tempPath, json);
			// File.Move with overwrite is atomic on NTFS at the directory-entry level; if the
			// destination exists we replace it so the freshest failure is always visible.
			File.Move(tempPath, finalPath, overwrite: true);
		}
		catch
		{
			// Swallow — writing the marker is best-effort. The underlying migration exception is
			// already surfaced through the logger and rethrown; this file is only a recovery hint.
		}
	}

	/// <summary>Tries to read the marker file. Returns null when the file is missing, empty, or malformed.</summary>
	public static MigrationFailureMarkerPayload? TryRead(string programDataDirectory)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataDirectory);
		string path = GetMarkerPath(programDataDirectory);
		try
		{
			if (!File.Exists(path))
			{
				return null;
			}

			string json = File.ReadAllText(path);
			if (string.IsNullOrWhiteSpace(json))
			{
				return null;
			}

			return JsonSerializer.Deserialize<MigrationFailureMarkerPayload>(json, SerializerOptions);
		}
		catch
		{
			return null;
		}
	}

	/// <summary>Best-effort delete. Silently ignores missing files and IO races.</summary>
	[SupportedOSPlatform("windows")]
	public static void Delete(string programDataDirectory)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataDirectory);
		string path = GetMarkerPath(programDataDirectory);
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch
		{
			// Ignore — a stale marker is preferable to a crash while attempting recovery.
		}
	}
}

/// <summary>Thrown by <see cref="AuditDbInitializer"/> when a schema migration cannot be applied.
/// Signals the hosted worker to stop the process cleanly instead of feeding the SCM restart loop.</summary>
public sealed class DatabaseMigrationFailedException : Exception
{
	/// <summary>Marker payload persisted for the Configurator.</summary>
	public MigrationFailureMarkerPayload Marker { get; }

	/// <inheritdoc />
	public DatabaseMigrationFailedException(string message, Exception inner, MigrationFailureMarkerPayload marker)
		: base(message, inner)
	{
		Marker = marker ?? throw new ArgumentNullException(nameof(marker));
	}
}
