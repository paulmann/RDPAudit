// File:    src/RdpAudit.Core/Backup/BackupMetadata.cs
// Module:  RdpAudit.Core.Backup
// Purpose: JSON metadata document written into every backup snapshot. Documents
//          when, where, by whom, and which RdpAudit version produced the
//          snapshot so future restore operations can reason about compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Backup;

/// <summary>JSON metadata document written into every backup snapshot.</summary>
public sealed class BackupMetadata
{
	/// <summary>Schema version for forward compatibility of the metadata document.</summary>
	[JsonPropertyName("schemaVersion")]
	public int SchemaVersion { get; init; } = 1;

	/// <summary>UTC timestamp when the backup snapshot was captured.</summary>
	[JsonPropertyName("createdUtc")]
	public DateTime CreatedUtc { get; init; }

	/// <summary>Snapshot identifier — same as the directory name (yyyyMMdd-HHmmss).</summary>
	[JsonPropertyName("snapshotId")]
	public string SnapshotId { get; init; } = string.Empty;

	/// <summary>Machine name of the host that produced the snapshot.</summary>
	[JsonPropertyName("machineName")]
	public string MachineName { get; init; } = string.Empty;

	/// <summary>User account that initiated the snapshot.</summary>
	[JsonPropertyName("userName")]
	public string UserName { get; init; } = string.Empty;

	/// <summary>OS description (Environment.OSVersion / RuntimeInformation).</summary>
	[JsonPropertyName("osDescription")]
	public string OsDescription { get; init; } = string.Empty;

	/// <summary>RdpAudit product / configurator informational version.</summary>
	[JsonPropertyName("productVersion")]
	public string ProductVersion { get; init; } = string.Empty;

	/// <summary>What triggered the snapshot — "first-run-install", "manual" or "pre-restore".</summary>
	[JsonPropertyName("reason")]
	public string Reason { get; init; } = string.Empty;

	/// <summary>True when the snapshot includes a copy of appsettings.json.</summary>
	[JsonPropertyName("includesAppSettings")]
	public bool IncludesAppSettings { get; init; }

	/// <summary>True when the snapshot includes an auditpol /backup CSV.</summary>
	[JsonPropertyName("includesAuditPolicy")]
	public bool IncludesAuditPolicy { get; init; }

	/// <summary>True when the snapshot includes a reg.exe export of RdpAudit registry keys.</summary>
	[JsonPropertyName("includesRegistry")]
	public bool IncludesRegistry { get; init; }

	/// <summary>True when the snapshot includes a service configuration capture.</summary>
	[JsonPropertyName("includesServiceConfig")]
	public bool IncludesServiceConfig { get; init; }

	/// <summary>Notes about redactions performed. Always set; documents the redaction policy
	/// even when no secrets were present in the source files.</summary>
	[JsonPropertyName("redactions")]
	public IReadOnlyList<string> Redactions { get; init; } = Array.Empty<string>();

	/// <summary>Subset of the audit-policy subcategory GUIDs captured in the snapshot.</summary>
	[JsonPropertyName("auditPolicyGuids")]
	public IReadOnlyList<string> AuditPolicyGuids { get; init; } = Array.Empty<string>();

	/// <summary>Registry hive paths captured (HKLM\... style strings).</summary>
	[JsonPropertyName("registryKeys")]
	public IReadOnlyList<string> RegistryKeys { get; init; } = Array.Empty<string>();

	private static readonly JsonSerializerOptions Options = new()
	{
		WriteIndented = true,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
	};

	/// <summary>Serializes the metadata document to indented JSON.</summary>
	public string ToJson() => JsonSerializer.Serialize(this, Options);

	/// <summary>Deserializes a metadata document; throws on schema mismatch.</summary>
	public static BackupMetadata FromJson(string json)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(json);
		BackupMetadata? value = JsonSerializer.Deserialize<BackupMetadata>(json, Options);
		return value ?? throw new InvalidOperationException("Backup metadata JSON deserialized to null.");
	}
}
