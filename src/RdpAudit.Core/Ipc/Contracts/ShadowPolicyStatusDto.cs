// File:    src/RdpAudit.Core/Ipc/Contracts/ShadowPolicyStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO describing the current Terminal Services shadow policy plus backup metadata.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One registry value reported by the shadow policy status snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShadowPolicyValueDto
{
	[Key(0)]
	public string KeyPath { get; set; } = string.Empty;

	[Key(1)]
	public string ValueName { get; set; } = string.Empty;

	/// <summary>Current value (-1 = not configured / missing).</summary>
	[Key(2)]
	public int CurrentValue { get; set; } = -1;

	/// <summary>Recommended / desired value, -1 if no recommendation.</summary>
	[Key(3)]
	public int RecommendedValue { get; set; } = -1;

	[Key(4)]
	public string? Description { get; set; }
}

/// <summary>DTO describing the current Terminal Services shadow policy plus backup metadata.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShadowPolicyStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Current Shadow registry value (0..4); -1 means not configured / unknown.</summary>
	[Key(1)]
	public int ShadowMode { get; set; } = -1;

	[Key(2)]
	public bool HasBackup { get; set; }

	[Key(3)]
	public DateTime? BackupCreatedUtc { get; set; }

	[Key(4)]
	public string? Message { get; set; }

	/// <summary>Per-registry value rows — append-only and stable across versions.</summary>
	[Key(5)]
	public List<ShadowPolicyValueDto> Values { get; set; } = new();

	/// <summary>True when the policy values are at or stronger than "enable all permissions".</summary>
	[Key(6)]
	public bool AllPermissionsEnabled { get; set; }

	/// <summary>Latest snapshot id (yyyyMMdd-HHmmss) used by the backup-restore handler when restoring.</summary>
	[Key(7)]
	public string? LatestSnapshotId { get; set; }
}
