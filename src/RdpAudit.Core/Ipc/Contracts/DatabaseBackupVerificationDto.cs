/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupVerificationDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Result of verifying one database snapshot (IPC ordinal 87). Distinguishes the failure modes
//          an operator must act on differently - a damaged file, an unreadable manifest, a schema that
//          is ahead of the running binaries - instead of collapsing them into one "invalid" flag.
// Depends: MessagePack, IpcResultStatus, DatabaseSnapshotVerdict, SchemaCompatibilityVerdict
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;
using RdpAudit.Core.Backup;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Evidence and verdict of verifying one snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseBackupVerificationDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the verification itself completed, whether
	/// or not the snapshot passed; <see cref="IpcResultStatus.NotFound"/> when no such snapshot exists;
	/// <see cref="IpcResultStatus.Unavailable"/> when the check could not be performed at all.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant of the verification.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Snapshot directory name that was verified.</summary>
	[Key(2)]
	public string SnapshotName { get; set; } = string.Empty;

	/// <summary>Absolute directory that was verified.</summary>
	[Key(3)]
	public string SnapshotDirectory { get; set; } = string.Empty;

	/// <summary>Machine-readable verdict.</summary>
	[Key(4)]
	public DatabaseSnapshotVerdict Verdict { get; set; } = DatabaseSnapshotVerdict.Ok;

	/// <summary>Name of <see cref="Verdict"/>, so a client can render it without sharing the enum
	/// ordinal table.</summary>
	[Key(5)]
	public string VerdictName { get; set; } = string.Empty;

	/// <summary>True when every check passed and the snapshot may be restored.</summary>
	[Key(6)]
	public bool IsUsable { get; set; }

	/// <summary>SHA-256 recorded when the snapshot was taken.</summary>
	[Key(7)]
	public string? ExpectedSha256 { get; set; }

	/// <summary>SHA-256 computed now from the snapshot database.</summary>
	[Key(8)]
	public string? ActualSha256 { get; set; }

	/// <summary>First row of <c>PRAGMA quick_check</c>; <c>ok</c> when the copy is sound.</summary>
	[Key(9)]
	public string? QuickCheckResult { get; set; }

	/// <summary>Schema comparison against the running binaries; null when it was not requested.</summary>
	[Key(10)]
	public SchemaCompatibilityVerdict? SchemaVerdict { get; set; }

	/// <summary>Human-readable schema comparison result; null when it was not requested.</summary>
	[Key(11)]
	public string? SchemaMessage { get; set; }

	/// <summary>Operator-facing explanation of the verdict.</summary>
	[Key(12)]
	public string? Message { get; set; }
}
