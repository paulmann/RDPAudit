/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RestoreDatabaseBackupToDirectoryRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Request payload for RestoreDatabaseBackupToDirectory (IPC ordinal 90): restore one
//          database snapshot into an operator-chosen scratch directory. The live store is never
//          touched - the service verifies the snapshot first and refuses to write a byte when the
//          verification fails, then copies only into the supplied directory. The response is the
//          existing DatabaseBackupRestoreReportDto.
// Depends: MessagePack
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request DTO for <c>RestoreDatabaseBackupToDirectory</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RestoreDatabaseBackupToDirectoryRequest
{
	/// <summary>Snapshot directory name to restore; null or empty means "the newest snapshot".</summary>
	[Key(0)]
	public string? Name { get; set; }

	/// <summary>Absolute target directory the snapshot is copied into. Created when missing; the
	/// live database and the backup root are never modified by this command.</summary>
	[Key(1)]
	public string TargetDirectory { get; set; } = string.Empty;
}
