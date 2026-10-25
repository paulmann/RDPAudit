/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : VerifyDatabaseBackupRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Request DTO for VerifyDatabaseBackup (IPC ordinal 87). The snapshot is selected by name; the
//          name is server-validated against the snapshot timestamp format and combined through
//          PathSafety, so it can never address a directory outside the backup root. An absent name
//          verifies the newest database snapshot, which is what an operator wants after a warning.
// Depends: MessagePack
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request to verify one database snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class VerifyDatabaseBackupRequest
{
	/// <summary>Snapshot directory name to verify (<c>yyyyMMdd-HHmmss</c>, optionally with a
	/// <c>-NN</c> collision suffix). Null or empty verifies the newest database snapshot.</summary>
	[Key(0)]
	public string? Name { get; set; }
}
