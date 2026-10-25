/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : CreateDatabaseBackupRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Request DTO for CreateDatabaseBackup (IPC ordinal 85). Bounded by construction: the only
//          input is an optional override of whether the shard tree travels with the database, and the
//          server clamps it against the configured BackupOptions.IncludeShards. An absent payload means
//          "use the configured scope", which is the safe default because copying the shard tree can be
//          far larger than the database.
// Depends: MessagePack
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request for a database snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CreateDatabaseBackupRequest
{
	/// <summary>Optional override of the snapshot scope: true also copies the shard tree, false copies
	/// the database only, null uses the configured <c>BackupOptions.IncludeShards</c>.</summary>
	[Key(0)]
	public bool? IncludeShards { get; set; }
}
