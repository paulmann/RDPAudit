/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseMaintenanceKind.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Selects one safe maintenance action for RunDatabaseMaintenance (IPC ordinal 89). The
//          enum deliberately has NO full-VACUUM member: a full VACUUM rewrites the entire database
//          file and can hold the SQLite writer lock for minutes on a multi-gigabyte evidence store,
//          which the no-freeze rule forbids on a live database (docs/88 documents the policy). The
//          request validator refuses any value outside this set, so a hand-crafted numeric payload
//          cannot smuggle a destructive operation in.
// Depends: System
// Extends: Add a new safe maintenance action as a new ordinal; never repurpose existing ones.

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One safe maintenance action offered by <c>RunDatabaseMaintenance</c>.</summary>
public enum DatabaseMaintenanceKind
{
	/// <summary>Placeholder for an unset or unknown request. The validator refuses it.</summary>
	Unknown = 0,

	/// <summary><c>PRAGMA quick_check</c> - the cheap structural check.</summary>
	QuickCheck = 1,

	/// <summary><c>PRAGMA integrity_check</c> - the full structural check.</summary>
	FullIntegrityCheck = 2,

	/// <summary><c>PRAGMA foreign_key_check</c> - referential-integrity check; recommended after a restore.</summary>
	ForeignKeyCheck = 3,

	/// <summary><c>PRAGMA wal_checkpoint(PASSIVE)</c> - best-effort checkpoint that never blocks readers or writers.</summary>
	WalCheckpointPassive = 4,

	/// <summary><c>PRAGMA wal_checkpoint(TRUNCATE)</c> - checkpoint that truncates the WAL; may wait briefly for readers.</summary>
	WalCheckpointTruncate = 5,

	/// <summary><c>PRAGMA incremental_vacuum(N)</c> - bounded release of free pages back to the filesystem.</summary>
	IncrementalVacuum = 6,

	/// <summary><c>PRAGMA optimize</c> - the recommended statistics maintenance per SQLite documentation.</summary>
	Optimize = 7,
}
