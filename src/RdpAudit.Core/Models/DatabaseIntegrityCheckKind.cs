/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseIntegrityCheckKind.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Identifies which SQLite integrity check a stored result describes. The ordinals are an
//          append-only ABI because they are persisted in DatabaseIntegrityCheckResult.Kind: renumbering
//          one would silently relabel every historical row.
// Depends: none
// Extends: Append new members; never renumber.

namespace RdpAudit.Core.Models;

/// <summary>Which integrity check produced a stored result.</summary>
public enum DatabaseIntegrityCheckKind
{
	/// <summary>Not a check: the value a default-initialized row would carry, and always rejected.</summary>
	Unknown = 0,

	/// <summary><c>PRAGMA quick_check</c> - cheap, structural, safe to run often.</summary>
	QuickCheck = 1,

	/// <summary><c>PRAGMA integrity_check</c> - full page-by-page verification, expensive.</summary>
	FullIntegrityCheck = 2,

	/// <summary><c>PRAGMA foreign_key_check</c> - referential verification, run after every restore.</summary>
	ForeignKeyCheck = 3,

	/// <summary>Deletion-ledger hash-chain verification (no PRAGMA): proves no ledger row was modified,
	/// deleted from the middle or reordered after it was written.</summary>
	LedgerChainVerify = 4,
}

/// <summary>How a check turned out.</summary>
public enum DatabaseIntegrityOutcome
{
	/// <summary>The check ran and reported no problem.</summary>
	Ok = 0,

	/// <summary>The check ran and reported a problem, or could not complete. Never conflated with
	/// <see cref="Ok"/>: an unavailable check is not a passed check.</summary>
	Warning = 1,

	/// <summary>The check reported corruption that makes the store unsafe to trust.</summary>
	Failed = 2,
}
