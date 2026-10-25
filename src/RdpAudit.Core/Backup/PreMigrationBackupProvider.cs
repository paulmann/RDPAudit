/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : PreMigrationBackupProvider.cs
// Project: RdpAudit.Core (RdpAudit.Core.Backup)
// Purpose: The seam between the schema initializer and the database backup implementation. The
//          initializer lives in Core and must not depend on the Service; the Service owns the snapshot
//          engine. This interface is what lets AuditDbInitializer enforce "no migration without a
//          restorable pre-state" while the actual work happens in DatabaseBackupService. A host that
//          registers no provider, or an operator who sets PreMigrationBackupEnabled=false, gets
//          IsEnabled=false and the initializer migrates while logging that it did so without a snapshot.
// Depends: System.Threading
// Extends: Add a member here only when the initializer needs a new guarantee from the snapshot engine.

namespace RdpAudit.Core.Backup;

/// <summary>Outcome of a pre-migration snapshot attempt. On failure it carries the directory the
/// snapshot was expected in, so the initializer's operator message can name the path to fix.</summary>
public sealed record PreMigrationBackupResult(
	bool Success,
	string ExpectedDirectory,
	string? SnapshotDirectory,
	string? Error)
{
	/// <summary>Builds a failure that names the expected directory and the reason.</summary>
	public static PreMigrationBackupResult Failed(string expectedDirectory, string error)
		=> new(false, expectedDirectory, null, error);

	/// <summary>Builds a success naming the snapshot that was written.</summary>
	public static PreMigrationBackupResult Created(string expectedDirectory, string snapshotDirectory)
		=> new(true, expectedDirectory, snapshotDirectory, null);
}

/// <summary>
/// Takes the snapshot the schema initializer requires before it applies EF migrations. Implemented by
/// the Service's backup engine; Core only depends on this contract.
/// </summary>
public interface IPreMigrationBackupProvider
{
	/// <summary>True when this host must take a snapshot before migrating. False means the operator
	/// disabled it or no snapshot engine is wired up; the initializer then migrates and says so.</summary>
	bool IsEnabled { get; }

	/// <summary>Absolute directory the snapshot is expected in. Used verbatim in the operator message
	/// when a snapshot cannot be taken.</summary>
	string ExpectedDirectory { get; }

	/// <summary>Takes one snapshot of <paramref name="databasePath"/> before any migration is applied.
	/// Must not throw for a failure it can describe: return a failed
	/// <see cref="PreMigrationBackupResult"/> instead.</summary>
	Task<PreMigrationBackupResult> CreateAsync(string databasePath, CancellationToken cancellationToken);
}
