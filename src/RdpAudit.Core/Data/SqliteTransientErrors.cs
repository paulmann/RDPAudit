/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : SqliteTransientErrors.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data)
// Purpose: Single classifier for the SQLite failures the workers are allowed to retry. EF Core wraps
//          every provider failure raised while saving changes in DbUpdateException, so a retry filter
//          that only matches SqliteException never fires on the persistence path.
// Depends: Microsoft.Data.Sqlite
// Extends: System.Object

using Microsoft.Data.Sqlite;

namespace RdpAudit.Core.Data;

/// <summary>Recognises the transient SQLite busy / locked failures that are worth retrying.</summary>
/// <remarks>
/// <para>
/// The two codes are not interchangeable and the difference is operational, not cosmetic.
/// <c>SQLITE_BUSY</c> (5) means another connection holds the write lock; the busy handler has already
/// waited for it, so a bounded application retry only has to cover the tail. <c>SQLITE_LOCKED</c> (6)
/// means a table lock inside a shared page cache is held elsewhere in this process, and SQLite returns
/// it immediately without consulting the busy handler at all.
/// </para>
/// <para>
/// Retrying is the last line of defence, not the design: the connection strings deliberately avoid
/// shared cache so ordinary writer-versus-writer contention upstream arrives as code 5 and is absorbed
/// by the wait rather than by this classifier (see <see cref="AuditDbContextOptionsFactory"/>).
/// </para>
/// </remarks>
public static class SqliteTransientErrors
{
	/// <summary>SQLITE_BUSY - the database file is write-locked by another connection.</summary>
	private const int Busy = 5;

	/// <summary>SQLITE_LOCKED - a table inside a shared cache is locked by another connection.</summary>
	private const int Locked = 6;

	/// <summary>True when the exception, or any exception it wraps, carries a transient SQLite
	/// busy / locked code (5 or 6). Everything else - a constraint violation (19), a corrupt store
	/// (11), a missing table - is deliberately not retried, because a retry would only repeat the
	/// same deterministic failure while holding the writer's turn.</summary>
	/// <param name="exception">Exception raised by the persistence path; may be null.</param>
	public static bool IsTransient(Exception? exception)
	{
		for (Exception? current = exception; current is not null; current = current.InnerException)
		{
			if (current is SqliteException sqlite && sqlite.SqliteErrorCode is Busy or Locked)
			{
				return true;
			}
		}

		return false;
	}
}
