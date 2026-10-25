// File:    src/RdpAudit.Core/Data/SqlitePragmaInterceptor.cs
// Module:  RdpAudit.Core.Data
// Purpose: Applies SQLite PRAGMAs (WAL, synchronous, cache, FK, auto_vacuum) on every read-write
//          connection open, and only the connection-local subset when EF opens its read-only
//          existence probe (that probe would otherwise fail with SQLITE_READONLY).
//          Statement ORDER matters for exactly one of them: `auto_vacuum` is applied FIRST, before
//          `journal_mode = WAL` materialises page 1 of a brand-new store. SQLite applies an
//          auto_vacuum change immediately only while the database still has no pages; once page 1
//          exists the statement sets a PENDING mode that nothing but a full VACUUM applies, and
//          `PRAGMA auto_vacuum` keeps reporting the old value. Measured on the store this product
//          creates (SQLite 3.41.2): with the shipped WAL-first order a fresh store ends up in mode
//          `0` and `PRAGMA incremental_vacuum` releases nothing (B27); with `auto_vacuum` first the
//          same fresh store ends up in mode `2` and `incremental_vacuum` releases free pages. The
//          order is inert on an existing store: there the statement can only ever be pending, which
//          is the state every connection already put it in before this change.
// Extends: Microsoft.EntityFrameworkCore.Diagnostics.DbConnectionInterceptor
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace RdpAudit.Core.Data;

/// <summary>Applies SQLite PRAGMAs on every connection open.</summary>
/// <remarks>
/// <para>
/// The <c>auto_vacuum</c> statement comes first on purpose. SQLite honours an auto-vacuum change
/// immediately only while the store has no pages yet; <c>journal_mode = WAL</c> is the statement that
/// creates page 1 of a new store, and after that the auto-vacuum change is merely pending until a full
/// <c>VACUUM</c> runs. Since this interceptor fires on the connection that also creates the schema,
/// putting <c>auto_vacuum</c> first is what makes a store created by the product start in
/// <c>INCREMENTAL</c> mode (see <c>docs/88-database-backup-and-restore.md</c>; the measurement is in
/// <c>AutoVacuumModeTests</c>).
/// </para>
/// <para>
/// On an existing store the order changes nothing observable: the statement there can only become
/// pending (the purge and maintenance paths read <c>PRAGMA auto_vacuum</c>, which reports the mode
/// actually in effect) and no code path in the product runs a full <c>VACUUM</c> over a connection
/// this interceptor touches. Shrinking an existing store stays an explicit, offline operator action.
/// </para>
/// </remarks>
public sealed class SqlitePragmaInterceptor : DbConnectionInterceptor
{
	public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
	{
		ApplyPragmas(connection);
		base.ConnectionOpened(connection, eventData);
	}

	public override async Task ConnectionOpenedAsync(
		DbConnection connection,
		ConnectionEndEventData eventData,
		CancellationToken cancellationToken = default)
	{
		ApplyPragmas(connection);
		await base.ConnectionOpenedAsync(connection, eventData, cancellationToken).ConfigureAwait(false);
	}

	private static void ApplyPragmas(DbConnection connection)
	{
		using var cmd = connection.CreateCommand();
		if (IsReadOnly(connection))
		{
			// EF's existence probe: connection-local settings only, none of them touch the file.
			cmd.CommandText =
				"PRAGMA cache_size   = -32000;" +
				"PRAGMA foreign_keys = ON;" +
				"PRAGMA temp_store   = MEMORY;" +
				"PRAGMA busy_timeout = 5000;";
		}
		else
		{
			// Order matters: auto_vacuum first, before journal_mode creates page 1 (B27).
			cmd.CommandText =
				"PRAGMA auto_vacuum  = INCREMENTAL;" +
				"PRAGMA journal_mode = WAL;" +
				"PRAGMA synchronous  = NORMAL;" +
				"PRAGMA cache_size   = -32000;" +
				"PRAGMA foreign_keys = ON;" +
				"PRAGMA temp_store   = MEMORY;";
		}

		cmd.ExecuteNonQuery();
	}

	/// <summary>True when this connection physically cannot write.</summary>
	/// <remarks>
	/// EF Core answers "does the database exist?" by re-opening the configured connection string with
	/// <c>Mode=ReadOnly</c>. The interceptor fires on that throwaway probe too, and the write PRAGMAs -
	/// <c>auto_vacuum</c> first of all - then raise SQLITE_READONLY ("attempt to write a readonly
	/// database") before the first migration runs. Measured 2026-10-23: without shared cache every
	/// fresh-store migration failed this way. The probe does not need those PRAGMAs; the connection
	/// that actually creates the store applies them.
	/// </remarks>
	private static bool IsReadOnly(DbConnection connection)
	{
		if (connection is not SqliteConnection sqlite)
		{
			return false;
		}

		return new SqliteConnectionStringBuilder(sqlite.ConnectionString).Mode == SqliteOpenMode.ReadOnly;
	}
}
