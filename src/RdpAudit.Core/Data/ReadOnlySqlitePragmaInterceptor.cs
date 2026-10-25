/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : ReadOnlySqlitePragmaInterceptor.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data)
// Purpose: Applies SQLite PRAGMAs that are SAFE on a read-only connection. The regular
//          SqlitePragmaInterceptor issues journal_mode=WAL / synchronous / auto_vacuum,
//          each of which requires a write on the database and therefore fails with
//          SQLITE_READONLY (8) when the connection string uses Mode=ReadOnly. The REST API
//          read-only context uses THIS interceptor instead so the connection can open a
//          live WAL-mode database without ever mutating it.
// Depends: Microsoft.EntityFrameworkCore.Diagnostics
// Extends: DbConnectionInterceptor

using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace RdpAudit.Core.Data;

/// <summary>Applies read-only-safe SQLite PRAGMAs on every connection open.</summary>
public sealed class ReadOnlySqlitePragmaInterceptor : DbConnectionInterceptor
{
	/// <summary>How long (ms) a blocked read waits before failing with SQLITE_BUSY.</summary>
	public const int BusyTimeoutMs = 5000;

	/// <summary>Compile-time SQL text (no runtime concatenation) so the query is visibly constant.</summary>
	private const string ReadOnlyPragmasSql =
		"PRAGMA query_only   = ON;" +
		"PRAGMA busy_timeout = 5000;" +
		"PRAGMA cache_size   = -32000;" +
		"PRAGMA foreign_keys = OFF;" +
		"PRAGMA temp_store   = MEMORY;";

	public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
	{
		ApplyReadOnlyPragmas(connection);
		base.ConnectionOpened(connection, eventData);
	}

	public override async Task ConnectionOpenedAsync(
		DbConnection connection,
		ConnectionEndEventData eventData,
		CancellationToken cancellationToken = default)
	{
		ApplyReadOnlyPragmas(connection);
		await base.ConnectionOpenedAsync(connection, eventData, cancellationToken).ConfigureAwait(false);
	}

	private static void ApplyReadOnlyPragmas(DbConnection connection)
	{
		using var cmd = connection.CreateCommand();
		// Only connection-local, non-writing settings are applied. journal_mode,
		// synchronous and auto_vacuum are intentionally absent: on a Mode=ReadOnly
		// connection each of them raises SQLITE_READONLY.
		cmd.CommandText = ReadOnlyPragmasSql;
		cmd.ExecuteNonQuery();
	}
}
