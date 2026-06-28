// File:    src/RdpAudit.Core/Data/SqlitePragmaInterceptor.cs
// Module:  RdpAudit.Core.Data
// Purpose: Applies SQLite PRAGMAs (WAL, synchronous, cache, FK) on every connection open.
// Extends: Microsoft.EntityFrameworkCore.Diagnostics.DbConnectionInterceptor
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace RdpAudit.Core.Data;

/// <summary>Applies SQLite PRAGMAs on every connection open.</summary>
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
		cmd.CommandText =
			"PRAGMA journal_mode = WAL;" +
			"PRAGMA synchronous  = NORMAL;" +
			"PRAGMA cache_size   = -32000;" +
			"PRAGMA foreign_keys = ON;" +
			"PRAGMA auto_vacuum  = INCREMENTAL;" +
			"PRAGMA temp_store   = MEMORY;";
		cmd.ExecuteNonQuery();
	}
}
