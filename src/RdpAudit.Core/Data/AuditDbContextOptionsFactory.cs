/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : AuditDbContextOptionsFactory.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data)
// Purpose: Single source of truth for constructing AuditDbContext options. The normal path
//          builds the write connection (WAL, private page cache, 30 s busy timeout) plus the
//          write-enabling SqlitePragmaInterceptor; the read-only path opens the SAME database file
//          with Mode=ReadOnly and swaps in ReadOnlySqlitePragmaInterceptor so the REST API can
//          serve a live WAL database while no connection obtained from those options is physically
//          able to write. Both paths apply AuditDbContextOptions.ApplyWarningPolicy.
// Depends: AuditDbContext, SqlitePragmaInterceptor, ReadOnlySqlitePragmaInterceptor
// Extends: System.Object

using Microsoft.EntityFrameworkCore;

namespace RdpAudit.Core.Data;

/// <summary>Constructs <see cref="AuditDbContext"/> options for the normal and read-only paths.</summary>
public static class AuditDbContextOptionsFactory
{
	/// <summary>Builds the SQLite connection string for a normal (read-write) context.</summary>
	/// <remarks>
	/// <para>
	/// <c>Cache=Shared</c> must stay out of this string. In shared-cache mode SQLite hands the second
	/// writer <c>SQLITE_LOCKED</c> (error 6, "database table is locked") instead of making it wait, and
	/// the busy handler is never consulted for that class of lock - so neither <c>busy_timeout</c> nor
	/// <c>SqliteCommand.CommandTimeout</c> can absorb ordinary writer-versus-writer contention.
	/// Measured 2026-10-23 against the shipped <c>e_sqlite3</c>: two connections, one write transaction
	/// open, second write attempt - shared cache returned code 6 after 2 ms even with
	/// busy_timeout = 2000; a private cache in WAL returned code 5 only after the full 2206 ms wait.
	/// In production that difference surfaced as
	/// <c>SQLite Error 6: 'database table is locked: RawEvents'</c> on the ingest path whenever a
	/// retention or maintenance pass wrote at the same moment (host 192.168.1.50).
	/// </para>
	/// <para>
	/// WAL already isolates readers from the writer, so a shared page cache buys nothing here; it only
	/// turns a queueable wait into an immediate hard failure. The explicit <c>Default Timeout</c> keeps
	/// that wait bounded and independent of the provider default.
	/// </para>
	/// </remarks>
	public static string BuildConnectionString(string dbPath) =>
		$"Data Source={dbPath};Default Timeout=30";

	/// <summary>Builds the SQLite connection string for a read-only context.</summary>
	/// <remarks>The reader waits at most five seconds: a blocked dashboard query has to fail fast
	/// instead of holding an operator for the thirty-second writer budget.</remarks>
	public static string BuildReadOnlyConnectionString(string dbPath) =>
		$"Data Source={dbPath};Mode=ReadOnly;Default Timeout=5";

	/// <summary>Creates options for a normal context (the path used by Program.RegisterServices).</summary>
	public static DbContextOptions<AuditDbContext> Create(
		string dbPath,
		SqlitePragmaInterceptor? pragmaInterceptor = null)
	{
		DbContextOptionsBuilder<AuditDbContext> builder = new();
		builder.UseSqlite(BuildConnectionString(dbPath));
		if (pragmaInterceptor is not null)
		{
			builder.AddInterceptors(pragmaInterceptor);
		}

		AuditDbContextOptions.ApplyWarningPolicy(builder);
		return builder.Options;
	}

	/// <summary>Creates options for a read-only context used by the REST API event reader.</summary>
	public static DbContextOptions<AuditDbContext> CreateReadOnly(
		string dbPath,
		ReadOnlySqlitePragmaInterceptor? readOnlyPragmaInterceptor = null)
	{
		DbContextOptionsBuilder<AuditDbContext> builder = new();
		builder.UseSqlite(BuildReadOnlyConnectionString(dbPath));
		if (readOnlyPragmaInterceptor is not null)
		{
			builder.AddInterceptors(readOnlyPragmaInterceptor);
		}

		AuditDbContextOptions.ApplyWarningPolicy(builder);
		return builder.Options;
	}
}
