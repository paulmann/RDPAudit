// File:    tests/RdpAudit.Core.Tests/SqliteConcurrencyGuardsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the two properties that keep ordinary SQLite write contention from turning into
//          hard failures: the shipped connection strings must not enable a shared page cache, and
//          the retry classifier must see a busy/locked code through EF Core's DbUpdateException.
//          Both were broken on 2026-10-23 (host 192.168.1.50): the service logged
//          "SQLite Error 6: 'database table is locked: RawEvents'" and the bounded retry never ran,
//          because a filter on SqliteException cannot match the wrapper EF Core throws.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Guards the shared-cache ban and the transient-failure classifier.</summary>
public class SqliteConcurrencyGuardsTests
{
	/// <summary>A shared page cache makes the second writer fail immediately instead of waiting;
	/// the write connection must therefore use a private cache with an explicit bounded wait.</summary>
	[Fact]
	public void WriteConnectionString_UsesPrivateCacheAndExplicitBusyTimeout()
	{
		string connectionString = AuditDbContextOptionsFactory.BuildConnectionString(@"C:\data\rdpaudit.db");

		Assert.False(
			connectionString.Contains("Cache=Shared", StringComparison.OrdinalIgnoreCase),
			"the write connection must not enable shared cache: SQLITE_LOCKED bypasses the busy handler");
		Assert.Contains("Default Timeout=30", connectionString, StringComparison.Ordinal);
	}

	/// <summary>The REST reader keeps Mode=ReadOnly but drops the shared cache for the same reason,
	/// and waits on a shorter budget so a blocked dashboard query fails fast.</summary>
	[Fact]
	public void ReadOnlyConnectionString_StaysReadOnlyWithoutSharedCache()
	{
		string connectionString = AuditDbContextOptionsFactory.BuildReadOnlyConnectionString(@"C:\data\rdpaudit.db");

		Assert.Contains("Mode=ReadOnly", connectionString, StringComparison.Ordinal);
		Assert.False(
			connectionString.Contains("Cache=Shared", StringComparison.OrdinalIgnoreCase),
			"the read-only connection must not enable shared cache either");
		Assert.Contains("Default Timeout=5", connectionString, StringComparison.Ordinal);
	}

	/// <summary>The persistence path throws DbUpdateException, not SqliteException; the classifier has
	/// to look through the wrapper or the bounded retry is dead code.</summary>
	[Fact]
	public void IsTransient_SeesBusyLockedCodeThroughEfWrapper()
	{
		DbUpdateException wrapped = new(
			"An error occurred while saving the entity changes.",
			new SqliteException("database table is locked: RawEvents", 6));

		Assert.True(SqliteTransientErrors.IsTransient(wrapped));
	}

	/// <summary>A deterministic failure (constraint violation, code 19) must never be retried: the
	/// retry would repeat it while holding the writer's turn.</summary>
	[Fact]
	public void IsTransient_RejectsDeterministicFailures()
	{
		DbUpdateException wrapped = new(
			"An error occurred while saving the entity changes.",
			new SqliteException("UNIQUE constraint failed: Addresses.Ip", 19));

		Assert.False(SqliteTransientErrors.IsTransient(wrapped));
		Assert.False(SqliteTransientErrors.IsTransient(new InvalidOperationException("unrelated")));
		Assert.False(SqliteTransientErrors.IsTransient(null));
	}
}
