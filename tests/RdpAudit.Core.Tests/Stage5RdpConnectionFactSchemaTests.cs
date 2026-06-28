// File:    tests/RdpAudit.Core.Tests/Stage5RdpConnectionFactSchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage IP-C RdpConnectionFacts table — EF mapping, column nullability,
//          default values, and the supporting indexes used by Remote RDP Clients historical
//          enrichment and Attack Statistics export.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class Stage5RdpConnectionFactSchemaTests : IDisposable
{
	private readonly SqliteConnection _connection;
	private readonly DbContextOptions<AuditDbContext> _options;

	public Stage5RdpConnectionFactSchemaTests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		_options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;

		using AuditDbContext db = new(_options);
		db.Database.EnsureCreated();
	}

	public void Dispose()
	{
		_connection.Dispose();
	}

	[Fact]
	public void DbContext_ExposesRdpConnectionFactsDbSet()
	{
		using AuditDbContext db = new(_options);
		Assert.NotNull(db.RdpConnectionFacts);
	}

	[Fact]
	public void RdpConnectionFact_PersistsAndReads()
	{
		DateTime now = DateTime.UtcNow;
		using (AuditDbContext db = new(_options))
		{
			db.RdpConnectionFacts.Add(new RdpConnectionFact
			{
				LogonId = "0x12345",
				WtsSessionId = 7,
				UserName = "alice",
				Domain = "CORP",
				Ip = "203.0.113.4",
				FirstSeenUtc = now,
				LastSeenUtc = now,
				ConnectedUtc = now,
				AuthenticatedUtc = now,
				ObservedEventIds = "1149,21",
				UserNamesAttempted = "alice",
				SuccessfulLogons = 1,
				FailedLogons = 0,
				IsActive = true,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			RdpConnectionFact? row = db.RdpConnectionFacts.SingleOrDefault();
			Assert.NotNull(row);
			Assert.Equal("0x12345", row!.LogonId);
			Assert.Equal(7, row.WtsSessionId);
			Assert.Equal("alice", row.UserName);
			Assert.Equal("CORP", row.Domain);
			Assert.Equal("203.0.113.4", row.Ip);
			Assert.Equal("1149,21", row.ObservedEventIds);
			Assert.Equal("alice", row.UserNamesAttempted);
			Assert.Equal(1, row.SuccessfulLogons);
			Assert.True(row.IsActive);
		}
	}

	[Fact]
	public void RdpConnectionFact_DefaultsForCountersAndIsActive()
	{
		using AuditDbContext db = new(_options);
		RdpConnectionFact row = new()
		{
			Ip = "203.0.113.10",
			FirstSeenUtc = DateTime.UtcNow,
			LastSeenUtc = DateTime.UtcNow,
		};
		db.RdpConnectionFacts.Add(row);
		db.SaveChanges();

		RdpConnectionFact? read = db.RdpConnectionFacts.Single();
		Assert.Equal(0, read.FailedLogons);
		Assert.Equal(0, read.SuccessfulLogons);
		Assert.False(read.IsActive);
	}

	[Fact]
	public void MigrationsAssembly_DeclaresStage5Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		IEnumerable<string> migrations = db.Database.GetMigrations();
		Assert.Contains(migrations, m => m.EndsWith("_Stage5RdpConnectionFact", StringComparison.Ordinal));
	}

	[Fact]
	public void Indexes_AllPresent_OnRdpConnectionFacts()
	{
		using AuditDbContext db = new(_options);
		using SqliteCommand cmd = _connection.CreateCommand();
		cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'RdpConnectionFacts';";
		using SqliteDataReader rd = cmd.ExecuteReader();
		HashSet<string> indexes = new(StringComparer.OrdinalIgnoreCase);
		while (rd.Read())
		{
			indexes.Add(rd.GetString(0));
		}

		Assert.Contains("IX_RdpConnectionFacts_Ip_LastSeenUtc", indexes);
		Assert.Contains("IX_RdpConnectionFacts_WtsSessionId_UserName", indexes);
		Assert.Contains("IX_RdpConnectionFacts_LogonId", indexes);
		Assert.Contains("IX_RdpConnectionFacts_LastSeenUtc", indexes);
		Assert.Contains("IX_RdpConnectionFacts_UserName_LastSeenUtc", indexes);
	}
}
