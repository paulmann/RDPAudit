// File:    tests/RdpAudit.Core.Tests/Stage4SessionIpCorrelationSchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage IP-B SessionIpCorrelations table — EF mapping, column nullability,
//          and the supporting indexes used by Remote RDP Clients lookup and maintenance retention.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class Stage4SessionIpCorrelationSchemaTests : IDisposable
{
	private readonly SqliteConnection _connection;
	private readonly DbContextOptions<AuditDbContext> _options;

	public Stage4SessionIpCorrelationSchemaTests()
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
	public void DbContext_ExposesSessionIpCorrelationsDbSet()
	{
		using AuditDbContext db = new(_options);
		Assert.NotNull(db.SessionIpCorrelations);
	}

	[Fact]
	public void SessionIpCorrelation_PersistsAndReads()
	{
		DateTime now = DateTime.UtcNow;
		using (AuditDbContext db = new(_options))
		{
			db.SessionIpCorrelations.Add(new SessionIpCorrelation
			{
				LogonId = "0x12345",
				WtsSessionId = 7,
				UserName = "alice",
				Domain = "CORP",
				Ip = "203.0.113.4",
				FirstSeenUtc = now,
				LastSeenUtc = now,
				ObservedEventIds = "4624",
				IsDirectObservation = true,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			SessionIpCorrelation? row = db.SessionIpCorrelations.SingleOrDefault();
			Assert.NotNull(row);
			Assert.Equal("0x12345", row!.LogonId);
			Assert.Equal(7, row.WtsSessionId);
			Assert.Equal("alice", row.UserName);
			Assert.Equal("CORP", row.Domain);
			Assert.Equal("203.0.113.4", row.Ip);
			Assert.Equal("4624", row.ObservedEventIds);
			Assert.True(row.IsDirectObservation);
		}
	}

	[Fact]
	public void SessionIpCorrelation_AllowsNullSessionKeyFields()
	{
		using AuditDbContext db = new(_options);
		db.SessionIpCorrelations.Add(new SessionIpCorrelation
		{
			LogonId = null,
			WtsSessionId = null,
			UserName = "carol",
			Domain = null,
			Ip = "198.51.100.7",
			FirstSeenUtc = DateTime.UtcNow,
			LastSeenUtc = DateTime.UtcNow,
		});

		Assert.Equal(1, db.SaveChanges());
	}

	[Fact]
	public void SessionIpCorrelation_IsDirectObservation_DefaultsToFalse()
	{
		using AuditDbContext db = new(_options);
		SessionIpCorrelation row = new()
		{
			Ip = "203.0.113.99",
			FirstSeenUtc = DateTime.UtcNow,
			LastSeenUtc = DateTime.UtcNow,
		};
		db.SessionIpCorrelations.Add(row);
		db.SaveChanges();

		SessionIpCorrelation? read = db.SessionIpCorrelations.Single();
		Assert.False(read.IsDirectObservation);
	}

	[Fact]
	public void MigrationsAssembly_DeclaresStage4Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		IEnumerable<string> migrations = db.Database.GetMigrations();
		Assert.Contains(migrations, m => m.EndsWith("_Stage4SessionIpCorrelation", StringComparison.Ordinal));
	}

	[Fact]
	public void Indexes_AllPresent_OnSessionIpCorrelations()
	{
		using AuditDbContext db = new(_options);
		using SqliteCommand cmd = _connection.CreateCommand();
		cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'SessionIpCorrelations';";
		using SqliteDataReader rd = cmd.ExecuteReader();
		HashSet<string> indexes = new(StringComparer.OrdinalIgnoreCase);
		while (rd.Read())
		{
			indexes.Add(rd.GetString(0));
		}

		Assert.Contains("IX_SessionIpCorrelations_LogonId", indexes);
		Assert.Contains("IX_SessionIpCorrelations_WtsSessionId_UserName", indexes);
		Assert.Contains("IX_SessionIpCorrelations_Ip_LastSeenUtc", indexes);
		Assert.Contains("IX_SessionIpCorrelations_UserName_LastSeenUtc", indexes);
		Assert.Contains("IX_SessionIpCorrelations_LastSeenUtc", indexes);
	}
}
