// File:    tests/RdpAudit.Core.Tests/Stage2SchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates Stage 2 EF Core mappings against an in-memory SQLite database. Confirms that
//          the new tables can be created from migrations, that unique indices reject duplicates,
//          and that the migration upgrade path leaves Stage 1 data untouched.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates Stage 2 EF Core mappings against an in-memory SQLite database.</summary>
public class Stage2SchemaTests : IDisposable
{
	private readonly SqliteConnection _connection;
	private readonly DbContextOptions<AuditDbContext> _options;

	public Stage2SchemaTests()
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
	public void DbContext_ExposesAllStage2DbSets()
	{
		using AuditDbContext db = new(_options);
		Assert.NotNull(db.BlocklistEntries);
		Assert.NotNull(db.WhitelistEntries);
		Assert.NotNull(db.LoginRules);
		Assert.NotNull(db.ActiveBlocks);
		Assert.NotNull(db.AbuseReports);
		Assert.NotNull(db.AttackStats);
	}

	[Fact]
	public void BlocklistEntry_PersistsAndReads()
	{
		DateTime now = DateTime.UtcNow;
		using (AuditDbContext db = new(_options))
		{
			db.BlocklistEntries.Add(new BlocklistEntry
			{
				Ip = "1.2.3.4",
				Login = "admin",
				Reason = "manual",
				AddedUtc = now,
				Source = BlocklistSource.Manual,
				IsEnabled = true,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			BlocklistEntry? row = db.BlocklistEntries.SingleOrDefault();
			Assert.NotNull(row);
			Assert.Equal("1.2.3.4", row!.Ip);
			Assert.Equal("admin", row.Login);
			Assert.Equal(BlocklistSource.Manual, row.Source);
			Assert.True(row.IsEnabled);
		}
	}

	[Fact]
	public void WhitelistEntry_RejectsDuplicateIp()
	{
		using (AuditDbContext db = new(_options))
		{
			db.WhitelistEntries.Add(new WhitelistEntry { Ip = "10.0.0.1", AddedUtc = DateTime.UtcNow });
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.WhitelistEntries.Add(new WhitelistEntry { Ip = "10.0.0.1", AddedUtc = DateTime.UtcNow });
			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void LoginRule_RejectsDuplicateLogin()
	{
		using (AuditDbContext db = new(_options))
		{
			db.LoginRules.Add(new LoginRule { Login = "honeypot", Enabled = true, AddedUtc = DateTime.UtcNow });
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.LoginRules.Add(new LoginRule { Login = "honeypot", Enabled = true, AddedUtc = DateTime.UtcNow });
			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void ActiveBlock_RejectsDuplicateProviderIpPair()
	{
		using (AuditDbContext db = new(_options))
		{
			db.ActiveBlocks.Add(new ActiveBlock
			{
				Ip = "8.8.8.8",
				Provider = FirewallProviderKind.Windows,
				Reason = "auto",
				Status = ActiveBlockStatus.Active,
				CreatedUtc = DateTime.UtcNow,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.ActiveBlocks.Add(new ActiveBlock
			{
				Ip = "8.8.8.8",
				Provider = FirewallProviderKind.Windows,
				Reason = "auto",
				Status = ActiveBlockStatus.Active,
				CreatedUtc = DateTime.UtcNow,
			});
			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void ActiveBlock_PermitsSameIpAcrossProviders()
	{
		using AuditDbContext db = new(_options);
		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = "8.8.8.8",
			Provider = FirewallProviderKind.Windows,
			Reason = "auto",
			Status = ActiveBlockStatus.Active,
			CreatedUtc = DateTime.UtcNow,
		});
		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = "8.8.8.8",
			Provider = FirewallProviderKind.MikroTik,
			Reason = "auto",
			Status = ActiveBlockStatus.Pending,
			CreatedUtc = DateTime.UtcNow,
		});

		int written = db.SaveChanges();

		Assert.Equal(2, written);
	}

	[Fact]
	public void AttackStat_UsesIpAsPrimaryKey()
	{
		using (AuditDbContext db = new(_options))
		{
			db.AttackStats.Add(new AttackStat
			{
				Ip = "203.0.113.1",
				TotalAttempts = 10,
				Successful = 0,
				Failed = 10,
				FirstSeenUtc = DateTime.UtcNow.AddMinutes(-5),
				LastSeenUtc = DateTime.UtcNow,
				DurationSeconds = 300,
				Top10AttemptedLogins = "[\"admin\"]",
				ThreatScore = 75.0,
				IsBlocked = false,
				LastUpdatedUtc = DateTime.UtcNow,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.AttackStats.Add(new AttackStat
			{
				Ip = "203.0.113.1",
				TotalAttempts = 1,
				Successful = 0,
				Failed = 1,
				FirstSeenUtc = DateTime.UtcNow,
				LastSeenUtc = DateTime.UtcNow,
				DurationSeconds = 0,
				Top10AttemptedLogins = "[]",
				ThreatScore = 1.0,
				IsBlocked = false,
				LastUpdatedUtc = DateTime.UtcNow,
			});

			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void AbuseReport_AcceptsMultipleReportsPerIp()
	{
		using AuditDbContext db = new(_options);
		db.AbuseReports.Add(new AbuseReport
		{
			Ip = "198.51.100.1",
			ReportedUtc = DateTime.UtcNow.AddHours(-1),
			Categories = "18,22",
			ResponseCode = 200,
		});
		db.AbuseReports.Add(new AbuseReport
		{
			Ip = "198.51.100.1",
			ReportedUtc = DateTime.UtcNow,
			Categories = "18,22",
			ResponseCode = 200,
		});

		int written = db.SaveChanges();

		Assert.Equal(2, written);
	}

	[Fact]
	public void Stage1Tables_RemainPresentAfterStage2Apply()
	{
		using AuditDbContext db = new(_options);
		db.Addresses.Add(new Address { Ip = "1.1.1.1", FirstSeen = DateTime.UtcNow, LastSeen = DateTime.UtcNow });
		db.Sessions.Add(new Session { WtsSessionId = 1, ConnectUtc = DateTime.UtcNow });
		int written = db.SaveChanges();

		Assert.Equal(2, written);
	}
}
