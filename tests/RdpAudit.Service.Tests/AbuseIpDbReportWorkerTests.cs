// File:    tests/RdpAudit.Service.Tests/AbuseIpDbReportWorkerTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end tests for the Stage 8 AbuseIpDbReportWorker. Confirms it submits reports for
//          high-threat hostile IPs, respects the local dedup window via AbuseReports, persists
//          structured results, and never submits when the configuration is disabled.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AbuseIpDbReportWorkerTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class FakeAbuseClient : IAbuseIpDbClient
	{
		public List<AbuseIpDbReportRequest> Submitted { get; } = new();

		public AbuseIpDbReportResult NextResult { get; set; } = new()
		{
			Outcome = AbuseIpDbReportOutcome.Accepted,
			ResponseCode = 200,
			Message = "ok",
		};

		public Task<AbuseIpDbReportResult> ReportAsync(AbuseIpDbReportRequest request, CancellationToken ct)
		{
			Submitted.Add(request);
			return Task.FromResult(NextResult);
		}

		public Task<AbuseIpDbReportResult> ValidateKeyAsync(CancellationToken ct) =>
			Task.FromResult(NextResult);
	}

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}
		return (new TestDbContextFactory(options), conn);
	}

	[Fact]
	public async Task RunOnceAsync_DoesNothing_WhenDisabled()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, submitted);
			Assert.Empty(fake.Submitted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_SubmitsReportForHighThreatIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				DateTime now = DateTime.UtcNow;
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.66",
					TotalAttempts = 100,
					Successful = 0,
					Failed = 100,
					FirstSeenUtc = now.AddHours(-1),
					LastSeenUtc = now,
					DurationSeconds = 3600,
					Top10AttemptedLogins = "[\"admin\",\"root\"]",
					ThreatScore = 90.0,
					IsBlocked = false,
					LastUpdatedUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "{\"$protected\":\"YWJjZA==\",\"scope\":\"LocalMachine\"}";
			opts.AbuseIpDb.MinThreatScore = 60.0;
			opts.AbuseIpDb.MinFailedAttempts = 10;
			opts.AbuseIpDb.DeduplicationWindowMinutes = 15;
			opts.AbuseIpDb.MaxReportsPerHour = 100;
			opts.AbuseIpDb.MaxReportsPerDay = 500;

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, submitted);
			Assert.Single(fake.Submitted);
			Assert.Equal("203.0.113.66", fake.Submitted[0].Ip);
			Assert.Contains("Connection Type: RDP Attack", fake.Submitted[0].Comment, StringComparison.Ordinal);

			await using AuditDbContext db = factory.CreateDbContext();
			AbuseReport[] reports = await db.AbuseReports.ToArrayAsync();
			Assert.Single(reports);
			Assert.Equal(200, reports[0].ResponseCode);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_SkipsIp_RecentlyReported()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.66",
					TotalAttempts = 100,
					Failed = 100,
					Successful = 0,
					FirstSeenUtc = now.AddHours(-1),
					LastSeenUtc = now,
					ThreatScore = 90.0,
					Top10AttemptedLogins = "[]",
					LastUpdatedUtc = now,
				});
				seed.AbuseReports.Add(new AbuseReport
				{
					Ip = "203.0.113.66",
					ReportedUtc = now.AddMinutes(-5),
					Categories = "18,22",
					ResponseCode = 200,
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "envelope";
			opts.AbuseIpDb.MinThreatScore = 50;
			opts.AbuseIpDb.MinFailedAttempts = 5;

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, submitted);
			Assert.Empty(fake.Submitted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_SkipsPrivateIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "10.1.2.3",
					TotalAttempts = 200,
					Failed = 200,
					Successful = 0,
					FirstSeenUtc = now.AddHours(-1),
					LastSeenUtc = now,
					ThreatScore = 99.0,
					Top10AttemptedLogins = "[]",
					LastUpdatedUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "envelope";

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, submitted);
			Assert.Empty(fake.Submitted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_RecordsTransportErrorAsAbuseReport()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.77",
					TotalAttempts = 100,
					Failed = 100,
					Successful = 0,
					FirstSeenUtc = now.AddHours(-1),
					LastSeenUtc = now,
					ThreatScore = 90.0,
					Top10AttemptedLogins = "[]",
					LastUpdatedUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "envelope";
			opts.AbuseIpDb.MinThreatScore = 50;
			opts.AbuseIpDb.MinFailedAttempts = 5;

			FakeAbuseClient fake = new()
			{
				NextResult = new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.TransportError,
					ResponseCode = 0,
					Message = "synthetic transport error",
				},
			};
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, submitted);

			await using AuditDbContext db = factory.CreateDbContext();
			AbuseReport[] reports = await db.AbuseReports.ToArrayAsync();
			Assert.Single(reports);
			Assert.Equal(0, reports[0].ResponseCode);
			Assert.Contains("transport error", reports[0].Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private static AttackStat HostileStat(string ip, DateTime now) => new()
	{
		Ip = ip,
		TotalAttempts = 100,
		Failed = 100,
		Successful = 0,
		FirstSeenUtc = now.AddHours(-1),
		LastSeenUtc = now,
		DurationSeconds = 3600,
		ThreatScore = 90.0,
		Top10AttemptedLogins = "[]",
		IsBlocked = false,
		LastUpdatedUtc = now,
	};

	private static void EnableDedupe(RdpAuditOptions opts, int cooldownHours)
	{
		opts.AbuseIpDb.Enabled = true;
		opts.AbuseIpDb.ReportAttacks = true;
		opts.AbuseIpDb.ApiKey = "envelope";
		opts.AbuseIpDb.MinThreatScore = 50;
		opts.AbuseIpDb.MinFailedAttempts = 5;
		opts.AbuseIpDb.ReportDedupeEnabled = true;
		opts.AbuseIpDb.ReportCooldownHours = cooldownHours;
	}

	[Fact]
	public async Task RunOnceAsync_RecordsHistoryRow_OnEveryAttempt()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(HostileStat("203.0.113.66", now));
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "envelope";
			opts.AbuseIpDb.MinThreatScore = 50;
			opts.AbuseIpDb.MinFailedAttempts = 5;

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, submitted);

			await using AuditDbContext db = factory.CreateDbContext();
			AbuseIpDbReportHistory[] history = await db.AbuseIpDbReportHistory.ToArrayAsync();
			AbuseIpDbReportHistory row = Assert.Single(history);
			Assert.Equal("203.0.113.66", row.IpAddress);
			Assert.True(row.Succeeded);
			Assert.Equal(200, row.HttpStatusCode);
			Assert.Equal("worker", row.Source);
			Assert.False(string.IsNullOrEmpty(row.CommentHash));
			// v1.2.6 report-log columns are populated on every attempt.
			Assert.Equal(AbuseIpDbReportAction.Sent, row.Action);
			// 203.0.113.0/24 is TEST-NET-3 (documentation range); the classifier records that verbatim.
			Assert.Equal(IpReportClassification.Documentation, row.Classification);
			Assert.Equal(100, row.FailedCount);
			Assert.Equal(0, row.SuccessfulCount);
			Assert.False(string.IsNullOrEmpty(row.CommentPreview));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_DedupeEnabled_SkipsIp_WithRecentSuccessfulHistory()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(HostileStat("203.0.113.66", now));
				seed.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
				{
					IpAddress = "203.0.113.66",
					ReportedAtUtc = now.AddHours(-2),
					Succeeded = true,
					HttpStatusCode = 200,
					ResultCode = "Accepted",
					AbuseCategories = "18,22",
					Source = "worker",
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			EnableDedupe(opts, cooldownHours: 24);

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, submitted);
			Assert.Empty(fake.Submitted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_DedupeEnabled_FailedHistory_DoesNotSuppress()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AttackStats.Add(HostileStat("203.0.113.66", now));
				// A recent FAILED attempt must never gate a future report.
				seed.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
				{
					IpAddress = "203.0.113.66",
					ReportedAtUtc = now.AddHours(-2),
					Succeeded = false,
					HttpStatusCode = 0,
					ResultCode = "TransportError",
					AbuseCategories = "18,22",
					Source = "worker",
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			EnableDedupe(opts, cooldownHours: 24);

			FakeAbuseClient fake = new();
			AbuseIpDbReportWorker worker = new(factory, new StaticOptionsMonitorLocal<RdpAuditOptions>(opts),
				fake, NullLogger<AbuseIpDbReportWorker>.Instance);

			int submitted = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, submitted);
			Assert.Single(fake.Submitted);
			Assert.Equal("203.0.113.66", fake.Submitted[0].Ip);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public void BuildEvidence_PopulatesEvidenceEventIds_FromCounts()
	{
		AttackStat both = new()
		{
			Ip = "203.0.113.7",
			Failed = 10,
			Successful = 2,
			FirstSeenUtc = DateTime.UtcNow.AddHours(-1),
			LastSeenUtc = DateTime.UtcNow,
			Top10AttemptedLogins = "[\"admin\"]",
		};
		AbuseIpDbEvidence ev = AbuseIpDbReportWorker.BuildEvidence(both);
		Assert.Equal(new[] { 4625, 4776, 4624, 4648 }, ev.EvidenceEventIds);

		AttackStat failedOnly = new()
		{
			Ip = "203.0.113.8",
			Failed = 3,
			Successful = 0,
			FirstSeenUtc = DateTime.UtcNow.AddHours(-1),
			LastSeenUtc = DateTime.UtcNow,
			Top10AttemptedLogins = "[]",
		};
		Assert.Equal(new[] { 4625, 4776 }, AbuseIpDbReportWorker.BuildEvidence(failedOnly).EvidenceEventIds);
	}

	[Theory]
	[InlineData(0, 0, new int[0])]
	[InlineData(5, 0, new[] { 4625, 4776 })]
	[InlineData(0, 5, new[] { 4624, 4648 })]
	[InlineData(5, 5, new[] { 4625, 4776, 4624, 4648 })]
	public void DeriveEvidenceEventIds_MapsCountsToWindowsEventIds(long failed, long successful, int[] expected)
	{
		Assert.Equal(expected, AbuseIpDbReportWorker.DeriveEvidenceEventIds(failed, successful));
	}

	[Fact]
	public void FormatUsernamesSample_NullOrEmpty_ReturnsNull()
	{
		Assert.Null(AbuseIpDbReportWorker.FormatUsernamesSample(null));
		Assert.Null(AbuseIpDbReportWorker.FormatUsernamesSample("[]"));
	}

	[Fact]
	public void FormatUsernamesSample_CapsAtTenAndJoins()
	{
		string json = System.Text.Json.JsonSerializer.Serialize(
			Enumerable.Range(0, 25).Select(i => "user" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray());

		string? sample = AbuseIpDbReportWorker.FormatUsernamesSample(json);

		Assert.NotNull(sample);
		Assert.Equal(10, sample!.Split(", ", StringSplitOptions.None).Length);
		Assert.StartsWith("user0, user1", sample, StringComparison.Ordinal);
	}
}
