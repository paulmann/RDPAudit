// File:    tests/RdpAudit.Core.Tests/RawEventDecimationEngineTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the RawEventDecimationEngine contract on a shared in-memory SQLite database:
//          disabled pass is a no-op, a single call fully decimates its selected candidates so the
//          head and tail of every burst survive while the middle is deleted, repeated calls then
//          delete nothing, the candidate-minimum threshold excludes rare events, rows without a
//          source IP and rows newer than MinAgeDays are never candidates, MaxCandidateEventIds
//          bounds one pass, BatchSize chunks the DELETE statements, and small bursts of other IPs
//          are left intact. A regression here could silently erase forensic evidence or the whole
//          RawEvents table.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Storage;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>End-to-end SQL-logic tests for <see cref="RawEventDecimationEngine"/>.</summary>
public sealed class RawEventDecimationEngineTests : IDisposable
{
	private const string AttackerIp = "203.0.113.77";
	private const string SecondIp = "198.51.100.9";
	private const int BurstGap = 3600;
	private static readonly DateTime BaseUtc = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	private readonly SqliteConnection _connection;
	private readonly DbContextOptions<AuditDbContext> _options;

	public RawEventDecimationEngineTests()
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

	// ── Core contract ───────────────────────────────────────────────────────────

	[Fact]
	public async Task Disabled_ReturnsZero_AndDeletesNothing()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 12_000);

		DecimationOptions options = new() { Enabled = false };

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		Assert.Equal(0, deleted);
		Assert.Equal(12_000, await CountAsync(4625, AttackerIp));
	}

	[Fact]
	public async Task ThreeBurstsWithGap_HeadAndTailSurvive_MiddleDeleted()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 12_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		// Three bursts of 4000 rows each; only 100 head + 100 tail per burst survive.
		Assert.Equal(11_400, deleted);
		Assert.Equal(600, await CountAsync(4625, AttackerIp));
	}

	[Fact]
	public async Task SingleCall_FullyDecimates_AndRepeatedCallDeletesNothing()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 12_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000, batchSize: 1_000);

		await using AuditDbContext db = new(_options);
		long first = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		// The middle-row set is computed once per call and deleted in BatchSize chunks;
		// a repeated call finds no eligible middle rows left and deletes nothing.
		Assert.Equal(11_400, first);
		Assert.Equal(600, await CountAsync(4625, AttackerIp));

		long second = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);
		Assert.Equal(0, second);
		Assert.Equal(600, await CountAsync(4625, AttackerIp));
	}

	[Fact]
	public async Task CandidateMinRows_BelowThreshold_KeepsAllRows()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 9_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		Assert.Equal(0, deleted);
		Assert.Equal(9_000, await CountAsync(4625, AttackerIp));
	}

	[Fact]
	public async Task RowsWithoutSourceIp_AreNeverCandidates()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, ip: null, BaseUtc, 10_000);
		SeedBurst(4625, SecondIp, BaseUtc, 10_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		// Only the SecondIp rows are eligible; NULL-SourceIp rows are untouchable.
		// 10,000 rows split into three bursts keep 3 x (100 head + 100 tail) = 600 rows.
		Assert.Equal(9_400, deleted);
		Assert.Equal(10_000, await CountAsync(4625, ip: null));
		Assert.Equal(600, await CountAsync(4625, SecondIp));
	}

	[Fact]
	public async Task FreshRows_NewerThanMinAge_AreNeverCandidates()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, nowUtc.AddDays(-10), 10_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000, minAgeDays: 30);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		Assert.Equal(0, deleted);
		Assert.Equal(10_000, await CountAsync(4625, AttackerIp));
	}

	[Fact]
	public async Task MaxCandidateEventIds_BoundsOnePass()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 12_000);
		SeedBurst(4776, SecondIp, BaseUtc, 11_000);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000, maxCandidates: 1);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		// Only the most frequent event id (4625) is processed; it is fully decimated.
		Assert.Equal(11_400, deleted);
		Assert.Equal(11_000, await CountAsync(4776, SecondIp));
	}

	[Fact]
	public async Task RareEvent_NotACandidate_KeptWhole()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 10_000);
		SeedBurst(4776, AttackerIp, BaseUtc, 500);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		Assert.Equal(9_400, deleted);
		Assert.Equal(500, await CountAsync(4776, AttackerIp));
	}

	[Fact]
	public async Task SecondIpSmallBurst_IsLeftIntact()
	{
		DateTime nowUtc = BaseUtc.AddDays(40);
		SeedBurst(4625, AttackerIp, BaseUtc, 10_000);
		SeedBurst(4625, SecondIp, BaseUtc.AddDays(20), 150);

		DecimationOptions options = EnabledOptions(candidateMinRows: 10_000);

		await using AuditDbContext db = new(_options);
		long deleted = await RawEventDecimationEngine.RunAsync(
			db, options, BaseUtc.AddDays(-365), nowUtc, CancellationToken.None);

		Assert.Equal(9_400, deleted);
		Assert.Equal(150, await CountAsync(4625, SecondIp));
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static DecimationOptions EnabledOptions(
		int candidateMinRows,
		int minAgeDays = 30,
		int batchSize = 5_000,
		int maxCandidates = 5)
	=> new()
	{
		Enabled = true,
		MinAgeDays = minAgeDays,
		BurstGapSeconds = BurstGap,
		CandidateMinRows = candidateMinRows,
		HeadKeepPerBurst = 100,
		TailKeepPerBurst = 100,
		MaxCandidateEventIds = maxCandidates,
		BatchSize = batchSize,
	};

	/// <summary>Seeds rows for one event id from one IP with 1-second spacing and a large gap between bursts.</summary>
	private void SeedBurst(int eventId, string? ip, DateTime startUtc, int totalRows)
	{
		using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = """
			INSERT INTO "RawEvents" ("EventId", "Channel", "TimeUtc", "SourceIp", "Processed")
			VALUES ($eventId, 'Security', $timeUtc, $sourceIp, 0);
			""";
		SqliteParameter eventIdParam = command.Parameters.Add("$eventId", SqliteType.Integer);
		SqliteParameter timeParam = command.Parameters.Add("$timeUtc", SqliteType.Text);
		SqliteParameter ipParam = command.Parameters.Add("$sourceIp", SqliteType.Text);

		DateTime cursor = startUtc;
		for (int i = 0; i < totalRows; i++)
		{
			// Split long runs into three bursts separated by BurstGap to exercise burst windows.
			if (i > 0 && i % 4_000 == 0)
			{
				cursor = cursor.AddSeconds(BurstGap);
			}

			eventIdParam.Value = eventId;
			timeParam.Value = cursor.ToString("yyyy-MM-dd HH:mm:ss.fffffff");
			ipParam.Value = ip is null ? DBNull.Value : ip;
			command.ExecuteNonQuery();
			cursor = cursor.AddSeconds(1);
		}
	}

	private async Task<int> CountAsync(int eventId, string? ip)
	{
		await using AuditDbContext db = new(_options);
		if (ip is null)
		{
			return await db.RawEvents.CountAsync(r => r.EventId == eventId && r.SourceIp == null);
		}

		return await db.RawEvents.CountAsync(r => r.EventId == eventId && r.SourceIp == ip);
	}
}
