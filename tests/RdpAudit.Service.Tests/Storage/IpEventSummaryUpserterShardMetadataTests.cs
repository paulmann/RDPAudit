/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : IpEventSummaryUpserterShardMetadataTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Storage)
// Purpose: Pins the rule that IpEventSummaryUpserter never fabricates shard metadata, and that the aggregate counters it does own stay correct.
// Depends: IpEventSummaryUpserter, AuditDbContext, RawEvent, SqliteConnection
// Extends: Add a case here whenever a new column is added to IpEventSummary, asserting who is allowed to write it.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Storage;
using Xunit;

namespace RdpAudit.Service.Tests.Storage;

/// <summary>
/// Shard columns describe a shard file on disk and are owned solely by ShardIngestionSink.
/// This upserter never creates a shard, so every shard column it writes must remain NULL. A
/// non-null value is a promise to an analyst that a readable shard exists; these tests make
/// accidental fabrication by the aggregate upserter impossible.
/// </summary>
public sealed class IpEventSummaryUpserterShardMetadataTests : IAsyncLifetime, IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string Ip = "203.0.113.77";
	private static readonly DateTime BaseUtc = new(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc);

	private SqliteConnection _connection = null!;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public async Task InitializeAsync()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		await _connection.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		await using AuditDbContext context = new(options);
		await context.Database.EnsureCreatedAsync();
	}

	/// <inheritdoc />
	public async Task DisposeAsync()
	{
		await _connection.DisposeAsync();
	}

	// CA1001 does not recognise xUnit's IAsyncLifetime as an ownership contract, so the
	// synchronous counterpart is declared explicitly. Disposing twice is safe here.
	/// <inheritdoc />
	public void Dispose()
	{
		_connection.Dispose();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	[Fact]
	public async Task Insert_LeavesEveryShardColumnNull()
	{
		await UpsertAsync(CreateEvent(4625, 1, BaseUtc));

		ShardColumns columns = ReadShardColumns();

		Assert.Null(columns.RelativePath);
		Assert.Null(columns.RecordCount);
		Assert.Null(columns.Bytes);
		Assert.Null(columns.FormatVersion);
		Assert.Null(columns.EvictedCount);
		Assert.Null(columns.OldestRetainedUtc);
	}

	[Fact]
	public async Task RepeatedUpsert_NeverStartsWritingShardColumns()
	{
		for (int index = 0; index < 25; index++)
		{
			await UpsertAsync(CreateEvent(4625, index + 1, BaseUtc.AddSeconds(index)));
		}

		ShardColumns columns = ReadShardColumns();

		Assert.Null(columns.RelativePath);
		Assert.Null(columns.RecordCount);
		Assert.Null(columns.Bytes);
		Assert.Null(columns.FormatVersion);
		Assert.Null(columns.EvictedCount);
		Assert.Null(columns.OldestRetainedUtc);
	}

	[Fact]
	public async Task HasShard_IsFalseForEveryRowTheUpserterWrites()
	{
		await UpsertAsync(CreateEvent(4624, 1, BaseUtc));

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		await using AuditDbContext context = new(options);
		IpEventSummary summary = Assert.Single(context.IpEventSummaries);

		Assert.False(summary.HasShard);
		Assert.Null(summary.ShardRelativePath);
	}

	[Fact]
	public async Task AggregateCounters_RemainCorrectAfterShardColumnsWereRemoved()
	{
		// Dropping the shard columns from the statement must not disturb the columns this type
		// genuinely owns: the first event stays pinned, the last event advances, and the success
		// and failure tallies track event identity.
		await UpsertAsync(CreateEvent(4625, 1, BaseUtc));
		await UpsertAsync(CreateEvent(4625, 2, BaseUtc.AddSeconds(10)));
		await UpsertAsync(CreateEvent(4624, 3, BaseUtc.AddSeconds(20)));

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		await using AuditDbContext context = new(options);
		IpEventSummary summary = Assert.Single(context.IpEventSummaries);

		Assert.Equal(3, summary.TotalEventCount);
		Assert.Equal(1, summary.SuccessCount);
		Assert.Equal(2, summary.FailureCount);
		Assert.Equal(BaseUtc.Ticks, summary.FirstEventUtc);
		Assert.Equal(4625, summary.FirstEventId);
		Assert.Equal(1, summary.FirstEventSequence);
		Assert.Equal(BaseUtc.AddSeconds(20).Ticks, summary.LastEventUtc);
		Assert.Equal(4624, summary.LastEventId);
		Assert.Equal(3, summary.LastEventSequence);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static RawEvent CreateEvent(int eventId, long sequence, DateTime timeUtc) => new()
	{
		EventId = eventId,
		Channel = "Security",
		TimeUtc = timeUtc,
		SourceIp = Ip,
		UserName = "md",
		IngestionSequence = sequence,
		Details = "{\"LogonType\":\"10\"}",
	};

	private async Task UpsertAsync(RawEvent rawEvent)
	{
		IpEventSummaryUpserter upserter = new();
		await using SqliteTransaction transaction =
			(SqliteTransaction)await _connection.BeginTransactionAsync(CancellationToken.None);
		await upserter.UpsertBatchAsync(_connection, transaction, [rawEvent], CancellationToken.None);
		await transaction.CommitAsync(CancellationToken.None);
	}

	private ShardColumns ReadShardColumns()
	{
		using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = """
			SELECT ShardRelativePath, ShardRecordCount, ShardBytes,
			       ShardFormatVersion, ShardEvictedCount, ShardOldestRetainedUtc
			FROM IpEventSummary;
			""";
		using SqliteDataReader reader = command.ExecuteReader();
		Assert.True(reader.Read());
		ShardColumns columns = new(
			reader.IsDBNull(0) ? null : reader.GetString(0),
			reader.IsDBNull(1) ? null : reader.GetInt64(1),
			reader.IsDBNull(2) ? null : reader.GetInt64(2),
			reader.IsDBNull(3) ? null : reader.GetInt32(3),
			reader.IsDBNull(4) ? null : reader.GetInt64(4),
			reader.IsDBNull(5) ? null : reader.GetInt64(5));
		Assert.False(reader.Read());
		return columns;
	}

	private readonly record struct ShardColumns(
		string? RelativePath,
		long? RecordCount,
		long? Bytes,
		int? FormatVersion,
		long? EvictedCount,
		long? OldestRetainedUtc);
}
