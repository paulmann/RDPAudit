/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardIngestionSinkTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Storage)
// Purpose: Verifies optional shard ingestion writes only truthful on-disk metadata.
// Depends: ShardIngestionSink, ShardReader, AuditDbContext, SqliteConnection
// Extends: Add recovery and aggregate-shard cases when cardinality protection is implemented.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Storage;
using Xunit;

namespace RdpAudit.Service.Tests.Storage;

public sealed class ShardIngestionSinkTests : IDisposable
{
	private readonly string _directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
	private readonly SqliteConnection _connection = new("DataSource=:memory:");

	public ShardIngestionSinkTests()
	{
		Directory.CreateDirectory(_directory);
		_connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(_connection).Options;
		using AuditDbContext context = new(options);
		context.Database.EnsureCreated();
	}

	[Fact]
	public async Task Disabled_DoesNotCreateFileOrShardMetadata()
	{
		RawEvent rawEvent = CreateEvent("203.0.113.10", 1);
		await AddSummaryAsync(rawEvent);
		using ShardIngestionSink sink = CreateSink(enabled: false, capacity: 4, maximumFiles: 4);

		sink.Append(rawEvent);
		await CommitAsync(sink);

		Assert.Empty(Directory.EnumerateFiles(_directory, "*" + ShardPath.ShardExtension, SearchOption.AllDirectories));
		Assert.Equal(default, ReadColumns(rawEvent.SourceIp!));
	}

	[Fact]
	public async Task Enabled_CreatesReadableShardAndTruthfulMetadata()
	{
		RawEvent rawEvent = CreateEvent("203.0.113.11", 42);
		await AddSummaryAsync(rawEvent);
		using ShardIngestionSink sink = CreateSink(enabled: true, capacity: 4, maximumFiles: 4);

		sink.Append(rawEvent);
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns(rawEvent.SourceIp!);
		Assert.False(string.IsNullOrEmpty(columns.RelativePath));
		Assert.Equal(1, columns.RecordCount);
		Assert.NotNull(columns.Bytes);
		Assert.True(columns.Bytes > 0);
		Assert.Equal((int)ShardHeader.CurrentFormatVersion, columns.FormatVersion);
		string shardPath = Path.Combine(_directory, columns.RelativePath!.Replace('/', Path.DirectorySeparatorChar));
		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(shardPath));
		ShardRecord record = Assert.Single(reader.ReadAll());
		Assert.Equal(rawEvent.IngestionSequence, record.Sequence);
		Assert.Equal(rawEvent.EventId, record.EventId);
		Assert.Equal(rawEvent.TimeUtc.Ticks, record.TimeUtcTicks);
	}

	[Fact]
	public async Task RingOverflow_ReportsHeaderEvictionsWithoutFabrication()
	{
		const string ip = "203.0.113.12";
		using ShardIngestionSink sink = CreateSink(enabled: true, capacity: 4, maximumFiles: 4);
		for (int index = 1; index <= 10; index++)
		{
			RawEvent rawEvent = CreateEvent(ip, index);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns(ip);
		Assert.Equal(4, columns.RecordCount);
		Assert.Equal(6, columns.EvictedCount);
		Assert.Null(columns.OldestRetainedUtc);
	}

	[Fact]
	public async Task FileBudget_RefusesSecondAddressWithoutFailure()
	{
		RawEvent first = CreateEvent("203.0.113.13", 1);
		RawEvent second = CreateEvent("203.0.113.14", 2);
		await AddSummaryAsync(first);
		await AddSummaryAsync(second);
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(enabled: true, capacity: 4, maximumFiles: 1, metrics);

		sink.Append(first);
		sink.Append(second);
		await CommitAsync(sink);

		Assert.Single(Directory.EnumerateFiles(_directory, "*" + ShardPath.ShardExtension, SearchOption.AllDirectories));
		Assert.True(metrics.ShardBudgetRefusals > 0);
		Assert.Null(ReadColumns(second.SourceIp!).RelativePath);
	}

	[Fact]
	public async Task UnavailableActionsRoot_DoesNotThrow()
	{
		string rootFile = Path.Combine(_directory, "not-a-directory");
		File.WriteAllText(rootFile, "x");
		RawEvent rawEvent = CreateEvent("203.0.113.15", 1);
		await AddSummaryAsync(rawEvent);
		RdpAuditOptions options = new() { Sharding = new ShardingOptions { Enabled = true, ActionsRoot = rootFile } };
		using ShardIngestionSink sink = new(new StaticOptionsMonitor<RdpAuditOptions>(options), NullLogger<ShardIngestionSink>.Instance, new ServiceMetrics());

		sink.Append(rawEvent);
		await CommitAsync(sink);

		Assert.Null(ReadColumns(rawEvent.SourceIp!).RelativePath);
	}

	public void Dispose()
	{
		_connection.Dispose();
		try { Directory.Delete(_directory, recursive: true); }
		catch (IOException) { }
		catch (UnauthorizedAccessException) { }
	}

	private ShardIngestionSink CreateSink(bool enabled, int capacity, int maximumFiles, ServiceMetrics? metrics = null)
	{
		RdpAuditOptions options = new()
		{
			Sharding = new ShardingOptions
			{
				Enabled = enabled,
				ActionsRoot = Path.Combine(_directory, ShardPath.ActionsRootFolder),
				ShardCapacityRecords = capacity,
				MaxOpenWriters = 4,
				MaxShardFiles = maximumFiles,
			},
		};
		return new ShardIngestionSink(new StaticOptionsMonitor<RdpAuditOptions>(options), NullLogger<ShardIngestionSink>.Instance, metrics ?? new ServiceMetrics());
	}

	private static RawEvent CreateEvent(string ip, long sequence) => new()
	{
		EventId = 4625,
		Channel = "Security",
		TimeUtc = new DateTime(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc).AddSeconds(sequence),
		IngestionSequence = sequence,
		SourceIp = ip,
		Status = "0xC000006D",
		LogonType = 10,
	};

	private async Task AddSummaryAsync(RawEvent rawEvent)
	{
		IpEventSummaryUpserter upserter = new();
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await upserter.UpsertBatchAsync(_connection, transaction, [rawEvent], CancellationToken.None);
		await transaction.CommitAsync();
	}

	private async Task CommitAsync(ShardIngestionSink sink)
	{
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await sink.CommitAsync(_connection, transaction, CancellationToken.None);
		await transaction.CommitAsync();
	}

	private ShardColumns ReadColumns(string ip)
	{
		using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = """
SELECT ShardRelativePath, ShardRecordCount, ShardBytes, ShardFormatVersion, ShardEvictedCount, ShardOldestRetainedUtc
FROM IpEventSummary WHERE IpText = $ip;
""";
		command.Parameters.AddWithValue("$ip", ip);
		using SqliteDataReader reader = command.ExecuteReader();
		Assert.True(reader.Read());
		return new(
			reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetInt64(1),
			reader.IsDBNull(2) ? null : reader.GetInt64(2), reader.IsDBNull(3) ? null : reader.GetInt32(3),
			reader.IsDBNull(4) ? null : reader.GetInt64(4), reader.IsDBNull(5) ? null : reader.GetInt64(5));
	}

	private readonly record struct ShardColumns(string? RelativePath, long? RecordCount, long? Bytes, int? FormatVersion, long? EvictedCount, long? OldestRetainedUtc);

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}
}
