/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.4
// File   : EventProcessorWorkerShardCommitTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Stage 1 regression for the forensic shard commit defect (EventID 7013). After the
//          main RawEvents transaction commits, shard rows must be written on a dedicated live
//          SqliteConnection - never by calling BeginTransaction on the EF-owned connection that
//          EF Core closes together with the disposed transaction. A shard-phase failure must not
//          rethrow into PersistBatchAsync (which would attempt to roll back the already-committed
//          RawEvents and discard the pending shard queue); the queue is retained for the next flush.
//          v2.3.4: adds failure-injection INSIDE ShardIngestionSink.CommitAsync via the internal
//          IShardFileWriter seam. Proves that a writer Commit() failure keeps RawEvents committed,
//          keeps the pending queue non-empty, and lets the next flush succeed without resetting
//          the cumulative ShardWriteFailures counter.
// Depends: EventProcessorWorker, ShardIngestionSink, IpEventSummaryUpserter, AuditDbContext,
//          RawEventDto, EventNormalizer, xunit, Microsoft.EntityFrameworkCore.Sqlite
// Extends: Add a new case here when the shard flush gains another failure classification that
//          must preserve the two independent durability boundaries (RawEvents vs shard metadata).

using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Storage;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Stage 1 regression tests for the forensic shard commit path in <see cref="EventProcessorWorker"/>.
/// </summary>
public sealed class EventProcessorWorkerShardCommitTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string AttackerIp = "203.0.113.77";
	private readonly string _rootDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
	private readonly string _dbPath;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventProcessorWorkerShardCommitTests()
	{
		Directory.CreateDirectory(_rootDirectory);
		_dbPath = Path.Combine(_rootDirectory, "rdpaudit-test.db");
	}

	/// <inheritdoc />
	public void Dispose()
	{
		try
		{
			Directory.Delete(_rootDirectory, recursive: true);
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Tests ────────────────────────────────────────────────────────────────────

	[Fact]
	public async Task PersistBatchAsync_CommitsRawEvents_AndWritesIpEventSummary()
	{
		(SqliteConnection connection, TestContextFactory factory) = CreateTestDb();
		try
		{
			ServiceMetrics metrics = new();
			using EventProcessorWorker worker = CreateWorker(
				factory,
				metrics,
				BuildOptions(),
				ipEventSummaryUpserter: new IpEventSummaryUpserter());

			await InvokePersistBatchAsync(worker, new List<RawEventDto> { BuildSecurity4625Dto(AttackerIp) });

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> rawEvents = await verify.RawEvents.AsNoTracking().ToListAsync();
			RawEvent rawEvent = Assert.Single(rawEvents);
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			List<IpEventSummary> summaries = await verify.IpEventSummaries.AsNoTracking().ToListAsync();
			IpEventSummary summary = Assert.Single(summaries);
			Assert.Equal(1, summary.TotalEventCount);
			Assert.Equal(0, metrics.ShardWriteFailures);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task CommitShardsAfterDatabaseCommitAsync_ConnectionFailure_RetainsPendingQueue_AndDoesNotThrow()
	{
		ServiceMetrics metrics = new();
		string sinkRoot = Path.Combine(_rootDirectory, "commit-failure-sink");
		Directory.CreateDirectory(sinkRoot);
		using ShardIngestionSink sink = CreateSink(Path.Combine(sinkRoot, ShardPath.ActionsRootFolder), metrics);
		sink.Append(CreateRawEvent("203.0.113.99", 1));

		using EventProcessorWorker worker = CreateCommitOnlyWorker(metrics, sink);

		SqliteConnectionStringBuilder badBuilder = new()
		{
			DataSource = Path.Combine(_rootDirectory, "missing", "shard.db"),
			Mode = SqliteOpenMode.ReadWriteCreate,
		};
		await InvokeCommitShardsAfterDatabaseCommitAsync(worker, badBuilder.ToString(), CancellationToken.None);

		Assert.True(metrics.ShardWriteFailures > 0, "A failed dedicated-connection open must be recorded.");
		Assert.Equal(1, GetTouchedCount(sink));
	}

	[Fact]
	public async Task CommitShardsAfterDatabaseCommitAsync_Cancellation_RetainsPendingQueue_AndDoesNotThrow()
	{
		ServiceMetrics metrics = new();
		string sinkRoot = Path.Combine(_rootDirectory, "commit-cancel-sink");
		Directory.CreateDirectory(sinkRoot);
		using ShardIngestionSink sink = CreateSink(Path.Combine(sinkRoot, ShardPath.ActionsRootFolder), metrics);
		sink.Append(CreateRawEvent("203.0.113.100", 2));

		using EventProcessorWorker worker = CreateCommitOnlyWorker(metrics, sink);

		SqliteConnectionStringBuilder builder = new()
		{
			DataSource = _dbPath,
			Mode = SqliteOpenMode.ReadWriteCreate,
		};
		using CancellationTokenSource cts = new();
		cts.Cancel();
		await InvokeCommitShardsAfterDatabaseCommitAsync(worker, builder.ToString(), cts.Token);

		Assert.Equal(1, GetTouchedCount(sink));
	}

	/// <summary>
	/// The defect was previously only exercised by a connection-open failure (missing database
	/// directory), which never reaches <see cref="ShardIngestionSink.CommitAsync"/>. This test
	/// injects an IOException from INSIDE the sink (the writer's Commit call), proving that the
	/// already-committed RawEvents survive and the pending shard queue is retained.
	/// </summary>
	[Fact]
	public async Task PersistBatchAsync_ShardCommitFailureInsideSink_KeepsRawEventsAndPendingQueue()
	{
		(SqliteConnection connection, TestContextFactory factory) = CreateTestDb();
		try
		{
			ServiceMetrics metrics = new();
			string sinkRoot = Path.Combine(_rootDirectory, "fail-inside-sink");
			Directory.CreateDirectory(sinkRoot);

			FailFirstCommitShardWriter? failWriter = null;
			using ShardIngestionSink sink = CreateSink(
				Path.Combine(sinkRoot, ShardPath.ActionsRootFolder),
				metrics,
				(path, capacity) =>
				{
					failWriter = new FailFirstCommitShardWriter(path, capacity);
					return failWriter;
				});

			using EventProcessorWorker worker = CreateWorker(
				factory,
				metrics,
				BuildOptions(),
				shardSink: sink,
				ipEventSummaryUpserter: new IpEventSummaryUpserter());

			await InvokePersistBatchAsync(worker, new List<RawEventDto> { BuildSecurity4625Dto(AttackerIp) });

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> rawEvents = await verify.RawEvents.AsNoTracking().ToListAsync();
			RawEvent rawEvent = Assert.Single(rawEvents);
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			List<IpEventSummary> summaries = await verify.IpEventSummaries.AsNoTracking().ToListAsync();
			IpEventSummary summary = Assert.Single(summaries);
			Assert.Equal(1, summary.TotalEventCount);

			Assert.True(metrics.ShardWriteFailures > 0, "The shard-phase failure must be counted.");
			Assert.Equal(1, GetTouchedCount(sink));
			Assert.NotNull(failWriter);
			Assert.Equal(1, failWriter.CommitCalls);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task PersistBatchAsync_NextFlushAfterShardFailure_SucceedsAndKeepsFailureCounter()
	{
		(SqliteConnection connection, TestContextFactory factory) = CreateTestDb();
		try
		{
			ServiceMetrics metrics = new();
			string sinkRoot = Path.Combine(_rootDirectory, "retry-after-failure-sink");
			Directory.CreateDirectory(sinkRoot);

			FailFirstCommitShardWriter? flakyWriter = null;
			using ShardIngestionSink sink = CreateSink(
				Path.Combine(sinkRoot, ShardPath.ActionsRootFolder),
				metrics,
				(path, capacity) =>
				{
					flakyWriter = new FailFirstCommitShardWriter(path, capacity);
					return flakyWriter;
				});

			using EventProcessorWorker worker = CreateWorker(
				factory,
				metrics,
				BuildOptions(),
				shardSink: sink,
				ipEventSummaryUpserter: new IpEventSummaryUpserter());

			await InvokePersistBatchAsync(worker, new List<RawEventDto> { BuildSecurity4625Dto(AttackerIp) });
			long failuresAfterFirstFlush = metrics.ShardWriteFailures;
			Assert.True(failuresAfterFirstFlush > 0, "The first flush must fail exactly once.");
			Assert.Equal(1, GetTouchedCount(sink));

			// Same sink, same still-open writer. The second Commit() succeeds and must empty the queue.
			await InvokePersistBatchAsync(worker, new List<RawEventDto> { BuildSecurity4625Dto(AttackerIp) });

			await using AuditDbContext verify = factory.CreateDbContext();
			List<IpEventSummary> summaries = await verify.IpEventSummaries.AsNoTracking().ToListAsync();
			IpEventSummary summary = Assert.Single(summaries);
			Assert.False(string.IsNullOrEmpty(summary.ShardRelativePath), "Shard metadata must be written on the successful retry.");
			Assert.True(summary.ShardRecordCount > 0, "ShardRecordCount must be populated.");
			Assert.True(summary.ShardBytes > 0, "ShardBytes must be populated.");
			Assert.True((summary.ShardFormatVersion ?? 0) > 0, "ShardFormatVersion must be populated.");

			Assert.Equal(0, GetTouchedCount(sink));
			Assert.True(metrics.ShardWriteFailures >= failuresAfterFirstFlush, "ShardWriteFailures is cumulative and must not be reset.");
			Assert.NotNull(flakyWriter);
			Assert.Equal(2, flakyWriter.CommitCalls);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task PersistBatchAsync_ShardPhaseCancellation_KeepsCommittedRawEventsAndQueue()
	{
		(SqliteConnection connection, TestContextFactory factory) = CreateTestDb();
		CancellationTokenSource? cts = null;
		try
		{
			ServiceMetrics metrics = new();
			string sinkRoot = Path.Combine(_rootDirectory, "cancel-inside-sink");
			Directory.CreateDirectory(sinkRoot);

			cts = new CancellationTokenSource();
			using ShardIngestionSink sink = CreateSink(
				Path.Combine(sinkRoot, ShardPath.ActionsRootFolder),
				metrics,
				(path, capacity) => new CancelOnCommitShardWriter(path, capacity, cts));

			using EventProcessorWorker worker = CreateWorker(
				factory,
				metrics,
				BuildOptions(),
				shardSink: sink,
				ipEventSummaryUpserter: new IpEventSummaryUpserter());

			await InvokePersistBatchAsync(
				worker,
				new List<RawEventDto> { BuildSecurity4625Dto(AttackerIp) },
				cts.Token);

			Assert.True(cts.IsCancellationRequested, "The CancellationTokenSource must be cancelled by the fake writer.");

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> rawEvents = await verify.RawEvents.AsNoTracking().ToListAsync();
			RawEvent rawEvent = Assert.Single(rawEvents);
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			// The committed RawEvents must survive cancellation in the shard phase, and the pending
			// shard queue must remain untouched for the next flush.
			Assert.Equal(1, GetTouchedCount(sink));
		}
		finally
		{
			cts?.Dispose();
			await connection.DisposeAsync();
		}
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private (SqliteConnection Connection, TestContextFactory Factory) CreateTestDb()
	{
		SqliteConnectionStringBuilder builder = new()
		{
			DataSource = _dbPath,
			Mode = SqliteOpenMode.ReadWriteCreate,
		};
		SqliteConnection connection = new(builder.ToString());
		connection.Open();

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;
		using AuditDbContext bootstrap = new(options);
		bootstrap.Database.EnsureCreated();

		return (connection, new TestContextFactory(options));
	}

	private static EventProcessorWorker CreateWorker(
		TestContextFactory factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		ShardIngestionSink? shardSink = null,
		IpEventSummaryUpserter? ipEventSummaryUpserter = null)
	{
		return new EventProcessorWorker(
			new NullPipe(),
			factory,
			new EventNormalizer(new SessionCorrelationCache()),
			new SessionIpCorrelationUpserter(),
			new RdpConnectionFactUpserter(),
			new AuthAttemptFactUpserter(new RdpTransportIpCache()),
			new SecurityCorrelationWatchdog(metrics),
			metrics,
			NullLogger<EventProcessorWorker>.Instance,
			options,
			opLog: null!,
			bookmarks: null,
			checkpoints: null,
			ipEventSummaryUpserter: ipEventSummaryUpserter,
			shardSink: shardSink);
	}

	private static EventProcessorWorker CreateCommitOnlyWorker(ServiceMetrics metrics, ShardIngestionSink sink)
	{
		return new EventProcessorWorker(
			new NullPipe(),
			factory: null!,
			normalizer: null!,
			correlationUpserter: null!,
			connectionFactUpserter: null!,
			authAttemptFactUpserter: null!,
			securityWatchdog: null!,
			metrics,
			NullLogger<EventProcessorWorker>.Instance,
			BuildOptions(),
			opLog: null!,
			bookmarks: null,
			checkpoints: null,
			ipEventSummaryUpserter: null,
			shardSink: sink);
	}

	private static ShardIngestionSink CreateSink(string actionsRoot, ServiceMetrics metrics)
		=> CreateSink(actionsRoot, metrics, writerFactory: null);

	private static ShardIngestionSink CreateSink(
		string actionsRoot,
		ServiceMetrics metrics,
		Func<string, int, IShardFileWriter>? writerFactory)
	{
		RdpAuditOptions options = new()
		{
			Sharding = new ShardingOptions
			{
				Enabled = true,
				ActionsRoot = actionsRoot,
				ShardCapacityRecords = 16,
				MaxOpenWriters = 4,
				MaxShardFiles = 16,
			},
		};
		return new ShardIngestionSink(
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<ShardIngestionSink>.Instance,
			metrics,
			writerFactory);
	}

	private static IOptionsMonitor<RdpAuditOptions> BuildOptions()
	{
		RdpAuditOptions options = new()
		{
			Monitoring = new MonitoringOptions { BatchSize = 64, BatchTimeoutMilliseconds = 100 },
		};
		return new StaticOptionsMonitor<RdpAuditOptions>(options);
	}

	private static RawEventDto BuildSecurity4625Dto(string ip)
	{
		string xml =
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System><EventID>4625</EventID></System>" +
			"<EventData>" +
			"<Data Name='TargetUserName'>md</Data>" +
			"<Data Name='TargetDomainName'>WORKGROUP</Data>" +
			$"<Data Name='IpAddress'>{ip}</Data>" +
			"<Data Name='IpPort'>3389</Data>" +
			"<Data Name='LogonType'>3</Data>" +
			"<Data Name='Status'>-1073741715</Data>" +
			"<Data Name='SubStatus'>-1073741718</Data>" +
			"</EventData></Event>";

		return new RawEventDto
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = new DateTime(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc),
			XmlPayload = xml,
		};
	}

	private static RawEvent CreateRawEvent(string ip, long sequence) => new()
	{
		EventId = 4625,
		Channel = "Security",
		TimeUtc = new DateTime(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc),
		IngestionSequence = sequence,
		SourceIp = ip,
		Status = "0xC000006D",
		LogonType = 10,
	};

	private static Task InvokePersistBatchAsync(
		EventProcessorWorker worker,
		List<RawEventDto> dtos,
		CancellationToken ct = default)
	{
		MethodInfo method = typeof(EventProcessorWorker).GetMethod("PersistBatchAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
		return (Task)method.Invoke(worker, new object[] { dtos, ct })!;
	}

	private static Task InvokeCommitShardsAfterDatabaseCommitAsync(EventProcessorWorker worker, string connectionString, CancellationToken ct)
	{
		MethodInfo method = typeof(EventProcessorWorker).GetMethod("CommitShardsAfterDatabaseCommitAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
		return (Task)method.Invoke(worker, new object[] { connectionString, ct })!;
	}

	private static int GetTouchedCount(ShardIngestionSink sink)
	{
		FieldInfo field = typeof(ShardIngestionSink).GetField("_touched", BindingFlags.NonPublic | BindingFlags.Instance)!;
		return ((System.Collections.ICollection)field.GetValue(sink)!).Count;
	}

	// ── Fakes ────────────────────────────────────────────────────────────────────

	/// <summary>Fake writer whose first Commit() throws IOException; subsequent commits succeed.</summary>
	private sealed class FailFirstCommitShardWriter : IShardFileWriter
	{
		private uint _count;
		private int _commitAttempts;

		public FailFirstCommitShardWriter(string absolutePath, int capacity)
		{
			if (!File.Exists(absolutePath))
			{
				Directory.CreateDirectory(Path.GetDirectoryName(absolutePath)!);
				File.WriteAllText(absolutePath, "fake shard file");
			}
		}

		public uint Count => _count;
		public ulong TotalEvicted => 0;
		public int CommitCalls => _commitAttempts;

		public void Append(in ShardRecord record, out bool evictedOne)
		{
			_count++;
			evictedOne = false;
		}

		public void Commit()
		{
			_commitAttempts++;
			if (_commitAttempts == 1)
			{
				throw new IOException("Deterministic first-commit failure injected inside the sink.");
			}
		}

		public void Dispose()
		{
		}
	}

	/// <summary>Fake writer that cancels the supplied token and throws OCE from Commit().</summary>
	private sealed class CancelOnCommitShardWriter : IShardFileWriter
	{
		private readonly CancellationTokenSource _cts;
		private uint _count;

		public CancelOnCommitShardWriter(string absolutePath, int capacity, CancellationTokenSource cts)
		{
			_cts = cts;
			if (!File.Exists(absolutePath))
			{
				Directory.CreateDirectory(Path.GetDirectoryName(absolutePath)!);
				File.WriteAllText(absolutePath, "fake shard file");
			}
		}

		public uint Count => _count;
		public ulong TotalEvicted => 0;

		public void Append(in ShardRecord record, out bool evictedOne)
		{
			_count++;
			evictedOne = false;
		}

		public void Commit()
		{
			_cts.Cancel();
			throw new OperationCanceledException(_cts.Token);
		}

		public void Dispose()
		{
		}
	}

	private sealed class TestContextFactory(DbContextOptions<AuditDbContext> options) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => new(options);

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
			=> Task.FromResult(new AuditDbContext(options));
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;

		public T Get(string? name) => value;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class NullPipe : IEventPipe
	{
		public int Capacity => 0;

		public long OverflowCount => 0;

		public bool TryWrite(RawEventDto dto) => false;

		public bool TryRead(out RawEventDto dto)
		{
			dto = default!;
			return false;
		}

		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct) => new(false);
	}
}
