/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.4
// File   : ShardCommitDurabilityScenarios.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Scenarios)
// Purpose: End-to-end scenario coverage for the two independent durability boundaries in
//          EventProcessorWorker. Each scenario walks the worker through its public ExecuteAsync
//          entry point and the IEventPipe contract (the same surface the production collector
//          uses), never through internal helpers:
//          1. Happy path - an event flows end-to-end, RawEvents commits, the shard flush writes
//             truthful metadata, and the pending queue empties.
//          2. Shard-phase failure INSIDE ShardIngestionSink.CommitAsync - RawEvents stays
//             durable, the pending queue is retained, and the next successful flush recovers.
//          3. Cancellation during the shard phase - committed RawEvents survive and the queue
//             is left untouched for the next flush.
// Depends: EventProcessorWorker, ShardIngestionSink, IShardFileWriter (internal seam),
//          IpEventSummaryUpserter, AuditDbContext, RawEventDto, EventNormalizer, xunit
// Extends: Add a subnet-aggregate scenario when cardinality protection lands, and a
//          SQLITE_BUSY retry scenario once a deterministic busy injection is available.

using System.Collections.Concurrent;
using System.Diagnostics;
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

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>
/// User-level scenarios for the forensic shard durability contract, driven through
/// <see cref="EventProcessorWorker.ExecuteAsync"/> and a real in-process
/// <see cref="IEventPipe"/> implementation.
/// </summary>
public sealed class ShardCommitDurabilityScenarios : IDisposable
{
	private const string AttackerIp = "203.0.113.77";
	private readonly string _rootDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
	private readonly string _dbPath;

	public ShardCommitDurabilityScenarios()
	{
		Directory.CreateDirectory(_rootDirectory);
		_dbPath = Path.Combine(_rootDirectory, "rdpaudit-test.db");
	}

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

	[Fact]
	public async Task HappyPath_EventCommitted_AndShardMetadataWritten()
	{
		TestContextFactory factory = CreateTestDb();
		CancellationTokenSource cts = new();
		ServiceMetrics metrics = new();
		InProcPipe pipe = new();
		using ShardIngestionSink sink = CreateSink(Path.Combine(_rootDirectory, "happy"), metrics, writerFactory: null);
		using EventProcessorWorker worker = CreateWorker(factory, metrics, pipe, sink);

		Task run = worker.StartAsync(cts.Token);
		try
		{
			pipe.TryWrite(BuildSecurity4625Dto(AttackerIp));

			await PollUntilAsync(TimeSpan.FromSeconds(15), async () =>
			{
				await using AuditDbContext db = factory.CreateDbContext();
				bool rawEventCommitted = await db.RawEvents.AsNoTracking().AnyAsync();
				bool metadataWritten = await db.IpEventSummaries
					.AsNoTracking()
					.AnyAsync(s => s.ShardRelativePath != null);
				return rawEventCommitted && metadataWritten;
			});

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> rawEvents = await verify.RawEvents.AsNoTracking().ToListAsync();
			RawEvent rawEvent = Assert.Single(rawEvents);
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			List<IpEventSummary> summaries = await verify.IpEventSummaries.AsNoTracking().ToListAsync();
			IpEventSummary summary = Assert.Single(summaries);
			Assert.Equal(1, summary.TotalEventCount);
			Assert.False(string.IsNullOrEmpty(summary.ShardRelativePath));
			Assert.True(summary.ShardRecordCount > 0);
			Assert.True(summary.ShardBytes > 0);

			Assert.Equal(0, GetTouchedCount(sink));
			Assert.Equal(0, metrics.ShardWriteFailures);
		}
		finally
		{
			await StopWorkerAsync(run, cts);
		}
	}

	[Fact]
	public async Task ShardCommitFailureInsideSink_KeepsRawEvents_AndRecoversOnNextFlush()
	{
		TestContextFactory factory = CreateTestDb();
		CancellationTokenSource cts = new();
		ServiceMetrics metrics = new();
		InProcPipe pipe = new();
		FailNextCommitShardWriter? flakyWriter = null;
		using ShardIngestionSink sink = CreateSink(
			Path.Combine(_rootDirectory, "flaky"),
			metrics,
			(path, capacity) =>
			{
				flakyWriter = new FailNextCommitShardWriter(path);
				return flakyWriter;
			});
		using EventProcessorWorker worker = CreateWorker(factory, metrics, pipe, sink);

		Task run = worker.StartAsync(cts.Token);
		try
		{
			pipe.TryWrite(BuildSecurity4625Dto(AttackerIp));

			await PollUntilAsync(TimeSpan.FromSeconds(15), async () =>
			{
				await using AuditDbContext db = factory.CreateDbContext();
				bool rawEventCommitted = await db.RawEvents.AsNoTracking().AnyAsync();
				return rawEventCommitted && GetTouchedCount(sink) == 1 && metrics.ShardWriteFailures > 0;
			});

			// The main commit must be durable even though the shard phase failed inside the sink.
			await using AuditDbContext verifyCommitted = factory.CreateDbContext();
			RawEvent rawEvent = Assert.Single(await verifyCommitted.RawEvents.AsNoTracking().ToListAsync());
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			// The next event travel through the same still-open writer; its Commit() succeeds now
			// and must flush the retained queue plus the new record.
			pipe.TryWrite(BuildSecurity4625Dto(AttackerIp));

			await PollUntilAsync(TimeSpan.FromSeconds(15), async () =>
			{
				await using AuditDbContext db = factory.CreateDbContext();
				bool recovered = await db.IpEventSummaries
					.AsNoTracking()
					.AnyAsync(s => s.ShardRelativePath != null);
				return recovered && GetTouchedCount(sink) == 0;
			});

			await using AuditDbContext verifyRecovered = factory.CreateDbContext();
			Assert.Equal(2, await verifyRecovered.RawEvents.AsNoTracking().CountAsync());
			IpEventSummary summary = Assert.Single(await verifyRecovered.IpEventSummaries.AsNoTracking().ToListAsync());
			Assert.True(summary.ShardRecordCount > 0);
			Assert.True(summary.ShardBytes > 0);
			Assert.True(metrics.ShardWriteFailures > 0, "The cumulative failure counter must survive the recovery.");
			Assert.NotNull(flakyWriter);
			Assert.True(flakyWriter.CommitCalls >= 2);
		}
		finally
		{
			await StopWorkerAsync(run, cts);
		}
	}

	[Fact]
	public async Task ShardPhaseCancellation_KeepsCommittedRawEventsAndQueue()
	{
		TestContextFactory factory = CreateTestDb();
		CancellationTokenSource cts = new();
		ServiceMetrics metrics = new();
		InProcPipe pipe = new();
		using ShardIngestionSink sink = CreateSink(
			Path.Combine(_rootDirectory, "cancel"),
			metrics,
			(path, capacity) => new CancelOnCommitShardWriter(path, cts));
		using EventProcessorWorker worker = CreateWorker(factory, metrics, pipe, sink);

		Task run = worker.StartAsync(cts.Token);
		try
		{
			pipe.TryWrite(BuildSecurity4625Dto(AttackerIp));

			await PollUntilAsync(TimeSpan.FromSeconds(15), async () =>
			{
				await using AuditDbContext db = factory.CreateDbContext();
				bool rawEventCommitted = await db.RawEvents.AsNoTracking().AnyAsync();
				return rawEventCommitted && cts.IsCancellationRequested;
			});

			await using AuditDbContext verify = factory.CreateDbContext();
			RawEvent rawEvent = Assert.Single(await verify.RawEvents.AsNoTracking().ToListAsync());
			Assert.Equal(AttackerIp, rawEvent.SourceIp);

			// Cancellation in the shard phase must never discard the retained pending queue.
			Assert.Equal(1, GetTouchedCount(sink));
		}
		finally
		{
			await StopWorkerAsync(run, cts);
		}
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private TestContextFactory CreateTestDb()
	{
		SqliteConnectionStringBuilder builder = new()
		{
			DataSource = _dbPath,
			Mode = SqliteOpenMode.ReadWriteCreate,
		};

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(builder.ToString())
			.Options;
		using AuditDbContext bootstrap = new(options);
		bootstrap.Database.EnsureCreated();

		return new TestContextFactory(options);
	}

	private static EventProcessorWorker CreateWorker(
		TestContextFactory factory,
		ServiceMetrics metrics,
		IEventPipe pipe,
		ShardIngestionSink sink)
	{
		return new EventProcessorWorker(
			pipe,
			factory,
			new EventNormalizer(new SessionCorrelationCache()),
			new SessionIpCorrelationUpserter(),
			new RdpConnectionFactUpserter(),
			new AuthAttemptFactUpserter(new RdpTransportIpCache()),
			new SecurityCorrelationWatchdog(metrics),
			metrics,
			NullLogger<EventProcessorWorker>.Instance,
			BuildOptions(),
			opLog: null!,
			bookmarks: null,
			checkpoints: null,
			ipEventSummaryUpserter: new IpEventSummaryUpserter(),
			shardSink: sink);
	}

	private static ShardIngestionSink CreateSink(
		string sinkRoot,
		ServiceMetrics metrics,
		Func<string, int, IShardFileWriter>? writerFactory)
	{
		string actionsRoot = Path.Combine(sinkRoot, ShardPath.ActionsRootFolder);
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

	private static int GetTouchedCount(ShardIngestionSink sink)
	{
		System.Reflection.FieldInfo? field = typeof(ShardIngestionSink).GetField("_touched", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
		return ((System.Collections.ICollection)field!.GetValue(sink)!).Count;
	}

	private static async Task PollUntilAsync(TimeSpan timeout, Func<Task<bool>> probe)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		while (stopwatch.Elapsed < timeout)
		{
			if (await probe().ConfigureAwait(false))
			{
				return;
			}

			await Task.Delay(25).ConfigureAwait(false);
		}

		Assert.Fail("Condition was not met within the polling timeout.");
	}

	private static async Task StopWorkerAsync(Task run, CancellationTokenSource cts)
	{
		cts.Cancel();
		try
		{
			await run.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
		}
		catch (TimeoutException)
		{
		}
	}

	// ── Fakes ────────────────────────────────────────────────────────────────────

	private sealed class InProcPipe : IEventPipe
	{
		private readonly ConcurrentQueue<RawEventDto> _queue = new();
		private TaskCompletionSource<bool> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);

		public int Capacity => 4096;

		public long OverflowCount => 0;

		public bool TryWrite(RawEventDto dto)
		{
			_queue.Enqueue(dto);
			_ready.TrySetResult(true);
			return true;
		}

		public bool TryRead(out RawEventDto dto)
		{
			if (_queue.TryDequeue(out RawEventDto? next))
			{
				dto = next;
				return true;
			}

			dto = default!;
			return false;
		}

		public async ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
		{
			try
			{
				return await _ready.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
			}
			finally
			{
				_ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
			}
		}
	}

	private sealed class FailNextCommitShardWriter : IShardFileWriter
	{
		private uint _count;
		private int _commitAttempts;

		public FailNextCommitShardWriter(string absolutePath)
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

	private sealed class CancelOnCommitShardWriter : IShardFileWriter
	{
		private readonly CancellationTokenSource _workerCts;
		private uint _count;

		public CancelOnCommitShardWriter(string absolutePath, CancellationTokenSource workerCts)
		{
			_workerCts = workerCts;
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
			_workerCts.Cancel();
			throw new OperationCanceledException(_workerCts.Token);
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
}
