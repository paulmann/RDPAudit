/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.0
// File   : EventProcessorWorkerUnifiedCommitTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: End-to-end integration test for EventProcessorWorker.PersistBatchAsync in its
//          v2.3 shape: proves that events (RawEvents) and their bookmark cross ONE
//          SqliteTransaction. Uses a real in-memory shared-cache SQLite database, a real
//          AuditDbContext, a real BookmarkStore, and real (or minimally-wired) upserter
//          collaborators. Reflection reaches PersistBatchAsync because it is private —
//          this mirrors the pattern already used by EventProcessorWorkerRingBufferTests.
// Depends: xUnit, Moq, Microsoft.Data.Sqlite, Microsoft.EntityFrameworkCore,
//          AuditDbContext, BookmarkStore, EventProcessorWorker, EventNormalizer,
//          SessionIpCorrelationUpserter, RdpConnectionFactUpserter,
//          AuthAttemptFactUpserter, SecurityCorrelationWatchdog, ServiceMetrics,
//          RdpTransportIpCache, SessionCorrelationCache
// Extends: Add another [Fact] whenever the unified-commit path grows a new peer artefact
//          (e.g. shard watermark). Follow the fixture pattern: build DTOs via
//          MakeDto(...), invoke PersistBatchAsync via reflection, then assert against
//          BOTH the RawEvents table AND BookmarkStore.LoadAllAsync so any future
//          durability-boundary regression fails loudly.

using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Integration tests for the v2.3 unified-commit path in
/// <see cref="EventProcessorWorker.PersistBatchAsync"/>. Every test drives the worker end-to-end
/// against a real SQLite database and asserts the durability contract on both the event batch
/// and the bookmark simultaneously.
/// </summary>
public sealed class EventProcessorWorkerUnifiedCommitTests : IAsyncLifetime
{
	// ── Test fixture: single shared-cache in-memory SQLite database per test class ────────
	// We keep ONE connection open for the lifetime of the fixture so the in-memory database
	// survives across the ephemeral DbContext instances created by the pooled factory. Every
	// test uses a unique channel name to avoid cross-test collisions without requiring an
	// EnsureDeleted cycle between tests.

	private const string ConnectionString = "Data Source=file:processor-unified-commit-tests?mode=memory&cache=shared";

	private SqliteConnection _keepAlive = null!;
	private TestDbContextFactory _factory = null!;
	private BookmarkStore _bookmarkStore = null!;
	private ServiceMetrics _metrics = null!;
	private IOptionsMonitor<RdpAuditOptions> _optionsMonitor = null!;

	public async Task InitializeAsync()
	{
		_keepAlive = new SqliteConnection(ConnectionString);
		await _keepAlive.OpenAsync();

		_factory = new TestDbContextFactory(ConnectionString);

		// Materialise the schema exactly once via a throwaway context.
		await using (AuditDbContext ctx = _factory.CreateDbContext())
		{
			await ctx.Database.EnsureCreatedAsync();
		}

		_bookmarkStore = new BookmarkStore(_factory, NullLogger<BookmarkStore>.Instance);
		_metrics = new ServiceMetrics();

		RdpAuditOptions options = new()
		{
			Monitoring = new MonitoringOptions
			{
				BatchSize = 100,
				BatchTimeoutMilliseconds = 50,
			},
			Diagnostics = new DiagnosticsOptions { DebugMode = false },
		};

		Mock<IOptionsMonitor<RdpAuditOptions>> monitorMock = new();
		monitorMock.Setup(m => m.CurrentValue).Returns(options);
		_optionsMonitor = monitorMock.Object;
	}

	public async Task DisposeAsync()
	{
		await _keepAlive.DisposeAsync();
	}

	// ── Factory: assemble a real EventProcessorWorker on the shared fixture DB ────────────

	private EventProcessorWorker CreateWorker()
	{
		EventChannel channel = new(Options.Create(new RdpAuditOptions
		{
			Monitoring = new MonitoringOptions { BatchSize = 100, BatchTimeoutMilliseconds = 50 },
		}));

		SessionCorrelationCache correlationCache = new();
		EventNormalizer normalizer = new(correlationCache);
		SessionIpCorrelationUpserter correlationUpserter = new();
		RdpConnectionFactUpserter connectionUpserter = new();
		RdpTransportIpCache transportCache = new();
		AuthAttemptFactUpserter authUpserter = new(transportCache);
		SecurityCorrelationWatchdog watchdog = new(_metrics);

		Mock<IOperationLogWriter> opLogMock = new();

		return new EventProcessorWorker(
			channel,
			_factory,
			normalizer,
			correlationUpserter,
			connectionUpserter,
			authUpserter,
			watchdog,
			_metrics,
			NullLogger<EventProcessorWorker>.Instance,
			_optionsMonitor,
			opLogMock.Object,
			_bookmarkStore);
	}

	private static Task InvokePersistBatchAsync(
		EventProcessorWorker worker,
		List<RawEventDto> batch,
		CancellationToken ct)
	{
		MethodInfo method = typeof(EventProcessorWorker).GetMethod(
			"PersistBatchAsync",
			BindingFlags.NonPublic | BindingFlags.Instance)!;

		Assert.NotNull(method);
		object? invoked = method.Invoke(worker, new object[] { batch, ct });
		Assert.NotNull(invoked);
		return (Task)invoked!;
	}

	private static RawEventDto MakeDto(
		int eventId,
		string channel,
		string bookmarkXml,
		DateTime? timeUtc = null,
		string? sourceIp = null)
	{
		return new RawEventDto
		{
			EventId = eventId,
			Channel = channel,
			TimeUtc = timeUtc ?? DateTime.UtcNow,
			XmlPayload = BuildEventXml(eventId, channel, sourceIp),
			BookmarkXml = bookmarkXml,
			SourceIp = sourceIp,
		};
	}

	private static string BuildEventXml(int eventId, string channel, string? sourceIp)
	{
		// Minimum-viable XML that lets EventNormalizer succeed without exceptions. The
		// unified-commit path is orthogonal to normalization content — this is just enough to
		// avoid Normalize throwing (which would still work for us because the bookmark path
		// tolerates normalize failures, but a clean happy-path is more diagnostic).
		string ip = sourceIp ?? "203.0.113.10";
		return
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>{eventId}</EventID><Channel>{channel}</Channel>" +
			$"<TimeCreated SystemTime='{DateTime.UtcNow:o}'/></System>" +
			$"<EventData><Data Name='IpAddress'>{ip}</Data><Data Name='TargetUserName'>alice</Data></EventData>" +
			"</Event>";
	}

	private static string MakeBookmarkXml(string channel, long recordId)
	{
		return $"<BookmarkList><Bookmark Channel='{channel}' RecordId='{recordId}' IsCurrent='true'/></BookmarkList>";
	}

	// ── Test 1: Happy path ─────────────────────────────────────────────────────────────────

	[Fact]
	public async Task PersistBatchAsync_SingleDto_CommitsEventAndBookmarkTogether()
	{
		EventProcessorWorker worker = CreateWorker();

		string channel = "Test/HappyPath";
		string bookmark = MakeBookmarkXml(channel, 42);

		List<RawEventDto> batch = new()
		{
			MakeDto(4625, channel, bookmark),
		};

		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		// Event landed.
		await using AuditDbContext db = _factory.CreateDbContext();
		int rowCount = await db.RawEvents.CountAsync(e => e.Channel == channel);
		Assert.Equal(1, rowCount);

		// Bookmark landed on disk (fresh context — no cache leak possible).
		await _bookmarkStore.LoadAllAsync();
		string? loaded = _bookmarkStore.GetBookmarkXml(channel);
		Assert.Equal(bookmark, loaded);
	}

	// ── Test 2: Last bookmark per channel wins ─────────────────────────────────────────────

	[Fact]
	public async Task PersistBatchAsync_MultipleDtosSameChannel_KeepsOnlyLastBookmark()
	{
		EventProcessorWorker worker = CreateWorker();

		string channel = "Test/LastWins";
		string oldest = MakeBookmarkXml(channel, 100);
		string middle = MakeBookmarkXml(channel, 200);
		string latest = MakeBookmarkXml(channel, 300);

		List<RawEventDto> batch = new()
		{
			MakeDto(4625, channel, oldest,  DateTime.UtcNow.AddSeconds(-30)),
			MakeDto(4625, channel, middle,  DateTime.UtcNow.AddSeconds(-15)),
			MakeDto(4624, channel, latest,  DateTime.UtcNow),
		};

		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		// All three events landed.
		await using AuditDbContext db = _factory.CreateDbContext();
		int rowCount = await db.RawEvents.CountAsync(e => e.Channel == channel);
		Assert.Equal(3, rowCount);

		// But the bookmark row must reflect ONLY the newest DTO.
		await _bookmarkStore.LoadAllAsync();
		Assert.Equal(latest, _bookmarkStore.GetBookmarkXml(channel));
	}

	// ── Test 3: Bookmarks per DISTINCT channel are all persisted ───────────────────────────

	[Fact]
	public async Task PersistBatchAsync_MultipleDtosDistinctChannels_PersistsOneBookmarkPerChannel()
	{
		EventProcessorWorker worker = CreateWorker();

		string chA = "Test/Multi/A";
		string chB = "Test/Multi/B";
		string chC = "Test/Multi/C";

		string bmA = MakeBookmarkXml(chA, 1);
		string bmB = MakeBookmarkXml(chB, 2);
		string bmC = MakeBookmarkXml(chC, 3);

		List<RawEventDto> batch = new()
		{
			MakeDto(4624, chA, bmA),
			MakeDto(4625, chB, bmB),
			MakeDto(4634, chC, bmC),
		};

		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		await _bookmarkStore.LoadAllAsync();
		Assert.Equal(bmA, _bookmarkStore.GetBookmarkXml(chA));
		Assert.Equal(bmB, _bookmarkStore.GetBookmarkXml(chB));
		Assert.Equal(bmC, _bookmarkStore.GetBookmarkXml(chC));
	}

	// ── Test 4: DTO without bookmark is a no-op on the bookmark side ───────────────────────

	[Fact]
	public async Task PersistBatchAsync_DtoWithoutBookmark_LeavesBookmarkStoreUntouched()
	{
		EventProcessorWorker worker = CreateWorker();

		string channel = "Test/NoBookmark";

		RawEventDto dto = MakeDto(4625, channel, bookmarkXml: string.Empty);
		// Null bookmark is skipped by the unified-commit hot path.
		dto.BookmarkXml = null;

		List<RawEventDto> batch = new() { dto };

		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		// Event still landed.
		await using AuditDbContext db = _factory.CreateDbContext();
		int rowCount = await db.RawEvents.CountAsync(e => e.Channel == channel);
		Assert.Equal(1, rowCount);

		// But NO bookmark for this channel — the row does not exist.
		await _bookmarkStore.LoadAllAsync();
		Assert.Null(_bookmarkStore.GetBookmarkXml(channel));
	}

	// ── Test 5: Rollback of the caller (via cancelled token) preserves durability ──────────

	[Fact]
	public async Task PersistBatchAsync_CancelledMidFlight_LeavesNeitherEventNorBookmark()
	{
		// This test proves that a torn commit does not leave the bookmark ahead of the events.
		// We cancel a pre-cancelled token — SaveChangesAsync raises OperationCanceledException,
		// PersistBatchAsync's catch block issues tx.RollbackAsync and rethrows. Nothing is
		// visible on disk after this call, and the in-memory bookmark cache is restored.

		EventProcessorWorker worker = CreateWorker();

		string channel = "Test/Rollback";
		string bookmark = MakeBookmarkXml(channel, 999);

		// Seed the cache with a previous value so we can prove RollbackCache restored it.
		string previousBookmark = MakeBookmarkXml(channel, 100);
		await _bookmarkStore.SaveBookmarkAsync(channel, previousBookmark);
		Assert.Equal(previousBookmark, _bookmarkStore.GetBookmarkXml(channel));

		List<RawEventDto> batch = new()
		{
			MakeDto(4625, channel, bookmark),
		};

		using CancellationTokenSource cts = new();
		cts.Cancel(); // Pre-cancel: SaveChangesAsync will throw immediately.

		await Assert.ThrowsAnyAsync<OperationCanceledException>(
			() => InvokePersistBatchAsync(worker, batch, cts.Token));

		// In-memory cache reverted to the pre-batch value.
		Assert.Equal(previousBookmark, _bookmarkStore.GetBookmarkXml(channel));

		// Disk state also reflects the pre-batch value (the seeded bookmark), not the new one.
		await _bookmarkStore.LoadAllAsync();
		Assert.Equal(previousBookmark, _bookmarkStore.GetBookmarkXml(channel));

		// No new event landed either.
		await using AuditDbContext db = _factory.CreateDbContext();
		int rowCount = await db.RawEvents.CountAsync(e => e.Channel == channel);
		Assert.Equal(0, rowCount);
	}

	// ── Test 6: Empty batch is a fast no-op ────────────────────────────────────────────────

	[Fact]
	public async Task PersistBatchAsync_EmptyBatch_DoesNotThrowAndDoesNotWriteBookmark()
	{
		EventProcessorWorker worker = CreateWorker();

		// Snapshot bookmark count BEFORE.
		await _bookmarkStore.LoadAllAsync();
		string? sentinelBefore = _bookmarkStore.GetBookmarkXml("Test/Empty/Sentinel");
		Assert.Null(sentinelBefore);

		await InvokePersistBatchAsync(worker, new List<RawEventDto>(), CancellationToken.None);

		// Nothing appeared out of thin air.
		await _bookmarkStore.LoadAllAsync();
		string? sentinelAfter = _bookmarkStore.GetBookmarkXml("Test/Empty/Sentinel");
		Assert.Null(sentinelAfter);
	}

	// ── Test 7: BookmarkStore == null keeps the legacy path bit-identical ──────────────────

	[Fact]
	public async Task PersistBatchAsync_NullBookmarkStore_DoesNotThrowAndSkipsBookmarkWrite()
	{
		// Build a worker with a null bookmark store — matches the DrainBatchAsync unit-test
		// wiring in EventProcessorWorkerRingBufferTests and proves the default-null constructor
		// arg does not break the persist path (regression guard for the v2.3 signature bump).

		EventChannel channel = new(Options.Create(new RdpAuditOptions
		{
			Monitoring = new MonitoringOptions { BatchSize = 100, BatchTimeoutMilliseconds = 50 },
		}));

		SessionCorrelationCache correlationCache = new();
		EventNormalizer normalizer = new(correlationCache);
		SessionIpCorrelationUpserter correlationUpserter = new();
		RdpConnectionFactUpserter connectionUpserter = new();
		RdpTransportIpCache transportCache = new();
		AuthAttemptFactUpserter authUpserter = new(transportCache);
		SecurityCorrelationWatchdog watchdog = new(_metrics);
		Mock<IOperationLogWriter> opLogMock = new();

		EventProcessorWorker worker = new(
			channel,
			_factory,
			normalizer,
			correlationUpserter,
			connectionUpserter,
			authUpserter,
			watchdog,
			_metrics,
			NullLogger<EventProcessorWorker>.Instance,
			_optionsMonitor,
			opLogMock.Object,
			bookmarkStore: null);

		string chName = "Test/NullStore";
		string bookmark = MakeBookmarkXml(chName, 42);

		List<RawEventDto> batch = new()
		{
			MakeDto(4625, chName, bookmark),
		};

		// Must not throw — the null-store path skips the unified-commit branch entirely.
		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		// The RawEvent still landed through the shared factory.
		await using AuditDbContext db = _factory.CreateDbContext();
		int rowCount = await db.RawEvents.CountAsync(e => e.Channel == chName);
		Assert.Equal(1, rowCount);

		// And the (test-scope) bookmark store never saw it — because it wasn't passed in.
		await _bookmarkStore.LoadAllAsync();
		Assert.Null(_bookmarkStore.GetBookmarkXml(chName));
	}

	// ── Test 8: MarkCommitted / RollbackCache called exactly once per channel ──────────────

	[Fact]
	public async Task PersistBatchAsync_HappyPath_UpdatesCacheEagerlyAndKeepsFinalValue()
	{
		// Documents the cache-ordering contract from BookmarkStore v2.0 → EventProcessorWorker
		// v2.3: UpdateCache runs BEFORE BeginTransactionAsync, so a concurrent GetBookmarkXml
		// reader observes the freshest bookmark immediately once the persist call returns.

		EventProcessorWorker worker = CreateWorker();

		string chName = "Test/CacheOrdering";
		string bookmark = MakeBookmarkXml(chName, 555);

		List<RawEventDto> batch = new()
		{
			MakeDto(4625, chName, bookmark),
		};

		Assert.Null(_bookmarkStore.GetBookmarkXml(chName));

		await InvokePersistBatchAsync(worker, batch, CancellationToken.None);

		// Cache reflects the fresh bookmark without needing an explicit LoadAllAsync().
		Assert.Equal(bookmark, _bookmarkStore.GetBookmarkXml(chName));

		// And disk also reflects it — LoadAllAsync would overwrite the cache, so the round-trip
		// proves durability.
		await _bookmarkStore.LoadAllAsync();
		Assert.Equal(bookmark, _bookmarkStore.GetBookmarkXml(chName));
	}

	// ── Test fixture helpers ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Minimal <see cref="IDbContextFactory{TContext}"/> that hands out fresh
	/// <see cref="AuditDbContext"/> instances against a shared connection string. Every context
	/// opens its own connection into the shared in-memory database, so DbContext.Dispose does
	/// not tear down the database.
	/// </summary>
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly string _connectionString;

		public TestDbContextFactory(string connectionString)
		{
			_connectionString = connectionString;
		}

		public AuditDbContext CreateDbContext()
		{
			DbContextOptionsBuilder<AuditDbContext> builder = new();
			builder.UseSqlite(_connectionString);
			return new AuditDbContext(builder.Options);
		}

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken ct = default)
		{
			return Task.FromResult(CreateDbContext());
		}
	}
}
