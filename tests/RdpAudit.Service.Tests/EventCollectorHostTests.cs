/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectorHostTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Contract tests for EventCollectorHost. Uses a hand-rolled fake IEventSourceFactory /
//          IEventSource pair so the host can be exercised on any platform (net8.0-windows still
//          links, but no EventLogWatcher is instantiated). Verifies channel lifecycle, bookmark
//          aggregation with threshold-driven flushing, health-policy dispatch, restart-in-flight
//          gating, and shutdown correctness.
// Depends: xUnit, Microsoft.Extensions.Logging.Abstractions, Microsoft.EntityFrameworkCore.Sqlite,
//          RdpAudit.Core (BookmarkStore, AuditDbContext, IEventSource), RdpAudit.Service
//          (ChannelHealthPolicy, EventCollectorHost, IEventSourceFactory, IChannelStatusSink)
// Extends: When adding a new ChannelDecision, add a fact here that pins the host's response to
//          it (status label, restart-or-not, bookmark reset behavior).

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class EventCollectorHostTests
{
	// ── Fake plumbing ────────────────────────────────────────────────────────────

	private sealed class FakeSource : IEventSource, IDisposable
	{
		public string Name { get; }
		public IEventPipe Pipe { get; } = new NullPipe();
		public EventSourceStatus Status { get; private set; } = EventSourceStatus.Idle;
		public event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

		public int StartCalls;
		public int StopCalls;
		public int DisposeCalls;
		public Exception? StartException;

		public Action<string, string, long>? OnBookmark { get; }
		public Action<string, Exception, bool>? OnWatcherFault { get; }

		public FakeSource(string channel,
			Action<string, string, long>? onBookmark,
			Action<string, Exception, bool>? onWatcherFault)
		{
			Name = channel;
			OnBookmark = onBookmark;
			OnWatcherFault = onWatcherFault;
		}

		public Task StartAsync(CancellationToken ct)
		{
			Interlocked.Increment(ref StartCalls);
			if (StartException is Exception ex)
			{
				Status = EventSourceStatus.Faulted;
				StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(EventSourceStatus.Idle, EventSourceStatus.Faulted));
				throw ex;
			}

			Status = EventSourceStatus.Running;
			StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(EventSourceStatus.Idle, EventSourceStatus.Running));
			return Task.CompletedTask;
		}

		public Task StopAsync(CancellationToken ct)
		{
			Interlocked.Increment(ref StopCalls);
			EventSourceStatus prev = Status;
			Status = EventSourceStatus.Stopped;
			if (prev != EventSourceStatus.Stopped)
			{
				StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(prev, EventSourceStatus.Stopped));
			}

			return Task.CompletedTask;
		}

		public void Dispose() => Interlocked.Increment(ref DisposeCalls);
	}

	private sealed class NullPipe : IEventPipe
	{
		public int Capacity => 0;
		public long OverflowCount => 0;
		public bool TryWrite(RawEventDto dto) => true;
		public bool TryRead(out RawEventDto dto) { dto = default!; return false; }
		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
			=> new ValueTask<bool>(false);
	}

	private sealed class FakeFactory : IEventSourceFactory
	{
		public List<FakeSource> Created { get; } = new();
		public Func<string, Exception?>? StartExceptionSelector;

		public IEventSource Create(string channel, string xpathQuery, string? bookmarkXml,
			Action<string, string, long> onBookmark, Action<string, Exception, bool> onWatcherFault)
		{
			FakeSource src = new(channel, onBookmark, onWatcherFault);
			if (StartExceptionSelector is not null)
			{
				src.StartException = StartExceptionSelector(channel);
			}

			Created.Add(src);
			return src;
		}
	}

	private sealed class RecordingSink : IChannelStatusSink
	{
		public List<(string Channel, string Status)> Statuses { get; } = new();
		public int Dropped;

		public void SetChannelStatus(string channel, string status) => Statuses.Add((channel, status));
		public void IncrementDropped() => Interlocked.Increment(ref Dropped);
	}

	private static (BookmarkStore Store, IDbContextFactory<AuditDbContext> Factory) CreateBookmarkStore()
	{
		SqliteInMemoryDbContextFactory factory = new();
		using AuditDbContext ctx = factory.CreateDbContext();
		ctx.Database.EnsureCreated();

		return (new BookmarkStore(factory, NullLogger<BookmarkStore>.Instance), factory);
	}

	private sealed class SqliteInMemoryDbContextFactory : IDbContextFactory<AuditDbContext>, IDisposable
	{
		private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;

		public SqliteInMemoryDbContextFactory()
		{
#pragma warning disable CA2000 // ownership transferred to this factory; disposed in Dispose()
			_connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
#pragma warning restore CA2000
			_connection.Open();
		}

		public AuditDbContext CreateDbContext()
		{
			DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
				.UseSqlite(_connection)
				.Options;
			return new AuditDbContext(options);
		}

		public void Dispose() => _connection.Dispose();
	}

	private static ChannelHealthPolicy CreatePolicy(Func<DateTime>? clock = null)
	{
		return new ChannelHealthPolicy(
			clock ?? (() => DateTime.UtcNow),
			ChannelHealthPolicy.DefaultOptionalChannels);
	}

	private static EventCollectorHost CreateHost(
		FakeFactory factory,
		BookmarkStore store,
		ChannelHealthPolicy policy,
		IChannelStatusSink? sink = null)
	{
		return new EventCollectorHost(
			factory,
			policy,
			store,
			NullLogger<EventCollectorHost>.Instance,
			sink);
	}

	// ── Tests ────────────────────────────────────────────────────────────────────

	[Fact]
	public async Task StartChannelAsync_ArmsSource_AndReportsSuccess()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();
		RecordingSink sink = new();

		EventCollectorHost host = CreateHost(factory, store, policy, sink);

		await host.StartChannelAsync("Security", "*", CancellationToken.None);

		Assert.Single(factory.Created);
		Assert.Equal(1, factory.Created[0].StartCalls);
		Assert.Contains(("Security", "Armed"), sink.Statuses);
		Assert.Contains("Security", host.Channels);
	}

	[Fact]
	public async Task StartChannelAsync_DisabledChannel_DoesNotCreateSource()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		// Force channel into Disabled state.
		policy.ReportUnavailable("Optional/Ch", "test-disable");

		EventCollectorHost host = CreateHost(factory, store, policy);

		await host.StartChannelAsync("Optional/Ch", "*", CancellationToken.None);

		Assert.Empty(factory.Created);
	}

	[Fact]
	public async Task StartChannelAsync_ReplacesExistingRuntime_DisposesOldSource()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);

		await host.StartChannelAsync("Security", "*", CancellationToken.None);
		await host.StartChannelAsync("Security", "*", CancellationToken.None);

		Assert.Equal(2, factory.Created.Count);
		// First source must have been stopped when the second arm replaced it.
		Assert.True(factory.Created[0].StopCalls >= 1);
	}

	[Fact]
	public async Task StopChannelAsync_UnknownChannel_IsNoOp()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);

		// Should not throw.
		await host.StopChannelAsync("Missing", CancellationToken.None);
	}

	[Fact]
	public async Task StopAllAsync_StopsEveryChannel()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);

		await host.StartChannelAsync("Security", "*", CancellationToken.None);
		await host.StartChannelAsync("System", "*", CancellationToken.None);

		await host.StopAllAsync(CancellationToken.None);

		Assert.Empty(host.Channels);
		Assert.All(factory.Created, s => Assert.True(s.StopCalls >= 1));
	}

	[Fact]
	public async Task Bookmark_BelowThreshold_IsAggregatedButNotAutoFlushed()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);
		await host.StartChannelAsync("Security", "*", CancellationToken.None);

		FakeSource src = factory.Created[0];
		src.OnBookmark!("Security", "<bm-v1/>", 1);

		Assert.True(host.HasUnflushedBookmarks());
		Assert.Null(store.GetBookmarkXml("Security"));

		await host.FlushBookmarksAsync(CancellationToken.None);

		Assert.Equal("<bm-v1/>", store.GetBookmarkXml("Security"));
		Assert.False(host.HasUnflushedBookmarks());
	}

	[Fact]
	public async Task Bookmark_SameValueTwice_IsFlushedOnce()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);
		await host.StartChannelAsync("Security", "*", CancellationToken.None);

		FakeSource src = factory.Created[0];
		src.OnBookmark!("Security", "<bm/>", 1);

		await host.FlushBookmarksAsync(CancellationToken.None);
		Assert.Equal("<bm/>", store.GetBookmarkXml("Security"));

		// Second call with an identical bookmark must NOT re-flush (contract: idempotent).
		Assert.False(host.HasUnflushedBookmarks());
		src.OnBookmark!("Security", "<bm/>", 2);
		Assert.False(host.HasUnflushedBookmarks());
	}

	[Fact]
	public async Task WatcherFault_InvalidHandle_TriggersBookmarkReset()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();
		RecordingSink sink = new();

		EventCollectorHost host = CreateHost(factory, store, policy, sink);
		try
		{
			await host.StartChannelAsync("Security", "*", CancellationToken.None);

			// Seed a bookmark then fault with EventLogException — health policy demands
			// ResetBookmarkAndRestart on the first invalid-handle-like failure.
			FakeSource src = factory.Created[0];
			src.OnBookmark!("Security", "<bm/>", 1);
			await host.FlushBookmarksAsync(CancellationToken.None);
			Assert.Equal("<bm/>", store.GetBookmarkXml("Security"));

			src.OnWatcherFault!("Security", new System.Diagnostics.Eventing.Reader.EventLogException("stale"), true);

			// The status is set synchronously; ResetBookmarkStateAsync runs on a fire-and-forget task
			// and clears the persisted bookmark shortly after. Wait for the bookmark to be gone, which
			// is the stronger post-condition and implies the status has already been emitted.
			await WaitForConditionAsync(() => store.GetBookmarkXml("Security") is null,
				TimeSpan.FromSeconds(5));

			Assert.Contains(sink.Statuses, s => s.Status == "BookmarkReset");
			Assert.Null(store.GetBookmarkXml("Security"));
		}
		finally
		{
			await host.DisposeAsync();
		}
	}

	[Fact]
	public async Task WatcherFault_SecondFailure_TriggersCooldownStatus()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();
		RecordingSink sink = new();

		EventCollectorHost host = CreateHost(factory, store, policy, sink);
		try
		{
			await host.StartChannelAsync("Security", "*", CancellationToken.None);

			FakeSource src = factory.Created[0];

			// First fault: invalid-handle-like -> BookmarkReset.
			src.OnWatcherFault!("Security", new System.Diagnostics.Eventing.Reader.EventLogException("first"), false);
			await WaitForConditionAsync(() => sink.Statuses.Any(s => s.Status == "BookmarkReset"),
				TimeSpan.FromSeconds(2));

			// After the first fault the host re-arms and reports success, which resets the
			// per-channel failure counters. That is intentional prod behavior. To exercise the
			// Cooldown / RestartScheduled path deterministically we deliver a non-invalid-handle
			// exception on the freshly armed source: the policy short-circuits past the bookmark
			// reset branch and returns Cooldown directly.
			FakeSource? newSrc = factory.Created.LastOrDefault();
			Assert.NotNull(newSrc);
			newSrc!.OnWatcherFault!("Security", new InvalidOperationException("transient-non-handle"), true);

			await WaitForConditionAsync(() => sink.Statuses.Any(s => s.Status == "RestartScheduled"),
				TimeSpan.FromSeconds(2));

			Assert.Contains(sink.Statuses, s => s.Status == "RestartScheduled");
		}
		finally
		{
			// Host owns a 2-minute Cooldown Task.Delay in the fire-and-forget restart loop.
			// DisposeAsync cancels it so dotnet test can exit promptly instead of hanging.
			await host.DisposeAsync();
		}
	}

	[Fact]
	public async Task ArmFailure_IsRoutedThroughHealthPolicy()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new()
		{
			StartExceptionSelector = _ => new System.Diagnostics.Eventing.Reader.EventLogException("arm-blew-up"),
		};
		ChannelHealthPolicy policy = CreatePolicy();
		RecordingSink sink = new();

		EventCollectorHost host = CreateHost(factory, store, policy, sink);

		// Arm should NOT throw — the host converts the exception into a health-policy decision
		// and continues.
		await host.StartChannelAsync("Security", "*", CancellationToken.None);

		Assert.NotEmpty(sink.Statuses);
		Assert.Contains(sink.Statuses, s => s.Status is "BookmarkReset" or "RestartScheduled");
	}

	[Fact]
	public async Task DisposeAsync_ShutsDownEveryChannel()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		EventCollectorHost host = CreateHost(factory, store, policy);

		await host.StartChannelAsync("Security", "*", CancellationToken.None);
		await host.StartChannelAsync("System", "*", CancellationToken.None);

		await host.DisposeAsync();

		Assert.Empty(host.Channels);
		Assert.All(factory.Created, s => Assert.True(s.StopCalls >= 1));
	}

	[Fact]
	public void Ctor_RejectsNullDependencies()
	{
		(BookmarkStore store, _) = CreateBookmarkStore();
		FakeFactory factory = new();
		ChannelHealthPolicy policy = CreatePolicy();

		Assert.Throws<ArgumentNullException>(() =>
			new EventCollectorHost(null!, policy, store, NullLogger<EventCollectorHost>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EventCollectorHost(factory, null!, store, NullLogger<EventCollectorHost>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EventCollectorHost(factory, policy, null!, NullLogger<EventCollectorHost>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EventCollectorHost(factory, policy, store, null!));
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static async Task WaitForConditionAsync(Func<bool> condition, TimeSpan timeout)
	{
		DateTime deadline = DateTime.UtcNow + timeout;
		while (!condition() && DateTime.UtcNow < deadline)
		{
			await Task.Delay(10);
		}
	}
}
