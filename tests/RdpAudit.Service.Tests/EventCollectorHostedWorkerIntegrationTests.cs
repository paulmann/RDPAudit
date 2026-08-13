/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectorHostedWorkerIntegrationTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Runtime lifecycle tests for EventCollectorHostedWorker composed against a real
//          EventCollectorHost with a hand-rolled fake IEventSourceFactory. Verifies:
//          - Non-Windows ExecuteAsync path idles under Task.Delay and honors cancellation.
//          - StopAsync flushes pending bookmarks and asks the host to stop all channels.
//          - Duplicate StopAsync calls are idempotent (no ObjectDisposedException on the
//            internal linked CancellationTokenSource).
//          - StopAsync before ExecuteAsync completes cleanly.
//          - Constructor null-guards fire for every non-optional dependency, and the two
//            optional dependencies (IDbContextFactory<AuditDbContext>, IOperationLogWriter)
//            can be omitted without side effects.
//          - Timing/threshold constants stay pinned (FlushTimerPeriod = 30s,
//            SecurityBookmarkStalenessThreshold = 15min, SkippedUnavailableReasonMaxLength = 120).
//          Deliberately does NOT exercise ArmChannelAsync — that path calls
//          ChannelCapability.Probe which requires a live Windows EventLog subsystem and is
//          out of scope for a Linux-friendly integration test. EventCollectorHostTests already
//          pins host arm semantics with the same FakeSource plumbing.
// Depends: xUnit, Moq (IOptionsMonitor<RdpAuditOptions>), Microsoft.EntityFrameworkCore.Sqlite,
//          Microsoft.Extensions.Logging.Abstractions, RdpAudit.Core (BookmarkStore,
//          AuditDbContext, IEventSource/IEventPipe), RdpAudit.Service (ChannelHealthPolicy,
//          EventCollectorHost, IEventSourceFactory, ServiceMetrics, EventCollectorHostedWorker).
// Extends: When a new orchestration responsibility lands on the hosted worker (e.g. a
//          per-source health snapshot loop), add a lifecycle fact here and update the
//          "Purpose" block above so the intent stays visible to reviewers.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.EventSources;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class EventCollectorHostedWorkerIntegrationTests
{
	// ── Fakes ────────────────────────────────────────────────────────────────────

	private sealed class FakeIntegrationSource : IEventSource
	{
		public string Name { get; }
		public IEventPipe Pipe { get; } = new NullIntegrationPipe();
		public EventSourceStatus Status { get; private set; } = EventSourceStatus.Idle;
		public event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

		public FakeIntegrationSource(string channel) => Name = channel;

		public Task StartAsync(CancellationToken ct)
		{
			EventSourceStatus prev = Status;
			Status = EventSourceStatus.Running;
			StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(prev, Status));
			return Task.CompletedTask;
		}

		public Task StopAsync(CancellationToken ct)
		{
			EventSourceStatus prev = Status;
			Status = EventSourceStatus.Stopped;
			if (prev != EventSourceStatus.Stopped)
			{
				StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(prev, Status));
			}

			return Task.CompletedTask;
		}
	}

	private sealed class NullIntegrationPipe : IEventPipe
	{
		public int Capacity => 0;
		public long OverflowCount => 0;
		public bool TryWrite(RawEventDto dto) => true;
		public bool TryRead(out RawEventDto dto) { dto = default!; return false; }
		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
			=> new(false);
	}

	private sealed class FakeIntegrationFactory : IEventSourceFactory
	{
		public int CreateCalls;

		public IEventSource Create(
			string channel,
			string xpathQuery,
			string? bookmarkXml,
			Action<string, string> onBookmark,
			Action<string, Exception, bool> onWatcherFault)
		{
			Interlocked.Increment(ref CreateCalls);
			return new FakeIntegrationSource(channel);
		}
	}

	private sealed class InMemoryDbContextFactory : IDbContextFactory<AuditDbContext>, IDisposable
	{
		private readonly SqliteConnection _connection;

		public InMemoryDbContextFactory()
		{
#pragma warning disable CA2000 // ownership transferred to this factory; disposed in Dispose()
			_connection = new SqliteConnection("DataSource=:memory:");
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

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static IOptionsMonitor<RdpAuditOptions> BuildOptionsMonitor(RdpAuditOptions? options = null)
	{
		Mock<IOptionsMonitor<RdpAuditOptions>> mock = new();
		mock.Setup(m => m.CurrentValue).Returns(options ?? new RdpAuditOptions());
		return mock.Object;
	}

	private static (EventCollectorHost Host, BookmarkStore Store, ChannelHealthPolicy Policy, InMemoryDbContextFactory Factory, FakeIntegrationFactory SourceFactory)
		BuildComposition()
	{
		InMemoryDbContextFactory factory = new();
		using (AuditDbContext ctx = factory.CreateDbContext())
		{
			ctx.Database.EnsureCreated();
		}

		BookmarkStore store = new(factory, NullLogger<BookmarkStore>.Instance);
		ChannelHealthPolicy policy = new(() => DateTime.UtcNow, ChannelHealthPolicy.DefaultOptionalChannels);
		FakeIntegrationFactory sourceFactory = new();

		EventCollectorHost host = new(
			sourceFactory,
			policy,
			store,
			NullLogger<EventCollectorHost>.Instance);

		return (host, store, policy, factory, sourceFactory);
	}

	private static EventCollectorHostedWorker BuildWorker(
		EventCollectorHost host,
		BookmarkStore store,
		ChannelHealthPolicy policy,
		IDbContextFactory<AuditDbContext>? factory = null)
	{
		return new EventCollectorHostedWorker(
			host,
			store,
			policy,
			new ServiceMetrics(),
			BuildOptionsMonitor(),
			NullLogger<EventCollectorHostedWorker>.Instance,
			factory,
			opLog: null);
	}

	// ── Non-Windows idle path ────────────────────────────────────────────────────

	[Fact]
	public async Task ExecuteAsync_NonWindows_IdlesUntilCanceled()
	{
		if (OperatingSystem.IsWindows())
		{
			// The idle branch is guarded by !OperatingSystem.IsWindows(); on Windows the worker
			// would try to probe channels through ChannelCapability, which needs a live EventLog.
			// The Windows arm path is covered indirectly by EventCollectorHostTests + the
			// pinning tests in EventCollectorHostedWorkerTests. Skip cleanly.
			return;
		}

		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			EventCollectorHostedWorker worker = BuildWorker(host, store, policy, factory);

			using CancellationTokenSource cts = new();
			Task run = worker.StartAsync(cts.Token);
			await run.ConfigureAwait(false);

			// Yield to let the ExecuteAsync loop reach its Task.Delay(Infinite, token) call.
			await Task.Delay(50).ConfigureAwait(false);

			await worker.StopAsync(CancellationToken.None).ConfigureAwait(false);

			// If we got here without hanging or throwing, the idle branch honored cancellation.
			Assert.True(true);
		}
		finally
		{
			await host.DisposeAsync().ConfigureAwait(false);
			factory.Dispose();
		}
	}

	// ── Shutdown semantics ───────────────────────────────────────────────────────

	[Fact]
	public async Task StopAsync_WithoutExecuteAsync_CompletesCleanly()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			EventCollectorHostedWorker worker = BuildWorker(host, store, policy, factory);

			// StopAsync without StartAsync must not touch _linkedCts (null) and must still
			// invoke Host.FlushBookmarksAsync + Host.StopAllAsync safely.
			await worker.StopAsync(CancellationToken.None).ConfigureAwait(false);

			Assert.False(host.HasUnflushedBookmarks());
		}
		finally
		{
			await host.DisposeAsync().ConfigureAwait(false);
			factory.Dispose();
		}
	}

	[Fact]
	public async Task StopAsync_CalledTwice_IsIdempotent()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			EventCollectorHostedWorker worker = BuildWorker(host, store, policy, factory);

			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token).ConfigureAwait(false);
			await Task.Delay(30).ConfigureAwait(false);

			await worker.StopAsync(CancellationToken.None).ConfigureAwait(false);

			// Second StopAsync must not throw ObjectDisposedException or NullReferenceException
			// even though _linkedCts has already been cancelled once.
			await worker.StopAsync(CancellationToken.None).ConfigureAwait(false);
		}
		finally
		{
			await host.DisposeAsync().ConfigureAwait(false);
			factory.Dispose();
		}
	}

	[Fact]
	public async Task StopAsync_AfterFullExecution_LeavesHostWithZeroChannels()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			EventCollectorHostedWorker worker = BuildWorker(host, store, policy, factory);

			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token).ConfigureAwait(false);
			await Task.Delay(30).ConfigureAwait(false);

			await worker.StopAsync(CancellationToken.None).ConfigureAwait(false);

			// StopAsync unconditionally calls Host.StopAllAsync — regardless of platform,
			// the host must report zero live channels after shutdown.
			Assert.Empty(host.Channels);
		}
		finally
		{
			await host.DisposeAsync().ConfigureAwait(false);
			factory.Dispose();
		}
	}

	// ── Constructor guards ───────────────────────────────────────────────────────

	[Fact]
	public void Constructor_NullHost_Throws()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host: null!,
				store,
				policy,
				new ServiceMetrics(),
				BuildOptionsMonitor(),
				NullLogger<EventCollectorHostedWorker>.Instance));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_NullBookmarks_Throws()
	{
		(EventCollectorHost host, _, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host,
				bookmarks: null!,
				policy,
				new ServiceMetrics(),
				BuildOptionsMonitor(),
				NullLogger<EventCollectorHostedWorker>.Instance));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_NullHealth_Throws()
	{
		(EventCollectorHost host, BookmarkStore store, _, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host,
				store,
				health: null!,
				new ServiceMetrics(),
				BuildOptionsMonitor(),
				NullLogger<EventCollectorHostedWorker>.Instance));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_NullMetrics_Throws()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host,
				store,
				policy,
				metrics: null!,
				BuildOptionsMonitor(),
				NullLogger<EventCollectorHostedWorker>.Instance));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_NullOptions_Throws()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host,
				store,
				policy,
				new ServiceMetrics(),
				options: null!,
				NullLogger<EventCollectorHostedWorker>.Instance));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_NullLogger_Throws()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			Assert.Throws<ArgumentNullException>(() => new EventCollectorHostedWorker(
				host,
				store,
				policy,
				new ServiceMetrics(),
				BuildOptionsMonitor(),
				logger: null!));
		}
		finally
		{
			factory.Dispose();
		}
	}

	[Fact]
	public void Constructor_OptionalDependencies_AllowNull()
	{
		(EventCollectorHost host, BookmarkStore store, ChannelHealthPolicy policy, InMemoryDbContextFactory factory, _) = BuildComposition();
		try
		{
			// Both IDbContextFactory<AuditDbContext> and IOperationLogWriter are optional.
			// Constructing with both null must not throw — the reconciliation branch is
			// gated on _factory being non-null.
			EventCollectorHostedWorker worker = new(
				host,
				store,
				policy,
				new ServiceMetrics(),
				BuildOptionsMonitor(),
				NullLogger<EventCollectorHostedWorker>.Instance,
				factory: null,
				opLog: null);

			Assert.NotNull(worker);
		}
		finally
		{
			factory.Dispose();
		}
	}

	// ── Constant pinning ─────────────────────────────────────────────────────────

	[Fact]
	public void FlushTimerPeriod_Is30Seconds()
	{
		Assert.Equal(TimeSpan.FromSeconds(30), EventCollectorHostedWorker.FlushTimerPeriod);
	}

	[Fact]
	public void SecurityBookmarkStalenessThreshold_Is15Minutes()
	{
		Assert.Equal(TimeSpan.FromMinutes(15), EventCollectorHostedWorker.SecurityBookmarkStalenessThreshold);
	}

	[Fact]
	public void SkippedUnavailableReasonMaxLength_Is120()
	{
		Assert.Equal(120, EventCollectorHostedWorker.SkippedUnavailableReasonMaxLength);
	}
}
