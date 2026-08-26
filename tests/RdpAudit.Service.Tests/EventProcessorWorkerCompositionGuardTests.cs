/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : EventProcessorWorkerCompositionGuardTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Pins the P2 composition guard on EventProcessorWorker: the unified bookmark commit
//          needs BookmarkStore AND BookmarkCheckpointLedger together. Supplying exactly one is
//          a composition mistake and must fail loudly - a Critical log line plus a hard
//          constructor throw so DI activation fails at startup instead of silently degrading
//          to the legacy split-commit behaviour.
// Depends: EventProcessorWorker, BookmarkStore, BookmarkCheckpointLedger, Moq, xUnit
// Extends: When the unified commit grows a third mandatory peer, mirror the pairing check here.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class EventProcessorWorkerCompositionGuardTests
{
	[Fact]
	public void Ctor_BookmarksWithoutCheckpoints_Throws_AndLogsCritical()
	{
		Mock<ILogger<EventProcessorWorker>> logger = new();
		BookmarkStore bookmarks = new(factory: null!, NullLogger<BookmarkStore>.Instance);

		ArgumentException ex = Assert.Throws<ArgumentException>(() =>
			CreateWorker(logger, bookmarks, checkpoints: null));

		Assert.Contains("BookmarkStore", ex.Message, StringComparison.Ordinal);
		logger.Verify(
			x => x.Log(
				LogLevel.Critical,
				It.IsAny<EventId>(),
				It.Is<It.IsAnyType>((state, _) =>
					state.ToString()!.Contains("composition error", StringComparison.Ordinal)),
				It.IsAny<Exception?>(),
				It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
			Times.Once);
	}

	[Fact]
	public void Ctor_CheckpointsWithoutBookmarks_Throws_AndLogsCritical()
	{
		Mock<ILogger<EventProcessorWorker>> logger = new();
		BookmarkCheckpointLedger checkpoints = new();

		ArgumentException ex = Assert.Throws<ArgumentException>(() =>
			CreateWorker(logger, bookmarks: null, checkpoints));

		Assert.Contains("BookmarkStore", ex.Message, StringComparison.Ordinal);
		logger.Verify(
			x => x.Log(
				LogLevel.Critical,
				It.IsAny<EventId>(),
				It.Is<It.IsAnyType>((state, _) =>
					state.ToString()!.Contains("composition error", StringComparison.Ordinal)),
				It.IsAny<Exception?>(),
				It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
			Times.Once);
	}

	[Fact]
	public void Ctor_NeitherBookmarkDependency_KeepsLegacySplitCommit()
	{
		Mock<ILogger<EventProcessorWorker>> logger = new();

		EventProcessorWorker worker = CreateWorker(logger, bookmarks: null, checkpoints: null);

		Assert.NotNull(worker);
		logger.Verify(
			x => x.Log(
				LogLevel.Critical,
				It.IsAny<EventId>(),
				It.IsAny<It.IsAnyType>(),
				It.IsAny<Exception?>(),
				It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
			Times.Never);
	}

	[Fact]
	public void Ctor_BothBookmarkDependencies_PassesQuietly()
	{
		Mock<ILogger<EventProcessorWorker>> logger = new();
		BookmarkStore bookmarks = new(factory: null!, NullLogger<BookmarkStore>.Instance);
		BookmarkCheckpointLedger checkpoints = new();

		EventProcessorWorker worker = CreateWorker(logger, bookmarks, checkpoints);

		Assert.NotNull(worker);
		logger.Verify(
			x => x.Log(
				LogLevel.Critical,
				It.IsAny<EventId>(),
				It.IsAny<It.IsAnyType>(),
				It.IsAny<Exception?>(),
				It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
			Times.Never);
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static EventProcessorWorker CreateWorker(
		Mock<ILogger<EventProcessorWorker>> logger,
		BookmarkStore? bookmarks,
		BookmarkCheckpointLedger? checkpoints)
	{
		return new EventProcessorWorker(
			new NullPipe(),
			factory: null!,
			normalizer: null!,
			correlationUpserter: null!,
			connectionFactUpserter: null!,
			authAttemptFactUpserter: null!,
			securityWatchdog: null!,
			new ServiceMetrics(),
			logger.Object,
			new StaticOptionsMonitor<RdpAuditOptions>(new RdpAuditOptions()),
			opLog: null!,
			bookmarks,
			checkpoints);
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

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;

		public T Get(string? name) => value;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}
}
