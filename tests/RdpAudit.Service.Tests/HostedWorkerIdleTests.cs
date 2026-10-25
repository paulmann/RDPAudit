/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : HostedWorkerIdleTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: P3-1 regression tests for the shared non-Windows idle-wait helper. Pins the
//          cancellation contract: (1) when the wait token is cancelled, the helper logs an
//          informational stop breadcrumb and returns normally; (2) a cancellation-shaped fault
//          that arrives while the token is NOT cancelled stays visible and propagates; (3) any
//          other exception shape propagates untouched. These facts lock the behaviour that four
//          hosted workers (IpcServerWorker, EventCollectorHostedWorker, SecurityBackfillWorker,
//          TerminalServicesBackfillWorker) now rely on for their non-Windows idle branch.
// Depends: HostedWorkerIdle (internal, via InternalsVisibleTo), xUnit,
//          Microsoft.Extensions.Logging
// Extends: Add a fact here whenever the idle-wait logging contract changes.

using Microsoft.Extensions.Logging;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class HostedWorkerIdleTests
{
	private sealed class CapturingLogger<T> : ILogger<T>
	{
		public List<(LogLevel Level, string Message)> Entries { get; } = new();

		public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

		public bool IsEnabled(LogLevel logLevel) => true;

		public void Log<TState>(
			LogLevel logLevel,
			EventId eventId,
			TState state,
			Exception? exception,
			Func<TState, Exception?, string> formatter)
		{
			Entries.Add((logLevel, formatter(state, exception)));
		}
	}

	[Fact]
	public async Task WaitUntilCancelledAsync_WhenTokenIsCancelled_LogsBreadcrumbAndReturns()
	{
		CapturingLogger<HostedWorkerIdleTests> logger = new();
		using CancellationTokenSource cts = new();

		// The public overload drives the real Task.Delay(Timeout.InfiniteTimeSpan); the short
		// pause guarantees the delay has registered its cancellation callback before Cancel().
		Task wait = HostedWorkerIdle.WaitUntilCancelledAsync(logger, "TestWorker", cts.Token);
		await Task.Delay(100);
		cts.Cancel();

		await wait.WaitAsync(TimeSpan.FromSeconds(5));

		Assert.Contains(
			logger.Entries,
			e => e.Level == LogLevel.Information
				&& e.Message.Contains("TestWorker", StringComparison.Ordinal)
				&& e.Message.Contains("cancelled", StringComparison.Ordinal));
	}

	[Fact]
	public async Task WaitUntilCancelledAsync_OperationCanceledWithoutCancelledToken_Propagates()
	{
		CapturingLogger<HostedWorkerIdleTests> logger = new();
		Func<CancellationToken, Task> exoticCancellation = _ => throw new OperationCanceledException("exotic");

		// The token is NOT cancelled, so the catch filter must reject this fault class.
		await Assert.ThrowsAsync<OperationCanceledException>(
			() => HostedWorkerIdle.WaitUntilCancelledAsync(logger, "TestWorker", exoticCancellation, default));

		Assert.Empty(logger.Entries);
	}

	[Fact]
	public async Task WaitUntilCancelledAsync_NonCancellationFault_Propagates()
	{
		CapturingLogger<HostedWorkerIdleTests> logger = new();
		Func<CancellationToken, Task> fault = _ => throw new InvalidOperationException("boom");

		await Assert.ThrowsAsync<InvalidOperationException>(
			() => HostedWorkerIdle.WaitUntilCancelledAsync(logger, "TestWorker", fault, default));

		Assert.Empty(logger.Entries);
	}
}
