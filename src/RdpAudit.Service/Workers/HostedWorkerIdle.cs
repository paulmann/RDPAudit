/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : src/RdpAudit.Service/Workers/HostedWorkerIdle.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Shared idle-wait helper for workers whose real work requires Windows (named-pipe ACLs,
//          EventLog / ETW readers). On a non-Windows host such a worker waits for host shutdown
//          instead of running its loop. This helper replaces the per-worker pattern of
//          `Task.Delay(Timeout.InfiniteTimeSpan, ct)` wrapped in an empty
//          `catch (OperationCanceledException) { }` (P3-1): cancellation now logs an
//          informational breadcrumb before the worker returns, and the catch is narrowed with
//          `when (ct.IsCancellationRequested)` so a cancellation that arrives while the token is
//          NOT cancelled - or any other exception shape - stays visible instead of being
//          swallowed.
//          RdpAudit is a Windows-only product; this branch exists only so unit tests and
//          diagnostics can run on non-Windows hosts without touching Windows APIs.
// Depends: Microsoft.Extensions.Logging
// Extends: Microsoft.Extensions.Hosting workers that idle on non-Windows hosts; add new hosts
//          here when another Windows-only worker needs the same cancellation contract.

using Microsoft.Extensions.Logging;

namespace RdpAudit.Service.Workers;

internal static class HostedWorkerIdle
{
	/// <summary>Idles until <paramref name="ct"/> is cancelled, then logs the stop breadcrumb and
	/// returns normally. Any exception other than a cancellation of <paramref name="ct"/> propagates
	/// to the caller so unexpected faults stay visible.</summary>
	public static async Task WaitUntilCancelledAsync(ILogger logger, string workerName, CancellationToken ct)
	{
		await WaitUntilCancelledAsync(
			logger,
			workerName,
			static token => Task.Delay(Timeout.InfiniteTimeSpan, token),
			ct).ConfigureAwait(false);
	}

	/// <summary>Test seam: identical contract, but the infinite delay is supplied by the caller so
	/// unit tests can exercise the uncommon paths (cancellation without a cancelled token, a
	/// non-cancellation fault) deterministically.</summary>
	internal static async Task WaitUntilCancelledAsync(
		ILogger logger,
		string workerName,
		Func<CancellationToken, Task> delay,
		CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(delay);

		try
		{
			await delay(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			logger.LogInformation("{Worker} idle wait cancelled; worker is stopping", workerName);
		}
	}
}
