// File:    src/RdpAudit.Service/Firewall/PowerShellProbeLatch.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Lock-free latch for the PowerShell live-firewall scan retry policy.
//          After the first PowerShell probe failure / timeout the scanner latches onto the
//          netsh text fallback. While latched every scan is served by netsh and PowerShell
//          is re-probed at most once per configured interval: the latch stores the next
//          allowed probe instant as a Volatile long of UTC ticks, and the retry slot is
//          claimed with an Interlocked.CompareExchange so concurrent scan callers can never
//          both spawn PowerShell inside one interval. A successful re-probe unlatches.
//          Pure logic + TimeProvider only - no I/O, no Win32 - so the retry policy is
//          unit-testable on any host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Threading;

namespace RdpAudit.Service.Firewall;

/// <summary>What a single scan call must do with respect to the PowerShell probe.</summary>
internal enum PowerShellProbeAction
{
	/// <summary>The scanner is not latched: run the normal PowerShell-first probe.</summary>
	Probe = 0,

	/// <summary>The scanner was latched but the retry interval elapsed and THIS call claimed the
	/// re-probe slot. Run PowerShell; on failure the latch stays armed (the deadline was already
	/// advanced by the claim), on success the latch is released.</summary>
	ProbeAfterLatch = 1,

	/// <summary>The scanner is latched and the retry interval has not elapsed (or another call
	/// already claimed the re-probe slot). Serve the netsh fallback without spawning PowerShell.</summary>
	UseFallback = 2,
}

/// <summary>Lock-free state machine deciding when a latched PowerShell scanner may re-probe.
/// All mutable state is a single <c>long</c> of UTC ticks (<c>0</c> = not latched) accessed via
/// <see cref="Volatile"/> / <see cref="Interlocked"/>; there are no locks.</summary>
internal sealed class PowerShellProbeLatch
{
	private readonly TimeProvider _time;

	/// <summary>UTC ticks of the next allowed PowerShell probe; <c>0</c> means "not latched".
	/// Volatile-long so decisions are always read from main memory, never a stale register.</summary>
	private long _nextProbeAtTicks;

	public PowerShellProbeLatch(TimeProvider time)
	{
		ArgumentNullException.ThrowIfNull(time);
		_time = time;
	}

	/// <summary>True when the scanner is currently latched onto the netsh fallback.</summary>
	public bool Latched => Volatile.Read(ref _nextProbeAtTicks) != 0;

	/// <summary>The next allowed PowerShell probe instant, or null when not latched. Test seam.</summary>
	public DateTimeOffset? NextProbeAt
	{
		get
		{
			long ticks = Volatile.Read(ref _nextProbeAtTicks);
			return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
		}
	}

	/// <summary>Decides what the current scan call must do. See <see cref="PowerShellProbeAction"/>.
	/// When the retry interval elapsed, only ONE concurrent caller wins the probe slot (CompareExchange);
	/// every other caller gets <see cref="PowerShellProbeAction.UseFallback"/>.</summary>
	public PowerShellProbeAction DecidePowerShellProbe(TimeSpan retryInterval)
	{
		long intervalTicks = SanitizeInterval(retryInterval);
		while (true)
		{
			long nowTicks = _time.GetUtcNow().UtcTicks;
			long next = Volatile.Read(ref _nextProbeAtTicks);

			if (next == 0)
			{
				// Not latched: normal PowerShell-first path.
				return PowerShellProbeAction.Probe;
			}

			if (nowTicks < next)
			{
				// Latched and still cooling down.
				return PowerShellProbeAction.UseFallback;
			}

			// Probe is due: atomically advance the deadline to claim the slot for this caller.
			long deadline = nowTicks + intervalTicks;
			long observed = Interlocked.CompareExchange(ref _nextProbeAtTicks, deadline, next);
			if (observed == next)
			{
				return PowerShellProbeAction.ProbeAfterLatch;
			}

			// Someone else raced us and mutated the latch; recompute with the fresh state.
		}
	}

	/// <summary>Must be called after ANY failed / timed-out PowerShell probe. Latches the scanner and
	/// re-arms the next-probe deadline to "now + interval" so the cool-off runs from the moment the
	/// failure was actually observed.</summary>
	public void OnProbeFailure(TimeSpan retryInterval)
	{
		long intervalTicks = SanitizeInterval(retryInterval);
		long deadline = _time.GetUtcNow().UtcTicks + intervalTicks;
		Volatile.Write(ref _nextProbeAtTicks, deadline);
	}

	/// <summary>Must be called after a successful PowerShell re-probe while latched. Releases the
	/// latch so the next scan returns to the normal PowerShell-first path.</summary>
	public void OnProbeSuccess()
	{
		Volatile.Write(ref _nextProbeAtTicks, 0);
	}

	/// <summary>Never allow a zero / negative interval to collapse the latch into a hot loop.
	/// The scanner already falls back to the configured default for values below 1; this is the
	/// last-line defensive floor if the latch is driven with a raw interval.</summary>
	private static long SanitizeInterval(TimeSpan retryInterval)
	{
		TimeSpan safe = retryInterval > TimeSpan.Zero ? retryInterval : TimeSpan.FromMinutes(15);
		return Math.Max(TimeSpan.TicksPerSecond, safe.Ticks);
	}
}
