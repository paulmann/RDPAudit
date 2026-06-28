// File:    src/RdpAudit.Service/Collectors/ChannelHealthPolicy.cs
// Module:  RdpAudit.Service.Collectors
// Purpose: Pure, thread-safe per-channel failure accounting and restart decision policy for the
//          EventCollectorWorker. Classifies channels as Critical or Optional, debounces repeated
//          invalid-handle failures, schedules a single bookmark-reset retry, and disables a
//          channel after a saturating burst of failures so the Application log is not spammed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Service.Collectors;

/// <summary>Whether a channel is required for security coverage or merely opportunistic.</summary>
public enum ChannelImportance
{
	/// <summary>Channel is required (e.g. Security). Failures trigger recovery + cooldown but the channel is never permanently dropped silently.</summary>
	Critical,

	/// <summary>Channel is opportunistic (e.g. Gateway on a non-Gateway host). One clear warning, then silence.</summary>
	Optional,
}

/// <summary>What the worker should do next for a channel after a failure or restart attempt.</summary>
public enum ChannelDecision
{
	/// <summary>Restart immediately after disposing the old watcher (no bookmark change).</summary>
	RestartNow,

	/// <summary>Delete the persisted bookmark, then restart from no bookmark.</summary>
	ResetBookmarkAndRestart,

	/// <summary>Quiet cooldown — back off, do not log every error, attempt again after the cooldown elapses.</summary>
	Cooldown,

	/// <summary>Disable the channel for the lifetime of this process. Log once at warning/error.</summary>
	DisablePermanently,

	/// <summary>Channel was never armed (validation failed). Skip with one warning. Optional only.</summary>
	SkipUnavailable,
}

/// <summary>Snapshot of policy decision and the human-readable reason that produced it.</summary>
public readonly record struct ChannelHealthOutcome(ChannelDecision Decision, string Reason);

/// <summary>
/// Pure, thread-safe per-channel failure accounting and restart decision policy.
/// All time-dependent state is keyed on an injected <see cref="Func{TResult}"/> clock so the
/// policy is unit-testable without sleeping.
/// </summary>
public sealed class ChannelHealthPolicy
{
	/// <summary>How many consecutive invalid-handle failures before we permanently disable a channel.</summary>
	public const int MaxConsecutiveFailures = 5;

	/// <summary>Window inside which repeated failures count toward <see cref="MaxConsecutiveFailures"/>.</summary>
	public static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(5);

	/// <summary>Quiet cooldown applied after the first/second failure before the next restart attempt.</summary>
	public static readonly TimeSpan CooldownDuration = TimeSpan.FromMinutes(2);

	private readonly Func<DateTime> _clock;
	private readonly object _gate = new();
	private readonly Dictionary<string, ChannelState> _states = new(StringComparer.OrdinalIgnoreCase);
	private readonly HashSet<string> _optionalChannels;

	public ChannelHealthPolicy()
		: this(() => DateTime.UtcNow, DefaultOptionalChannels)
	{
	}

	public ChannelHealthPolicy(Func<DateTime> clock, IEnumerable<string> optionalChannels)
	{
		_clock = clock;
		_optionalChannels = new HashSet<string>(optionalChannels, StringComparer.OrdinalIgnoreCase);
	}

	/// <summary>Default list of channels considered optional on non-server / non-Gateway hosts.</summary>
	public static IEnumerable<string> DefaultOptionalChannels { get; } = new[]
	{
		"Microsoft-Windows-TerminalServices-Gateway/Operational",
		"Microsoft-Windows-TerminalServices-RDPClient/Operational",
	};

	public ChannelImportance ClassifyChannel(string channel)
		=> _optionalChannels.Contains(channel) ? ChannelImportance.Optional : ChannelImportance.Critical;

	/// <summary>Records a successful arm/restart and clears the failure counters for the channel.</summary>
	public void ReportSuccess(string channel)
	{
		lock (_gate)
		{
			if (_states.TryGetValue(channel, out ChannelState? state))
			{
				state.ConsecutiveFailures = 0;
				state.FirstFailureUtc = null;
				state.BookmarkResetTried = false;
				state.Disabled = false;
				state.NextAllowedRestartUtc = null;
			}
		}
	}

	/// <summary>
	/// Reports a failure (arm or restart). Returns the next action the worker should take.
	/// </summary>
	/// <param name="channel">Channel name (case-insensitive).</param>
	/// <param name="isInvalidHandleLike">
	/// True if the underlying exception is an EventLogException / invalid-handle-style fault that
	/// can be caused by a stale bookmark or by the channel being unavailable.
	/// </param>
	public ChannelHealthOutcome ReportFailure(string channel, bool isInvalidHandleLike)
	{
		lock (_gate)
		{
			DateTime now = _clock();
			if (!_states.TryGetValue(channel, out ChannelState? state))
			{
				state = new ChannelState();
				_states[channel] = state;
			}

			if (state.Disabled)
			{
				return new ChannelHealthOutcome(ChannelDecision.DisablePermanently, "Channel already disabled");
			}

			// Reset the rolling counter if the last failure is outside the window.
			if (state.FirstFailureUtc is DateTime first && now - first > FailureWindow)
			{
				state.ConsecutiveFailures = 0;
				state.FirstFailureUtc = null;
				state.BookmarkResetTried = false;
			}

			state.ConsecutiveFailures++;
			state.FirstFailureUtc ??= now;
			state.LastFailureUtc = now;

			ChannelImportance importance = ClassifyChannel(channel);

			// First invalid-handle failure on any channel: try resetting the persisted bookmark once.
			if (isInvalidHandleLike && !state.BookmarkResetTried)
			{
				state.BookmarkResetTried = true;
				state.NextAllowedRestartUtc = now; // restart immediately after reset
				return new ChannelHealthOutcome(
					ChannelDecision.ResetBookmarkAndRestart,
					"Invalid-handle-class fault on first observation — resetting stale bookmark and retrying");
			}

			if (state.ConsecutiveFailures >= MaxConsecutiveFailures)
			{
				state.Disabled = true;
				string reason = importance == ChannelImportance.Optional
					? "Optional channel disabled after repeated failures (likely unavailable on this host)"
					: "Critical channel disabled after repeated invalid-handle failures — manual investigation required";
				return new ChannelHealthOutcome(ChannelDecision.DisablePermanently, reason);
			}

			// Otherwise cool down quietly.
			state.NextAllowedRestartUtc = now + CooldownDuration;
			return new ChannelHealthOutcome(
				ChannelDecision.Cooldown,
				$"Cooling down channel for {CooldownDuration.TotalMinutes:F0}m before next restart attempt");
		}
	}

	/// <summary>
	/// Convenience: marks a channel as skipped at arm-time because validation said it does not
	/// exist or is disabled. Only valid for Optional channels.
	/// </summary>
	public ChannelHealthOutcome ReportUnavailable(string channel, string reason)
	{
		lock (_gate)
		{
			if (!_states.TryGetValue(channel, out ChannelState? state))
			{
				state = new ChannelState();
				_states[channel] = state;
			}

			state.Disabled = true;
			return new ChannelHealthOutcome(ChannelDecision.SkipUnavailable, reason);
		}
	}

	/// <summary>Whether the channel is currently in the disabled state.</summary>
	public bool IsDisabled(string channel)
	{
		lock (_gate)
		{
			return _states.TryGetValue(channel, out ChannelState? state) && state.Disabled;
		}
	}

	/// <summary>The earliest UTC time at which a restart attempt may be made, or null if no cooldown is active.</summary>
	public DateTime? NextAllowedRestartUtc(string channel)
	{
		lock (_gate)
		{
			return _states.TryGetValue(channel, out ChannelState? state) ? state.NextAllowedRestartUtc : null;
		}
	}

	/// <summary>Number of consecutive failures recorded for the channel (used by tests / diagnostics).</summary>
	public int ConsecutiveFailures(string channel)
	{
		lock (_gate)
		{
			return _states.TryGetValue(channel, out ChannelState? state) ? state.ConsecutiveFailures : 0;
		}
	}

	private sealed class ChannelState
	{
		public int ConsecutiveFailures;
		public DateTime? FirstFailureUtc;
		public DateTime? LastFailureUtc;
		public DateTime? NextAllowedRestartUtc;
		public bool BookmarkResetTried;
		public bool Disabled;
	}
}
