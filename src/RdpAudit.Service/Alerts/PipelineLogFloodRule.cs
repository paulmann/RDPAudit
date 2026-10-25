/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : PipelineLogFloodRule.cs
// Project: RdpAudit.Service (RdpAudit.Service.Alerts)
// Purpose: Detects sustained event-pipeline pressure from deltas in ring-buffer overflows and flood
//          suppression over a real observation window (not the gap between two adjacent events).
// Depends: AlertRuleBase, AlertCooldownTracker, ServiceMetrics, RdpAuditOptions, TimeProvider
// Extends: Include a new pipeline-pressure metric in CaptureSnapshot when its delta indicates loss of monitoring evidence.

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>
/// Raises a high-severity alert when the monitoring pipeline is losing or suppressing a material
/// number of events inside <see cref="AlertOptions.PipelineFloodWindowSeconds"/>.
/// </summary>
/// <remarks>
/// The rule is evaluated once per processed event, but it accumulates the metric deltas against a
/// baseline that is advanced only when the window expires or after it fires. The previous
/// implementation advanced the baseline on every evaluation, so it measured the gap between two
/// adjacent events and a sustained flood was diluted below the threshold and never detected.
/// The window is deliberately tumbling rather than sliding: without intermediate samples a
/// sliding window cannot be reconstructed, and a tumbling window makes a sustained flood cross the
/// threshold within one window while an idle gap resets the measurement.
/// </remarks>
public sealed class PipelineLogFloodRule : AlertRuleBase
{
	private const string CooldownKey = "pipeline";

	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ServiceMetrics _metrics;
	private readonly AlertCooldownTracker _cooldown;
	private readonly TimeProvider _time;
	private readonly object _windowGate = new();

	private long _baselineOverflow;
	private long _baselineSuppressed;
	private DateTime _windowStartUtc;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a rule backed by the service-wide pipeline metrics singleton.</summary>
	/// <param name="metrics">Pipeline counters.</param>
	/// <param name="cooldown">Per-rule cooldown tracker.</param>
	/// <param name="timeProvider">Clock; defaults to <see cref="TimeProvider.System"/>. Injected so the
	/// window-expiry behaviour is testable without sleeping.</param>
	public PipelineLogFloodRule(ServiceMetrics metrics, AlertCooldownTracker cooldown, TimeProvider? timeProvider = null)
	{
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(cooldown);

		_metrics = metrics;
		_cooldown = cooldown;
		_time = timeProvider ?? TimeProvider.System;
		_windowStartUtc = _time.GetUtcNow().UtcDateTime;
		_baselineOverflow = _metrics.RingBufferOverflowCount;
		_baselineSuppressed = _metrics.FloodSuppressedCount;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public override string RuleId => "PIPELINE_LOG_FLOOD";

	/// <inheritdoc />
	public override string Name => "Monitoring Pipeline Log Flood";

	/// <inheritdoc />
	public override AlertSeverity Severity => AlertSeverity.High;

	/// <inheritdoc />
	public override bool IsEnabled(RdpAuditOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);
		return options.Alerts.EnablePipelineFloodDetection;
	}

	/// <inheritdoc />
	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(evt);
		ArgumentNullException.ThrowIfNull(ctx);
		ct.ThrowIfCancellationRequested();

		if (!ctx.Options.Alerts.EnablePipelineFloodDetection)
		{
			return Task.FromResult<Alert?>(null);
		}

		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		int maximumWindowSeconds = Math.Max(1, ctx.Options.Alerts.PipelineFloodWindowSeconds);
		TimeSpan window = TimeSpan.FromSeconds(maximumWindowSeconds);
		PipelineSnapshot snapshot = CaptureSnapshot(nowUtc, window);

		if (snapshot.WindowReset)
		{
			// The previous window expired without reaching the threshold: start a fresh measurement.
			return Task.FromResult<Alert?>(null);
		}

		long threshold = Math.Max(1L, ctx.Options.Alerts.PipelineFloodThreshold);
		if (snapshot.TotalDelta < threshold)
		{
			return Task.FromResult<Alert?>(null);
		}

		TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
		if (!_cooldown.TryRegister(RuleId, CooldownKey, cooldown))
		{
			return Task.FromResult<Alert?>(null);
		}

		// Do not let the same accumulated delta re-fire once the cooldown lapses.
		ResetWindow(nowUtc);

		return Task.FromResult<Alert?>(CreateAlert(
			evt,
			$"Possible log flood against the monitoring pipeline: {snapshot.TotalDelta} events were overflowed or suppressed in {snapshot.Elapsed.TotalSeconds:0.##} seconds.",
			new
			{
				RingBufferOverflowDelta = snapshot.OverflowDelta,
				FloodSuppressedDelta = snapshot.SuppressedDelta,
				TotalDelta = snapshot.TotalDelta,
				WindowSeconds = snapshot.Elapsed.TotalSeconds,
			}));
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private PipelineSnapshot CaptureSnapshot(DateTime nowUtc, TimeSpan window)
	{
		lock (_windowGate)
		{
			long currentOverflowCount = _metrics.RingBufferOverflowCount;
			long currentSuppressedCount = _metrics.FloodSuppressedCount;
			TimeSpan elapsed = nowUtc - _windowStartUtc;

			if (elapsed > window)
			{
				_baselineOverflow = currentOverflowCount;
				_baselineSuppressed = currentSuppressedCount;
				_windowStartUtc = nowUtc;
				return new PipelineSnapshot(0, 0, TimeSpan.Zero, WindowReset: true);
			}

			long overflowDelta = Math.Max(0L, currentOverflowCount - _baselineOverflow);
			long suppressedDelta = Math.Max(0L, currentSuppressedCount - _baselineSuppressed);
			return new PipelineSnapshot(overflowDelta, suppressedDelta, elapsed, WindowReset: false);
		}
	}

	private void ResetWindow(DateTime nowUtc)
	{
		lock (_windowGate)
		{
			_baselineOverflow = _metrics.RingBufferOverflowCount;
			_baselineSuppressed = _metrics.FloodSuppressedCount;
			_windowStartUtc = nowUtc;
		}
	}

	private readonly record struct PipelineSnapshot(
		long OverflowDelta,
		long SuppressedDelta,
		TimeSpan Elapsed,
		bool WindowReset)
	{
		public long TotalDelta => OverflowDelta + SuppressedDelta;
	}
}
