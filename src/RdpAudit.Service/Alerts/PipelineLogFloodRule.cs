/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : PipelineLogFloodRule.cs
// Project: RdpAudit.Service (RdpAudit.Service.Alerts)
// Purpose: Detects sustained event-pipeline pressure from deltas in ring-buffer overflows and flood suppression.
// Depends: AlertRuleBase, AlertCooldownTracker, ServiceMetrics, RdpAuditOptions
// Extends: Include a new pipeline-pressure metric in CaptureSnapshot when its delta indicates loss of monitoring evidence.

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>
/// Raises a high-severity alert when the monitoring pipeline is losing or suppressing a material
/// number of events in a short interval.
/// </summary>
public sealed class PipelineLogFloodRule : AlertRuleBase
{
	private const string CooldownKey = "pipeline";

	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ServiceMetrics _metrics;
	private readonly AlertCooldownTracker _cooldown;
	private readonly object _snapshotGate = new();

	private long _previousOverflowCount;
	private long _previousSuppressedCount;
	private DateTime _previousSnapshotUtc = DateTime.UtcNow;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a rule backed by the service-wide pipeline metrics singleton.</summary>
	public PipelineLogFloodRule(ServiceMetrics metrics, AlertCooldownTracker cooldown)
	{
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(cooldown);

		_metrics = metrics;
		_cooldown = cooldown;
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

		PipelineSnapshot snapshot = CaptureSnapshot();
		long threshold = Math.Max(1L, ctx.Options.Alerts.PipelineFloodThreshold);
		int maximumWindowSeconds = Math.Max(1, ctx.Options.Alerts.PipelineFloodWindowSeconds);

		if (snapshot.Elapsed > TimeSpan.FromSeconds(maximumWindowSeconds)
			|| snapshot.TotalDelta < threshold)
		{
			return Task.FromResult<Alert?>(null);
		}

		TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
		if (!_cooldown.TryRegister(RuleId, CooldownKey, cooldown))
		{
			return Task.FromResult<Alert?>(null);
		}

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

	private PipelineSnapshot CaptureSnapshot()
	{
		lock (_snapshotGate)
		{
			DateTime nowUtc = DateTime.UtcNow;
			long currentOverflowCount = _metrics.RingBufferOverflowCount;
			long currentSuppressedCount = _metrics.FloodSuppressedCount;

			long overflowDelta = Math.Max(0L, currentOverflowCount - _previousOverflowCount);
			long suppressedDelta = Math.Max(0L, currentSuppressedCount - _previousSuppressedCount);
			TimeSpan elapsed = nowUtc - _previousSnapshotUtc;

			_previousOverflowCount = currentOverflowCount;
			_previousSuppressedCount = currentSuppressedCount;
			_previousSnapshotUtc = nowUtc;

			return new PipelineSnapshot(overflowDelta, suppressedDelta, elapsed);
		}
	}

	private readonly record struct PipelineSnapshot(
		long OverflowDelta,
		long SuppressedDelta,
		TimeSpan Elapsed)
	{
		public long TotalDelta => OverflowDelta + SuppressedDelta;
	}
}
