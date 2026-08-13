/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ServiceMetricsChannelStatusSink.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Bridge between EventCollectorHost's IChannelStatusSink contract and the concrete
//          ServiceMetrics instance held by the rest of the service. Keeps the Host decoupled
//          from ServiceMetrics — swap this for a null sink in tests, or for a different metrics
//          backend without touching Host code.
// Depends: IChannelStatusSink, ServiceMetrics
// Extends: When a second sink is required (e.g. Prometheus exporter), register both via a
//          composite sink implementation rather than expanding this class.

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Adapter that forwards <see cref="IChannelStatusSink"/> callbacks from
/// <see cref="EventCollectorHost"/> into the singleton <see cref="ServiceMetrics"/> instance.
/// </summary>
public sealed class ServiceMetricsChannelStatusSink : IChannelStatusSink
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ServiceMetrics _metrics;

	// ── Construction ─────────────────────────────────────────────────────────────

	public ServiceMetricsChannelStatusSink(ServiceMetrics metrics)
	{
		ArgumentNullException.ThrowIfNull(metrics);
		_metrics = metrics;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public void SetChannelStatus(string channel, string status) =>
		_metrics.SetChannelStatus(channel, status);

	/// <inheritdoc />
	public void IncrementDropped() => _metrics.IncrementDropped();
}
