// File:    src/RdpAudit.Configurator/Services/LocalActiveTcpEnrichmentProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side adapter that wires the dynamically-resolved RDP listener port
//          (RdpListenerPortResolver) to the live TCP table (ActiveRdpTcpProvider) and feeds
//          the pure ActiveRdpTcpEnricher so the Remote RDP Clients tab can fill Client IP on
//          an unambiguous Active RDP session when the DB-backed LocalSessionEnricher has no
//          correlation rows (the typical state on a freshly-installed host where
//          SessionCorrelationCache hydration entered 0 entries).
//
//          The provider runs AFTER the DB enrichment so it only fills missing Client IPs and
//          never overrides stronger DB / service-correlated evidence. It refuses to assign
//          an IP to a disconnected session — those require a DB correlation, not a live TCP
//          observation, because a disconnected session no longer has a live TCP endpoint.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of <see cref="LocalActiveTcpEnrichmentProvider.EnrichAsync"/>.</summary>
public sealed record LocalActiveTcpEnrichmentReport(
	int RdpListenerPort,
	RdpListenerPortSource PortSource,
	string PortDetail,
	ActiveRdpTcpEnrichmentResult? Result,
	string Status)
{
	/// <summary>True when at least one Active RDP session received a Client IP from the live TCP table.</summary>
	public bool AnyApplied => Result?.AnyApplied == true;
}

/// <summary>Read-only Configurator adapter that runs the live-TCP enricher for Active sessions.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalActiveTcpEnrichmentProvider
{
	private readonly ActiveRdpTcpProvider _tcpProvider;

	/// <summary>Production constructor — backed by the system TCP table.</summary>
	public LocalActiveTcpEnrichmentProvider()
		: this(new ActiveRdpTcpProvider(new SystemActiveTcpConnectionSource()))
	{
	}

	/// <summary>Test-friendly constructor.</summary>
	public LocalActiveTcpEnrichmentProvider(ActiveRdpTcpProvider tcpProvider)
	{
		_tcpProvider = tcpProvider ?? throw new ArgumentNullException(nameof(tcpProvider));
	}

	/// <summary>Resolves the RDP listener port from the registry, reads the live TCP table for
	/// established peers on that port, and assigns Client IP to a single Active RDP user
	/// session when both sides are unambiguous. Never throws — failures populate Status.</summary>
	public Task<LocalActiveTcpEnrichmentReport> EnrichAsync(
		IList<RdpSessionDto> sessions,
		CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(sessions);
		ct.ThrowIfCancellationRequested();

		RdpListenerPortResolution port = RdpListenerPortResolver.Resolve();

		IReadOnlyList<ActiveRdpTcpEndpoint> endpoints;
		try
		{
			endpoints = _tcpProvider.GetEstablishedEndpoints(port.Port);
		}
		catch (Exception ex)
		{
			return Task.FromResult(new LocalActiveTcpEnrichmentReport(
				RdpListenerPort: port.Port,
				PortSource: port.Source,
				PortDetail: port.Detail ?? string.Empty,
				Result: null,
				Status: "live TCP table read failed: " + ex.GetType().Name + " — " + ex.Message));
		}

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);
		string status = string.Format(System.Globalization.CultureInfo.InvariantCulture,
			"RDP port {0} ({1}); {2}",
			port.Port,
			port.Source == RdpListenerPortSource.Registry ? "registry" : "default",
			result.Detail);

		return Task.FromResult(new LocalActiveTcpEnrichmentReport(
			RdpListenerPort: port.Port,
			PortSource: port.Source,
			PortDetail: port.Detail ?? string.Empty,
			Result: result,
			Status: status));
	}
}
