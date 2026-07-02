/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : IThirdPartyFirewallProbe.cs
// Project: RdpAudit.Core (RdpAudit.Core.Firewall)
// Purpose: Platform-agnostic contract for collecting raw service/CLI facts that
//          FirewallProviderClassifier needs to determine whether a third-party
//          firewall (Kaspersky, ESET, Bitdefender, etc.) is present. Separates
//          the Win32 data-collection concern from the pure classification logic
//          so both Service and Configurator share a single classifier while each
//          supplies facts through its own probe implementation.
// Depends: FirewallServiceState, FirewallCliToolPresence
// Extends: Add new AV/EDR vendors by extending KasperskyServiceFragments /
//          ThirdPartyFirewallServiceFragments in FirewallProviderClassifier; the
//          probe interface itself never needs to change for new vendors.

namespace RdpAudit.Core.Firewall;

/// <summary>Raw snapshot of OS-level facts consumed by
/// <see cref="FirewallProviderClassifier.Classify"/>.</summary>
public sealed record ThirdPartyFirewallSnapshot(
	IReadOnlyList<FirewallServiceState> Services,
	IReadOnlyList<FirewallCliToolPresence> CliTools,
	bool KasperskyManagesWindowsFirewall);

/// <summary>Collects the raw Win32 / filesystem facts that
/// <see cref="FirewallProviderClassifier"/> needs.  Implemented once in Service
/// (via <c>ServiceController</c>) and once in Configurator (via the existing
/// <c>FirewallProviderDiagnosticsProbe</c>).  Must be called only on explicit
/// on-demand requests (GetFirewallDiagnostics / GetFirewallStatus) — never on
/// the hot-path background workers.</summary>
public interface IThirdPartyFirewallProbe
{
	/// <summary>Collects services and CLI-tool presence asynchronously.
	/// Implementations MUST be async-safe and honour
	/// <paramref name="ct"/>.</summary>
	Task<ThirdPartyFirewallSnapshot> CollectAsync(CancellationToken ct);
}
