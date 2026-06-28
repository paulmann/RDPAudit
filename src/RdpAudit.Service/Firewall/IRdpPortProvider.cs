// File:    src/RdpAudit.Service/Firewall/IRdpPortProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Abstraction over the resolved RDP listener TCP port so the Windows firewall provider
//          can build RDP-port-only block rules without hardcoding 3389 and without taking a direct
//          registry dependency that would be impossible to unit test cross-platform. The default
//          implementation delegates to RdpListenerPortResolver (registry -> documented default);
//          tests substitute a fixed-port stub.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Resolves the configured RDP listener TCP port for firewall rule construction.</summary>
public interface IRdpPortProvider
{
	/// <summary>Returns the resolved RDP listener port (registry value, or documented default).</summary>
	int GetRdpPort();
}

/// <summary>Default <see cref="IRdpPortProvider"/> backed by the host registry via
/// <see cref="RdpListenerPortResolver"/>. Never hardcodes 3389: the fallback is the documented
/// Microsoft default resolved inside <see cref="RdpListenerPortResolver"/>.</summary>
public sealed class RegistryRdpPortProvider : IRdpPortProvider
{
	/// <inheritdoc/>
	[SupportedOSPlatform("windows")]
	public int GetRdpPort() => RdpListenerPortResolver.Resolve().Port;
}
