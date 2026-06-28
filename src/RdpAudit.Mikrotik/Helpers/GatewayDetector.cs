/*
 * File   : GatewayDetector.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Helpers)
 * Purpose: Discovers candidate RouterOS management IPs from the local machine — the default IPv4
 *          gateways of every operational, non-loopback interface — so the wizard can pre-fill the
 *          router IP instead of forcing the operator to type it. Pure, read-only, deterministic.
 * Depends: System.Net.NetworkInformation
 * Extends: To add another discovery source (e.g. DHCP option 121 routes, a manual override list,
 *          or ARP neighbours), add a private collector and merge its results in DetectGatewayIps.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RdpAudit.Mikrotik.Helpers;

/// <summary>Discovers candidate RouterOS management IPs from local network configuration.</summary>
public sealed class GatewayDetector
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Returns the distinct, ordered list of IPv4 default-gateway addresses across every operational,
	/// non-loopback, non-tunnel interface. The most likely management gateway (lowest metric is not
	/// exposed by the API, so insertion order follows interface enumeration) appears first. Never throws;
	/// returns an empty list when nothing is discoverable.
	/// </summary>
	public IReadOnlyList<string> DetectGatewayIps()
	{
		List<string> gateways = new();
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

		NetworkInterface[] interfaces;
		try
		{
			interfaces = NetworkInterface.GetAllNetworkInterfaces();
		}
		catch (NetworkInformationException)
		{
			return gateways;
		}

		foreach (NetworkInterface nic in interfaces)
		{
			if (nic.OperationalStatus != OperationalStatus.Up)
			{
				continue;
			}
			if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
			{
				continue;
			}

			IPInterfaceProperties properties;
			try
			{
				properties = nic.GetIPProperties();
			}
			catch (NetworkInformationException)
			{
				continue;
			}

			foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
			{
				if (gateway.Address.AddressFamily != AddressFamily.InterNetwork)
				{
					continue;
				}

				string text = gateway.Address.ToString();
				if (IPAddress.IsLoopback(gateway.Address) || text == "0.0.0.0")
				{
					continue;
				}

				if (seen.Add(text))
				{
					gateways.Add(text);
				}
			}
		}

		return gateways;
	}

	/// <summary>Returns the single best-guess gateway IP, or null when none is discoverable.</summary>
	public string? DetectPrimaryGatewayIp()
	{
		IReadOnlyList<string> all = DetectGatewayIps();
		return all.Count > 0 ? all[0] : null;
	}
}
