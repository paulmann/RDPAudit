/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixLocalAddresses.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: Describes the addresses this machine can appear as on the wire, for the trapper item's
//          allowed-hosts list. Measured on 2026-10-25: a trapper item accepts values only from
//          "127.0.0.1,::1" until its allowed hosts are widened, so without this list a correctly
//          provisioned host still rejects every push and the failure looks like a client defect.
// Extends: System.Object

using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RdpAudit.Service.Zabbix;

/// <summary>Collects the unicast addresses of this machine as a comma-separated list.</summary>
public static class ZabbixLocalAddresses
{
	/// <summary>Returns a comma-separated list of the machine's unicast addresses, loopback excluded.
	/// An empty string means "nothing could be determined" — the caller must then leave the item's
	/// default alone and say so, rather than silently provisioning a host that cannot be written to.</summary>
	public static string Describe()
	{
		List<string> addresses = new();
		try
		{
			foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (nic.OperationalStatus != OperationalStatus.Up
					|| nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
				{
					continue;
				}

				foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
				{
					IPAddress address = unicast.Address;
					if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal)
					{
						continue;
					}

					string text = address.ToString();
					if (!addresses.Contains(text, StringComparer.OrdinalIgnoreCase))
					{
						addresses.Add(text);
					}
				}
			}
		}
		catch (NetworkInformationException)
		{
			return string.Empty;
		}
		catch (PlatformNotSupportedException)
		{
			return string.Empty;
		}

		return string.Join(',', addresses);
	}

	/// <summary>Merges two comma-separated host lists, keeping the order and dropping duplicates.</summary>
	/// <param name="existing">List already stored on the item; may be a user macro, which is kept.</param>
	/// <param name="required">List that must be accepted; empty means "nothing to add".</param>
	public static string Merge(string? existing, string? required)
	{
		List<string> parts = new();
		foreach (string candidate in (existing ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			if (!parts.Contains(candidate, StringComparer.OrdinalIgnoreCase))
			{
				parts.Add(candidate);
			}
		}

		foreach (string candidate in (required ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			if (!parts.Contains(candidate, StringComparer.OrdinalIgnoreCase))
			{
				parts.Add(candidate);
			}
		}

		return string.Join(',', parts);
	}

	/// <summary>True when every entry of <paramref name="required"/> already appears in
	/// <paramref name="existing"/>, ignoring order, case and surrounding spaces.</summary>
	/// <param name="existing">List stored on the item.</param>
	/// <param name="required">List that must be accepted.</param>
	public static bool Covers(string? existing, string? required)
	{
		HashSet<string> have = new(
			(existing ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
			StringComparer.OrdinalIgnoreCase);
		foreach (string candidate in (required ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			if (!have.Contains(candidate))
			{
				return false;
			}
		}

		return true;
	}

	/// <summary>Formats an address list for a log or a message, or a marker when it is empty.</summary>
	/// <param name="addresses">Comma-separated list.</param>
	public static string DescribeForMessage(string? addresses)
		=> string.IsNullOrWhiteSpace(addresses)
			? "(not determined)"
			: string.Format(CultureInfo.InvariantCulture, "{0}", addresses);
}
