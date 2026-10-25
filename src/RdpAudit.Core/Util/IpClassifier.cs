// File:    src/RdpAudit.Core/Util/IpClassifier.cs
// Module:  RdpAudit.Core.Util
// Purpose: Classifies IP addresses as public / private / special-purpose.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>Classifies IP addresses as public, private, or special-purpose.</summary>
public static class IpClassifier
{
	private static readonly string[] LocalSentinels = { "::1", "127.0.0.1", "-", "0.0.0.0", "LOCAL", "localhost" };

	/// <summary>Returns true when the address parses, is not loopback / link-local / RFC1918 / CGN / reserved.</summary>
	public static bool IsPublicIp(string? ip)
	{
		if (string.IsNullOrWhiteSpace(ip))
		{
			return false;
		}

		if (!IPAddress.TryParse(ip, out IPAddress? addr))
		{
			return false;
		}

		if (IPAddress.IsLoopback(addr))
		{
			return false;
		}

		if (addr.AddressFamily == AddressFamily.InterNetworkV6)
		{
			return !addr.IsIPv6LinkLocal && !addr.IsIPv6SiteLocal && !addr.IsIPv6Multicast;
		}

		byte[] b = addr.GetAddressBytes();
		return !(b[0] == 10
			|| (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
			|| (b[0] == 192 && b[1] == 168)
			|| (b[0] == 169 && b[1] == 254)
			|| (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
			|| b[0] == 127
			|| b[0] == 0
			|| b[0] >= 224);
	}

	/// <summary>Returns true if the supplied value matches a local-host sentinel that should be filtered.</summary>
	public static bool IsLocalSentinel(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return true;
		}

		foreach (string s in LocalSentinels)
		{
			if (string.Equals(value, s, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}
}
