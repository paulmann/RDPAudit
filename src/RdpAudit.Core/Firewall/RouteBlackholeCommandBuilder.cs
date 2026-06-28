// File:    src/RdpAudit.Core/Firewall/RouteBlackholeCommandBuilder.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure builders + validators for the experimental route-blackhole enforcement backend.
//          Windows has no native Linux-style discard/blackhole route, so this backend installs a
//          per-IP host route ("route add <ip> mask 255.255.255.255 <unreachable-gateway>") that
//          points the attacker IP at an unreachable next-hop, dropping outbound replies. Every
//          helper validates the IP and gateway defensively and emits arguments that can ONLY be
//          passed through ProcessStartInfo.ArgumentList — no shell concatenation, ever.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Firewall;

/// <summary>Why a proposed blackhole gateway was accepted or rejected.</summary>
/// <remarks>Append-only enum: ordinals are surfaced in diagnostics; never reorder or reuse.</remarks>
public enum BlackholeGatewayValidation
{
	/// <summary>Gateway is a syntactically valid IPv4 address and is currently unreachable — usable.</summary>
	UsableUnreachable = 0,

	/// <summary>Gateway text is not a valid IPv4 address.</summary>
	InvalidAddress = 1,

	/// <summary>Gateway is reachable on the host; using it would forward (not drop) attacker traffic.</summary>
	ReachableUnsafe = 2,

	/// <summary>Gateway is loopback / multicast / unspecified and is unsuitable as a next-hop.</summary>
	UnsuitableNextHop = 3,
}

/// <summary>Pure builders + validators for the experimental route-blackhole backend.</summary>
public static class RouteBlackholeCommandBuilder
{
	/// <summary>Host-route mask: a single host route is always /32.</summary>
	public const string HostMask = "255.255.255.255";

	/// <summary>Validates a destination IP for a host route. Only IPv4 is supported by `route add`
	/// host routes in this backend; IPv6 callers receive an explanatory throw upstream.</summary>
	public static IPAddress ParseAndValidateDestination(string ip)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		if (!IPAddress.TryParse(ip, out IPAddress? parsed))
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Not a valid IP address: '{0}'.", ip),
				nameof(ip));
		}
		if (parsed.AddressFamily != AddressFamily.InterNetwork)
		{
			throw new ArgumentException(
				"Route-blackhole backend supports IPv4 destinations only.",
				nameof(ip));
		}
		return parsed;
	}

	/// <summary>Classifies a candidate blackhole gateway. <paramref name="isReachable"/> is supplied
	/// by the caller (a host probe) so this stays a pure, cross-platform-testable function: the
	/// backend MUST confirm the gateway is unreachable before relying on it, otherwise the host
	/// route would forward attacker traffic to a live next-hop instead of dropping it.</summary>
	public static BlackholeGatewayValidation ClassifyGateway(string? gateway, bool isReachable)
	{
		if (string.IsNullOrWhiteSpace(gateway) || !IPAddress.TryParse(gateway, out IPAddress? parsed))
		{
			return BlackholeGatewayValidation.InvalidAddress;
		}

		if (parsed.AddressFamily != AddressFamily.InterNetwork)
		{
			return BlackholeGatewayValidation.InvalidAddress;
		}

		if (IPAddress.IsLoopback(parsed)
			|| parsed.Equals(IPAddress.Any)
			|| parsed.Equals(IPAddress.Broadcast)
			|| parsed.GetAddressBytes()[0] >= 224)
		{
			return BlackholeGatewayValidation.UnsuitableNextHop;
		}

		return isReachable
			? BlackholeGatewayValidation.ReachableUnsafe
			: BlackholeGatewayValidation.UsableUnreachable;
	}

	/// <summary>Builds the argument vector for <c>route add &lt;dest&gt; mask 255.255.255.255 &lt;gw&gt;</c>.</summary>
	public static IReadOnlyList<string> BuildAddRouteArgs(string destinationIp, string gateway)
	{
		string dest = ParseAndValidateDestination(destinationIp).ToString();
		string gw = ValidateGatewaySyntax(gateway);
		return new List<string>
		{
			"add",
			dest,
			"mask",
			HostMask,
			gw,
		};
	}

	/// <summary>Builds the argument vector for <c>route delete &lt;dest&gt;</c>.</summary>
	public static IReadOnlyList<string> BuildDeleteRouteArgs(string destinationIp)
	{
		string dest = ParseAndValidateDestination(destinationIp).ToString();
		return new List<string> { "delete", dest };
	}

	/// <summary>Builds the argument vector for <c>route print &lt;dest&gt;</c> (verification probe).</summary>
	public static IReadOnlyList<string> BuildPrintRouteArgs(string destinationIp)
	{
		string dest = ParseAndValidateDestination(destinationIp).ToString();
		return new List<string> { "print", dest };
	}

	private static string ValidateGatewaySyntax(string gateway)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(gateway);
		if (!IPAddress.TryParse(gateway, out IPAddress? parsed)
			|| parsed.AddressFamily != AddressFamily.InterNetwork)
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Not a valid IPv4 gateway: '{0}'.", gateway),
				nameof(gateway));
		}
		return parsed.ToString();
	}
}
