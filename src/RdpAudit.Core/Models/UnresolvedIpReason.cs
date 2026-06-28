// File:    src/RdpAudit.Core/Models/UnresolvedIpReason.cs
// Module:  RdpAudit.Core.Models
// Purpose: Reason taxonomy for why a logon-relevant event carried no usable source IP. Lets the
//          Attack Statistics tab group the unresolved sentinel row by *why* it is unresolved rather
//          than presenting one opaque bucket. Pure / DB-agnostic so it can be unit tested and shared
//          by the normalizer, the aggregator, and the Configurator UI without an EF Core context.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;

namespace RdpAudit.Core.Models;

/// <summary>
/// Why a logon-relevant event ended up without a usable source IP. The ordinals are append-only and
/// MUST NOT be reordered or reused — they may be persisted by future stages.
/// </summary>
public enum UnresolvedIpReason
{
	/// <summary>The IP is resolved and valid; the event is NOT unresolved. Default sentinel value.</summary>
	None = 0,

	/// <summary>The event semantically carried a source-IP slot (e.g. Security 4625) but the payload
	/// value was missing, blank, or "-".</summary>
	NoIpInSecurityEvent = 1,

	/// <summary>A source IP was expected but in-memory session correlation could not supply one.</summary>
	CorrelationFailed = 2,

	/// <summary>A non-empty value was present but failed IP-address parsing.</summary>
	InvalidIp = 3,

	/// <summary>The resolved address was a private, loopback, or otherwise non-routable address that the
	/// policy intentionally ignores for attacker attribution.</summary>
	IgnoredPrivateLoopback = 4,

	/// <summary>The event payload could not be parsed at all (malformed / truncated XML).</summary>
	ParserError = 5,
}

/// <summary>
/// Pure classifier mapping the signals available at normalization time to an
/// <see cref="UnresolvedIpReason"/>. Kept free of EF Core / Win32 types so it is unit-testable and can
/// be reused by the Service normalizer and the Configurator UI alike.
/// </summary>
public static class UnresolvedIpClassifier
{
	/// <summary>
	/// Classifies why an event has no usable source IP.
	/// </summary>
	/// <param name="rawIpValue">The raw source-IP text extracted from the payload (may be null / blank / "-").</param>
	/// <param name="payloadParsed">False when the event XML could not be parsed at all.</param>
	/// <param name="expectedIpSlot">True when the event kind semantically carries a source-IP field
	/// (e.g. Security 4625) so a missing value is meaningful rather than simply absent.</param>
	/// <param name="correlationAttempted">True when in-memory session correlation was attempted to
	/// recover a missing IP.</param>
	/// <returns>The most specific applicable reason; <see cref="UnresolvedIpReason.None"/> when the
	/// value parses to a routable public address.</returns>
	public static UnresolvedIpReason Classify(
		string? rawIpValue,
		bool payloadParsed,
		bool expectedIpSlot,
		bool correlationAttempted)
	{
		if (!payloadParsed)
		{
			return UnresolvedIpReason.ParserError;
		}

		string? trimmed = rawIpValue?.Trim();
		bool blank = string.IsNullOrEmpty(trimmed) || string.Equals(trimmed, "-", StringComparison.Ordinal);

		if (blank)
		{
			if (correlationAttempted)
			{
				return UnresolvedIpReason.CorrelationFailed;
			}

			return expectedIpSlot ? UnresolvedIpReason.NoIpInSecurityEvent : UnresolvedIpReason.CorrelationFailed;
		}

		if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
		{
			return UnresolvedIpReason.InvalidIp;
		}

		if (IsPrivateOrLoopback(parsed))
		{
			return UnresolvedIpReason.IgnoredPrivateLoopback;
		}

		return UnresolvedIpReason.None;
	}

	/// <summary>Operator-facing label for an <see cref="UnresolvedIpReason"/>.</summary>
	public static string Describe(UnresolvedIpReason reason) => reason switch
	{
		UnresolvedIpReason.None => "Resolved",
		UnresolvedIpReason.NoIpInSecurityEvent => "No IP in security event",
		UnresolvedIpReason.CorrelationFailed => "Session correlation failed",
		UnresolvedIpReason.InvalidIp => "Invalid IP value",
		UnresolvedIpReason.IgnoredPrivateLoopback => "Private / loopback (ignored)",
		UnresolvedIpReason.ParserError => "Event payload parse error",
		_ => "Unknown",
	};

	private static bool IsPrivateOrLoopback(IPAddress address)
	{
		if (IPAddress.IsLoopback(address))
		{
			return true;
		}

		if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
		{
			byte[] b = address.GetAddressBytes();
			// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (link-local), 0.0.0.0/8.
			if (b[0] == 10)
			{
				return true;
			}
			if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
			{
				return true;
			}
			if (b[0] == 192 && b[1] == 168)
			{
				return true;
			}
			if (b[0] == 169 && b[1] == 254)
			{
				return true;
			}
			if (b[0] == 0)
			{
				return true;
			}
			return false;
		}

		if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
		{
			return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal;
		}

		return false;
	}
}
