// File:    src/RdpAudit.Core/Util/IpReportability.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for deciding whether a source IP may be reported to AbuseIPDB,
//          counted as a real attacker in Attack Statistics, surfaced in live RDP diagnostics, or
//          considered eligible for auto-block. Returns a classification + machine-readable reason
//          rather than a bare bool so every caller can log *why* an address was skipped. Pure and
//          DB-agnostic so it is unit-testable and shared by Core / Service / Configurator alike.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>Coarse classification of an IP address for reporting / blocking decisions.</summary>
/// <remarks>
/// Ordinals are append-only and persisted (AbuseIPDB report log <c>Classification</c> column);
/// MUST NOT be reordered or reused.
/// </remarks>
public enum IpReportClassification
{
	/// <summary>Globally routable public address — eligible to report when not whitelisted.</summary>
	Public = 0,

	/// <summary>RFC1918 private address (10/8, 172.16/12, 192.168/16).</summary>
	Private = 1,

	/// <summary>Loopback (127.0.0.0/8, ::1/128).</summary>
	Loopback = 2,

	/// <summary>Link-local / APIPA (169.254.0.0/16, fe80::/10).</summary>
	LinkLocal = 3,

	/// <summary>Carrier-grade NAT (100.64.0.0/10).</summary>
	Cgnat = 4,

	/// <summary>Protocol / reserved range (0/8, 192.0.0.0/24, 240/4, 255.255.255.255/32, fc00::/7).</summary>
	SpecialPurpose = 5,

	/// <summary>Documentation / test range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).</summary>
	Documentation = 6,

	/// <summary>Multicast (224.0.0.0/4, ff00::/8).</summary>
	Multicast = 7,

	/// <summary>Non-empty value that failed IP parsing, or a hostname-like token.</summary>
	Invalid = 8,

	/// <summary>Empty / null / "unresolved" / "unknown" / "-" sentinel.</summary>
	Unresolved = 9,

	/// <summary>Matched the configured whitelist / allowlist. Whitelist always wins.</summary>
	Whitelisted = 10,
}

/// <summary>Result of classifying an address for reportability.</summary>
/// <param name="Classification">Coarse bucket the address fell into.</param>
/// <param name="IsReportable">True only when the address may be reported to AbuseIPDB.</param>
/// <param name="Reason">Machine-readable reason token (mirrors AbuseIPDB report-log Reason values).</param>
public readonly record struct IpReportabilityResult(
	IpReportClassification Classification,
	bool IsReportable,
	string Reason)
{
	/// <summary>True when the underlying address is a globally routable public IP (ignores whitelist).</summary>
	public bool IsPublic => Classification == IpReportClassification.Public
		|| Classification == IpReportClassification.Whitelisted && IsPublicUnderlying;

	/// <summary>Set when a whitelisted address was nonetheless a public address underneath.</summary>
	internal bool IsPublicUnderlying { get; init; }
}

/// <summary>
/// Centralized reportability / classification helper. Use <see cref="Classify(string?,Func{string,bool}?)"/>
/// everywhere a decision is made about whether an address is a real, reportable attacker source.
/// </summary>
public static class IpReportability
{
	private static readonly string[] UnresolvedSentinels =
	{
		"-", "unresolved", "unknown", "(unresolved)", "(unknown)", "null", "n/a", "na", "none", "local", "localhost",
	};

	/// <summary>Reason tokens emitted by <see cref="Classify(string?,Func{string,bool}?)"/>.</summary>
	public static class Reasons
	{
		public const string Reportable = "Reportable";
		public const string WhitelistedIp = "WhitelistedIp";
		public const string PrivateIp = "PrivateIp";
		public const string LoopbackIp = "LoopbackIp";
		public const string LinkLocalIp = "LinkLocalIp";
		public const string CgnatIp = "CgnatIp";
		public const string ReservedIp = "ReservedIp";
		public const string DocumentationIp = "DocumentationIp";
		public const string MulticastIp = "MulticastIp";
		public const string InvalidIp = "InvalidIp";
		public const string UnresolvedIp = "UnresolvedIp";
	}

	/// <summary>
	/// Classifies <paramref name="rawIp"/> and decides whether it may be reported to AbuseIPDB.
	/// </summary>
	/// <param name="rawIp">Raw or normalized IP text (may be null / blank / sentinel / hostname).</param>
	/// <param name="isWhitelisted">
	/// Optional predicate that returns true when the canonical address is whitelisted. The canonical
	/// (normalized) form is supplied to the predicate. When null, no whitelist check is performed.
	/// </param>
	public static IpReportabilityResult Classify(string? rawIp, Func<string, bool>? isWhitelisted = null)
	{
		string? trimmed = rawIp?.Trim();
		if (string.IsNullOrEmpty(trimmed) || IsUnresolvedSentinel(trimmed))
		{
			return new IpReportabilityResult(IpReportClassification.Unresolved, false, Reasons.UnresolvedIp);
		}

		// Use the same canonicalization the ingestion pipeline uses. A value that fails to normalize
		// is either truly invalid or a local sentinel; distinguish the two so the operator sees why.
		string candidate = IpNormalizer.Sanitize(trimmed);
		if (!IPAddress.TryParse(candidate, out IPAddress? addr))
		{
			// Distinguish a deliberate local sentinel ("::1" / "127.0.0.1") from a hostname-like token.
			if (IPAddress.TryParse(trimmed, out IPAddress? rawAddr))
			{
				addr = rawAddr;
			}
			else
			{
				return new IpReportabilityResult(IpReportClassification.Invalid, false, Reasons.InvalidIp);
			}
		}

		if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv4MappedToIPv6)
		{
			addr = addr.MapToIPv4();
		}

		IpReportClassification classification = ClassifyAddress(addr);
		string canonical = addr.ToString();

		if (classification == IpReportClassification.Public)
		{
			if (isWhitelisted is not null && isWhitelisted(canonical))
			{
				return new IpReportabilityResult(IpReportClassification.Whitelisted, false, Reasons.WhitelistedIp)
				{
					IsPublicUnderlying = true,
				};
			}

			return new IpReportabilityResult(IpReportClassification.Public, true, Reasons.Reportable);
		}

		return new IpReportabilityResult(classification, false, ReasonFor(classification));
	}

	/// <summary>True when the address is a globally routable public IP (ignores whitelist).</summary>
	public static bool IsPublic(string? rawIp) =>
		Classify(rawIp).Classification == IpReportClassification.Public;

	/// <summary>Operator-facing label for a classification.</summary>
	public static string Describe(IpReportClassification c) => c switch
	{
		IpReportClassification.Public => "Public",
		IpReportClassification.Private => "Private",
		IpReportClassification.Loopback => "Loopback",
		IpReportClassification.LinkLocal => "LinkLocal",
		IpReportClassification.Cgnat => "Cgnat",
		IpReportClassification.SpecialPurpose => "Reserved",
		IpReportClassification.Documentation => "Documentation",
		IpReportClassification.Multicast => "Multicast",
		IpReportClassification.Invalid => "Invalid",
		IpReportClassification.Unresolved => "Unresolved",
		IpReportClassification.Whitelisted => "Whitelisted",
		_ => "Unknown",
	};

	private static string ReasonFor(IpReportClassification c) => c switch
	{
		IpReportClassification.Private => Reasons.PrivateIp,
		IpReportClassification.Loopback => Reasons.LoopbackIp,
		IpReportClassification.LinkLocal => Reasons.LinkLocalIp,
		IpReportClassification.Cgnat => Reasons.CgnatIp,
		IpReportClassification.SpecialPurpose => Reasons.ReservedIp,
		IpReportClassification.Documentation => Reasons.DocumentationIp,
		IpReportClassification.Multicast => Reasons.MulticastIp,
		IpReportClassification.Invalid => Reasons.InvalidIp,
		IpReportClassification.Unresolved => Reasons.UnresolvedIp,
		_ => Reasons.Reportable,
	};

	private static bool IsUnresolvedSentinel(string value)
	{
		foreach (string s in UnresolvedSentinels)
		{
			if (string.Equals(value, s, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	private static IpReportClassification ClassifyAddress(IPAddress addr)
	{
		if (IPAddress.IsLoopback(addr))
		{
			return IpReportClassification.Loopback;
		}

		if (addr.AddressFamily == AddressFamily.InterNetwork)
		{
			return ClassifyV4(addr.GetAddressBytes());
		}

		if (addr.AddressFamily == AddressFamily.InterNetworkV6)
		{
			return ClassifyV6(addr);
		}

		return IpReportClassification.SpecialPurpose;
	}

	private static IpReportClassification ClassifyV4(byte[] b)
	{
		// 0.0.0.0/8 — "this network" / reserved.
		if (b[0] == 0)
		{
			return IpReportClassification.SpecialPurpose;
		}

		// 127.0.0.0/8 loopback handled by IPAddress.IsLoopback before reaching here, but keep the
		// branch defensive for the rare non-127.0.0.1 loopback literal.
		if (b[0] == 127)
		{
			return IpReportClassification.Loopback;
		}

		// RFC1918 private.
		if (b[0] == 10
			|| (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
			|| (b[0] == 192 && b[1] == 168))
		{
			return IpReportClassification.Private;
		}

		// 169.254.0.0/16 link-local / APIPA.
		if (b[0] == 169 && b[1] == 254)
		{
			return IpReportClassification.LinkLocal;
		}

		// 100.64.0.0/10 CGNAT.
		if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
		{
			return IpReportClassification.Cgnat;
		}

		// Documentation / test ranges.
		if (b[0] == 192 && b[1] == 0 && b[2] == 2)
		{
			return IpReportClassification.Documentation; // 192.0.2.0/24 TEST-NET-1
		}
		if (b[0] == 198 && b[1] == 51 && b[2] == 100)
		{
			return IpReportClassification.Documentation; // 198.51.100.0/24 TEST-NET-2
		}
		if (b[0] == 203 && b[1] == 0 && b[2] == 113)
		{
			return IpReportClassification.Documentation; // 203.0.113.0/24 TEST-NET-3
		}

		// 192.0.0.0/24 IETF protocol assignments.
		if (b[0] == 192 && b[1] == 0 && b[2] == 0)
		{
			return IpReportClassification.SpecialPurpose;
		}

		// 255.255.255.255 limited broadcast.
		if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255)
		{
			return IpReportClassification.SpecialPurpose;
		}

		// 224.0.0.0/4 multicast.
		if (b[0] >= 224 && b[0] <= 239)
		{
			return IpReportClassification.Multicast;
		}

		// 240.0.0.0/4 reserved (incl. 255/8 except the broadcast handled above).
		if (b[0] >= 240)
		{
			return IpReportClassification.SpecialPurpose;
		}

		return IpReportClassification.Public;
	}

	private static IpReportClassification ClassifyV6(IPAddress addr)
	{
		if (addr.IsIPv6Multicast)
		{
			return IpReportClassification.Multicast; // ff00::/8
		}

		if (addr.IsIPv6LinkLocal)
		{
			return IpReportClassification.LinkLocal; // fe80::/10
		}

		byte[] b = addr.GetAddressBytes();

		// fc00::/7 unique local.
		if ((b[0] & 0xFE) == 0xFC)
		{
			return IpReportClassification.SpecialPurpose;
		}

		if (addr.IsIPv6SiteLocal)
		{
			return IpReportClassification.SpecialPurpose; // fec0::/10 (deprecated site-local)
		}

		// 2001:db8::/32 documentation.
		if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8)
		{
			return IpReportClassification.Documentation;
		}

		return IpReportClassification.Public;
	}
}
