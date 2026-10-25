// File:    src/RdpAudit.Core/Util/IpReputationUrlBuilder.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure URL composition helpers for the third-party IP-reputation deep links exposed by the
//          Configurator context menus (Stage 3). Each builder validates the supplied IP literal
//          strictly via System.Net.IPAddress, rejects local / sentinel placeholders that operators
//          must never resolve against an external service, strips IPv6 zone identifiers and
//          normalises IPv4-mapped IPv6 to IPv4 so the resulting URL targets the canonical address.
//          Tested in RdpAudit.Core.Tests so the UI seams stay thin and deterministic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>Pure URL composition for third-party IP-reputation deep links (RIPEstat, AbuseIPDB).</summary>
/// <remarks>
/// The same validation pipeline gates every supported destination so the Configurator cannot leak
/// hostnames, blanks, "(unresolved)" sentinels or the 0.0.0.0 placeholder to an external service.
/// IPv6 zone identifiers (the "%scope" suffix) are stripped before parsing because no upstream API
/// accepts them, and IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) collapse to their IPv4 form so the
/// resulting page lines up with what the operator sees in the grid.
/// </remarks>
public static class IpReputationUrlBuilder
{
	private const string RipeStatTemplate = "https://stat.ripe.net/resource/{0}#tab=overview";
	private const string AbuseIpDbTemplate = "https://www.abuseipdb.com/check/{0}";

	private static readonly string[] RejectedSentinels =
	{
		"-",
		"--",
		"n/a",
		"na",
		"null",
		"none",
		"unknown",
		"(unresolved)",
		"unresolved",
		"localhost",
		"local",
	};

	/// <summary>Outcome of a URL composition attempt.</summary>
	public sealed class Result
	{
		/// <summary>True when the supplied IP passed validation and a URL is available.</summary>
		public bool Ok { get; init; }

		/// <summary>Canonical URL when <see cref="Ok"/> is true; empty string otherwise.</summary>
		public string Url { get; init; } = string.Empty;

		/// <summary>Operator-facing reason when <see cref="Ok"/> is false; null otherwise.</summary>
		public string? Error { get; init; }

		internal static Result Success(string url) => new() { Ok = true, Url = url };

		internal static Result Fail(string message) => new() { Ok = false, Error = message };
	}

	/// <summary>Builds the RIPEstat overview deep link for the supplied IP.</summary>
	public static Result BuildRipeStat(string? ip) => Build(ip, RipeStatTemplate);

	/// <summary>Builds the AbuseIPDB check deep link for the supplied IP.</summary>
	public static Result BuildAbuseIpDb(string? ip) => Build(ip, AbuseIpDbTemplate);

	/// <summary>Returns true when <paramref name="ip"/> would pass the lookup validation pipeline.</summary>
	public static bool IsLookupEligible(string? ip) => TryNormalize(ip, out _, out _);

	private static Result Build(string? ip, string template)
	{
		if (!TryNormalize(ip, out string normalized, out string? error))
		{
			return Result.Fail(error ?? "Invalid IP address.");
		}

		string url = string.Format(CultureInfo.InvariantCulture, template, normalized);
		return Result.Success(url);
	}

	/// <summary>Normalises and validates an operator-supplied IP string for external lookups.</summary>
	internal static bool TryNormalize(string? raw, out string normalized, out string? error)
	{
		normalized = string.Empty;
		error = null;

		if (string.IsNullOrWhiteSpace(raw))
		{
			error = "IP is empty.";
			return false;
		}

		string candidate = raw.Trim();

		// Strip surrounding IPv6 brackets so "[fd00::1]" parses cleanly.
		if (candidate.Length >= 2 && candidate[0] == '[' && candidate[^1] == ']')
		{
			candidate = candidate[1..^1];
		}

		// IPv6 scope id ("%eth0" / "%12") is meaningful only on the local host; strip before parse.
		int percent = candidate.IndexOf('%', StringComparison.Ordinal);
		if (percent >= 0)
		{
			candidate = candidate[..percent];
		}

		if (candidate.Length == 0)
		{
			error = "IP is empty.";
			return false;
		}

		foreach (string sentinel in RejectedSentinels)
		{
			if (string.Equals(candidate, sentinel, StringComparison.OrdinalIgnoreCase))
			{
				error = "IP is a sentinel placeholder, not a real address.";
				return false;
			}
		}

		if (!IPAddress.TryParse(candidate, out IPAddress? addr))
		{
			error = "Value is not a valid IPv4 / IPv6 address.";
			return false;
		}

		// Collapse IPv4-mapped IPv6 (::ffff:1.2.3.4) so the deep link matches what the operator sees.
		if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv4MappedToIPv6)
		{
			addr = addr.MapToIPv4();
		}

		// Reject the unspecified addresses (0.0.0.0 / ::) — these are sentinels for "unresolved".
		if (IsUnspecified(addr))
		{
			error = "IP is the unspecified-address sentinel (0.0.0.0 / ::).";
			return false;
		}

		normalized = addr.ToString();
		return true;
	}

	private static bool IsUnspecified(IPAddress address)
	{
		if (address.AddressFamily == AddressFamily.InterNetwork)
		{
			byte[] b = address.GetAddressBytes();
			return b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0;
		}

		if (address.AddressFamily == AddressFamily.InterNetworkV6)
		{
			return address.Equals(IPAddress.IPv6Any);
		}

		return false;
	}
}
