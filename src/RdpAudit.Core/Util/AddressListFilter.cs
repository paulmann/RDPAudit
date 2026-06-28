// File:    src/RdpAudit.Core/Util/AddressListFilter.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI-agnostic predicate used by the Configurator Firewall tab to filter
//          blocklist / whitelist / active-block / login-rule grids by a free-text search.
//          Lifted into Core so the matching rules can be unit tested without a UI host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.0

using System.Globalization;
using System.Net;

namespace RdpAudit.Core.Util;

/// <summary>Pure, UI-agnostic predicate for the Firewall-tab grids.</summary>
/// <remarks>
/// Matching is case-insensitive substring across the supplied fields. Empty / whitespace
/// queries match every row, so the search box starts in a permissive state.
/// </remarks>
public sealed class AddressListFilter
{
	/// <summary>Free-text query; null / empty means "match everything".</summary>
	public string? Query { get; init; }

	/// <summary>Returns true when none of the constituent fields restrict the result set.</summary>
	public bool IsEmpty => string.IsNullOrWhiteSpace(Query);

	/// <summary>Tests whether at least one supplied field contains the query substring.</summary>
	public bool Matches(params string?[] fields)
	{
		ArgumentNullException.ThrowIfNull(fields);
		if (IsEmpty)
		{
			return true;
		}

		string needle = Query!.Trim();
		foreach (string? field in fields)
		{
			if (!string.IsNullOrEmpty(field)
				&& field.Contains(needle, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>Returns true when <paramref name="value"/> parses as an IPv4 / IPv6 literal.</summary>
	public static bool IsValidIp(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		return IPAddress.TryParse(value.Trim(), out _);
	}

	/// <summary>Normalises an IP literal to its canonical textual form, throwing on failure.</summary>
	public static string NormalizeIp(string value)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(value);
		string trimmed = value.Trim();
		if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
		{
			throw new FormatException(string.Format(CultureInfo.InvariantCulture,
				"Value '{0}' is not a valid IPv4 / IPv6 address.", trimmed));
		}
		return parsed.ToString();
	}

	/// <summary>Returns true when <paramref name="value"/> parses as either an IPv4 / IPv6 literal or an
	/// IPv4 / IPv6 CIDR network (e.g. "10.0.0.0/8", "fc00::/7"). Used by the whitelist add path, which
	/// accepts ranges; the blocklist path keeps the stricter single-IP <see cref="IsValidIp"/>.</summary>
	public static bool IsValidIpOrCidr(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		string trimmed = value.Trim();
		return CidrRange.LooksLikeCidr(trimmed)
			? CidrRange.TryParse(trimmed, out _)
			: IPAddress.TryParse(trimmed, out _);
	}

	/// <summary>Normalises an IP literal or CIDR network to its canonical textual form (host bits beyond
	/// the prefix are masked to zero for CIDR), throwing on failure.</summary>
	public static string NormalizeIpOrCidr(string value)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(value);
		string trimmed = value.Trim();
		if (CidrRange.LooksLikeCidr(trimmed))
		{
			return CidrRange.Parse(trimmed).ToString();
		}

		return NormalizeIp(trimmed);
	}

	/// <summary>Normalises a login (trim, lower-case invariant) for case-insensitive comparison.</summary>
	public static string NormalizeLogin(string value)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(value);
		string trimmed = value.Trim();
		foreach (char c in trimmed)
		{
			if (char.IsControl(c))
			{
				throw new FormatException("Login contains control characters.");
			}
		}

		return trimmed.ToLowerInvariant();
	}
}
