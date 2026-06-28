// File:    src/RdpAudit.Core/Util/CidrRange.cs
// Module:  RdpAudit.Core.Util
// Purpose: Parses and represents an IPv4 or IPv6 CIDR network (e.g. "10.0.0.0/8", "fc00::/7") and
//          tests whether a single IP address falls inside that network. Used by the firewall
//          whitelist so an operator can exempt an entire private range with one entry instead of
//          listing every host. Matching is family-aware: an IPv4 address never matches an IPv6
//          network and vice versa, and the comparison is a pure bitwise prefix test on the raw
//          address bytes, so it is correct for both families including IPv6 :: compression.
// Depends: System.Net.IPAddress, System.Net.Sockets.AddressFamily
// Extends: To support a new textual form, extend TryParse; the byte-mask Contains logic already
//          covers any prefix length for both address families and needs no change.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>
/// Immutable IPv4 / IPv6 CIDR network. Construct via <see cref="TryParse"/> or <see cref="Parse"/>;
/// test membership with <see cref="Contains(IPAddress?)"/>. The network address is canonicalised on
/// parse (host bits beyond the prefix are masked to zero), so <see cref="ToString"/> always returns
/// the normalised "network/prefix" form regardless of the host bits supplied by the caller.
/// </summary>
public sealed class CidrRange : IEquatable<CidrRange>
{
	// ── Fields ───────────────────────────────────────────────────────────────────
	private readonly byte[] _networkBytes;
	private readonly int _prefixLength;
	private readonly AddressFamily _family;

	// ── Construction ─────────────────────────────────────────────────────────────
	private CidrRange(byte[] networkBytes, int prefixLength, AddressFamily family)
	{
		_networkBytes = networkBytes;
		_prefixLength = prefixLength;
		_family = family;
	}

	/// <summary>Prefix length in bits (e.g. 8 for "/8", 7 for "/7").</summary>
	public int PrefixLength => _prefixLength;

	/// <summary>Address family of the network (InterNetwork for IPv4, InterNetworkV6 for IPv6).</summary>
	public AddressFamily Family => _family;

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Returns true when <paramref name="text"/> looks like CIDR ("address/prefix"). It does not
	/// fully validate; use <see cref="TryParse"/> for that.</summary>
	public static bool LooksLikeCidr(string? text) =>
		!string.IsNullOrWhiteSpace(text) && text.Contains('/', StringComparison.Ordinal);

	/// <summary>Attempts to parse a CIDR string ("10.0.0.0/8", "fc00::/7"). Returns false on any
	/// malformed input, a prefix outside the family's valid range, or a missing '/'.</summary>
	public static bool TryParse(string? text, out CidrRange? range)
	{
		range = null;
		if (string.IsNullOrWhiteSpace(text))
		{
			return false;
		}

		string trimmed = text.Trim();
		int slash = trimmed.IndexOf('/', StringComparison.Ordinal);
		if (slash <= 0 || slash == trimmed.Length - 1)
		{
			return false;
		}

		string addressPart = trimmed[..slash];
		string prefixPart = trimmed[(slash + 1)..];

		if (!IPAddress.TryParse(addressPart, out IPAddress? address))
		{
			return false;
		}

		if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix))
		{
			return false;
		}

		int maxPrefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
		if (prefix < 0 || prefix > maxPrefix)
		{
			return false;
		}

		byte[] bytes = address.GetAddressBytes();
		MaskHostBits(bytes, prefix);
		range = new CidrRange(bytes, prefix, address.AddressFamily);
		return true;
	}

	/// <summary>Parses a CIDR string, throwing <see cref="FormatException"/> on failure.</summary>
	public static CidrRange Parse(string text)
	{
		if (!TryParse(text, out CidrRange? range) || range is null)
		{
			throw new FormatException(string.Format(CultureInfo.InvariantCulture,
				"Value '{0}' is not a valid IPv4 / IPv6 CIDR network.", text));
		}

		return range;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Returns true when <paramref name="address"/> is non-null, of the same address family,
	/// and falls within this network. A different family always returns false.</summary>
	public bool Contains(IPAddress? address)
	{
		if (address is null || address.AddressFamily != _family)
		{
			return false;
		}

		byte[] candidate = address.GetAddressBytes();
		if (candidate.Length != _networkBytes.Length)
		{
			return false;
		}

		int fullBytes = _prefixLength / 8;
		for (int i = 0; i < fullBytes; i++)
		{
			if (candidate[i] != _networkBytes[i])
			{
				return false;
			}
		}

		int remainingBits = _prefixLength % 8;
		if (remainingBits == 0)
		{
			return true;
		}

		int mask = (byte)(0xFF << (8 - remainingBits));
		return (candidate[fullBytes] & mask) == (_networkBytes[fullBytes] & mask);
	}

	/// <summary>Returns true when the textual IP literal falls within this network.</summary>
	public bool Contains(string? ip) =>
		!string.IsNullOrWhiteSpace(ip)
		&& IPAddress.TryParse(ip.Trim(), out IPAddress? parsed)
		&& Contains(parsed);

	// ── Helpers ──────────────────────────────────────────────────────────────────

	/// <summary>Zeroes every bit beyond the prefix so the stored value is always the canonical network
	/// address; this makes equality and ToString stable regardless of supplied host bits.</summary>
	private static void MaskHostBits(byte[] bytes, int prefix)
	{
		for (int i = 0; i < bytes.Length; i++)
		{
			int bitOffset = i * 8;
			if (bitOffset >= prefix)
			{
				bytes[i] = 0;
				continue;
			}

			int bitsInThisByte = prefix - bitOffset;
			if (bitsInThisByte >= 8)
			{
				continue;
			}

			bytes[i] &= (byte)(0xFF << (8 - bitsInThisByte));
		}
	}

	// ── Equality & Formatting ──────────────────────────────────────────────────────

	/// <summary>Returns the canonical "network/prefix" textual form.</summary>
	public override string ToString()
	{
		IPAddress network = new(_networkBytes);
		return string.Format(CultureInfo.InvariantCulture, "{0}/{1}", network, _prefixLength);
	}

	/// <inheritdoc/>
	public bool Equals(CidrRange? other)
	{
		if (other is null || other._prefixLength != _prefixLength || other._family != _family)
		{
			return false;
		}

		return _networkBytes.AsSpan().SequenceEqual(other._networkBytes);
	}

	/// <inheritdoc/>
	public override bool Equals(object? obj) => Equals(obj as CidrRange);

	/// <inheritdoc/>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(_prefixLength);
		hash.Add((int)_family);
		foreach (byte b in _networkBytes)
		{
			hash.Add(b);
		}

		return hash.ToHashCode();
	}
}
