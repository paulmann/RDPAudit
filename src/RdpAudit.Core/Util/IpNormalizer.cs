// File:    src/RdpAudit.Core/Util/IpNormalizer.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for IP-address normalization across the ingestion pipeline.
//          Windows event payloads, the RdpCoreTS pre-auth listener, and some operator-pasted
//          values arrive with surrounding punctuation, bracket wrappers, port suffixes, IPv6
//          zone identifiers, or as IPv4-mapped IPv6 literals. To keep RawEvents,
//          AuthAttemptFacts, and the Attack / RDP Clients aggregates keyed on a single canonical
//          form per host, every layer that writes an IP MUST run the raw string through
//          <see cref="Normalize"/> first. Invalid values (after sanitisation) come back as null
//          and the caller is responsible for marking the row as "unresolved" rather than
//          inventing a placeholder.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.2.2

using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>Sanitises raw IP strings into a single canonical textual form.</summary>
/// <remarks>
/// The normalizer is intentionally permissive about leading / trailing punctuation that has been
/// observed in real Windows event payloads (e.g. ".77.37.192.246" surfaces from certain
/// stripped-Workstation+ClientAddress concatenations) and IPv6 textual variants. It is strict
/// about the *result*: only values that survive <c>IPAddress.TryParse</c> after cleanup
/// are returned. Loopback / link-local / blank sentinels are squashed to <c>null</c> so the
/// "unresolved" UI path can be entered cleanly.
/// </remarks>
public static class IpNormalizer
{
	// Mirrors AttackStatsAggregator.SentinelUnresolvedIp. Declared locally to keep RdpAudit.Core.Util
	// free of a RdpAudit.Core.Models dependency (Util must not reference the entity layer).
	private const string SentinelUnresolvedIp = "0.0.0.0";

	// Wrapping punctuation that can safely be stripped from BOTH ends of the raw input without
	// ever damaging a valid IPv4 / IPv6 literal. Crucially this set does NOT contain '.' or ':'
	// because each of those is part of every literal — stripping them blindly would destroy
	// "::ffff:1.2.3.4". Leading / trailing single dots (the ".77.37.192.246" case the v1.2.1
	// bug brief names) are handled by a second, narrower trim pass.
	private static readonly char[] SafeWrapPunctuation = { ',', ';', '\'', '"', '`', '(', ')', '{', '}', '<', '>', ' ', '\t', '\r', '\n' };

	// Bracket characters are handled separately by the dedicated bracket-unwrap step. Keeping
	// them out of <see cref="SafeWrapPunctuation"/> ensures the unwrap step sees the full
	// "[ip]:port" form intact instead of a half-trimmed "ip]:port".
	private static readonly char[] BracketWrap = { '[', ']' };

	/// <summary>
	/// Returns the canonical textual form of the supplied IP, or <c>null</c> when the value is
	/// blank, a known local sentinel, or fails to parse after sanitisation. IPv4-mapped IPv6
	/// (<c>::ffff:1.2.3.4</c>) is collapsed to its dotted-quad form. IPv6 zone identifiers and
	/// <c>[…]:port</c> wrappers are stripped before parsing.
	/// </summary>
	public static string? Normalize(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return null;
		}

		string cleaned = Sanitize(raw);
		if (cleaned.Length == 0)
		{
			return null;
		}

		// v1.2.2: the unresolved-attacker sentinel (0.0.0.0) is written verbatim by
		// AttackStatsRefreshWorker for failures whose IpAddress field Windows stripped. It is also a
		// member of IpClassifier.LocalSentinels, so a naive IsLocalSentinel gate squashed it back to
		// null on any read path that re-normalised an already-aggregated key — silently dropping the
		// (unresolved) row. Preserve it here so the sentinel survives a Normalize round-trip while all
		// other local sentinels (::1, 127.0.0.1, "-", LOCAL, localhost) still collapse to null.
		if (string.Equals(cleaned, SentinelUnresolvedIp, StringComparison.Ordinal))
		{
			return SentinelUnresolvedIp;
		}

		if (IpClassifier.IsLocalSentinel(cleaned))
		{
			return null;
		}

		if (!IPAddress.TryParse(cleaned, out IPAddress? parsed))
		{
			return null;
		}

		if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.IsIPv4MappedToIPv6)
		{
			return parsed.MapToIPv4().ToString();
		}

		return parsed.ToString();
	}

	/// <summary>True when the raw string maps to a parseable canonical IP.</summary>
	public static bool IsParseable(string? raw) => Normalize(raw) is not null;

	/// <summary>
	/// Pure string-only sanitisation (no parsing). Returns the trimmed candidate ready for
	/// <c>IPAddress.TryParse</c>. Exposed so callers that need to inspect the pre-parse form
	/// (e.g. classifier tests) get the same view as the parser path.
	/// </summary>
	internal static string Sanitize(string raw)
	{
		// Step 1 — trim leading / trailing whitespace and safe wrapping punctuation. The bracket
		// characters are deliberately NOT in this set so the dedicated bracket-unwrap step (Step
		// 3) can still recognise the full "[ip]:port" form.
		string trimmed = raw.Trim().Trim(SafeWrapPunctuation).Trim();
		if (trimmed.Length == 0)
		{
			return string.Empty;
		}

		// Step 2 — narrow leading / trailing single-character strip for '.' and ':' that surround
		// (rather than belong to) the literal. We never strip more than one of each end so the IPv6
		// double-colon "::1" / "::ffff:1.2.3.4" prefixes are preserved.
		trimmed = TrimSingleEndChar(trimmed, '.');
		// A trailing single colon shows up in scraped log lines like "ip:" (with the port stripped
		// elsewhere); a leading single colon (without a second one) is never legal for either
		// IPv4 or IPv6, so it can be removed safely.
		if (trimmed.Length > 1 && trimmed[^1] == ':' && trimmed[^2] != ':')
		{
			trimmed = trimmed[..^1];
		}

		if (trimmed.Length > 1 && trimmed[0] == ':' && trimmed[1] != ':')
		{
			trimmed = trimmed[1..];
		}

		if (trimmed.Length == 0)
		{
			return string.Empty;
		}

		// Step 3 — unwrap "[ip]" / "[ip]:port" / "ip:port" forms. Bracket form is unambiguous and
		// must be unwrapped first because the closing "]" determines whether a trailing colon is
		// a port separator or part of an IPv6 literal.
		if (trimmed[0] == '[')
		{
			int close = trimmed.IndexOf(']', StringComparison.Ordinal);
			if (close > 1)
			{
				trimmed = trimmed[1..close];
			}
			else
			{
				// Unmatched bracket — drop and continue with whatever followed.
				trimmed = trimmed[1..].TrimEnd(BracketWrap).Trim();
			}
		}
		else if (trimmed.Contains(':', StringComparison.Ordinal) && trimmed.Contains('.', StringComparison.Ordinal))
		{
			// IPv4 with a "host:port" suffix; an IPv6 textual literal always has more than one
			// colon, so the single-colon + dot combination is a safe IPv4-only signal — but only
			// if the colons are NOT part of an IPv4-mapped IPv6 literal ("::ffff:1.2.3.4").
			int colonCount = 0;
			for (int i = 0; i < trimmed.Length; i++)
			{
				if (trimmed[i] == ':')
				{
					colonCount++;
				}
			}

			if (colonCount == 1)
			{
				int colon = trimmed.IndexOf(':', StringComparison.Ordinal);
				trimmed = trimmed[..colon];
			}
		}

		// Step 4 — strip IPv6 zone identifier ("fe80::1%eth0"). Always safe even on IPv4 strings
		// because the percent character is not part of any IPv4 literal.
		int pct = trimmed.IndexOf('%', StringComparison.Ordinal);
		if (pct > 0)
		{
			trimmed = trimmed[..pct];
		}

		// Final whitespace + safe-punctuation pass (covers values that gained whitespace via the
		// bracket / port unwrap above).
		return trimmed.Trim().Trim(SafeWrapPunctuation).Trim();
	}

	private static string TrimSingleEndChar(string s, char c)
	{
		// Remove one leading and one trailing occurrence of <c>c</c>, but never two in a row.
		// This is what keeps ".77.37.192.246" -> "77.37.192.246" without converting "::1" -> "1".
		int start = 0;
		int end = s.Length;
		if (end > 1 && s[0] == c && s[1] != c)
		{
			start = 1;
		}

		if (end - start > 1 && s[end - 1] == c && s[end - 2] != c)
		{
			end--;
		}

		return start == 0 && end == s.Length ? s : s[start..end];
	}
}
