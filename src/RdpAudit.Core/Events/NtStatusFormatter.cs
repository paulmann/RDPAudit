// File:    src/RdpAudit.Core/Events/NtStatusFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Canonicalises NTSTATUS values that surface in Security 4625/4776/4771 EventData fields.
//          Windows writes the same NTSTATUS in at least three different textual forms depending on
//          the producer and version: hex with the "0x" prefix (e.g. "0xC000006A"), unsigned
//          decimal (e.g. "3221225578"), and signed decimal int32 (e.g. "-1073741715") — and on
//          freshly-installed hosts the *signed* form is by far the most common because PowerShell
//          and many built-in views render Properties[Status] as Int32. Without a single canonical
//          string the SubStatus dictionary lookup misses, the SQL/EF column varies between rows,
//          and attack-statistics counters never line up. This helper produces one canonical
//          "0xXXXXXXXX" form per code, accepts every textual variant we have observed in the wild,
//          and is safe to call on user-controlled values (no exceptions on garbage input).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Events;

/// <summary>Canonical formatter for Windows NTSTATUS codes that arrive as strings in EventData.</summary>
public static class NtStatusFormatter
{
	/// <summary>Tries to parse an NTSTATUS textual value. Accepts the canonical hex form
	/// (<c>0xC000006A</c> with or without the <c>0x</c> prefix), unsigned decimal (e.g.
	/// <c>3221225578</c>), and signed decimal int32 (e.g. <c>-1073741715</c>). Returns the
	/// canonical uppercase hex form (<c>0xXXXXXXXX</c>) when parsing succeeds; otherwise the
	/// trimmed input verbatim so the caller can still persist forensic evidence.</summary>
	public static string? Canonicalize(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return null;
		}

		string trimmed = raw.Trim();
		if (trimmed.Length == 0)
		{
			return null;
		}

		if (TryParse(trimmed, out uint canonical))
		{
			return "0x" + canonical.ToString("X8", CultureInfo.InvariantCulture);
		}

		// Preserve original evidence — the downstream UI / tests can still display the raw
		// value, and the SubStatus catalog will fall back to the "Unknown SubStatus ({raw})"
		// rendering rather than crashing.
		return trimmed;
	}

	/// <summary>True when <paramref name="value"/> parses to NTSTATUS 0 (a successful Status field —
	/// the 4776 success indicator).</summary>
	public static bool IsZero(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return true;
		}

		return TryParse(value.Trim(), out uint code) && code == 0u;
	}

	/// <summary>True when the (un-prefixed) string is composed entirely of hex digits AND at
	/// least one of them is in [A-F]. Used to recognise "C000006A"-style values that drop the
	/// "0x" prefix without misclassifying pure-digit unsigned-decimal forms as hex.</summary>
	internal static bool LooksLikeBareHex(string s)
	{
		ArgumentNullException.ThrowIfNull(s);
		if (s.Length == 0)
		{
			return false;
		}

		bool hasLetter = false;
		foreach (char c in s)
		{
			bool isDigit = c >= '0' && c <= '9';
			bool isHexLetter = (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
			if (!isDigit && !isHexLetter)
			{
				return false;
			}

			if (isHexLetter)
			{
				hasLetter = true;
			}
		}

		return hasLetter;
	}

	/// <summary>Parse the canonical NTSTATUS code as an unsigned 32-bit integer. Handles every
	/// textual variant <see cref="Canonicalize"/> accepts. Returns false on garbage input.</summary>
	public static bool TryParse(string? raw, out uint canonical)
	{
		canonical = 0;
		if (string.IsNullOrWhiteSpace(raw))
		{
			return false;
		}

		string s = raw.Trim();
		if (s.Length == 0)
		{
			return false;
		}

		bool negative = false;
		if (s[0] == '-')
		{
			negative = true;
			s = s[1..];
		}
		else if (s[0] == '+')
		{
			s = s[1..];
		}

		if (s.Length == 0 || s[0] == '-' || s[0] == '+')
		{
			// Reject leading sign-after-sign forms like "--1" or "+-1" — these are not valid
			// NTSTATUS strings even though strict int.TryParse would happily accept "-1" after
			// we stripped the outer "-".
			return false;
		}

		bool isHex = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || s.StartsWith("0X", StringComparison.OrdinalIgnoreCase);
		if (isHex)
		{
			s = s[2..];
		}
		else if (LooksLikeBareHex(s))
		{
			// Bare hex like "C000006A" — operators and event-log dumps sometimes drop the 0x
			// prefix. Only treat the string as hex when at least one digit is in [A-F]; pure
			// digit strings stay decimal so "3221225578" is not misread as hex.
			isHex = true;
		}

		if (s.Length == 0)
		{
			return false;
		}

		if (isHex)
		{
			if (uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint hex))
			{
				canonical = negative ? unchecked((uint)-(int)hex) : hex;
				return true;
			}

			return false;
		}

		// Decimal: try uint first (covers unsigned decimal like 3221225578), then signed int32
		// (covers negative-decimal int32 like -1073741715). The cast preserves bit-pattern under
		// two's-complement which is what NTSTATUS expects.
		if (!negative && uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint udec))
		{
			canonical = udec;
			return true;
		}

		if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int sdec))
		{
			canonical = unchecked((uint)(negative ? -sdec : sdec));
			return true;
		}

		// Fall back to long for very large unsigned decimals that don't quite fit uint cleanly
		// (defensive — Windows event writers should never emit these but we have seen exotic
		// values from third-party security suites).
		if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long sl))
		{
			canonical = unchecked((uint)(negative ? -sl : sl));
			return true;
		}

		return false;
	}
}
