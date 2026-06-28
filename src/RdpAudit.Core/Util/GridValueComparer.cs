// File:    src/RdpAudit.Core/Util/GridValueComparer.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, type-aware comparison used by the Configurator's sortable DataGridView helper so
//          every grid sorts IP addresses, dates, durations, and numbers by their natural order rather
//          than lexicographically. Lifted into Core (away from WinForms) so the ordering rules are
//          unit-testable without a UI host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace RdpAudit.Core.Util;

/// <summary>Type-aware comparison for grid cell values rendered as strings.</summary>
public static class GridValueComparer
{
	/// <summary>
	/// Compares two cell values using the most specific natural ordering both sides support: IP address,
	/// then DateTime, then TimeSpan-style duration, then numeric, falling back to case-insensitive
	/// string order. Null / empty values sort last (treated as "greater than" any populated value) so a
	/// blank column does not jump to the top of an ascending sort.
	/// </summary>
	/// <returns>Negative when <paramref name="left"/> precedes <paramref name="right"/>, positive when it
	/// follows, zero when equal under the chosen ordering.</returns>
	public static int Compare(string? left, string? right)
	{
		bool leftEmpty = string.IsNullOrWhiteSpace(left);
		bool rightEmpty = string.IsNullOrWhiteSpace(right);
		if (leftEmpty || rightEmpty)
		{
			if (leftEmpty && rightEmpty)
			{
				return 0;
			}

			return leftEmpty ? 1 : -1;
		}

		string l = left!.Trim();
		string r = right!.Trim();

		if (TryParseIp(l, out IPAddress? li) && TryParseIp(r, out IPAddress? ri))
		{
			return CompareIp(li!, ri!);
		}

		if (DateTime.TryParse(l, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime ld)
			&& DateTime.TryParse(r, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime rd))
		{
			return ld.CompareTo(rd);
		}

		if (TryParseDuration(l, out TimeSpan lt) && TryParseDuration(r, out TimeSpan rt))
		{
			return lt.CompareTo(rt);
		}

		if (double.TryParse(l, NumberStyles.Any, CultureInfo.InvariantCulture, out double ln)
			&& double.TryParse(r, NumberStyles.Any, CultureInfo.InvariantCulture, out double rn))
		{
			return ln.CompareTo(rn);
		}

		return string.Compare(l, r, StringComparison.OrdinalIgnoreCase);
	}

	private static bool TryParseIp(string value, out IPAddress? address)
	{
		// IPAddress.TryParse accepts bare integers like "12" as an IPv4 address; reject those so numeric
		// columns are not misclassified as IPs.
		if (value.IndexOf('.') < 0 && value.IndexOf(':') < 0)
		{
			address = null;
			return false;
		}

		return IPAddress.TryParse(value, out address);
	}

	private static int CompareIp(IPAddress left, IPAddress right)
	{
		if (left.AddressFamily != right.AddressFamily)
		{
			// IPv4 sorts before IPv6 for a stable, predictable grouping.
			return left.AddressFamily == AddressFamily.InterNetwork ? -1 : 1;
		}

		byte[] lb = left.GetAddressBytes();
		byte[] rb = right.GetAddressBytes();
		int len = Math.Min(lb.Length, rb.Length);
		for (int i = 0; i < len; i++)
		{
			int cmp = lb[i].CompareTo(rb[i]);
			if (cmp != 0)
			{
				return cmp;
			}
		}

		return lb.Length.CompareTo(rb.Length);
	}

	/// <summary>
	/// Parses the duration spellings the Configurator renders: "1d 02h 03m", "03h 07m", "04m 12s", and the
	/// invariant "d.hh:mm:ss" / "hh:mm:ss" forms produced by <see cref="TimeSpan.ToString()"/>.
	/// </summary>
	private static bool TryParseDuration(string value, out TimeSpan duration)
	{
		duration = TimeSpan.Zero;

		if (TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out duration))
		{
			return true;
		}

		bool any = false;
		long days = 0, hours = 0, minutes = 0, seconds = 0;
		foreach (string token in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
		{
			if (token.Length < 2)
			{
				return false;
			}

			char unit = token[^1];
			string numberPart = token[..^1];
			if (!long.TryParse(numberPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n))
			{
				return false;
			}

			switch (unit)
			{
				case 'd':
					days = n;
					break;
				case 'h':
					hours = n;
					break;
				case 'm':
					minutes = n;
					break;
				case 's':
					seconds = n;
					break;
				default:
					return false;
			}

			any = true;
		}

		if (!any)
		{
			return false;
		}

		duration = new TimeSpan((int)days, (int)hours, (int)minutes, (int)seconds);
		return true;
	}
}
