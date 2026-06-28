// File:    src/RdpAudit.Core/Firewall/BlockExpiryFormatter.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure, culture-invariant formatters for an ActiveBlock's expiry column and its remaining
//          time, shared by the Configurator's Active Blocks grid and unit tests. A permanent
//          (manual, never-expiring) block renders its expiry as "Never" and its remaining time as
//          "Permanent"; a still-active timed block renders a compact "1d 02h 03m" remaining; an
//          already-past expiry renders "Expired". Keeping this here (not in WinForms) makes the
//          "manual permanent = Never, auto = remaining" contract verifiable without a UI host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Firewall;

/// <summary>Pure formatters for an ActiveBlock's expiry / remaining-time display columns.</summary>
public static class BlockExpiryFormatter
{
	/// <summary>Sentinel shown in the "Expires (UTC)" column for a permanent (never-expiring) block.</summary>
	public const string NeverText = "Never";

	/// <summary>Sentinel shown in the "Remaining" column for a permanent block.</summary>
	public const string PermanentText = "Permanent";

	/// <summary>Sentinel shown in the "Remaining" column once an expiry is in the past.</summary>
	public const string ExpiredText = "Expired";

	/// <summary>Formats the absolute expiry instant. A null expiry (manual permanent block) renders
	/// as <see cref="NeverText"/>; a value renders as <c>yyyy-MM-dd HH:mm:ss</c> in UTC.</summary>
	public static string FormatExpiresUtc(DateTime? expiresUtc)
	{
		if (expiresUtc is null)
		{
			return NeverText;
		}

		return expiresUtc.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
	}

	/// <summary>Formats the remaining time until <paramref name="expiresUtc"/> relative to
	/// <paramref name="nowUtc"/>. Null expiry => <see cref="PermanentText"/>; an expiry at or before
	/// now => <see cref="ExpiredText"/>; otherwise a compact "Nd HHh MMm" / "HHh MMm" / "MMm SSs"
	/// string so the operator sees how long a timed auto-block has left.</summary>
	public static string FormatRemaining(DateTime? expiresUtc, DateTime nowUtc)
	{
		if (expiresUtc is null)
		{
			return PermanentText;
		}

		TimeSpan remaining = expiresUtc.Value - nowUtc;
		if (remaining <= TimeSpan.Zero)
		{
			return ExpiredText;
		}

		if (remaining.TotalDays >= 1)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0}d {1:00}h {2:00}m",
				(int)remaining.TotalDays,
				remaining.Hours,
				remaining.Minutes);
		}

		if (remaining.TotalHours >= 1)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0:00}h {1:00}m",
				(int)remaining.TotalHours,
				remaining.Minutes);
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"{0:00}m {1:00}s",
			remaining.Minutes,
			remaining.Seconds);
	}
}
