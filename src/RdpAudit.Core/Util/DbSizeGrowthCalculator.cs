// File:    src/RdpAudit.Core/Util/DbSizeGrowthCalculator.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI-agnostic helper that derives DB size growth (day / week / month) from a
//          set of historical DbProps snapshots. Lifted into Core so the math can be unit tested
//          without filesystem or EF Core coupling.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>One historical DB-size measurement (size in bytes at <see cref="CapturedUtc"/>).</summary>
public readonly record struct DbSizeSnapshot(DateTime CapturedUtc, long SizeBytes);

/// <summary>Output of <see cref="DbSizeGrowthCalculator.Compute"/>: deltas in bytes vs older snapshots.</summary>
public sealed class DbSizeGrowth
{
	/// <summary>Growth in bytes versus the snapshot closest to (now - 1 day); <c>null</c> when no usable snapshot exists.</summary>
	public long? GrowthBytesDay { get; init; }

	/// <summary>Growth in bytes versus the snapshot closest to (now - 7 days); <c>null</c> when no usable snapshot exists.</summary>
	public long? GrowthBytesWeek { get; init; }

	/// <summary>Growth in bytes versus the snapshot closest to (now - 30 days); <c>null</c> when no usable snapshot exists.</summary>
	public long? GrowthBytesMonth { get; init; }
}

/// <summary>Pure helper that derives DB-size growth windows from a snapshot history.</summary>
public static class DbSizeGrowthCalculator
{
	/// <summary>Maximum window in days that is still considered "approximately 1 day".</summary>
	public const double DayLookbackMaxDays = 2.0;

	/// <summary>Maximum window in days that is still considered "approximately 1 week".</summary>
	public const double WeekLookbackMaxDays = 10.0;

	/// <summary>Maximum window in days that is still considered "approximately 1 month".</summary>
	public const double MonthLookbackMaxDays = 45.0;

	private const string SnapshotKeyPrefix = "OverviewDbSize:";

	/// <summary>DbProps key under which the daily DB-size snapshot is stored, encoded as
	/// "&lt;unix-utc-seconds&gt;:&lt;size-bytes&gt;" so a single key carries both timestamp and size.</summary>
	public static string GetDbPropKey(DateTime dayUtc)
	{
		string day = dayUtc.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
		return SnapshotKeyPrefix + day;
	}

	/// <summary>Returns true when <paramref name="key"/> is one of the keys produced by <see cref="GetDbPropKey"/>.</summary>
	public static bool IsSnapshotKey(string? key) =>
		!string.IsNullOrEmpty(key) && key.StartsWith(SnapshotKeyPrefix, StringComparison.Ordinal);

	/// <summary>Encodes a snapshot to the DbProp value string consumed by <see cref="TryDecode"/>.</summary>
	public static string Encode(DbSizeSnapshot snapshot)
	{
		long unix = new DateTimeOffset(DateTime.SpecifyKind(snapshot.CapturedUtc, DateTimeKind.Utc)).ToUnixTimeSeconds();
		return string.Format(CultureInfo.InvariantCulture, "{0}:{1}", unix, snapshot.SizeBytes);
	}

	/// <summary>Decodes a DbProp value emitted by <see cref="Encode"/>. Returns false on malformed input.</summary>
	public static bool TryDecode(string? value, out DbSizeSnapshot snapshot)
	{
		snapshot = default;
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		int colon = value.IndexOf(':');
		if (colon <= 0 || colon >= value.Length - 1)
		{
			return false;
		}

		ReadOnlySpan<char> ts = value.AsSpan(0, colon);
		ReadOnlySpan<char> bytes = value.AsSpan(colon + 1);
		if (!long.TryParse(ts, NumberStyles.Integer, CultureInfo.InvariantCulture, out long unix))
		{
			return false;
		}
		if (!long.TryParse(bytes, NumberStyles.Integer, CultureInfo.InvariantCulture, out long size))
		{
			return false;
		}
		if (size < 0)
		{
			return false;
		}

		snapshot = new DbSizeSnapshot(DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime, size);
		return true;
	}

	/// <summary>Computes day / week / month growth from <paramref name="snapshots"/> against
	/// <paramref name="currentSizeBytes"/> at <paramref name="nowUtc"/>. Each window picks the
	/// snapshot whose age is closest to the target lookback but not older than the documented max.</summary>
	public static DbSizeGrowth Compute(
		IEnumerable<DbSizeSnapshot> snapshots,
		long currentSizeBytes,
		DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(snapshots);
		if (currentSizeBytes < 0)
		{
			return new DbSizeGrowth();
		}

		List<DbSizeSnapshot> ordered = snapshots
			.Where(s => s.SizeBytes >= 0 && s.CapturedUtc <= nowUtc)
			.OrderBy(s => s.CapturedUtc)
			.ToList();

		long? day = PickGrowth(ordered, currentSizeBytes, nowUtc, 1.0, DayLookbackMaxDays);
		long? week = PickGrowth(ordered, currentSizeBytes, nowUtc, 7.0, WeekLookbackMaxDays);
		long? month = PickGrowth(ordered, currentSizeBytes, nowUtc, 30.0, MonthLookbackMaxDays);

		return new DbSizeGrowth
		{
			GrowthBytesDay = day,
			GrowthBytesWeek = week,
			GrowthBytesMonth = month,
		};
	}

	private static long? PickGrowth(
		IReadOnlyList<DbSizeSnapshot> ordered,
		long currentSizeBytes,
		DateTime nowUtc,
		double targetDays,
		double maxDays)
	{
		DbSizeSnapshot? best = null;
		double bestDelta = double.MaxValue;
		foreach (DbSizeSnapshot s in ordered)
		{
			double ageDays = (nowUtc - s.CapturedUtc).TotalDays;
			if (ageDays < 0 || ageDays > maxDays)
			{
				continue;
			}

			double delta = Math.Abs(ageDays - targetDays);
			if (delta < bestDelta)
			{
				bestDelta = delta;
				best = s;
			}
		}

		return best is null ? null : currentSizeBytes - best.Value.SizeBytes;
	}
}
