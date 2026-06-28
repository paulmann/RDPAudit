// File:    tests/RdpAudit.Core.Tests/DbSizeGrowthCalculatorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage A — locks the DB-size snapshot encode/decode round-trip and the day / week /
//          month growth-window selection rules consumed by the Overview tab.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage A — DB-size snapshot encode/decode + growth calculator.</summary>
public class DbSizeGrowthCalculatorTests
{
	[Fact]
	public void Encode_Decode_RoundTrips()
	{
		DbSizeSnapshot original = new(new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc), 1_234_567_890L);
		string encoded = DbSizeGrowthCalculator.Encode(original);

		Assert.True(DbSizeGrowthCalculator.TryDecode(encoded, out DbSizeSnapshot decoded));
		Assert.Equal(original.CapturedUtc, decoded.CapturedUtc);
		Assert.Equal(original.SizeBytes, decoded.SizeBytes);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("garbage")]
	[InlineData(":123")]
	[InlineData("abc:def")]
	[InlineData("100:-5")]
	public void TryDecode_ReturnsFalseForMalformedInput(string? input)
	{
		Assert.False(DbSizeGrowthCalculator.TryDecode(input, out _));
	}

	[Fact]
	public void Compute_ReturnsNullForEachWindow_WhenNoSnapshots()
	{
		DateTime now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		DbSizeGrowth result = DbSizeGrowthCalculator.Compute(Array.Empty<DbSizeSnapshot>(), 100, now);
		Assert.Null(result.GrowthBytesDay);
		Assert.Null(result.GrowthBytesWeek);
		Assert.Null(result.GrowthBytesMonth);
	}

	[Fact]
	public void Compute_PicksSnapshotClosestToEachWindow()
	{
		DateTime now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		long current = 10_000;
		DbSizeSnapshot[] snaps =
		{
			new(now.AddDays(-1), 7_500),
			new(now.AddDays(-7), 5_000),
			new(now.AddDays(-30), 1_000),
		};

		DbSizeGrowth result = DbSizeGrowthCalculator.Compute(snaps, current, now);

		Assert.Equal(2_500, result.GrowthBytesDay);
		Assert.Equal(5_000, result.GrowthBytesWeek);
		Assert.Equal(9_000, result.GrowthBytesMonth);
	}

	[Fact]
	public void Compute_IgnoresFutureSnapshots()
	{
		DateTime now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		DbSizeSnapshot[] snaps =
		{
			new(now.AddDays(2), 9_999_999),
		};

		DbSizeGrowth result = DbSizeGrowthCalculator.Compute(snaps, 100, now);
		Assert.Null(result.GrowthBytesDay);
		Assert.Null(result.GrowthBytesWeek);
		Assert.Null(result.GrowthBytesMonth);
	}

	[Fact]
	public void Compute_IgnoresSnapshotsOlderThanWindowCap()
	{
		DateTime now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		// A 60-day-old snapshot is past every documented cap (max 45 days for the month window).
		DbSizeSnapshot[] snaps =
		{
			new(now.AddDays(-60), 1_000),
		};

		DbSizeGrowth result = DbSizeGrowthCalculator.Compute(snaps, 5_000, now);
		Assert.Null(result.GrowthBytesDay);
		Assert.Null(result.GrowthBytesWeek);
		Assert.Null(result.GrowthBytesMonth);
	}

	[Fact]
	public void Compute_AllowsNegativeGrowthAfterRetentionPrune()
	{
		// Simulate a maintenance pass that shrank the DB: current size < snapshot size.
		DateTime now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);
		long current = 4_000;
		DbSizeSnapshot[] snaps =
		{
			new(now.AddDays(-1), 6_000),
		};

		DbSizeGrowth result = DbSizeGrowthCalculator.Compute(snaps, current, now);
		Assert.Equal(-2_000, result.GrowthBytesDay);
	}

	[Fact]
	public void GetDbPropKey_UsesStablePrefix()
	{
		DateTime utc = new(2026, 5, 19, 0, 0, 0, DateTimeKind.Utc);
		string key = DbSizeGrowthCalculator.GetDbPropKey(utc);
		Assert.StartsWith("OverviewDbSize:", key, StringComparison.Ordinal);
		Assert.True(DbSizeGrowthCalculator.IsSnapshotKey(key));
		Assert.False(DbSizeGrowthCalculator.IsSnapshotKey("Other:Whatever"));
		Assert.False(DbSizeGrowthCalculator.IsSnapshotKey(null));
	}
}
