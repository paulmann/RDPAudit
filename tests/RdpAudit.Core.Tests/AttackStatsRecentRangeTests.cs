// File:    tests/RdpAudit.Core.Tests/AttackStatsRecentRangeTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 6B — locks the recent-period preset → SinceUtc mapping and the toolbar display
//          labels. Lifted to Core so the mapping is exercised without a WinForms host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class AttackStatsRecentRangeTests
{
	private static readonly DateTime Now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);

	[Theory]
	[InlineData(AttackStatsRecentRange.LastHour, -1, 0)]
	[InlineData(AttackStatsRecentRange.Last24Hours, 0, -1)]
	[InlineData(AttackStatsRecentRange.Last7Days, 0, -7)]
	[InlineData(AttackStatsRecentRange.Last30Days, 0, -30)]
	public void ToSinceUtc_SubtractsExpectedSpanFromNow(
		AttackStatsRecentRange range,
		int hours,
		int days)
	{
		DateTime? since = AttackStatsRecentRanges.ToSinceUtc(range, Now);
		DateTime expected = Now.AddHours(hours).AddDays(days);

		Assert.NotNull(since);
		Assert.Equal(expected, since!.Value);
	}

	[Fact]
	public void ToSinceUtc_All_ReturnsNull()
	{
		Assert.Null(AttackStatsRecentRanges.ToSinceUtc(AttackStatsRecentRange.All, Now));
	}

	[Theory]
	[InlineData(AttackStatsRecentRange.LastHour, "Last hour")]
	[InlineData(AttackStatsRecentRange.Last24Hours, "Last 24 hours")]
	[InlineData(AttackStatsRecentRange.Last7Days, "Last 7 days")]
	[InlineData(AttackStatsRecentRange.Last30Days, "Last 30 days")]
	[InlineData(AttackStatsRecentRange.All, "All time")]
	public void ToDisplayLabel_IsStable(AttackStatsRecentRange range, string expected)
	{
		Assert.Equal(expected, AttackStatsRecentRanges.ToDisplayLabel(range));
	}

	[Fact]
	public void Ordinals_AreStableAppendOnly()
	{
		// APPEND-ONLY enum — ordinals must not change.
		Assert.Equal(0, (int)AttackStatsRecentRange.LastHour);
		Assert.Equal(1, (int)AttackStatsRecentRange.Last24Hours);
		Assert.Equal(2, (int)AttackStatsRecentRange.Last7Days);
		Assert.Equal(3, (int)AttackStatsRecentRange.Last30Days);
		Assert.Equal(4, (int)AttackStatsRecentRange.All);
	}
}
