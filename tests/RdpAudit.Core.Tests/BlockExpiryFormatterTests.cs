// File:    tests/RdpAudit.Core.Tests/BlockExpiryFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for BlockExpiryFormatter, pinning the "manual permanent = Never / auto =
//          remaining time" contract for the Active Blocks grid without spinning up a WinForms host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class BlockExpiryFormatterTests
{
	[Fact]
	public void FormatExpiresUtc_Null_RendersNever()
	{
		Assert.Equal(BlockExpiryFormatter.NeverText, BlockExpiryFormatter.FormatExpiresUtc(null));
	}

	[Fact]
	public void FormatExpiresUtc_Value_RendersInvariantUtc()
	{
		DateTime expires = new(2026, 6, 8, 13, 5, 9, DateTimeKind.Utc);
		Assert.Equal("2026-06-08 13:05:09", BlockExpiryFormatter.FormatExpiresUtc(expires));
	}

	[Fact]
	public void FormatRemaining_Null_RendersPermanent()
	{
		DateTime now = new(2026, 6, 8, 0, 0, 0, DateTimeKind.Utc);
		Assert.Equal(BlockExpiryFormatter.PermanentText, BlockExpiryFormatter.FormatRemaining(null, now));
	}

	[Fact]
	public void FormatRemaining_PastExpiry_RendersExpired()
	{
		DateTime now = new(2026, 6, 8, 12, 0, 0, DateTimeKind.Utc);
		DateTime expires = now.AddMinutes(-1);
		Assert.Equal(BlockExpiryFormatter.ExpiredText, BlockExpiryFormatter.FormatRemaining(expires, now));
	}

	[Fact]
	public void FormatRemaining_AtExpiry_RendersExpired()
	{
		DateTime now = new(2026, 6, 8, 12, 0, 0, DateTimeKind.Utc);
		Assert.Equal(BlockExpiryFormatter.ExpiredText, BlockExpiryFormatter.FormatRemaining(now, now));
	}

	[Fact]
	public void FormatRemaining_MultiDay_RendersDaysHoursMinutes()
	{
		DateTime now = new(2026, 6, 8, 0, 0, 0, DateTimeKind.Utc);
		DateTime expires = now.AddDays(1).AddHours(2).AddMinutes(3).AddSeconds(30);
		Assert.Equal("1d 02h 03m", BlockExpiryFormatter.FormatRemaining(expires, now));
	}

	[Fact]
	public void FormatRemaining_SubDay_RendersHoursMinutes()
	{
		DateTime now = new(2026, 6, 8, 0, 0, 0, DateTimeKind.Utc);
		DateTime expires = now.AddHours(3).AddMinutes(7);
		Assert.Equal("03h 07m", BlockExpiryFormatter.FormatRemaining(expires, now));
	}

	[Fact]
	public void FormatRemaining_SubHour_RendersMinutesSeconds()
	{
		DateTime now = new(2026, 6, 8, 0, 0, 0, DateTimeKind.Utc);
		DateTime expires = now.AddMinutes(4).AddSeconds(12);
		Assert.Equal("04m 12s", BlockExpiryFormatter.FormatRemaining(expires, now));
	}
}
