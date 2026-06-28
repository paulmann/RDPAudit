// File:    tests/RdpAudit.Core.Tests/GridValueComparerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for GridValueComparer — pinning the type-aware ordering (IP, DateTime, duration,
//          numeric, string) used by the Configurator's sortable grids so columns sort naturally rather
//          than lexicographically, and blanks sort last.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class GridValueComparerTests
{
	[Theory]
	[InlineData("10.0.0.2", "10.0.0.10")]
	[InlineData("9.0.0.1", "10.0.0.1")]
	[InlineData("192.168.1.1", "192.168.1.2")]
	public void Ip_OrdersNumericallyNotLexically(string smaller, string larger)
	{
		Assert.True(GridValueComparer.Compare(smaller, larger) < 0);
		Assert.True(GridValueComparer.Compare(larger, smaller) > 0);
	}

	[Fact]
	public void Ip_Ipv4SortsBeforeIpv6()
	{
		Assert.True(GridValueComparer.Compare("10.0.0.1", "2606:4700::1") < 0);
	}

	[Fact]
	public void DateTime_OrdersChronologically()
	{
		Assert.True(GridValueComparer.Compare("2026-06-08 13:05:09", "2026-06-08 13:05:10") < 0);
		Assert.True(GridValueComparer.Compare("2026-01-01 00:00:00", "2026-12-31 23:59:59") < 0);
	}

	[Theory]
	[InlineData("04m 12s", "03h 07m")]
	[InlineData("03h 07m", "1d 02h 03m")]
	[InlineData("00m 30s", "01m 00s")]
	public void Duration_OrdersByTotalTime(string shorter, string longer)
	{
		Assert.True(GridValueComparer.Compare(shorter, longer) < 0);
		Assert.True(GridValueComparer.Compare(longer, shorter) > 0);
	}

	[Theory]
	[InlineData("2", "10")]
	[InlineData("9", "100")]
	[InlineData("-5", "5")]
	public void Numeric_OrdersByValueNotText(string smaller, string larger)
	{
		Assert.True(GridValueComparer.Compare(smaller, larger) < 0);
	}

	[Fact]
	public void String_OrdersCaseInsensitive()
	{
		Assert.True(GridValueComparer.Compare("administrator", "BACKUP") < 0);
		Assert.Equal(0, GridValueComparer.Compare("Admin", "admin"));
	}

	[Fact]
	public void Blank_SortsLast()
	{
		Assert.True(GridValueComparer.Compare("", "anything") > 0);
		Assert.True(GridValueComparer.Compare("anything", "") < 0);
		Assert.True(GridValueComparer.Compare(null, "x") > 0);
		Assert.Equal(0, GridValueComparer.Compare(null, ""));
		Assert.Equal(0, GridValueComparer.Compare("  ", null));
	}

	[Fact]
	public void Equal_Values_ReturnZero()
	{
		Assert.Equal(0, GridValueComparer.Compare("10.0.0.1", "10.0.0.1"));
		Assert.Equal(0, GridValueComparer.Compare("42", "42"));
		Assert.Equal(0, GridValueComparer.Compare("03h 07m", "03h 07m"));
	}
}
