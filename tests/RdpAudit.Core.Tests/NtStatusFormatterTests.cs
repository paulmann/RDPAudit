// File:    tests/RdpAudit.Core.Tests/NtStatusFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Covers NtStatusFormatter — canonicalises the three textual forms Windows writes for
//          NTSTATUS values (hex 0xXXXXXXXX, unsigned decimal, signed decimal int32) into one
//          stable form so SubStatusCatalog lookups and EF/SQL predicates align across producers
//          and OS builds. Pins the user-reported real-host values from PowerShell evidence:
//          Status / SubStatus rendered as signed decimal int32 such as -1073741715 (bad password).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class NtStatusFormatterTests
{
	[Theory]
	[InlineData("0xC000006A", "0xC000006A")]
	[InlineData("0xc000006a", "0xC000006A")]
	[InlineData("C000006A", "0xC000006A")]
	[InlineData("3221225578", "0xC000006A")] // unsigned-decimal form of 0xC000006A
	[InlineData("-1073741718", "0xC000006A")] // signed-decimal int32 form of 0xC000006A
	[InlineData("-1073741715", "0xC000006D")] // user-reported signed-decimal: Misc. Logon Failure
	[InlineData("0xC0000064", "0xC0000064")] // No Such User
	[InlineData("-1073741724", "0xC0000064")] // signed-decimal int32 form of 0xC0000064
	[InlineData("0", "0x00000000")]
	[InlineData("0x0", "0x00000000")]
	[InlineData("0x00000000", "0x00000000")]
	public void Canonicalize_NormalisesAllTextualForms(string raw, string expected)
	{
		Assert.Equal(expected, NtStatusFormatter.Canonicalize(raw));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	public void Canonicalize_NullOrBlank_ReturnsNull(string? raw)
	{
		Assert.Null(NtStatusFormatter.Canonicalize(raw));
	}

	[Theory]
	[InlineData("garbage")]
	[InlineData("0xZZ")]
	[InlineData("--1")]
	public void Canonicalize_UnparseableInput_PreservesRawTrimmed(string raw)
	{
		string? actual = NtStatusFormatter.Canonicalize("  " + raw + "  ");
		Assert.Equal(raw, actual);
	}

	[Theory]
	[InlineData("0", true)]
	[InlineData("0x0", true)]
	[InlineData("0x00000000", true)]
	[InlineData(null, true)]
	[InlineData("", true)]
	[InlineData("-1073741715", false)]
	[InlineData("0xC000006D", false)]
	[InlineData("0xC0000064", false)]
	public void IsZero_RecognisesAllZeroForms(string? value, bool expected)
	{
		Assert.Equal(expected, NtStatusFormatter.IsZero(value));
	}

	[Fact]
	public void TryParse_HandlesAllForms()
	{
		Assert.True(NtStatusFormatter.TryParse("0xC000006A", out uint a));
		Assert.True(NtStatusFormatter.TryParse("3221225578", out uint b));
		Assert.True(NtStatusFormatter.TryParse("-1073741718", out uint c));
		Assert.Equal(a, b);
		Assert.Equal(a, c);

		Assert.False(NtStatusFormatter.TryParse("not a number", out _));
		Assert.False(NtStatusFormatter.TryParse(null, out _));
	}
}
