// File:    tests/RdpAudit.Core.Tests/SubStatusCatalogTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the v3 SubStatus translation table (Detect_Attack_Strategy_v3.md §3.1) so attack
//          classification can rely on stable, human-readable failure reasons (Bad Password,
//          No Such User, Account Locked Out, ...).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class SubStatusCatalogTests
{
	[Theory]
	[InlineData("0xC000006A", "Bad Password")]
	[InlineData("0xC0000064", "No Such User")]
	[InlineData("0xC0000234", "Account Locked Out")]
	[InlineData("0xC0000072", "Account Disabled")]
	[InlineData("0xC000006F", "Outside Logon Hours")]
	[InlineData("0xC0000071", "Password Expired")]
	[InlineData("0xC000015B", "Logon Type Not Granted")]
	public void Translate_KnownCode_ReturnsExpectedMeaning(string code, string expected)
	{
		Assert.Equal(expected, SubStatusCatalog.Translate(code));
	}

	[Fact]
	public void Translate_AcceptsWithoutPrefix()
	{
		Assert.Equal("Bad Password", SubStatusCatalog.Translate("C000006A"));
	}

	[Fact]
	public void Translate_UnknownCode_ReturnsAnnotation()
	{
		string? meaning = SubStatusCatalog.Translate("0xDEADBEEF");
		Assert.NotNull(meaning);
		Assert.Contains("Unknown SubStatus", meaning);
	}

	[Fact]
	public void Translate_NullOrBlank_ReturnsNull()
	{
		Assert.Null(SubStatusCatalog.Translate(null));
		Assert.Null(SubStatusCatalog.Translate(""));
		Assert.Null(SubStatusCatalog.Translate("   "));
	}

	[Theory]
	// Signed-decimal int32 form Windows / PowerShell render as Properties[Status] — pinned to the
	// real-host evidence the user pasted from Get-WinEvent: bad password / misc-logon-failure /
	// no-such-user surface as negative int32 in the raw event payload.
	[InlineData("-1073741718", "Bad Password")]         // 0xC000006A
	[InlineData("-1073741724", "No Such User")]         // 0xC0000064
	[InlineData("-1073741715", "Misc. Logon Failure")]  // 0xC000006D
	// Unsigned-decimal form (some Windows producers emit this).
	[InlineData("3221225578", "Bad Password")]
	[InlineData("3221225572", "No Such User")]
	public void Translate_AcceptsSignedAndUnsignedDecimal(string code, string expected)
	{
		Assert.Equal(expected, SubStatusCatalog.Translate(code));
	}
}
