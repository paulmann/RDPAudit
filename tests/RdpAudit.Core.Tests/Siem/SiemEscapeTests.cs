// File:    tests/RdpAudit.Core.Tests/Siem/SiemEscapeTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Locks the strict per-format escaping table directly: backslash / pipe / equals /
//          caret escapes and CR / LF / TAB neutralisation, plus null / empty handling.
// Depends: SiemEscape, xUnit
// Extends: Append a case whenever an escape or neutralisation rule changes.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class SiemEscapeTests
{
	[Theory]
	[InlineData(null, "")]
	[InlineData("", "")]
	[InlineData("plain", "plain")]
	public void CefHeader_NullEmptyPlain(string? input, string expected)
	{
		Assert.Equal(expected, SiemEscape.CefHeader(input));
	}

	[Fact]
	public void CefHeader_EscapesBackslashPipeAndNeutralisesWhitespace()
	{
		string input = "a\\b|c\nd\re\tf";
		string actual = SiemEscape.CefHeader(input);
		Assert.Equal("a\\\\b\\|c d e f", actual);
	}

	[Fact]
	public void CefExtensionValue_EscapesBackslashEqualsPipe()
	{
		string input = "a=b|c\\d";
		string actual = SiemEscape.CefExtensionValue(input);
		Assert.Equal("a\\=b\\|c\\\\d", actual);
	}

	[Fact]
	public void CefExtensionValue_NeutralisesWhitespace()
	{
		string actual = SiemEscape.CefExtensionValue("x\r\ny\tz");
		Assert.Equal("x  y z", actual);
	}

	[Fact]
	public void LeefValue_EscapesBackslashCaretPipe()
	{
		string input = "a^b|c\\d";
		string actual = SiemEscape.LeefValue(input);
		Assert.Equal("a\\^b\\|c\\\\d", actual);
	}

	[Fact]
	public void LeefValue_NeutralisesWhitespace()
	{
		string actual = SiemEscape.LeefValue("x\ny\rz\ts");
		Assert.Equal("x y z s", actual);
	}

	[Fact]
	public void LeefHeader_UsesCefHeaderRules()
	{
		string input = "a|b\\c\td";
		Assert.Equal(SiemEscape.CefHeader(input), SiemEscape.LeefHeader(input));
		Assert.Equal("a\\|b\\\\c d", SiemEscape.LeefHeader(input));
	}
}
