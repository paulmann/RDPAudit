// File:    tests/RdpAudit.Core.Tests/QwinstaConsoleEncodingTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates that QwinstaConsoleEncoding registers the legacy code-page provider
//          and selects the right encoding for qwinsta stdout — cp866 for Russian (OEM
//          Cyrillic) hosts, cp437 for English ones. The mojibake regression on Russian
//          Windows came from .NET 8 defaulting Console.OutputEncoding to UTF-8, which
//          mis-decodes the Cyrillic state tokens emitted by qwinsta.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaConsoleEncodingTests
{
	[Fact]
	public void Resolve_RussianOemCodePage_DecodesActiveStateWithoutMojibake()
	{
		Encoding cp866 = QwinstaConsoleEncoding.Resolve(866);
		Assert.Equal(866, cp866.CodePage);

		// Pre-encode the Russian "Active" token the way qwinsta does on a Russian-locale host,
		// then verify the round-trip through the chosen encoding is byte-identical (i.e. no
		// mojibake will reach the parser).
		const string activeRussian = "Активно";
		byte[] bytes = cp866.GetBytes(activeRussian);
		string decoded = cp866.GetString(bytes);
		Assert.Equal(activeRussian, decoded);
	}

	[Fact]
	public void Resolve_RussianOutputDecodedAsUtf8_ProducesMojibake_DemonstratingPriorRegression()
	{
		Encoding cp866 = QwinstaConsoleEncoding.Resolve(866);
		byte[] bytes = cp866.GetBytes("Активно");

		// Decoding the cp866 bytes as UTF-8 (the pre-fix default) yields mojibake — the parser
		// would never recognise the Cyrillic state token in that shape, which is exactly the
		// regression the operator hit. This test pins the encoding choice — if we ever go
		// back to UTF-8, the failure mode is captured here.
		string asUtf8 = Encoding.UTF8.GetString(bytes);
		Assert.NotEqual("Активно", asUtf8);
	}

	[Fact]
	public void Resolve_EnglishOemCodePage_Returnscp437()
	{
		Encoding cp437 = QwinstaConsoleEncoding.Resolve(437);
		Assert.Equal(437, cp437.CodePage);
	}

	[Fact]
	public void Resolve_InvalidCodePage_FallsBackToCp437()
	{
		// This helper used to fall back to UTF-8 while OemConsoleEncoding fell back to cp437, so the
		// same redirected console bytes decoded two different ways depending on the call site. The
		// policy now lives in OemConsoleEncoding alone and cp437 is the shared fallback: it is a real
		// OEM console page, whereas UTF-8 is not what a legacy tool writes when its code page is unknown.
		Encoding encoding = QwinstaConsoleEncoding.Resolve(int.MaxValue);
		Assert.Equal(OemConsoleEncoding.Cp437, encoding.CodePage);
	}

	[Fact]
	public void Resolve_NegativeCodePage_FallsBackToCp437()
	{
		Encoding encoding = QwinstaConsoleEncoding.Resolve(-1);
		Assert.Equal(OemConsoleEncoding.Cp437, encoding.CodePage);
	}
}
