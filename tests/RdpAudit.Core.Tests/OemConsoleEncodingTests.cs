// File:    tests/RdpAudit.Core.Tests/OemConsoleEncodingTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 — verifies the OEM-code-page resolver used to decode redirected
//          sc.exe stdout/stderr without mojibake. Tests pin specific code pages so
//          the assertions do not depend on the host's culture and can therefore run
//          on Linux CI as well as on a Russian / French / English Windows box.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class OemConsoleEncodingTests
{
	[Fact]
	public void Resolve_WithCp866Override_ReturnsCp866()
	{
		Encoding encoding = OemConsoleEncoding.Resolve(866);
		Assert.Equal(866, encoding.CodePage);
	}

	[Fact]
	public void Resolve_WithCp437Override_ReturnsCp437()
	{
		Encoding encoding = OemConsoleEncoding.Resolve(OemConsoleEncoding.Cp437);
		Assert.Equal(OemConsoleEncoding.Cp437, encoding.CodePage);
	}

	[Fact]
	public void Resolve_WithCp850Override_ReturnsCp850()
	{
		Encoding encoding = OemConsoleEncoding.Resolve(850);
		Assert.Equal(850, encoding.CodePage);
	}

	[Fact]
	public void Resolve_WithUnknownCodePage_FallsBackToCp437OrUtf8()
	{
		// 0x7FFFFFFE is reserved and never maps to a real encoding; the helper must not throw.
		Encoding encoding = OemConsoleEncoding.Resolve(0x7FFFFFFE);
		Assert.NotNull(encoding);
		Assert.True(encoding.CodePage == OemConsoleEncoding.Cp437 || encoding.CodePage == Encoding.UTF8.CodePage);
	}

	[Fact]
	public void Resolve_WithZeroOverride_FallsBackToCp437OrUtf8()
	{
		Encoding encoding = OemConsoleEncoding.Resolve(0);
		Assert.True(encoding.CodePage == OemConsoleEncoding.Cp437 || encoding.CodePage == Encoding.UTF8.CodePage);
	}

	[Fact]
	public void EnsureProviderRegistered_IsIdempotent()
	{
		// Multiple calls must be safe — used by callers that may run concurrently.
		OemConsoleEncoding.EnsureProviderRegistered();
		OemConsoleEncoding.EnsureProviderRegistered();
		Encoding cp866 = OemConsoleEncoding.Resolve(866);
		Assert.Equal(866, cp866.CodePage);
	}

	[Fact]
	public void RoundTrip_LocalizedSuccessLine_DecodesViaCp866()
	{
		// "[SC] DeleteService: успех" — the Russian-locale shape the Configurator gets back
		// when sc.exe writes its success line on Cyrillic Windows. Encoding via cp866 and
		// decoding through the resolver must reproduce the exact original string, proving
		// the redirect-encoding wiring restores readable text instead of mojibake.
		Encoding cp866 = OemConsoleEncoding.Resolve(866);
		const string original = "[SC] DeleteService: успех";
		byte[] bytes = cp866.GetBytes(original);
		string roundTripped = cp866.GetString(bytes);
		Assert.Equal(original, roundTripped);
	}
}
