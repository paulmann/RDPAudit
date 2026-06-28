// File:    tests/RdpAudit.Core.Tests/ScDeleteOutputFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 — locks the English-fallback behaviour of the sc.exe delete output
//          formatter. The Service tab uninstall dialog must always show a readable
//          English banner, regardless of operator locale or whether the captured sc.exe
//          output decoded correctly.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ScDeleteOutputFormatterTests
{
	[Fact]
	public void ComposeSuccess_NullOutput_ReturnsEnglishBanner()
	{
		Assert.Equal("[SC] DeleteService SUCCESS", ScDeleteOutputFormatter.ComposeSuccess(null));
	}

	[Fact]
	public void ComposeSuccess_EmptyOutput_ReturnsEnglishBanner()
	{
		Assert.Equal("[SC] DeleteService SUCCESS", ScDeleteOutputFormatter.ComposeSuccess(string.Empty));
		Assert.Equal("[SC] DeleteService SUCCESS", ScDeleteOutputFormatter.ComposeSuccess("   \r\n\t"));
	}

	[Fact]
	public void ComposeSuccess_ReadableEnglishOutput_AppendsNative()
	{
		string detail = ScDeleteOutputFormatter.ComposeSuccess("[SC] DeleteService SUCCESS");
		Assert.StartsWith("[SC] DeleteService SUCCESS", detail);
		Assert.Contains("[SC] DeleteService SUCCESS", detail);
	}

	[Fact]
	public void ComposeSuccess_ReadableLocalizedCyrillicOutput_AppendsNative()
	{
		string detail = ScDeleteOutputFormatter.ComposeSuccess("[SC] DeleteService: успех");
		Assert.StartsWith("[SC] DeleteService SUCCESS", detail);
		Assert.Contains("успех", detail);
	}

	[Fact]
	public void ComposeSuccess_GarbledOutput_FallsBackToEnglishBannerOnly()
	{
		string garbled = new('�', 12);
		Assert.Equal("[SC] DeleteService SUCCESS", ScDeleteOutputFormatter.ComposeSuccess(garbled));
	}

	[Fact]
	public void ComposeFailure_IncludesExitCode()
	{
		string detail = ScDeleteOutputFormatter.ComposeFailure(5, null);
		Assert.Equal("[SC] DeleteService FAILED exit=5", detail);
	}

	[Fact]
	public void ComposeFailure_ReadableNativeMessage_IsAppended()
	{
		string detail = ScDeleteOutputFormatter.ComposeFailure(5, "Access is denied.");
		Assert.StartsWith("[SC] DeleteService FAILED exit=5", detail);
		Assert.Contains("Access is denied.", detail);
	}

	[Fact]
	public void ComposeFailure_GarbledOutput_FallsBackToBannerOnly()
	{
		string garbled = new('�', 10);
		string detail = ScDeleteOutputFormatter.ComposeFailure(1, garbled);
		Assert.Equal("[SC] DeleteService FAILED exit=1", detail);
	}

	[Fact]
	public void IsReadable_EmptyOrWhitespace_ReturnsFalse()
	{
		Assert.False(ScDeleteOutputFormatter.IsReadable(string.Empty));
		Assert.False(ScDeleteOutputFormatter.IsReadable("   "));
	}

	[Fact]
	public void IsReadable_PlainEnglish_ReturnsTrue()
	{
		Assert.True(ScDeleteOutputFormatter.IsReadable("[SC] DeleteService SUCCESS"));
	}

	[Fact]
	public void IsReadable_Cyrillic_ReturnsTrue()
	{
		Assert.True(ScDeleteOutputFormatter.IsReadable("успех"));
	}

	[Fact]
	public void IsReadable_AllReplacementChars_ReturnsFalse()
	{
		Assert.False(ScDeleteOutputFormatter.IsReadable("�����"));
	}
}
