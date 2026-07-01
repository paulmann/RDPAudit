// File:    tests/RdpAudit.Core.Tests/LogonTypeCatalogTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the LogonTypeCatalog decoding contract: well-known Windows logon type codes
//          decode to their canonical short names, unknown codes fall back gracefully without
//          throwing, and the inline formatter produces a stable, non-null tooltip string
//          (including a dedicated message for a null code).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Coverage for the Windows logon-type decoding catalog.</summary>
public class LogonTypeCatalogTests
{
	[Theory]
	[InlineData(0, "System")]
	[InlineData(2, "Interactive")]
	[InlineData(3, "Network")]
	[InlineData(4, "Batch")]
	[InlineData(5, "Service")]
	[InlineData(7, "Unlock")]
	[InlineData(8, "NetworkCleartext")]
	[InlineData(9, "NewCredentials")]
	[InlineData(10, "RemoteInteractive")]
	[InlineData(11, "CachedInteractive")]
	[InlineData(12, "CachedRemoteInteractive")]
	[InlineData(13, "CachedUnlock")]
	public void Describe_KnownCode_ReturnsCanonicalName(int code, string expectedName)
	{
		LogonTypeInfo info = LogonTypeCatalog.Describe(code);

		Assert.Equal(code, info.Code);
		Assert.Equal(expectedName, info.Name);
		Assert.False(string.IsNullOrWhiteSpace(info.Description));
	}

	[Fact]
	public void Describe_RemoteInteractive_MentionsRdp()
	{
		LogonTypeInfo info = LogonTypeCatalog.Describe(10);

		Assert.Contains("RDP", info.Description, System.StringComparison.OrdinalIgnoreCase);
	}

	[Theory]
	[InlineData(99)]
	[InlineData(-1)]
	[InlineData(int.MaxValue)]
	public void Describe_UnknownCode_ReturnsGracefulFallback(int code)
	{
		LogonTypeInfo info = LogonTypeCatalog.Describe(code);

		Assert.Equal(code, info.Code);
		Assert.Equal("Unknown", info.Name);
		Assert.False(string.IsNullOrWhiteSpace(info.Description));
	}

	[Fact]
	public void NameOf_KnownCode_ReturnsName()
	{
		Assert.Equal("Network", LogonTypeCatalog.NameOf(3));
	}

	[Fact]
	public void DescribeInline_NullCode_ReturnsNotAvailableMessage()
	{
		string text = LogonTypeCatalog.DescribeInline(null);

		Assert.False(string.IsNullOrWhiteSpace(text));
		Assert.Contains("not available", text, System.StringComparison.OrdinalIgnoreCase);
	}

	[Theory]
	[InlineData(3, "Network")]
	[InlineData(10, "RemoteInteractive")]
	public void DescribeInline_KnownCode_ContainsCodeAndName(int code, string expectedName)
	{
		string text = LogonTypeCatalog.DescribeInline(code);

		Assert.Contains(code.ToString(System.Globalization.CultureInfo.InvariantCulture), text, System.StringComparison.Ordinal);
		Assert.Contains(expectedName, text, System.StringComparison.Ordinal);
	}

	[Fact]
	public void DescribeInline_UnknownCode_DoesNotThrowAndIsNonEmpty()
	{
		string text = LogonTypeCatalog.DescribeInline(4242);

		Assert.False(string.IsNullOrWhiteSpace(text));
		Assert.Contains("Unknown", text, System.StringComparison.Ordinal);
	}
}
