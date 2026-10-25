// File:    tests/RdpAudit.Core.Tests/Siem/SiemSerializerFactoryTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Locks the SiemSerializerFactory contract: serializer resolution per format, the
//          SaveFileDialog file name helpers, extension / filter mapping and IP sanitisation.
// Depends: SiemSerializerFactory, SiemFormat, xUnit
// Extends: Append a case whenever a format or file-name feature is added.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class SiemSerializerFactoryTests
{
	[Theory]
	[InlineData(SiemFormat.Cef, typeof(CefSerializer))]
	[InlineData(SiemFormat.Leef, typeof(LeefSerializer))]
	[InlineData(SiemFormat.JsonNdjson, typeof(SiemJsonSerializer))]
	public void GetSerializer_ResolvesConcreteType(SiemFormat format, Type expected)
	{
		ISiemEventSerializer serializer = SiemSerializerFactory.GetSerializer(format);
		Assert.IsType(expected, serializer);
	}

	[Fact]
	public void GetSerializer_UnknownFormat_Throws()
	{
		Assert.Throws<ArgumentOutOfRangeException>(
			() => SiemSerializerFactory.GetSerializer((SiemFormat)99));
	}

	[Theory]
	[InlineData(SiemFormat.Cef, ".cef")]
	[InlineData(SiemFormat.Leef, ".leef")]
	[InlineData(SiemFormat.JsonNdjson, ".json")]
	public void GetFileExtension_IsCanonical(SiemFormat format, string expected) =>
		Assert.Equal(expected, SiemSerializerFactory.GetFileExtension(format));

	[Theory]
	[InlineData(SiemFormat.Cef, "CEF (*.cef)|*.cef")]
	[InlineData(SiemFormat.Leef, "LEEF (*.leef)|*.leef")]
	[InlineData(SiemFormat.JsonNdjson, "JSON Lines (*.json)|*.json")]
	public void GetSaveFileFilter_IsStable(SiemFormat format, string expected) =>
		Assert.Equal(expected, SiemSerializerFactory.GetSaveFileFilter(format));

	[Fact]
	public void GetDefaultFileName_UsesIpStampAndExtension()
	{
		DateTime now = new(2026, 9, 12, 13, 45, 0, DateTimeKind.Utc);
		string name = SiemSerializerFactory.GetDefaultFileName("203.0.113.7", SiemFormat.Cef, now);
		Assert.Equal("rdpaudit-siem-203.0.113.7-20260912-134500.cef", name);
	}

	[Fact]
	public void GetDefaultFileName_SanitisesIpv6()
	{
		DateTime now = new(2026, 9, 12, 13, 45, 0, DateTimeKind.Utc);
		string name = SiemSerializerFactory.GetDefaultFileName("2001:db8::1", SiemFormat.Leef, now);
		Assert.Equal("rdpaudit-siem-2001_db8__1-20260912-134500.leef", name);
	}

	[Fact]
	public void GetDefaultFileName_EmptyIp_FallsBackToIpLiteral()
	{
		DateTime now = new(2026, 9, 12, 13, 45, 0, DateTimeKind.Utc);
		string name = SiemSerializerFactory.GetDefaultFileName(" ", SiemFormat.JsonNdjson, now);
		Assert.Equal("rdpaudit-siem-ip-20260912-134500.json", name);
	}

	[Fact]
	public void GetDefaultFileName_MatchesExtensionForEveryFormat()
	{
		DateTime now = new(2026, 9, 12, 13, 45, 0, DateTimeKind.Utc);
		foreach (SiemFormat format in Enum.GetValues<SiemFormat>())
		{
			string name = SiemSerializerFactory.GetDefaultFileName("10.0.0.1", format, now);
			Assert.EndsWith(SiemSerializerFactory.GetFileExtension(format), name);
		}
	}
}
