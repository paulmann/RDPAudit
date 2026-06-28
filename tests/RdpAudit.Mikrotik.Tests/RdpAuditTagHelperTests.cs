/*
 * File   : RdpAuditTagHelperTests.cs
 * Project: RdpAudit.Mikrotik.Tests
 * Purpose: Verifies the RdpAudit ownership comment tag is built in the exact mandated format and is
 *          recognised case-insensitively, while operator comments without the marker are not — this
 *          is the safety guarantee that rollback never deletes non-RdpAudit objects.
 * Depends: RdpAudit.Mikrotik.Helpers.RdpAuditTagHelper, Xunit
 * Extends: When the tag format changes, update these expectations and the helper together.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using RdpAudit.Mikrotik.Helpers;
using Xunit;

namespace RdpAudit.Mikrotik.Tests;

public sealed class RdpAuditTagHelperTests
{
	[Fact]
	public void BuildComment_ProducesExactMandatedFormat()
	{
		string comment = RdpAuditTagHelper.BuildComment("rdp blocklist drop");
		Assert.Equal("[rdpaudit: rdp blocklist drop] https://github.com/paulmann/RDPAudit", comment);
	}

	[Fact]
	public void BuildComment_FallsBackToManaged_WhenPurposeBlank()
	{
		string comment = RdpAuditTagHelper.BuildComment("   ");
		Assert.Equal("[rdpaudit: managed] https://github.com/paulmann/RDPAudit", comment);
	}

	[Fact]
	public void BuildComment_TrimsPurpose()
	{
		string comment = RdpAuditTagHelper.BuildComment("  service account  ");
		Assert.Equal("[rdpaudit: service account] https://github.com/paulmann/RDPAudit", comment);
	}

	[Theory]
	[InlineData("[rdpaudit: drop] https://github.com/paulmann/RDPAudit", true)]
	[InlineData("[RDPAUDIT: drop] something", true)]
	[InlineData("prefixed [rdpaudit: x] suffix", true)]
	[InlineData("RdpAudit auto-block", false)]
	[InlineData("operator managed rule", false)]
	[InlineData("", false)]
	[InlineData(null, false)]
	public void IsRdpAuditManaged_MatchesOnlyTaggedComments(string? comment, bool expected)
	{
		Assert.Equal(expected, RdpAuditTagHelper.IsRdpAuditManaged(comment));
	}

	[Fact]
	public void BuildComment_RoundTrips_ThroughIsRdpAuditManaged()
	{
		string comment = RdpAuditTagHelper.BuildComment("integration self-test");
		Assert.True(RdpAuditTagHelper.IsRdpAuditManaged(comment));
	}
}
