/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionInfoHandlerTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Asserts the payload of the GetEditionInfo command (ordinal 102) against the edition this
//          build was compiled for. The command is the operator's only way to prove which package is
//          installed when every other subsystem is degraded, so the payload - not just the matrix -
//          has to be pinned: a wrong ordinal, a missing capability row or a budget that disagrees with
//          the matrix would send an operator to the wrong conclusion.
// Extends: Add a case when the DTO gains a member.

using RdpAudit.Core.Editions;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Service.Ipc;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Pins the edition report the service returns over IPC.</summary>
public class EditionInfoHandlerTests
{
	/// <summary>The payload describes exactly this build: edition, ordinal, licence, version, budget.</summary>
	[Fact]
	public void Handler_ReportsThisBuild()
	{
		EditionInfoDto dto = IpcDispatcher.GetEditionInfoHandler();

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(EditionContext.DisplayName, dto.Edition);
		Assert.Equal((int)EditionContext.Current, dto.EditionOrdinal);
		Assert.Equal(EditionContext.LicenseName, dto.License);
		Assert.Equal(EditionContext.BuildConstantName, dto.BuildConstant);
		Assert.Equal(EditionContext.ProductVersion, dto.ProductVersion);
		Assert.Equal(EditionContext.MaxCrossHostHosts, dto.MaxCrossHostHosts);
		Assert.False(string.IsNullOrWhiteSpace(dto.ProductVersion));
		Assert.Contains(dto.Edition, dto.Message, StringComparison.Ordinal);
	}

	/// <summary>Every capability of the product appears once, with the minimum edition and this build's answer.</summary>
	[Fact]
	public void Handler_ListsEveryCapabilityWithItsMinimumAndAvailability()
	{
		EditionInfoDto dto = IpcDispatcher.GetEditionInfoHandler();

		Assert.Equal(EditionMatrix.Features.Count, dto.Features.Count);

		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			EditionFeatureDto row = dto.Features.Single(f => string.Equals(f.Feature, feature.ToString(), StringComparison.Ordinal));
			Assert.Equal(EditionMatrix.DisplayName(EditionMatrix.MinimumFor(feature)), row.MinimumEdition);
			Assert.Equal(EditionContext.Allows(feature), row.Available);
		}
	}

	/// <summary>
	/// A capability the build does not contain must be reported as unavailable together with a minimum
	/// edition ABOVE the current one - a row saying "unavailable, minimum Community" would be nonsense.
	/// </summary>
	[Fact]
	public void Handler_UnavailableCapabilities_DeclareAHigherMinimum()
	{
		EditionInfoDto dto = IpcDispatcher.GetEditionInfoHandler();

		foreach (EditionFeatureDto row in dto.Features)
		{
			if (row.Available)
			{
				continue;
			}

			EditionFeature feature = Enum.Parse<EditionFeature>(row.Feature);
			Assert.True(
				EditionMatrix.MinimumFor(feature) > EditionContext.Current,
				row.Feature + " is reported unavailable but its minimum edition is not above the current one.");
		}
	}
}
