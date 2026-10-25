/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionsTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Pins the open-core matrix. The dangerous failure here is not an exception but a quiet
//          grant: a capability with no declared minimum, a comparison that lets a lower edition
//          through, or a host budget that grows downwards would ship without any other test noticing.
//          Every assertion therefore states the product decision, not the implementation.
// Extends: Add a case when a new capability or edition is declared.

using RdpAudit.Core.Editions;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Guards the edition matrix and the compile-time edition selection.</summary>
public class EditionsTests
{
	/// <summary>The edition ordinals are persisted (IPC payload, licence audit), so they are frozen.</summary>
	[Fact]
	public void EditionOrdinals_AreAppendOnly()
	{
		Assert.Equal(0, (int)ProductEdition.Community);
		Assert.Equal(1, (int)ProductEdition.Pro);
		Assert.Equal(2, (int)ProductEdition.Enterprise);
	}

	/// <summary>Feature ordinals travel in the IPC payload, so they are frozen too.</summary>
	[Fact]
	public void FeatureOrdinals_AreAppendOnly()
	{
		Assert.Equal(0, (int)EditionFeature.RestApi);
		Assert.Equal(1, (int)EditionFeature.CrossHostCorrelation);
		Assert.Equal(2, (int)EditionFeature.ZabbixIntegration);
		Assert.Equal(3, (int)EditionFeature.SiemExport);
		Assert.Equal(4, (int)EditionFeature.ResponseDryRun);
	}

	/// <summary>A capability without a declared minimum must fail loudly, never default to allowed.</summary>
	[Fact]
	public void UndeclaredFeature_ThrowsInsteadOfBeingAllowed()
	{
		EditionFeature unknown = (EditionFeature)999;
		Assert.Throws<ArgumentOutOfRangeException>(() => EditionMatrix.MinimumFor(unknown));
	}

	/// <summary>Every declared capability has a minimum, and no minimum is below Community.</summary>
	[Fact]
	public void EveryFeature_HasADeclaredMinimum()
	{
		Assert.NotEmpty(EditionMatrix.Features);
		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			ProductEdition minimum = EditionMatrix.MinimumFor(feature);
			Assert.True(Enum.IsDefined(typeof(ProductEdition), minimum), feature + " declares an unknown edition.");
			Assert.True(minimum >= ProductEdition.Community, feature + " declares a minimum below Community.");
		}
	}

	/// <summary>
	/// The open-core split itself: the Community edition contains NONE of the gated capabilities.
	/// This is the assertion that makes "Community is local-only" a fact rather than a description.
	/// </summary>
	[Fact]
	public void Community_ContainsNoGatedCapability()
	{
		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			Assert.False(EditionMatrix.Allows(ProductEdition.Community, feature), "Community must not contain " + feature + ".");
			Assert.False(EditionMatrix.FeaturesOf(ProductEdition.Community).Contains(feature), "FeaturesOf(Community) leaked " + feature + ".");
		}
	}

	/// <summary>A higher edition contains everything a lower one does — the matrix is ordered.</summary>
	[Fact]
	public void HigherEdition_ContainsEveryLowerCapability()
	{
		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			ProductEdition minimum = EditionMatrix.MinimumFor(feature);
			foreach (ProductEdition edition in EditionMatrix.Editions)
			{
				bool expected = edition >= minimum;
				Assert.Equal(expected, EditionMatrix.Allows(edition, feature));
			}
		}
	}

	/// <summary>The Pro edition is what carries the integrations: every gated feature is usable there.</summary>
	[Fact]
	public void Pro_ContainsEveryGatedCapability()
	{
		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			Assert.True(EditionMatrix.Allows(ProductEdition.Pro, feature), "Pro must contain " + feature + ".");
		}
	}

	/// <summary>The cross-host budget grows with the edition and is zero exactly where the feature is absent.</summary>
	[Fact]
	public void CrossHostBudget_IsMonotonicAndZeroInCommunity()
	{
		Assert.Equal(0, EditionMatrix.MaxCrossHostHosts(ProductEdition.Community));
		Assert.True(EditionMatrix.MaxCrossHostHosts(ProductEdition.Pro) > 0);
		Assert.True(EditionMatrix.MaxCrossHostHosts(ProductEdition.Enterprise) > EditionMatrix.MaxCrossHostHosts(ProductEdition.Pro));

		// A budget above zero on a build that cannot correlate would promise a fleet nobody polls.
		Assert.Equal(
			EditionMatrix.Allows(ProductEdition.Community, EditionFeature.CrossHostCorrelation),
			EditionMatrix.MaxCrossHostHosts(ProductEdition.Community) > 0);
	}

	/// <summary>A refusal must name the edition that would work, otherwise the operator files a bug.</summary>
	[Fact]
	public void DenialReason_NamesRequiredEditionAndCurrentBuild()
	{
		string reason = EditionMatrix.DenialReason(ProductEdition.Community, EditionFeature.RestApi);
		Assert.Contains("RestApi", reason, StringComparison.Ordinal);
		Assert.Contains("Pro", reason, StringComparison.Ordinal);
		Assert.Contains("Community", reason, StringComparison.Ordinal);
	}

	/// <summary>Names and licences are part of the operator surface and the IPC payload.</summary>
	[Fact]
	public void EditionNamesAndLicences_AreStable()
	{
		Assert.Equal("Community", EditionMatrix.DisplayName(ProductEdition.Community));
		Assert.Equal("Pro", EditionMatrix.DisplayName(ProductEdition.Pro));
		Assert.Equal("Enterprise", EditionMatrix.DisplayName(ProductEdition.Enterprise));
		Assert.Equal("BSL-1.1", EditionMatrix.LicenseName(ProductEdition.Community));
		Assert.Equal("Proprietary", EditionMatrix.LicenseName(ProductEdition.Pro));
		Assert.Equal("Proprietary", EditionMatrix.LicenseName(ProductEdition.Enterprise));
	}

	/// <summary>
	/// The build actually carries an edition, and its answers agree with the matrix — this is the one
	/// test whose outcome differs between the three trees on purpose.
	/// </summary>
	[Fact]
	public void CurrentBuild_ReportsAMatrixConsistentEdition()
	{
		Assert.True(Enum.IsDefined(typeof(ProductEdition), EditionContext.Current));
		Assert.Equal(EditionMatrix.DisplayName(EditionContext.Current), EditionContext.DisplayName);
		Assert.Equal(EditionMatrix.MaxCrossHostHosts(EditionContext.Current), EditionContext.MaxCrossHostHosts);
		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			Assert.Equal(EditionMatrix.Allows(EditionContext.Current, feature), EditionContext.Allows(feature));
		}

		Assert.False(string.IsNullOrWhiteSpace(EditionContext.BuildConstantName));
		Assert.False(string.IsNullOrWhiteSpace(EditionContext.ProductVersion));

		// The build constant and the selected edition must not disagree: a tree that sets the constant
		// but forgets the branch (or the reverse) would ship a mislabelled binary.
		string expectedConstant = "RDPAUDIT_EDITION_" + EditionContext.DisplayName.ToUpperInvariant();
		Assert.Equal(expectedConstant, EditionContext.BuildConstantName);
	}
}
