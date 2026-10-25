/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionMatrix.cs
// Project: RdpAudit.Core (RdpAudit.Core.Editions)
// Purpose: The single source of truth for the open-core split: which edition a capability needs, how
//          many hosts an edition may correlate, and how each edition presents itself. Every enforcement
//          site asks this class instead of comparing editions by hand, so a change of the product
//          matrix is one edit with one test gate (EditionsTests).
// Depends: System, System.Globalization
// Extends: Declare a new feature in MinimumFor, add a limit method when the edition widens a bound.

using System.Globalization;

namespace RdpAudit.Core.Editions;

/// <summary>Capability matrix and per-edition limits.</summary>
public static class EditionMatrix
{
	/// <summary>Every feature the product knows about, in ordinal order.</summary>
	public static readonly IReadOnlyList<EditionFeature> Features =
		Array.AsReadOnly((EditionFeature[])Enum.GetValues(typeof(EditionFeature)));

	private static readonly IReadOnlyList<ProductEdition> AllEditions =
		Array.AsReadOnly((ProductEdition[])Enum.GetValues(typeof(ProductEdition)));

	/// <summary>All editions, ordered from the lowest to the highest.</summary>
	public static IReadOnlyList<ProductEdition> Editions => AllEditions;

	/// <summary>The lowest edition that contains <paramref name="feature"/>.</summary>
	/// <exception cref="ArgumentOutOfRangeException">The feature has no declared minimum. This is a
	/// defect by construction: an undeclared feature must never be treated as allowed.</exception>
	public static ProductEdition MinimumFor(EditionFeature feature) => feature switch
	{
		EditionFeature.RestApi => ProductEdition.Pro,
		EditionFeature.CrossHostCorrelation => ProductEdition.Pro,
		EditionFeature.ZabbixIntegration => ProductEdition.Pro,
		EditionFeature.SiemExport => ProductEdition.Pro,
		EditionFeature.ResponseDryRun => ProductEdition.Pro,
		_ => throw new ArgumentOutOfRangeException(
			nameof(feature),
			feature,
			"No edition is declared for this feature. Declare it in EditionMatrix.MinimumFor."),
	};

	/// <summary>True when <paramref name="edition"/> contains <paramref name="feature"/>.</summary>
	public static bool Allows(ProductEdition edition, EditionFeature feature) =>
		edition >= MinimumFor(feature);

	/// <summary>Human-readable edition name used in logs, IPC payloads and the UI title.</summary>
	public static string DisplayName(ProductEdition edition) => edition switch
	{
		ProductEdition.Community => "Community",
		ProductEdition.Pro => "Pro",
		ProductEdition.Enterprise => "Enterprise",
		_ => throw new ArgumentOutOfRangeException(nameof(edition), edition, "Unknown edition."),
	};

	/// <summary>Licence the edition is distributed under.</summary>
	public static string LicenseName(ProductEdition edition) => edition switch
	{
		ProductEdition.Community => "BSL-1.1",
		ProductEdition.Pro => "Proprietary",
		ProductEdition.Enterprise => "Proprietary",
		_ => throw new ArgumentOutOfRangeException(nameof(edition), edition, "Unknown edition."),
	};

	/// <summary>
	/// Maximum number of cross-host correlation hosts an edition polls. Community cannot use the
	/// feature at all, which is why its budget is zero rather than "unset".
	/// </summary>
	/// <remarks>
	/// The value is a licensing bound, not a performance bound: the worker still clamps and still
	/// reports how many configured hosts were left out, so an operator can never believe the whole
	/// fleet is being correlated when only part of it is.
	/// </remarks>
	public static int MaxCrossHostHosts(ProductEdition edition) => edition switch
	{
		ProductEdition.Community => 0,
		ProductEdition.Pro => 25,
		ProductEdition.Enterprise => 500,
		_ => throw new ArgumentOutOfRangeException(nameof(edition), edition, "Unknown edition."),
	};

	/// <summary>Operator-facing sentence explaining why a feature is unavailable in this build.</summary>
	public static string DenialReason(ProductEdition edition, EditionFeature feature)
	{
		string required = DisplayName(MinimumFor(feature));
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0} requires the {1} edition; this build is {2} ({3}). Install the {1} build to use it.",
			feature,
			required,
			DisplayName(edition),
			LicenseName(edition));
	}

	/// <summary>Features this edition contains, in ordinal order.</summary>
	public static IReadOnlyList<EditionFeature> FeaturesOf(ProductEdition edition)
	{
		List<EditionFeature> allowed = new(Features.Count);
		foreach (EditionFeature feature in Features)
		{
			if (Allows(edition, feature))
			{
				allowed.Add(feature);
			}
		}

		return allowed.AsReadOnly();
	}
}
