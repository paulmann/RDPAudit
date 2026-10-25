/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionContext.cs
// Project: RdpAudit.Core (RdpAudit.Core.Editions)
// Purpose: Resolves which edition THIS build is and answers capability questions about it. The value
//          comes from the RDPAUDIT_EDITION_* compilation constant declared in Directory.Build.props,
//          so a lower edition physically does not contain the gated components instead of trusting a
//          configuration switch that anyone could flip.
// Depends: System.Reflection, RdpAudit.Core.Editions.EditionMatrix
// Extends: Add a constant to Directory.Build.props and a branch here; both must stay in sync, which
//          EditionsTests pins.

using System.Reflection;

namespace RdpAudit.Core.Editions;

/// <summary>Edition of the running build plus the capability questions the rest of the product asks.</summary>
public static class EditionContext
{
	/// <summary>The edition this assembly was compiled for. Fixed at build time; never configurable.</summary>
	public static ProductEdition Current
	{
		get
		{
#if RDPAUDIT_EDITION_ENTERPRISE
			return ProductEdition.Enterprise;
#elif RDPAUDIT_EDITION_PRO
			return ProductEdition.Pro;
#else
			return ProductEdition.Community;
#endif
		}
	}

	/// <summary>Edition name ("Community", "Pro", "Enterprise").</summary>
	public static string DisplayName => EditionMatrix.DisplayName(Current);

	/// <summary>Licence this edition is distributed under.</summary>
	public static string LicenseName => EditionMatrix.LicenseName(Current);

	/// <summary>Highest cross-host correlation host count this edition may poll.</summary>
	public static int MaxCrossHostHosts => EditionMatrix.MaxCrossHostHosts(Current);

	/// <summary>Informational product version of the RdpAudit.Core assembly (includes the build SHA
	/// suffix in pipeline builds), or "unknown" when the attribute is absent.</summary>
	public static string ProductVersion => VersionString;

	/// <summary>Name of the compilation constant that produced <see cref="Current"/>; used by the
	/// startup announcement and the diagnostic surfaces so a mismatched build is obvious.</summary>
	public static string BuildConstantName
	{
		get
		{
#if RDPAUDIT_EDITION_ENTERPRISE
			return "RDPAUDIT_EDITION_ENTERPRISE";
#elif RDPAUDIT_EDITION_PRO
			return "RDPAUDIT_EDITION_PRO";
#else
			return "RDPAUDIT_EDITION_COMMUNITY";
#endif
		}
	}

	/// <summary>True when this build contains <paramref name="feature"/>.</summary>
	public static bool Allows(EditionFeature feature) => EditionMatrix.Allows(Current, feature);

	/// <summary>Operator-facing reason why <paramref name="feature"/> is not available in this build.</summary>
	public static string DenialReason(EditionFeature feature) => EditionMatrix.DenialReason(Current, feature);

	private static readonly string VersionString = ResolveVersion();

	private static string ResolveVersion()
	{
		AssemblyInformationalVersionAttribute? attribute =
			typeof(EditionContext).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
		return string.IsNullOrWhiteSpace(attribute?.InformationalVersion) ? "unknown" : attribute.InformationalVersion;
	}
}
