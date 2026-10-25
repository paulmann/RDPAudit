/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixLinks.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: Builds the frontend links the tab opens. The URL shape was verified against the live
//          instance on 2026-10-25: the filtered Problems view and a dashboard view both answer 200.
//          Kept in one place so the "one window" link cannot drift between the tab, the docs and a
//          provisioning message. The canonical builders return a URI and the text helpers below them
//          serve DTOs, which carry strings.
// Extends: System.Object

using System.Globalization;

namespace RdpAudit.Core.Zabbix;

/// <summary>Frontend links for the integration.</summary>
public static class ZabbixLinks
{
	/// <summary>Tag name every problem of this integration carries.</summary>
	public const string ScopeTagName = "scope";

	/// <summary>Tag value every problem of this integration carries.</summary>
	public const string ScopeTagValue = "rdpaudit";

	/// <summary>Problems view filtered to the integration tag: every machine in one list.</summary>
	/// <param name="frontendOrigin">Scheme and authority, for example <c>https://22877.ru</c>.</param>
	/// <returns>The URI, or null when the origin is not usable.</returns>
	public static Uri? BuildProblemsUri(string? frontendOrigin)
	{
		if (string.IsNullOrWhiteSpace(frontendOrigin))
		{
			return null;
		}

		string text = string.Format(
			CultureInfo.InvariantCulture,
			"{0}/zabbix.php?action=problem.view&filter_set=1&tags%5B0%5D%5Btag%5D={1}&tags%5B0%5D%5Bvalue%5D={2}&tags%5B0%5D%5Boperator%5D=1",
			frontendOrigin.TrimEnd('/'),
			Uri.EscapeDataString(ScopeTagName),
			Uri.EscapeDataString(ScopeTagValue));

		return Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) ? uri : null;
	}

	/// <summary>Dashboard view showing the shared "one window" dashboard.</summary>
	/// <param name="frontendOrigin">Scheme and authority.</param>
	/// <returns>The URI, or null when the origin is not usable.</returns>
	public static Uri? BuildDashboardUri(string? frontendOrigin)
	{
		if (string.IsNullOrWhiteSpace(frontendOrigin))
		{
			return null;
		}

		string text = frontendOrigin.TrimEnd('/') + "/zabbix.php?action=dashboard.view";
		return Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) ? uri : null;
	}

	/// <summary>Text form of <see cref="BuildProblemsUri"/> for DTOs and log lines.</summary>
	/// <param name="frontendOrigin">Scheme and authority.</param>
	/// <returns>The URL text, or an empty string when the origin is not usable.</returns>
	public static string BuildProblemsText(string? frontendOrigin)
		=> BuildProblemsUri(frontendOrigin)?.AbsoluteUri ?? string.Empty;

	/// <summary>Text form of <see cref="BuildDashboardUri"/> for DTOs and log lines.</summary>
	/// <param name="frontendOrigin">Scheme and authority.</param>
	/// <returns>The URL text, or an empty string when the origin is not usable.</returns>
	public static string BuildDashboardText(string? frontendOrigin)
		=> BuildDashboardUri(frontendOrigin)?.AbsoluteUri ?? string.Empty;
}
