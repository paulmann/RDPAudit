// File:    src/RdpAudit.Configurator/Services/IpReputationBrowser.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Shared helper that turns an IP-bearing UI action into the matching third-party reputation
//          lookup. Reuses RdpAudit.Core.Util.IpReputationUrlBuilder for the URL composition and
//          opens the result in the operator's default browser via ProcessStartInfo + UseShellExecute.
//          Centralised so every Configurator page can wire RIPEstat / AbuseIPDB context-menu items
//          without duplicating the validation + Process.Start ceremony.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Opens RIPEstat / AbuseIPDB deep links for an IP cell in the operator's default browser.</summary>
[SupportedOSPlatform("windows")]
public static class IpReputationBrowser
{
	/// <summary>Default operator-facing label used by every RIPEstat context menu item.</summary>
	public const string RipeStatMenuLabel = "Open in RIPEstat";

	/// <summary>Default operator-facing label used by every AbuseIPDB context menu item.</summary>
	public const string AbuseIpDbMenuLabel = "Open in AbuseIPDB";

	/// <summary>Returns true when the supplied IP is eligible for an external reputation lookup.</summary>
	public static bool IsLookupEligible(string? ip) => IpReputationUrlBuilder.IsLookupEligible(ip);

	/// <summary>Opens the RIPEstat overview page for <paramref name="ip"/>; returns a structured outcome.</summary>
	public static LaunchOutcome OpenRipeStat(string? ip) => Launch(ip, IpReputationUrlBuilder.BuildRipeStat, "RIPEstat");

	/// <summary>Opens the AbuseIPDB check page for <paramref name="ip"/>; returns a structured outcome.</summary>
	public static LaunchOutcome OpenAbuseIpDb(string? ip) => Launch(ip, IpReputationUrlBuilder.BuildAbuseIpDb, "AbuseIPDB");

	private static LaunchOutcome Launch(string? ip, Func<string?, IpReputationUrlBuilder.Result> compose, string service)
	{
		IpReputationUrlBuilder.Result built = compose(ip);
		if (!built.Ok)
		{
			return LaunchOutcome.Refused(service, built.Error ?? "Unknown validation failure.");
		}

		try
		{
			Process.Start(new ProcessStartInfo(built.Url) { UseShellExecute = true });
			return LaunchOutcome.Launched(service, built.Url);
		}
		catch (Exception ex)
		{
			string reason = string.Format(CultureInfo.InvariantCulture,
				"{0}: {1}", ex.GetType().Name, ex.Message);
			return LaunchOutcome.Failed(service, built.Url, reason);
		}
	}

	/// <summary>Structured result for a deep-link launch attempt.</summary>
	public sealed class LaunchOutcome
	{
		/// <summary>Service that was targeted (RIPEstat / AbuseIPDB).</summary>
		public string Service { get; init; } = string.Empty;

		/// <summary>True when the OS accepted the open request. The browser may still surface a network error.</summary>
		public bool Started { get; init; }

		/// <summary>Composed URL when validation succeeded; empty string otherwise.</summary>
		public string Url { get; init; } = string.Empty;

		/// <summary>Operator-facing reason when <see cref="Started"/> is false; null otherwise.</summary>
		public string? Error { get; init; }

		/// <summary>Renders a status-strip-friendly summary line for the outcome.</summary>
		public string Format()
		{
			if (Started)
			{
				return string.Format(CultureInfo.InvariantCulture, "Opened {0}: {1}", Service, Url);
			}

			return string.Format(CultureInfo.InvariantCulture, "{0} lookup FAILED: {1}", Service, Error ?? "no detail");
		}

		internal static LaunchOutcome Launched(string service, string url) => new()
		{
			Service = service,
			Started = true,
			Url = url,
		};

		internal static LaunchOutcome Refused(string service, string error) => new()
		{
			Service = service,
			Started = false,
			Error = error,
		};

		internal static LaunchOutcome Failed(string service, string url, string error) => new()
		{
			Service = service,
			Started = false,
			Url = url,
			Error = error,
		};
	}
}
