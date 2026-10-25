// File:    src/RdpAudit.Configurator/Services/NotificationCatalogInfo.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Pure notification-visibility catalog shared by the Notifications tab and its tests.
//          It enumerates every registered alert rule with its default severity and defines the
//          default visibility rules: alert rules are shown unless hidden, catalog events are
//          shown by default only at High/Critical.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Services;

/// <summary>Static notification visibility catalog used by the Notifications tab.</summary>
public static class NotificationCatalogInfo
{
	/// <summary>One registered alert rule with its default severity.</summary>
	public sealed record AlertRule(string RuleId, AlertSeverity Severity);

	/// <summary>All registered alert rules as id:severity entries, pipe-separated.</summary>
	public const string AlertRuleCatalogCsv =
		"BRUTE_FORCE_01:High|BRUTE_FORCE_NTLM:Medium|PASS_THE_HASH:High|GOLDEN_TICKET:Critical|OFF_HOURS_LOGIN:Low|EXTERNAL_RDP_LOGIN:Medium|" +
		"RDP_SESSION_HIJACK:Critical|RAPID_RECONNECT:Medium|UNKNOWN_IP_SUCCESS:Low|PRIVILEGED_LOGIN:Medium|RDP_PORT_CHANGED:Critical|KERBEROS_SPRAY:High|" +
		"STICKY_KEYS_BACKDOOR:Critical|TASK_PERSISTENCE:High|LSASS_ACCESS:Critical|SERVICE_INSTALL:High|TASK_MODIFIED:Medium|LSASS_PPL_TAMPER:Critical|" +
		"PRIVILEGED_GROUP_CHANGE:High|NEW_ACCOUNT:High|PROCESS_ANOMALY:Medium|PROCESS_NEW:High|PIPELINE_LOG_FLOOD:High";

	/// <summary>Parsed alert rule catalog. 23 entries.</summary>
	public static readonly IReadOnlyList<AlertRule> AlertRules = BuildAlertRules().AsReadOnly();

	/// <summary>Stable event map key from a catalog event id.</summary>
	public static string EventKey(int eventId)
		=> eventId.ToString(CultureInfo.InvariantCulture);

	/// <summary>Default visibility for a catalog event: shown only at High or Critical.</summary>
	public static bool EventVisibleByDefault(EventDescriptor descriptor)
		=> descriptor.Criticality >= EventCriticality.High;

	private static List<AlertRule> BuildAlertRules()
	{
		List<AlertRule> catalog = new();
		foreach (string entry in AlertRuleCatalogCsv.Split('|'))
		{
			int colon = entry.IndexOf(':');
			if (colon > 0 && Enum.TryParse(entry[(colon + 1)..], ignoreCase: true, out AlertSeverity severity))
			{
				catalog.Add(new AlertRule(entry[..colon], severity));
			}
		}

		return catalog;
	}
}
