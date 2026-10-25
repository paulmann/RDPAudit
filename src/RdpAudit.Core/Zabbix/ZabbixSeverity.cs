/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSeverity.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: Maps the internal alert severity onto the Zabbix problem scale and defines the trigger set
//          provisioning installs. The mapping is not cosmetic: Zabbix takes a problem's severity from
//          its trigger priority, never from the value that triggered it, so one trigger per level is
//          what makes a Critical incident arrive as a Disaster problem instead of a Warning one.
// Extends: System.Object

using System.Globalization;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Zabbix;

/// <summary>Severity mapping and the trigger set installed by provisioning.</summary>
public static class ZabbixSeverity
{
	/// <summary>Zabbix severity used when there is nothing to report. This is also the recovery value:
	/// every trigger in the set compares against an exact level, so 0 closes whatever was open.</summary>
	public const int None = 0;

	/// <summary>Translates an <see cref="AlertSeverity"/> into the Zabbix 0..5 scale.</summary>
	/// <param name="severity">Internal severity.</param>
	/// <returns>1 (Information) to 5 (Disaster).</returns>
	public static int ToZabbix(AlertSeverity severity) => severity switch
	{
		AlertSeverity.Critical => 5,
		AlertSeverity.High => 4,
		AlertSeverity.Medium => 3,
		AlertSeverity.Low => 2,
		_ => 1,
	};

	/// <summary>Returns the Zabbix severity name for a 0..5 value, for logs and payloads.</summary>
	/// <param name="zabbixSeverity">Value produced by <see cref="ToZabbix"/> or <see cref="None"/>.</param>
	public static string Describe(int zabbixSeverity) => zabbixSeverity switch
	{
		5 => "Disaster",
		4 => "High",
		3 => "Average",
		2 => "Warning",
		1 => "Information",
		_ => "Not classified",
	};

	/// <summary>Lowest Zabbix severity that counts as an incident for the trigger set.</summary>
	public const int IncidentFloor = 1;

	/// <summary>One trigger of the set provisioning installs.</summary>
	/// <param name="Key">Stable identifier used when looking the trigger up before creating it.</param>
	/// <param name="Description">Trigger name; carries the <c>{HOST.NAME}</c> macro so the Problems
	/// window stays readable when it lists the whole fleet.</param>
	/// <param name="Expression">Trigger expression referencing <paramref name="Key"/>.</param>
	/// <param name="Priority">Zabbix severity of the resulting problem.</param>
	public sealed record ZabbixTriggerDefinition(string Key, string Description, string Expression, int Priority);

	/// <summary>Builds the per-host trigger set.</summary>
	/// <param name="hostName">Normalized technical host name.</param>
	/// <remarks>
	/// Expressions are mutually exclusive (<c>=N</c>, not <c>&gt;=N</c>): with a <c>&gt;=</c> chain a
	/// single Disaster batch would open five problems at once, and the operator would see one incident
	/// five times. Each expression recovers on its own when the value leaves that level, and a batch
	/// below <see cref="IncidentFloor"/> closes whatever was open.
	/// </remarks>
	public static IReadOnlyList<ZabbixTriggerDefinition> BuildTriggerSet(string hostName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

		string function = string.Format(
			CultureInfo.InvariantCulture,
			"last(/{0}/{1})",
			hostName,
			ZabbixItemKeys.IncidentsMaxSeverity);

		return new[]
		{
			new ZabbixTriggerDefinition(
				"rdpaudit.trigger.disaster",
				"RDPAudit: critical RDP security incident on {HOST.NAME}",
				function + "=5",
				5),
			new ZabbixTriggerDefinition(
				"rdpaudit.trigger.high",
				"RDPAudit: high-severity RDP security incident on {HOST.NAME}",
				function + "=4",
				4),
			new ZabbixTriggerDefinition(
				"rdpaudit.trigger.average",
				"RDPAudit: medium-severity RDP security incident on {HOST.NAME}",
				function + "=3",
				3),
			new ZabbixTriggerDefinition(
				"rdpaudit.trigger.warning",
				"RDPAudit: low-severity RDP security incident on {HOST.NAME}",
				function + "=2",
				2),
			new ZabbixTriggerDefinition(
				"rdpaudit.trigger.information",
				"RDPAudit: informational RDP security event on {HOST.NAME}",
				function + "=1",
				1),
		};
	}

	/// <summary>Builds the heartbeat trigger: a machine that stops reporting becomes a problem instead
	/// of a silent gap.</summary>
	/// <param name="hostName">Normalized technical host name.</param>
	/// <param name="noDataMinutes">Silence, in minutes, before the trigger fires.</param>
	public static ZabbixTriggerDefinition BuildHeartbeatTrigger(string hostName, int noDataMinutes = 15)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
		int minutes = Math.Clamp(noDataMinutes, 5, 1440);
		string expression = string.Format(
			CultureInfo.InvariantCulture,
			"nodata(/{0}/{1},{2}m)=1",
			hostName,
			ZabbixItemKeys.AgentStatus,
			minutes);
		return new ZabbixTriggerDefinition(
			"rdpaudit.trigger.heartbeat",
			"RDPAudit: agent stopped reporting from {HOST.NAME}",
			expression,
			3);
	}
}
