/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixItemKeys.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: The single definition of every item key the agent writes and provisioning creates. A key
//          appears in three places - the pushed value, the item created on the server and the trigger
//          expression - so it is defined once here and referenced everywhere else.
// Extends: System.Object

namespace RdpAudit.Core.Zabbix;

/// <summary>Item keys shared by the push payload, the provisioning calls and the trigger set.</summary>
/// <remarks>
/// Keys are lower-case dotted identifiers. Item value types are fixed by
/// <see cref="ZabbixItemDefinition"/>, because the value type cannot be changed after the item exists:
/// sending a non-numeric value to an unsigned item fails the whole batch.
/// </remarks>
public static class ZabbixItemKeys
{
	/// <summary>Text item carrying the JSON document of the current incident batch.</summary>
	public const string Incidents = "rdpaudit.incidents";

	/// <summary>Unsigned item: number of incidents in the batch.</summary>
	public const string IncidentsCount = "rdpaudit.incidents.count";

	/// <summary>Unsigned item: highest Zabbix severity in the batch, 0 when the batch is empty. This
	/// is the item the trigger set keys off; 0 is the recovery value.</summary>
	public const string IncidentsMaxSeverity = "rdpaudit.incidents.max_severity";

	/// <summary>Unsigned item: monotonically increasing push counter, so a gap is visible even when
	/// two consecutive payloads happen to be identical.</summary>
	public const string PushSequence = "rdpaudit.push.sequence";

	/// <summary>Unsigned item: 1 on every cycle. A <c>nodata(15m)</c> trigger on this item is what
	/// turns "the agent died" into a problem instead of silence.</summary>
	public const string AgentStatus = "rdpaudit.agent.status";

	/// <summary>Text item: machine summary (version, uptime, counters) for the fleet dashboard.</summary>
	public const string MachineSummary = "rdpaudit.machine.summary";

	/// <summary>Unsigned item: number of active blocks on this machine.</summary>
	public const string BlocksActive = "rdpaudit.blocks.active";

	/// <summary>Every key the agent writes, in a stable order.</summary>
	public static IReadOnlyList<string> All { get; } = new[]
	{
		Incidents,
		IncidentsCount,
		IncidentsMaxSeverity,
		PushSequence,
		AgentStatus,
		MachineSummary,
		BlocksActive,
	};

	/// <summary>Value type of one Zabbix item.</summary>
	/// <remarks>Ordinals are the Zabbix <c>value_type</c> numbers, so they are part of the API
	/// contract and are never reused.</remarks>
	public enum ValueKind
	{
		/// <summary>Not a value type; never sent. Present so the enum has a defined zero.</summary>
		None = 0,

		/// <summary>Numeric, non-negative (Zabbix value_type 3).</summary>
		Unsigned = 3,

		/// <summary>Free text (Zabbix value_type 4).</summary>
		Text = 4,
	}

	/// <summary>Name, value type and unit of one item, as provisioning creates it.</summary>
	/// <param name="Key">Item key.</param>
	/// <param name="DisplayName">Visible item name.</param>
	/// <param name="Kind">Value type.</param>
	/// <param name="Units">Optional unit string, empty when none.</param>
	public sealed record ZabbixItemDefinition(string Key, string DisplayName, ValueKind Kind, string Units);

	/// <summary>The full item set of one machine host.</summary>
	public static IReadOnlyList<ZabbixItemDefinition> Definitions { get; } = new[]
	{
		new ZabbixItemDefinition(Incidents, "RDPAudit incidents (JSON batch)", ValueKind.Text, string.Empty),
		new ZabbixItemDefinition(IncidentsCount, "RDPAudit incident count", ValueKind.Unsigned, string.Empty),
		new ZabbixItemDefinition(IncidentsMaxSeverity, "RDPAudit highest incident severity", ValueKind.Unsigned, string.Empty),
		new ZabbixItemDefinition(PushSequence, "RDPAudit push sequence", ValueKind.Unsigned, string.Empty),
		new ZabbixItemDefinition(AgentStatus, "RDPAudit agent heartbeat", ValueKind.Unsigned, string.Empty),
		new ZabbixItemDefinition(MachineSummary, "RDPAudit machine summary (JSON)", ValueKind.Text, string.Empty),
		new ZabbixItemDefinition(BlocksActive, "RDPAudit active blocks", ValueKind.Unsigned, string.Empty),
	};
}
