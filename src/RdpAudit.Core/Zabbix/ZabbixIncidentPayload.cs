/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixIncidentPayload.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: Turns a batch of incidents into the exact item values the sender transmits. Pure: no
//          clock sampling, no I/O, no configuration lookup, so the payload an operator previews is
//          byte-for-byte the payload that leaves the machine.
// Extends: System.Object

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Zabbix;

/// <summary>One incident as it is forwarded to Zabbix.</summary>
/// <param name="AlertId">Local alert identifier; the durable reference back into the evidence store.</param>
/// <param name="TimeUtc">Moment the alert was raised.</param>
/// <param name="RuleId">Alert rule that produced it.</param>
/// <param name="Severity">Internal severity.</param>
/// <param name="SourceIp">Attacker address, when the alert carries one.</param>
/// <param name="SourceIpDerived">True when the address was correlated rather than read from the event.
/// Kept in the payload because an operator must be able to tell a fact from a guess.</param>
/// <param name="UserName">Account involved, when known.</param>
/// <param name="Message">Human-readable description.</param>
public sealed record ZabbixIncident(
	long AlertId,
	DateTime TimeUtc,
	string RuleId,
	AlertSeverity Severity,
	string? SourceIp,
	bool SourceIpDerived,
	string? UserName,
	string Message);

/// <summary>Machine-level context pushed together with the incidents.</summary>
/// <param name="MachineName">Machine as Windows knows it.</param>
/// <param name="Version">Service version.</param>
/// <param name="Uptime">Process uptime.</param>
/// <param name="EventsCaptured">Events ingested since start.</param>
/// <param name="EventsDropped">Events dropped since start.</param>
/// <param name="AlertsRaised">Alerts raised since start.</param>
/// <param name="ActiveBlocks">Currently enforced blocks.</param>
/// <param name="PendingBacklog">Incidents still waiting to be pushed after this batch.</param>
/// <param name="SkippedIncidents">Incidents the backlog cap discarded before this batch.</param>
public sealed record ZabbixMachineSummary(
	string MachineName,
	string Version,
	TimeSpan Uptime,
	long EventsCaptured,
	long EventsDropped,
	long AlertsRaised,
	int ActiveBlocks,
	int PendingBacklog,
	int SkippedIncidents);

/// <summary>The item values of one push plus the JSON documents they carry.</summary>
/// <param name="Values">Key/value pairs, ready for the sender.</param>
/// <param name="IncidentsJson">The incident document exactly as pushed.</param>
/// <param name="SummaryJson">The machine summary exactly as pushed.</param>
/// <param name="MaxSeverity">Highest Zabbix severity in the batch, 0 when empty.</param>
/// <param name="OmittedIncidents">Incidents dropped to stay inside the value-length ceiling.</param>
public sealed record ZabbixPayload(
	IReadOnlyList<ZabbixValue> Values,
	string IncidentsJson,
	string SummaryJson,
	int MaxSeverity,
	int OmittedIncidents);

/// <summary>Builds the item values of one push.</summary>
public static class ZabbixIncidentPayloadBuilder
{
	/// <summary>Longest incident message forwarded verbatim; the rest is cut and marked.</summary>
	public const int MaxMessageLength = 400;

	/// <summary>Format version of the JSON documents, so a consumer can tell shapes apart.</summary>
	public const int SchemaVersion = 1;

	/// <summary>Builds every value of one push.</summary>
	/// <param name="hostName">Normalized technical host name.</param>
	/// <param name="incidents">Incidents to forward, oldest first.</param>
	/// <param name="summary">Machine context.</param>
	/// <param name="sequence">Monotonic push counter.</param>
	/// <param name="clockUtc">Moment of the batch.</param>
	public static ZabbixPayload Build(
		string hostName,
		IReadOnlyList<ZabbixIncident> incidents,
		ZabbixMachineSummary summary,
		long sequence,
		DateTime clockUtc)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
		ArgumentNullException.ThrowIfNull(incidents);
		ArgumentNullException.ThrowIfNull(summary);

		int maxSeverity = ZabbixSeverity.None;
		foreach (ZabbixIncident incident in incidents)
		{
			int mapped = ZabbixSeverity.ToZabbix(incident.Severity);
			if (mapped > maxSeverity)
			{
				maxSeverity = mapped;
			}
		}

		// The document is trimmed from the tail, never cut in the middle: a truncated JSON body would
		// be unparseable downstream, and "silently smaller" is exactly the failure mode this payload
		// must not have.
		int included = incidents.Count;
		string json = BuildIncidentsJson(hostName, incidents, included, summary.SkippedIncidents, sequence, clockUtc, omitted: 0);
		while (json.Length > ZabbixSenderProtocol.MaxValueLength && included > 0)
		{
			included--;
			int omitted = incidents.Count - included;
			json = BuildIncidentsJson(hostName, incidents, included, summary.SkippedIncidents, sequence, clockUtc, omitted);
		}

		if (json.Length > ZabbixSenderProtocol.MaxValueLength)
		{
			// Not even the envelope fits: send an explicit refusal document instead of a broken one.
			json = BuildIncidentsJson(hostName, Array.Empty<ZabbixIncident>(), 0, summary.SkippedIncidents, sequence, clockUtc, incidents.Count);
		}

		string summaryJson = BuildSummaryJson(summary, incidentCount: incidents.Count, clockUtc);
		if (summaryJson.Length > ZabbixSenderProtocol.MaxValueLength)
		{
			summaryJson = summaryJson[..ZabbixSenderProtocol.MaxValueLength];
		}

		List<ZabbixValue> values = new(ZabbixItemKeys.All.Count)
		{
			new ZabbixValue(hostName, ZabbixItemKeys.Incidents, json),
			new ZabbixValue(hostName, ZabbixItemKeys.IncidentsCount, incidents.Count.ToString(CultureInfo.InvariantCulture)),
			new ZabbixValue(hostName, ZabbixItemKeys.IncidentsMaxSeverity, maxSeverity.ToString(CultureInfo.InvariantCulture)),
			new ZabbixValue(hostName, ZabbixItemKeys.PushSequence, sequence.ToString(CultureInfo.InvariantCulture)),
			new ZabbixValue(hostName, ZabbixItemKeys.AgentStatus, "1"),
			new ZabbixValue(hostName, ZabbixItemKeys.MachineSummary, summaryJson),
			new ZabbixValue(hostName, ZabbixItemKeys.BlocksActive, summary.ActiveBlocks.ToString(CultureInfo.InvariantCulture)),
		};

		return new ZabbixPayload(values, json, summaryJson, maxSeverity, incidents.Count - included);
	}

	/// <summary>Builds the incident document. Exposed so a test and the tab preview can compare it
	/// with what <see cref="Build"/> produced.</summary>
	/// <param name="hostName">Normalized technical host name.</param>
	/// <param name="incidents">Incidents to include.</param>
	/// <param name="included">How many of them to serialize from the start.</param>
	/// <param name="skipped">Incidents discarded by the backlog cap before this batch.</param>
	/// <param name="sequence">Push counter.</param>
	/// <param name="clockUtc">Moment of the batch.</param>
	/// <param name="omitted">Incidents dropped to fit the value ceiling.</param>
	public static string BuildIncidentsJson(
		string hostName,
		IReadOnlyList<ZabbixIncident> incidents,
		int included,
		int skipped,
		long sequence,
		DateTime clockUtc,
		int omitted)
	{
		ArgumentNullException.ThrowIfNull(incidents);
		int take = Math.Clamp(included, 0, incidents.Count);

		IncidentDocument document = new()
		{
			Schema = SchemaVersion,
			Host = hostName,
			GeneratedUtc = FormatUtc(clockUtc),
			Sequence = sequence,
			Count = take,
			Skipped = Math.Max(0, skipped),
			Truncated = omitted > 0,
			Omitted = Math.Max(0, omitted),
			Incidents = new List<IncidentEntry>(take),
		};

		for (int i = 0; i < take; i++)
		{
			ZabbixIncident incident = incidents[i];
			document.Incidents.Add(new IncidentEntry
			{
				Id = incident.AlertId,
				Time = FormatUtc(incident.TimeUtc),
				Rule = incident.RuleId,
				Severity = incident.Severity.ToString(),
				ZabbixSeverity = ZabbixSeverity.ToZabbix(incident.Severity),
				Ip = incident.SourceIp ?? string.Empty,
				IpDerived = incident.SourceIpDerived,
				User = incident.UserName ?? string.Empty,
				Message = Truncate(incident.Message, MaxMessageLength),
			});
		}

		return JsonSerializer.Serialize(document, PayloadJson.Options);
	}

	/// <summary>Builds the machine-summary document.</summary>
	/// <param name="summary">Machine context.</param>
	/// <param name="incidentCount">Incidents carried by this batch.</param>
	/// <param name="clockUtc">Moment of the batch.</param>
	public static string BuildSummaryJson(ZabbixMachineSummary summary, int incidentCount, DateTime clockUtc)
	{
		ArgumentNullException.ThrowIfNull(summary);
		SummaryDocument document = new()
		{
			Schema = SchemaVersion,
			Machine = summary.MachineName,
			Version = summary.Version,
			UptimeSeconds = (long)Math.Max(0, summary.Uptime.TotalSeconds),
			EventsCaptured = summary.EventsCaptured,
			EventsDropped = summary.EventsDropped,
			AlertsRaised = summary.AlertsRaised,
			ActiveBlocks = summary.ActiveBlocks,
			PendingBacklog = Math.Max(0, summary.PendingBacklog),
			SkippedIncidents = Math.Max(0, summary.SkippedIncidents),
			IncidentsInBatch = incidentCount,
			GeneratedUtc = FormatUtc(clockUtc),
		};

		return JsonSerializer.Serialize(document, PayloadJson.Options);
	}

	/// <summary>Cuts a string to <paramref name="max"/> characters and marks the cut with an ellipsis,
	/// so a shortened message is never mistaken for a complete one.</summary>
	/// <param name="value">Source text.</param>
	/// <param name="max">Hard limit, at least 8 characters.</param>
	public static string Truncate(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		int limit = Math.Max(8, max);
		return value.Length <= limit ? value : value[..(limit - 1)] + "\u2026";
	}

	private static string FormatUtc(DateTime value)
		=> DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

	/// <summary>Serializer settings for the documents carried inside item values.</summary>
	private static class PayloadJson
	{
		internal static readonly JsonSerializerOptions Options = new()
		{
			PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
			DefaultIgnoreCondition = JsonIgnoreCondition.Never,
			WriteIndented = false,
		};
	}

	private sealed class IncidentDocument
	{
		[JsonPropertyName("schema")]
		public int Schema { get; set; }

		[JsonPropertyName("host")]
		public string Host { get; set; } = string.Empty;

		[JsonPropertyName("generatedUtc")]
		public string GeneratedUtc { get; set; } = string.Empty;

		[JsonPropertyName("sequence")]
		public long Sequence { get; set; }

		[JsonPropertyName("count")]
		public int Count { get; set; }

		[JsonPropertyName("skipped")]
		public int Skipped { get; set; }

		[JsonPropertyName("truncated")]
		public bool Truncated { get; set; }

		[JsonPropertyName("omitted")]
		public int Omitted { get; set; }

		[JsonPropertyName("incidents")]
		public List<IncidentEntry> Incidents { get; set; } = new();
	}

	private sealed class IncidentEntry
	{
		[JsonPropertyName("id")]
		public long Id { get; set; }

		[JsonPropertyName("time")]
		public string Time { get; set; } = string.Empty;

		[JsonPropertyName("rule")]
		public string Rule { get; set; } = string.Empty;

		[JsonPropertyName("severity")]
		public string Severity { get; set; } = string.Empty;

		[JsonPropertyName("zabbixSeverity")]
		public int ZabbixSeverity { get; set; }

		[JsonPropertyName("ip")]
		public string Ip { get; set; } = string.Empty;

		[JsonPropertyName("ipDerived")]
		public bool IpDerived { get; set; }

		[JsonPropertyName("user")]
		public string User { get; set; } = string.Empty;

		[JsonPropertyName("message")]
		public string Message { get; set; } = string.Empty;
	}

	private sealed class SummaryDocument
	{
		[JsonPropertyName("schema")]
		public int Schema { get; set; }

		[JsonPropertyName("machine")]
		public string Machine { get; set; } = string.Empty;

		[JsonPropertyName("version")]
		public string Version { get; set; } = string.Empty;

		[JsonPropertyName("uptimeSeconds")]
		public long UptimeSeconds { get; set; }

		[JsonPropertyName("eventsCaptured")]
		public long EventsCaptured { get; set; }

		[JsonPropertyName("eventsDropped")]
		public long EventsDropped { get; set; }

		[JsonPropertyName("alertsRaised")]
		public long AlertsRaised { get; set; }

		[JsonPropertyName("activeBlocks")]
		public int ActiveBlocks { get; set; }

		[JsonPropertyName("pendingBacklog")]
		public int PendingBacklog { get; set; }

		[JsonPropertyName("skippedIncidents")]
		public int SkippedIncidents { get; set; }

		[JsonPropertyName("incidentsInBatch")]
		public int IncidentsInBatch { get; set; }

		[JsonPropertyName("generatedUtc")]
		public string GeneratedUtc { get; set; } = string.Empty;
	}
}
