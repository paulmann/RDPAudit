/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixIncidentPayloadTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Pins the payload contract: every item key is present, the severity the trigger set keys off
//          is the highest one in the batch, a quiet cycle still pushes the heartbeat, and a payload that
//          outgrows the value ceiling is trimmed into valid JSON with an explicit "truncated" marker
//          instead of being cut in the middle.
// Extends: System.Object

using System.Text.Json;
using RdpAudit.Core.Models;
using RdpAudit.Core.Zabbix;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Tests of the incident payload builder and the host-name normalization.</summary>
public sealed class ZabbixIncidentPayloadTests
{
	private static readonly DateTime Clock = new(2026, 10, 25, 12, 30, 0, DateTimeKind.Utc);

	private static ZabbixMachineSummary Summary(int skipped = 0) => new(
		"WIN-BSG-50",
		"2.0.3",
		TimeSpan.FromHours(5),
		EventsCaptured: 1000,
		EventsDropped: 3,
		AlertsRaised: 42,
		ActiveBlocks: 2,
		PendingBacklog: 0,
		SkippedIncidents: skipped);

	private static ZabbixIncident Incident(long id, AlertSeverity severity, string message = "brute force") => new(
		id,
		Clock.AddMinutes(-1),
		"BRUTE_FORCE",
		severity,
		"203.0.113.9",
		false,
		"md",
		message);

	[Fact]
	public void Build_EmitsEveryItemKey()
	{
		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(
			"win-bsg-50",
			new[] { Incident(1, AlertSeverity.High) },
			Summary(),
			sequence: 12,
			Clock);

		Assert.Equal(ZabbixItemKeys.All.Count, payload.Values.Count);
		foreach (string key in ZabbixItemKeys.All)
		{
			Assert.Contains(payload.Values, v => string.Equals(v.Key, key, StringComparison.Ordinal));
		}

		Assert.All(payload.Values, v => Assert.Equal("win-bsg-50", v.Host));
		Assert.Equal("1", ValueOf(payload, ZabbixItemKeys.AgentStatus));
		Assert.Equal("12", ValueOf(payload, ZabbixItemKeys.PushSequence));
		Assert.Equal("1", ValueOf(payload, ZabbixItemKeys.IncidentsCount));
		Assert.Equal("2", ValueOf(payload, ZabbixItemKeys.BlocksActive));
	}

	[Fact]
	public void Build_MaxSeverityIsTheHighestInTheBatch()
	{
		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(
			"win-bsg-50",
			new[] { Incident(1, AlertSeverity.Low), Incident(2, AlertSeverity.Critical), Incident(3, AlertSeverity.Medium) },
			Summary(),
			sequence: 1,
			Clock);

		Assert.Equal(5, payload.MaxSeverity);
		Assert.Equal("5", ValueOf(payload, ZabbixItemKeys.IncidentsMaxSeverity));
	}

	[Fact]
	public void Build_QuietCycle_StillPushesHeartbeatAndZeroesTheSeverity()
	{
		// Zero is the recovery value the trigger set relies on: without it a problem would stay open
		// until someone closed it by hand.
		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(
			"win-bsg-50",
			Array.Empty<ZabbixIncident>(),
			Summary(),
			sequence: 7,
			Clock);

		Assert.Equal(ZabbixSeverity.None, payload.MaxSeverity);
		Assert.Equal("0", ValueOf(payload, ZabbixItemKeys.IncidentsMaxSeverity));
		Assert.Equal("0", ValueOf(payload, ZabbixItemKeys.IncidentsCount));
		Assert.Equal("1", ValueOf(payload, ZabbixItemKeys.AgentStatus));

		using JsonDocument document = JsonDocument.Parse(payload.IncidentsJson);
		Assert.Equal(0, document.RootElement.GetProperty("count").GetInt32());
		Assert.False(document.RootElement.GetProperty("truncated").GetBoolean());
	}

	[Fact]
	public void Build_IncidentJsonCarriesTheForensicFields()
	{
		ZabbixIncident derived = new(5, Clock, "BRUTE_FORCE_NTLM", AlertSeverity.High, "192.168.31.100", true, "md", "40 failures");
		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build("win-a", new[] { derived }, Summary(), 3, Clock);

		using JsonDocument document = JsonDocument.Parse(payload.IncidentsJson);
		JsonElement incident = document.RootElement.GetProperty("incidents")[0];

		Assert.Equal(5, incident.GetProperty("id").GetInt64());
		Assert.Equal("BRUTE_FORCE_NTLM", incident.GetProperty("rule").GetString());
		Assert.Equal("High", incident.GetProperty("severity").GetString());
		Assert.Equal(4, incident.GetProperty("zabbixSeverity").GetInt32());
		Assert.Equal("192.168.31.100", incident.GetProperty("ip").GetString());
		// A correlated address must stay marked as a guess all the way into Zabbix.
		Assert.True(incident.GetProperty("ipDerived").GetBoolean());
		Assert.Equal("2026-10-25T12:30:00Z", incident.GetProperty("time").GetString());
	}

	[Fact]
	public void Build_OversizedBatch_IsTrimmedIntoValidJsonWithAnExplicitMarker()
	{
		List<ZabbixIncident> incidents = new();
		for (int i = 0; i < 200; i++)
		{
			incidents.Add(Incident(i + 1, AlertSeverity.High, new string('x', ZabbixIncidentPayloadBuilder.MaxMessageLength)));
		}

		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build("win-a", incidents, Summary(skipped: 4), 1, Clock);

		Assert.True(payload.OmittedIncidents > 0);
		Assert.True(payload.IncidentsJson.Length <= ZabbixSenderProtocol.MaxValueLength);

		// The document must still parse: a cut in the middle would break every consumer downstream.
		using JsonDocument document = JsonDocument.Parse(payload.IncidentsJson);
		Assert.True(document.RootElement.GetProperty("truncated").GetBoolean());
		Assert.Equal(payload.OmittedIncidents, document.RootElement.GetProperty("omitted").GetInt32());
		Assert.Equal(4, document.RootElement.GetProperty("skipped").GetInt32());
	}

	[Fact]
	public void Truncate_MarksTheCut()
	{
		string cut = ZabbixIncidentPayloadBuilder.Truncate(new string('a', 50), 10);

		Assert.Equal(10, cut.Length);
		Assert.EndsWith("\u2026", cut, StringComparison.Ordinal);
		Assert.Equal(string.Empty, ZabbixIncidentPayloadBuilder.Truncate(null, 10));
		Assert.Equal("short", ZabbixIncidentPayloadBuilder.Truncate("short", 10));
	}

	[Fact]
	public void SummaryJson_CarriesTheMachineContext()
	{
		ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(
			"win-a",
			new[] { Incident(1, AlertSeverity.High) },
			Summary(skipped: 2),
			9,
			Clock);

		using JsonDocument document = JsonDocument.Parse(payload.SummaryJson);
		Assert.Equal("WIN-BSG-50", document.RootElement.GetProperty("machine").GetString());
		Assert.Equal("2.0.3", document.RootElement.GetProperty("version").GetString());
		Assert.Equal(18_000, document.RootElement.GetProperty("uptimeSeconds").GetInt64());
		Assert.Equal(2, document.RootElement.GetProperty("activeBlocks").GetInt32());
		Assert.Equal(2, document.RootElement.GetProperty("skippedIncidents").GetInt32());
		Assert.Equal(1, document.RootElement.GetProperty("incidentsInBatch").GetInt32());
	}

	[Theory]
	[InlineData("WIN-BSG-50", "WIN-BSG-50")]
	[InlineData("win bsg 50", "win-bsg-50")]
	[InlineData("host/with)injection=5", "host-with-injection-5")]
	[InlineData("  ..trimmed..  ", "trimmed")]
	[InlineData("", "rdpaudit")]
	public void HostName_NeverLeaksAnExpressionCharacter(string raw, string expected)
		=> Assert.Equal(expected, ZabbixHostName.Normalize(raw));

	[Fact]
	public void HostName_PrefersTheConfiguredValueAndFallsBackToTheMachine()
	{
		Assert.Equal("zabbix-name", ZabbixHostName.Resolve("zabbix-name", "WIN-BSG-50"));
		Assert.Equal("WIN-BSG-50", ZabbixHostName.Resolve("   ", "WIN-BSG-50"));
	}

	private static string ValueOf(ZabbixPayload payload, string key)
	{
		foreach (ZabbixValue value in payload.Values)
		{
			if (string.Equals(value.Key, key, StringComparison.Ordinal))
			{
				return value.Value;
			}
		}

		throw new InvalidOperationException("Missing item key " + key);
	}
}
