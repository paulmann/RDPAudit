/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSenderProtocolTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Locks the sender wire format and, more importantly, the accounting rule that a
//          {"response":"success"} envelope is NOT a delivery. Measured on Zabbix 8.0.0: a batch whose
//          every value was rejected still answers "success" with failed: N. Treating that answer as
//          success would silently drop every incident, so the rule is pinned here.
// Extends: System.Object

using System.Text;
using RdpAudit.Core.Zabbix;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Protocol-level tests of the Zabbix sender client.</summary>
public sealed class ZabbixSenderProtocolTests
{
	private static readonly DateTime Clock = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);

	[Fact]
	public void Frame_StartsWithMagicAndCarriesLittleEndianLength()
	{
		string json = ZabbixSenderProtocol.BuildRequestJson(
			new[] { new ZabbixValue("win-a", "rdpaudit.agent.status", "1") },
			Clock);

		byte[] frame = ZabbixSenderProtocol.BuildFrame(json);

		Assert.Equal((byte)'Z', frame[0]);
		Assert.Equal((byte)'B', frame[1]);
		Assert.Equal((byte)'X', frame[2]);
		Assert.Equal((byte)'D', frame[3]);
		Assert.Equal(0x01, frame[4]);

		ulong declared = BitConverter.ToUInt64(frame, 5);
		Assert.Equal((ulong)(frame.Length - ZabbixSenderProtocol.HeaderLength), declared);
		Assert.Equal(json, Encoding.UTF8.GetString(frame, ZabbixSenderProtocol.HeaderLength, frame.Length - ZabbixSenderProtocol.HeaderLength));
	}

	[Fact]
	public void RequestJson_EscapesQuotesInsideAnIncidentMessage()
	{
		const string message = "Failed logon from \"hostile\" client \\ with a backslash";
		string json = ZabbixSenderProtocol.BuildRequestJson(
			new[] { new ZabbixValue("win-a", "rdpaudit.incidents", message) },
			Clock);

		// The value must survive a round-trip; a hand-built JSON string would break here.
		using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
		Assert.Equal(message, document.RootElement.GetProperty("data")[0].GetProperty("value").GetString());
		Assert.Equal("sender data", document.RootElement.GetProperty("request").GetString());
		Assert.Equal(new DateTimeOffset(Clock).ToUnixTimeSeconds(), document.RootElement.GetProperty("clock").GetInt64());
	}

	[Fact]
	public void RequestJson_RejectsAnEmptyBatch()
		=> Assert.Throws<ArgumentException>(() => ZabbixSenderProtocol.BuildRequestJson(Array.Empty<ZabbixValue>(), Clock));

	[Fact]
	public void ParseResponse_AcceptedBatch_IsDelivered()
	{
		ZabbixSenderOutcome outcome = ZabbixSenderProtocol.ParseResponse(
			"{\"response\":\"success\",\"info\":\"processed: 7; failed: 0; total: 7; seconds spent: 0.000058\"}");

		Assert.True(outcome.ProtocolAccepted);
		Assert.True(outcome.Delivered);
		Assert.Equal(7, outcome.Processed);
		Assert.Equal(0, outcome.Failed);
		Assert.Equal(7, outcome.Total);
	}

	[Fact]
	public void ParseResponse_SuccessEnvelopeWithFailures_IsNotDelivered()
	{
		// This is the exact shape the server produced on 2026-10-25 when the host was not yet known.
		ZabbixSenderOutcome outcome = ZabbixSenderProtocol.ParseResponse(
			"{\"response\":\"success\",\"info\":\"processed: 0; failed: 1; total: 1; seconds spent: 0.000012\"}");

		Assert.True(outcome.ProtocolAccepted);
		Assert.False(outcome.Delivered);
		Assert.Equal(1, outcome.Failed);
		Assert.Contains("rejected 1 of 1", outcome.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseResponse_WithoutCounters_IsNotTreatedAsDelivery()
	{
		ZabbixSenderOutcome outcome = ZabbixSenderProtocol.ParseResponse("{\"response\":\"success\"}");

		Assert.True(outcome.ProtocolAccepted);
		Assert.False(outcome.Delivered);
		Assert.Contains("unconfirmed", outcome.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseResponse_ErrorEnvelope_IsRefused()
	{
		ZabbixSenderOutcome outcome = ZabbixSenderProtocol.ParseResponse("{\"response\":\"failed\",\"info\":\"boom\"}");

		Assert.False(outcome.ProtocolAccepted);
		Assert.False(outcome.Delivered);
	}

	[Fact]
	public void ParseResponse_EmptyBody_IsRefused()
	{
		ZabbixSenderOutcome outcome = ZabbixSenderProtocol.ParseResponse(string.Empty);

		Assert.False(outcome.ProtocolAccepted);
		Assert.False(outcome.Delivered);
	}

	[Fact]
	public void TryReadHeader_AcceptsTheSenderPrefix_AndRejectsForeignBytes()
	{
		byte[] good = { (byte)'Z', (byte)'B', (byte)'X', (byte)'D', 0x01, 34, 0, 0, 0, 0, 0, 0, 0 };
		Assert.True(ZabbixSenderProtocol.TryReadHeader(good, out int length));
		Assert.Equal(34, length);

		byte[] httpBanner = Encoding.ASCII.GetBytes("HTTP/1.1 400 ");
		Assert.False(ZabbixSenderProtocol.TryReadHeader(httpBanner, out _));

		byte[] zeroLength = { (byte)'Z', (byte)'B', (byte)'X', (byte)'D', 0x01, 0, 0, 0, 0, 0, 0, 0, 0 };
		Assert.False(ZabbixSenderProtocol.TryReadHeader(zeroLength, out _));
	}

	[Fact]
	public void Severity_MapsOntoTheZabbixScale()
	{
		Assert.Equal(1, ZabbixSeverity.ToZabbix(RdpAudit.Core.Models.AlertSeverity.Info));
		Assert.Equal(2, ZabbixSeverity.ToZabbix(RdpAudit.Core.Models.AlertSeverity.Low));
		Assert.Equal(3, ZabbixSeverity.ToZabbix(RdpAudit.Core.Models.AlertSeverity.Medium));
		Assert.Equal(4, ZabbixSeverity.ToZabbix(RdpAudit.Core.Models.AlertSeverity.High));
		Assert.Equal(5, ZabbixSeverity.ToZabbix(RdpAudit.Core.Models.AlertSeverity.Critical));
		Assert.Equal(0, ZabbixSeverity.None);
		Assert.Equal("Disaster", ZabbixSeverity.Describe(5));
		Assert.Equal("Not classified", ZabbixSeverity.Describe(0));
	}

	[Fact]
	public void TriggerSet_UsesExclusiveExpressions_SoOneBatchOpensOneProblem()
	{
		IReadOnlyList<ZabbixSeverity.ZabbixTriggerDefinition> triggers = ZabbixSeverity.BuildTriggerSet("win-a");

		Assert.Equal(5, triggers.Count);
		Assert.All(triggers, t => Assert.Contains("last(/win-a/rdpaudit.incidents.max_severity)", t.Expression, StringComparison.Ordinal));
		// A ">=" chain would open five problems for one Disaster batch; every expression is an exact level.
		Assert.All(triggers, t => Assert.DoesNotContain(">=", t.Expression, StringComparison.Ordinal));
		Assert.Contains(triggers, t => t.Expression.EndsWith("=5", StringComparison.Ordinal) && t.Priority == 5);
		Assert.Contains(triggers, t => t.Expression.EndsWith("=1", StringComparison.Ordinal) && t.Priority == 1);
	}

	[Fact]
	public void HeartbeatTrigger_KeysOffTheStatusItem()
	{
		ZabbixSeverity.ZabbixTriggerDefinition trigger = ZabbixSeverity.BuildHeartbeatTrigger("win-a", 15);

		Assert.Contains("nodata(/win-a/rdpaudit.agent.status,15m)", trigger.Expression, StringComparison.Ordinal);
		Assert.Equal(3, trigger.Priority);
	}

	[Fact]
	public void ProblemsUrl_CarriesTheIntegrationTag()
	{
		string url = ZabbixLinks.BuildProblemsText("https://22877.ru");

		Assert.Contains("problem.view", url, StringComparison.Ordinal);
		Assert.Contains("tags%5B0%5D%5Btag%5D=scope", url, StringComparison.Ordinal);
		Assert.Contains("tags%5B0%5D%5Bvalue%5D=rdpaudit", url, StringComparison.Ordinal);
		Assert.Equal(string.Empty, ZabbixLinks.BuildProblemsText(string.Empty));
	}
}
