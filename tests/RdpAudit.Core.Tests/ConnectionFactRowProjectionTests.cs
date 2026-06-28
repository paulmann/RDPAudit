// File:    tests/RdpAudit.Core.Tests/ConnectionFactRowProjectionTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage IP-E — validates the pure projection helpers used by the Configurator row
//          view-models so the Attack Statistics Fact* and Remote RDP Clients Historical* columns
//          map deterministically from the IPC DTOs. WinForms UI itself is not unit-tested here;
//          factoring this mapping into Core keeps it covered without dragging the WinForms host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage IP-E — projection coverage for the Configurator row view-models.</summary>
public class ConnectionFactRowProjectionTests
{
	// ---------------------------------------------------------------------------------------------
	// AttackStatEntryDto -> AttackStatFactDisplay
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void FromAttackStat_Null_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ConnectionFactRowProjection.FromAttackStat(null!));
	}

	[Fact]
	public void FromAttackStat_PopulatedDto_MapsAllFactFields()
	{
		AttackStatEntryDto dto = new()
		{
			Ip = "203.0.113.7",
			HasActiveConnectionFact = true,
			FactFailedLogons = 9,
			FactSuccessfulLogons = 2,
			FactFirstSeenUtc = new DateTime(2026, 5, 19, 8, 0, 0, DateTimeKind.Utc),
			FactLastSeenUtc = new DateTime(2026, 5, 20, 9, 30, 15, DateTimeKind.Utc),
		};

		AttackStatFactDisplay display = ConnectionFactRowProjection.FromAttackStat(dto);

		Assert.True(display.HasActiveConnectionFact);
		Assert.Equal("yes", display.HasActiveConnectionFactText);
		Assert.Equal(9, display.FactFailedLogons);
		Assert.Equal(2, display.FactSuccessfulLogons);
		Assert.Equal("2026-05-19 08:00:00", display.FactFirstSeenUtcText);
		Assert.Equal("2026-05-20 09:30:15", display.FactLastSeenUtcText);
	}

	[Fact]
	public void FromAttackStat_DtoWithoutFacts_RendersEmptyTimestampsAndNo()
	{
		AttackStatEntryDto dto = new()
		{
			Ip = "203.0.113.7",
			HasActiveConnectionFact = false,
			FactFailedLogons = 0,
			FactSuccessfulLogons = 0,
			FactFirstSeenUtc = null,
			FactLastSeenUtc = null,
		};

		AttackStatFactDisplay display = ConnectionFactRowProjection.FromAttackStat(dto);

		Assert.False(display.HasActiveConnectionFact);
		Assert.Equal("no", display.HasActiveConnectionFactText);
		Assert.Equal(0, display.FactFailedLogons);
		Assert.Equal(0, display.FactSuccessfulLogons);
		Assert.Equal(string.Empty, display.FactFirstSeenUtcText);
		Assert.Equal(string.Empty, display.FactLastSeenUtcText);
	}

	// ---------------------------------------------------------------------------------------------
	// RdpSessionDto -> RdpSessionHistoricalDisplay
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void FromRdpSession_Null_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ConnectionFactRowProjection.FromRdpSession(null!));
	}

	[Fact]
	public void FromRdpSession_PopulatedHistorical_MapsAllFields()
	{
		RdpSessionDto dto = new()
		{
			SessionId = 4,
			UserName = "alice",
			ClientAddress = "198.51.100.10",
			HistoricalFirstSeenUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
			HistoricalLastSeenUtc = new DateTime(2026, 5, 19, 23, 59, 1, DateTimeKind.Utc),
			HistoricalFailedLogons = 12,
			HistoricalSuccessfulLogons = 3,
			HistoricalUserNamesAttempted = "alice,bob,carol",
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal("2026-01-02 03:04:05", display.HistoricalFirstSeenUtcText);
		Assert.Equal("2026-05-19 23:59:01", display.HistoricalLastSeenUtcText);
		Assert.Equal(12, display.HistoricalFailedLogons);
		Assert.Equal(3, display.HistoricalSuccessfulLogons);
		Assert.Equal("alice,bob,carol", display.HistoricalUserNamesAttemptedText);
	}

	[Fact]
	public void FromRdpSession_NoHistoricalFacts_RendersEmptyStringsAndZeros()
	{
		RdpSessionDto dto = new()
		{
			SessionId = 7,
			UserName = "noone",
			ClientAddress = "198.51.100.11",
			HistoricalFirstSeenUtc = null,
			HistoricalLastSeenUtc = null,
			HistoricalFailedLogons = 0,
			HistoricalSuccessfulLogons = 0,
			HistoricalUserNamesAttempted = null,
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal(string.Empty, display.HistoricalFirstSeenUtcText);
		Assert.Equal(string.Empty, display.HistoricalLastSeenUtcText);
		Assert.Equal(0, display.HistoricalFailedLogons);
		Assert.Equal(0, display.HistoricalSuccessfulLogons);
		Assert.Equal(string.Empty, display.HistoricalUserNamesAttemptedText);
	}

	// ---------------------------------------------------------------------------------------------
	// Stage 2 — RdpSessionDto -> RdpSessionHistoricalByIpDisplay
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void FromRdpSessionByIp_Null_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ConnectionFactRowProjection.FromRdpSessionByIp(null!));
	}

	[Fact]
	public void FromRdpSessionByIp_PopulatedFields_MapDeterministically()
	{
		RdpSessionDto dto = new()
		{
			SessionId = 2,
			UserName = "alice",
			ClientAddress = "198.51.100.10",
			HistoricalFailedLogonsByIp = 42,
			HistoricalSuccessfulLogonsByIp = 3,
			HistoricalUsersAttemptedFromIp = "alice, bob",
			HistoricalFirstSeenByIpUtc = new DateTime(2026, 4, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalLastSeenByIpUtc = new DateTime(2026, 5, 25, 18, 30, 0, DateTimeKind.Utc),
		};

		RdpSessionHistoricalByIpDisplay display = ConnectionFactRowProjection.FromRdpSessionByIp(dto);

		Assert.Equal("42", display.HistoricalFailedLogonsByIpText);
		Assert.Equal("3", display.HistoricalSuccessfulLogonsByIpText);
		Assert.Equal("alice, bob", display.HistoricalUsersAttemptedFromIpText);
		Assert.Equal("2026-04-01 00:00:00", display.HistoricalFirstSeenByIpUtcText);
		Assert.Equal("2026-05-25 18:30:00", display.HistoricalLastSeenByIpUtcText);
	}

	[Fact]
	public void FromRdpSessionByIp_NullCounters_RenderBlank_NotZero()
	{
		// Stage 2 contract: when the session has no resolved IP, the *ByIp counters are null and
		// should render as blank so operators can distinguish "unknown IP" from "real zero".
		RdpSessionDto dto = new()
		{
			SessionId = 3,
			UserName = "noip",
			ClientAddress = null,
			HistoricalFailedLogonsByIp = null,
			HistoricalSuccessfulLogonsByIp = null,
			HistoricalUsersAttemptedFromIp = null,
			HistoricalFirstSeenByIpUtc = null,
			HistoricalLastSeenByIpUtc = null,
		};

		RdpSessionHistoricalByIpDisplay display = ConnectionFactRowProjection.FromRdpSessionByIp(dto);

		Assert.Equal(string.Empty, display.HistoricalFailedLogonsByIpText);
		Assert.Equal(string.Empty, display.HistoricalSuccessfulLogonsByIpText);
		Assert.Equal(string.Empty, display.HistoricalUsersAttemptedFromIpText);
		Assert.Equal(string.Empty, display.HistoricalFirstSeenByIpUtcText);
		Assert.Equal(string.Empty, display.HistoricalLastSeenByIpUtcText);
	}

	[Fact]
	public void FromRdpSessionByIp_ZeroCounters_RenderAsZero_NotBlank()
	{
		// Stage 2 contract: when the IP is known but no facts exist yet, the counters are 0 and
		// must render as "0" — not blank — so the row visibly distinguishes "no history" from
		// "unknown IP".
		RdpSessionDto dto = new()
		{
			SessionId = 5,
			UserName = "fresh",
			ClientAddress = "10.0.0.10",
			HistoricalFailedLogonsByIp = 0,
			HistoricalSuccessfulLogonsByIp = 0,
			HistoricalUsersAttemptedFromIp = null,
			HistoricalFirstSeenByIpUtc = null,
			HistoricalLastSeenByIpUtc = null,
		};

		RdpSessionHistoricalByIpDisplay display = ConnectionFactRowProjection.FromRdpSessionByIp(dto);

		Assert.Equal("0", display.HistoricalFailedLogonsByIpText);
		Assert.Equal("0", display.HistoricalSuccessfulLogonsByIpText);
	}

	// ---------------------------------------------------------------------------------------------
	// Stage 2 — RdpSessionDto MessagePack append-only roundtrip
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void RdpSessionDto_MessagePackRoundtrip_PreservesAllStage2Fields()
	{
		RdpSessionDto src = new()
		{
			SessionId = 10,
			UserName = "alice",
			ClientAddress = "203.0.113.99",
			State = "Active",
			IsActive = true,
			HistoricalFirstSeenUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalLastSeenUtc = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalFailedLogons = 4,
			HistoricalSuccessfulLogons = 2,
			HistoricalUserNamesAttempted = "alice",
			HistoricalFailedLogonsByIp = 22,
			HistoricalSuccessfulLogonsByIp = 1,
			HistoricalUsersAttemptedFromIp = "alice, root, admin",
			HistoricalFirstSeenByIpUtc = new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalLastSeenByIpUtc = new DateTime(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc),
		};

		byte[] bytes = MessagePack.MessagePackSerializer.Serialize(src);
		RdpSessionDto roundtrip = MessagePack.MessagePackSerializer.Deserialize<RdpSessionDto>(bytes);

		Assert.Equal(src.HistoricalFailedLogonsByIp, roundtrip.HistoricalFailedLogonsByIp);
		Assert.Equal(src.HistoricalSuccessfulLogonsByIp, roundtrip.HistoricalSuccessfulLogonsByIp);
		Assert.Equal(src.HistoricalUsersAttemptedFromIp, roundtrip.HistoricalUsersAttemptedFromIp);
		Assert.Equal(src.HistoricalFirstSeenByIpUtc, roundtrip.HistoricalFirstSeenByIpUtc);
		Assert.Equal(src.HistoricalLastSeenByIpUtc, roundtrip.HistoricalLastSeenByIpUtc);
		// Pre-existing Stage IP-D fields must still roundtrip — append-only contract.
		Assert.Equal(src.HistoricalFailedLogons, roundtrip.HistoricalFailedLogons);
		Assert.Equal(src.HistoricalSuccessfulLogons, roundtrip.HistoricalSuccessfulLogons);
		Assert.Equal(src.HistoricalUserNamesAttempted, roundtrip.HistoricalUserNamesAttempted);
	}

	[Fact]
	public void FromRdpSession_LiveClientAddress_IsNotShadowedByHistorical()
	{
		// Regression contract: historical projection must never overwrite or replace ClientAddress.
		// We assert this at the projection level by confirming the historical display doesn't expose
		// the live address — that responsibility stays on the live DTO field.
		RdpSessionDto dto = new()
		{
			SessionId = 1,
			ClientAddress = "10.0.0.5",
			HistoricalFirstSeenUtc = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalLastSeenUtc = new DateTime(2026, 5, 19, 0, 0, 0, DateTimeKind.Utc),
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal("2026-05-01 00:00:00", display.HistoricalFirstSeenUtcText);
		Assert.Equal("2026-05-19 00:00:00", display.HistoricalLastSeenUtcText);
		// Verifying the DTO's live address is still authoritative on the source side.
		Assert.Equal("10.0.0.5", dto.ClientAddress);
	}
}
