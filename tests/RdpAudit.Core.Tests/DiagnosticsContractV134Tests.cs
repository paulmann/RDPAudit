// File:    tests/RdpAudit.Core.Tests/DiagnosticsContractV134Tests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the v1.3.4 diagnostics / RDP Activity JSON contract additions: the resolved-RDP-port
//          and firewall-scope fields, the RDP Activity (AttackStats) freshness fields, the recent
//          operation-log tail, and the RebuildAttackStats result DTO all round-trip through the plain
//          JSON IPC payload channel (no MessagePack keys), and the operation-log query / row DTOs carry
//          the new noise-filter / duplicate-count fields. A non-3389 port (55554) is used throughout so
//          a regression that hard-codes 3389 is caught.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Round-trip tests for the v1.3.4 diagnostics / RDP Activity JSON contract additions.</summary>
public class DiagnosticsContractV134Tests
{
	[Fact]
	public void DiagnosticsSnapshot_RoundTrips_PortAndFreshnessFields()
	{
		DateTime now = DateTime.UtcNow;
		DiagnosticsSnapshotDto dto = new()
		{
			ResolvedRdpPort = 55554,
			ResolvedRdpPortSource = "Registry",
			ResolvedRdpPortDetail = "HKLM\\...\\PortNumber=55554",
			FirewallBlockScope = "RdpPortOnly",
			LatestRawEventUtc = now,
			LatestAuthAttemptFactUtc = now.AddMinutes(-1),
			LatestAttackStatUpdatedUtc = now.AddMinutes(-2),
			StatsWorkerLastRunUtc = now.AddMinutes(-3),
			StatsWorkerLastRowsUpserted = 7,
			StatsWorkerRunCount = 42,
			StatsWorkerLastError = null,
			AttackStatsTotal = 1234,
			RecentOperationLog = new List<DiagnosticsOperationLogLine>
			{
				new()
				{
					TimeUtc = now,
					Severity = "Error",
					Source = "Ipc",
					Operation = "AcceptLoopFault",
					Message = "boom",
				},
			},
		};

		string json = JsonSerializer.Serialize(dto);
		DiagnosticsSnapshotDto? back = JsonSerializer.Deserialize<DiagnosticsSnapshotDto>(json);

		Assert.NotNull(back);
		Assert.Equal(55554, back!.ResolvedRdpPort);
		Assert.Equal("Registry", back.ResolvedRdpPortSource);
		Assert.Equal("RdpPortOnly", back.FirewallBlockScope);
		Assert.Equal(7, back.StatsWorkerLastRowsUpserted);
		Assert.Equal(42, back.StatsWorkerRunCount);
		Assert.Equal(1234, back.AttackStatsTotal);
		Assert.Single(back.RecentOperationLog);
		Assert.Equal("AcceptLoopFault", back.RecentOperationLog[0].Operation);
	}

	[Fact]
	public void AttackStatsRebuildResult_RoundTrips()
	{
		AttackStatsRebuildResultDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Message = "rebuilt",
			GeneratedUtc = DateTime.UtcNow,
			RowsUpserted = 11,
			ElapsedMilliseconds = 250,
			AttackStatsTotal = 999,
		};

		string json = JsonSerializer.Serialize(dto);
		AttackStatsRebuildResultDto? back = JsonSerializer.Deserialize<AttackStatsRebuildResultDto>(json);

		Assert.NotNull(back);
		Assert.Equal(IpcResultStatus.Success, back!.Status);
		Assert.Equal(11, back.RowsUpserted);
		Assert.Equal(250, back.ElapsedMilliseconds);
		Assert.Equal(999, back.AttackStatsTotal);
	}

	[Fact]
	public void OperationLogDto_OccurrenceCount_DefaultsToOne_AndRoundTripsViaJson()
	{
		OperationLogDto dto = new() { Id = 1, Source = "Ipc", Operation = "X", Message = "m" };
		Assert.Equal(1, dto.OccurrenceCount);

		dto.OccurrenceCount = 5;
		string json = JsonSerializer.Serialize(dto);
		OperationLogDto? back = JsonSerializer.Deserialize<OperationLogDto>(json);
		Assert.NotNull(back);
		Assert.Equal(5, back!.OccurrenceCount);
	}
}
