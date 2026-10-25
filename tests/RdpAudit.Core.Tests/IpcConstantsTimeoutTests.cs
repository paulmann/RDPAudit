// File:    tests/RdpAudit.Core.Tests/IpcConstantsTimeoutTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the per-command IPC round-trip deadline policy that fixed the historic
//          "service not running" misreport: long-running firewall / diagnostics commands MUST
//          get the long (60 s) deadline so the client and server never abandon a request the
//          service is still completing, while cheap read-only commands keep the short default.
//          Both ends of a round-trip consult IpcConstants.TimeoutMsFor, so this single map is the
//          contract — if it regresses (e.g. a Repair command drops back to 5 s) the bug returns.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the IPC per-command timeout policy that keeps long firewall / diagnostics calls
/// from being abandoned mid-flight and misreported as a dead service.</summary>
public class IpcConstantsTimeoutTests
{
	/// <summary>Every command the deadline policy records as long-running. The theory below is built from
	/// this list so the theory cases and the exhaustive check
	/// (<see cref="TimeoutMsFor_EveryCommandNotRecordedAsLong_UsesTheShortDefault"/>) can never disagree.</summary>
	public static IReadOnlyList<IpcCommand> LongRunningCommandList { get; } = new[]
	{
		IpcCommand.RunToolsDiagnostics,
		IpcCommand.RunTemporaryFirewallRuleProbe,
		IpcCommand.GetFirewallStatus,
		IpcCommand.GetFirewallDiagnostics,
		IpcCommand.ListActiveBlocksDetailed,
		IpcCommand.ReconcileEnforcement,
		IpcCommand.RepairActiveBlock,
		IpcCommand.RemoveAllEnforcement,
		IpcCommand.RepairBlocklistEnforcement,
		IpcCommand.RepairAllEnabledBlocklistEnforcement,
		IpcCommand.BlockAddress,
		IpcCommand.UnblockAddress,
		IpcCommand.AddToBlocklist,
		IpcCommand.RemoveFromBlocklist,
		IpcCommand.UnblockActiveBlock,
		IpcCommand.ClearAllBlocklist,
		IpcCommand.ClearAllFirewallRules,
		IpcCommand.ClearAllApplicationData,
		IpcCommand.RebuildAttackStats,
		IpcCommand.GetCrossHostFacts,
		IpcCommand.ListCrossHostChains,
		IpcCommand.GetCrossHostChainDetails,
		IpcCommand.GetShardInventory,
		IpcCommand.RunDatabaseMaintenance,
		IpcCommand.RestoreDatabaseBackupToDirectory,
		IpcCommand.CollectShardGarbage,
		IpcCommand.PurgeBySubject,
		IpcCommand.CreateDatabaseBackup,
		IpcCommand.ListDatabaseBackups,
		IpcCommand.VerifyDatabaseBackup,
		IpcCommand.GetMikroTikSecurityAudit,
		// Zabbix integration: the test opens two network round-trips, the manual push waits for a TCP
		// answer, and provisioning issues one API call per object.
		IpcCommand.TestZabbixConnection,
		IpcCommand.PushZabbixNow,
		IpcCommand.ProvisionZabbix,
	};

	public static TheoryData<IpcCommand> LongRunningCommands { get; } = ToTheoryData(LongRunningCommandList);

	public static TheoryData<IpcCommand> CheapCommands => new()
	{
		IpcCommand.Ping,
		IpcCommand.GetStatus,
	};

	private static TheoryData<IpcCommand> ToTheoryData(IEnumerable<IpcCommand> commands)
	{
		TheoryData<IpcCommand> data = new();
		foreach (IpcCommand command in commands)
		{
			data.Add(command);
		}

		return data;
	}

	[Theory]
	[MemberData(nameof(LongRunningCommands))]
	public void TimeoutMsFor_LongRunningCommand_UsesLongDeadline(IpcCommand command)
	{
		Assert.Equal(IpcConstants.LongOperationTimeoutMs, IpcConstants.TimeoutMsFor(command));
	}

	[Theory]
	[MemberData(nameof(CheapCommands))]
	public void TimeoutMsFor_CheapCommand_UsesShortDefault(IpcCommand command)
	{
		Assert.Equal(IpcConstants.OperationTimeoutMs, IpcConstants.TimeoutMsFor(command));
	}

	[Fact]
	public void LongDeadline_IsStrictlyGreaterThanShortDefault()
	{
		// The server only widens its deadline when the per-command budget exceeds the short default
		// (IpcServerWorker), so the long deadline must be strictly larger or the widening is a no-op.
		Assert.True(IpcConstants.LongOperationTimeoutMs > IpcConstants.OperationTimeoutMs);
	}

	[Fact]
	public void ConnectTimeout_IsShorterThanShortDefault()
	{
		// Connect must fail fast (service stopped / not installed) well before the round-trip deadline,
		// so the UI can distinguish ConnectFailed from a slow-but-reachable service.
		Assert.True(IpcConstants.ConnectTimeoutMs < IpcConstants.OperationTimeoutMs);
	}

	[Fact]
	public void TimeoutMsFor_EveryDefinedCommand_HasAnExplicitEntry()
	{
		// Drift guard: the switch in IpcConstants.TimeoutMsFor ends with a catch-all that hands out the
		// short deadline, so a new storage / maintenance command would silently inherit 5 s and reproduce
		// the abandoned-request bug this class exists to prevent. Every command therefore needs an arm of
		// its own - the deadline decision must be stated per ordinal, never defaulted into.
		string source = File.ReadAllText(Path.Combine(
			FindRepositoryRoot(), "src", "RdpAudit.Core", "Ipc", "IpcConstants.cs"));

		List<string> missing = new();
		foreach (string name in Enum.GetNames(typeof(IpcCommand)))
		{
			if (!source.Contains("IpcCommand." + name + " =>", StringComparison.Ordinal))
			{
				missing.Add(name + " (" + ((int)Enum.Parse<IpcCommand>(name)).ToString(CultureInfo.InvariantCulture) + ")");
			}
		}

		Assert.True(missing.Count == 0,
			"IpcConstants.TimeoutMsFor has no explicit deadline for these IpcCommand values, so they would "
			+ "silently inherit the short default: " + string.Join(", ", missing));
	}

	[Fact]
	public void TimeoutMsFor_StorageBackupCommands_UseLongDeadline()
	{
		// Ordinals 85-87 copy / hash / enumerate the store and its snapshot folder, so they were the last
		// storage commands still answering on the 5 s deadline (B3).
		foreach (IpcCommand command in new[]
		{
			IpcCommand.CreateDatabaseBackup,
			IpcCommand.ListDatabaseBackups,
			IpcCommand.VerifyDatabaseBackup,
		})
		{
			Assert.Equal(IpcConstants.LongOperationTimeoutMs, IpcConstants.TimeoutMsFor(command));
		}
	}

	[Fact]
	public void TimeoutMsFor_EveryCommandNotRecordedAsLong_UsesTheShortDefault()
	{
		// The other half of the drift guard: with every command now stating its deadline explicitly, the
		// complete policy is "long if and only if recorded as long". A command that quietly acquires the
		// long deadline (or loses it) without being recorded in LongRunningCommandList fails here.
		HashSet<IpcCommand> recordedLong = LongRunningCommandList.ToHashSet();

		List<string> unexpected = new();
		foreach (IpcCommand command in Enum.GetValues<IpcCommand>())
		{
			if (recordedLong.Contains(command))
			{
				continue;
			}

			if (IpcConstants.TimeoutMsFor(command) != IpcConstants.OperationTimeoutMs)
			{
				unexpected.Add(command.ToString());
			}
		}

		Assert.True(unexpected.Count == 0,
			"These commands are not recorded as long-running but do not use the short default either: "
			+ string.Join(", ", unexpected));
	}

	private static string FindRepositoryRoot()
	{
		DirectoryInfo? directory = new(AppContext.BaseDirectory);
		while (directory is not null)
		{
			if (File.Exists(Path.Combine(directory.FullName, "RdpAudit.sln")))
			{
				return directory.FullName;
			}

			directory = directory.Parent;
		}

		throw new InvalidOperationException(
			"Repository root (RdpAudit.sln) not found above " + AppContext.BaseDirectory);
	}
}
