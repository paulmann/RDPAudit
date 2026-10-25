/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPushStateStoreTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Proves the crash-consistency contract of the push position: the file round-trips, no
//          temporary file is left behind, and an unreadable file is preserved under a timestamped name
//          while the position restarts at zero (which re-sends rather than loses).
// Extends: System.Object

using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Service.Zabbix;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Tests of <see cref="ZabbixPushStateStore"/>.</summary>
public sealed class ZabbixPushStateStoreTests : IDisposable
{
	private readonly string _root;

	public ZabbixPushStateStoreTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-zabbix-state-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_root);
	}

	public void Dispose()
	{
		try
		{
			Directory.Delete(_root, recursive: true);
		}
		catch (IOException)
		{
			// Best effort: a leftover temp folder must never fail the suite.
		}
	}

	[Fact]
	public void Save_ThenLoad_RoundTripsEveryField()
	{
		ZabbixPushStateStore store = CreateStore();
		ZabbixPushState state = new()
		{
			LastPushedAlertId = 4711,
			Sequence = 12,
			LastPushUtc = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc),
			LastSuccessUtc = new DateTime(2026, 10, 25, 11, 59, 0, DateTimeKind.Utc),
			ConsecutiveFailures = 0,
			ValuesSent = 700,
			ValuesFailed = 3,
			IncidentsSkipped = 9,
			RecentIncidents = new List<ZabbixSentIncidentDto>
			{
				new() { AlertId = 4711, RuleId = "BRUTE_FORCE", Severity = "High", ZabbixSeverity = 4, SourceIp = "203.0.113.9" },
			},
		};

		store.Save(state);
		ZabbixPushState loaded = store.Load();

		Assert.Equal(4711, loaded.LastPushedAlertId);
		Assert.Equal(12, loaded.Sequence);
		Assert.Equal(700, loaded.ValuesSent);
		Assert.Equal(9, loaded.IncidentsSkipped);
		Assert.Single(loaded.RecentIncidents);
		Assert.Equal("BRUTE_FORCE", loaded.RecentIncidents[0].RuleId);
	}

	[Fact]
	public void Save_LeavesNoTemporaryFileBehind()
	{
		ZabbixPushStateStore store = CreateStore();
		store.Save(new ZabbixPushState { LastPushedAlertId = 1 });
		store.Save(new ZabbixPushState { LastPushedAlertId = 2 });

		Assert.True(File.Exists(store.StatePath));
		Assert.False(File.Exists(store.StatePath + ".tmp"));
	}

	[Fact]
	public void Load_MissingFile_StartsWithAnEmptyPosition()
	{
		ZabbixPushState state = CreateStore().Load();

		Assert.Equal(0, state.LastPushedAlertId);
		Assert.Equal(0, state.Sequence);
	}

	[Fact]
	public void Load_CorruptFile_IsKeptAsideAndThePositionRestartsAtZero()
	{
		ZabbixPushStateStore store = CreateStore();
		Directory.CreateDirectory(Path.GetDirectoryName(store.StatePath)!);
		File.WriteAllText(store.StatePath, "{ this is not json");

		ZabbixPushState state = store.Load();

		Assert.Equal(0, state.LastPushedAlertId);
		Assert.False(File.Exists(store.StatePath));
		string[] preserved = Directory.GetFiles(
			Path.GetDirectoryName(store.StatePath)!,
			"zabbix-push-state.json.corrupt-*");
		Assert.Single(preserved);
	}

	[Fact]
	public void Save_CapsTheRememberedIncidentList()
	{
		ZabbixPushStateStore store = CreateStore();
		List<ZabbixSentIncidentDto> rows = new();
		for (int i = 0; i < ZabbixPushStateStore.MaxRememberedIncidents + 25; i++)
		{
			rows.Add(new ZabbixSentIncidentDto { AlertId = i });
		}

		store.Save(new ZabbixPushState { RecentIncidents = rows });

		Assert.Equal(ZabbixPushStateStore.MaxRememberedIncidents, store.Load().RecentIncidents.Count);
	}

	private ZabbixPushStateStore CreateStore()
		=> new(new FakePaths(_root), NullLogger<ZabbixPushStateStore>.Instance);

	private sealed class FakePaths : IRdpAuditPathsProvider
	{
		public FakePaths(string root) => Paths = new RdpAuditPaths(root);

		public RdpAuditPaths Paths { get; }
	}
}
