/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IpcDispatcherCrossHostTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Coverage for the P4-18 IPC handlers 67-69 on the real IpcDispatcher: bounded newest-first
//          chain listing with rule/ack filters, per-chain details with ordered links, and the ack
//          handler that flips the chain flag AND clears the linked CROSS_HOST_CHAIN alert.
// Depends: IpcDispatcher, CrossHostChain, CrossHostLink, Alert, Microsoft.Data.Sqlite
// Extends: Add MessagePack wire-level roundtrip coverage in IpcCommandStabilityTests.

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherCrossHostTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), conn);
	}

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(
			factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance);
	}

	private static long SeedChain(
		IDbContextFactory<AuditDbContext> factory,
		string chainKey,
		string ruleId,
		DateTime detectedUtc,
		bool acknowledged = false,
		long? alertId = null,
		string[]? hosts = null)
	{
		using AuditDbContext db = factory.CreateDbContext();
		CrossHostChain chain = new()
		{
			ChainKey = chainKey,
			RuleId = ruleId,
			NormalizedUserName = "attacker",
			FirstSeenUtc = detectedUtc.AddMinutes(-10),
			LastSeenUtc = detectedUtc,
			Score = 80,
			FailedAttemptCount = 3,
			DetectedUtc = detectedUtc,
			IsAcknowledged = acknowledged,
			AlertId = alertId,
		};

		string[] path = hosts ?? new[] { "SRV-A", "SRV-B", "SRV-C" };
		for (int i = 0; i < path.Length; i++)
		{
			chain.Links.Add(new CrossHostLink
			{
				Ordinal = i,
				HostName = path[i],
				Kind = i switch { 0 => CrossHostFactKind.FailedLogon, 1 => CrossHostFactKind.SuccessfulLogon, _ => CrossHostFactKind.PrivilegedLogon },
				EventId = i switch { 0 => 4625, 1 => 4624, _ => 4672 },
				TimeUtc = detectedUtc.AddMinutes(-10 + (i * 5)),
				SourceIp = "198.51.100." + (10 + i),
				UserName = "attacker",
			});
		}

		db.CrossHostChains.Add(chain);
		db.SaveChanges();
		return chain.Id;
	}

	private static async Task<T> DispatchAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
		where T : class
	{
		string? payloadJson = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default);
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = command, Payload = payloadJson },
			CancellationToken.None);
		Assert.True(response.Success);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	[Fact]
	public async Task ListCrossHostChains_ReturnsNewestFirstBoundedRowsWithHostPath()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			SeedChain(factory, "key-1", "RDP_LATERAL_MOVEMENT", now.AddMinutes(-30));
			SeedChain(factory, "key-2", "RDP_LATERAL_MOVEMENT", now.AddMinutes(-10));
			SeedChain(factory, "key-3", "OTHER_RULE", now.AddMinutes(-20));

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			CrossHostChainListDto list = await DispatchAsync<CrossHostChainListDto>(
				dispatcher, IpcCommand.ListCrossHostChains, new CrossHostChainsRequest { MaxRows = 5 });

			Assert.Equal(IpcResultStatus.Success, list.Status);
			Assert.Equal(3, list.TotalMatching);
			Assert.Equal(3, list.Chains.Count);
			Assert.Equal("key-2", list.Chains[0].ChainKey);
			Assert.Equal("key-3", list.Chains[1].ChainKey);
			Assert.Equal("key-1", list.Chains[2].ChainKey);
			Assert.Equal(new[] { "SRV-A", "SRV-B", "SRV-C" }, list.Chains[0].HostPath);
			Assert.Equal("198.51.100.12", list.Chains[0].LastSourceIp);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListCrossHostChains_WithMaxRowsAndRuleFilter_ClampsAndFilters()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			SeedChain(factory, "key-1", "RDP_LATERAL_MOVEMENT", now.AddMinutes(-30));
			SeedChain(factory, "key-2", "RDP_LATERAL_MOVEMENT", now.AddMinutes(-20));
			SeedChain(factory, "key-3", "OTHER_RULE", now.AddMinutes(-10));
			SeedChain(factory, "key-4", "RDP_LATERAL_MOVEMENT", now.AddMinutes(-5), acknowledged: true);

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			CrossHostChainListDto list = await DispatchAsync<CrossHostChainListDto>(
				dispatcher, IpcCommand.ListCrossHostChains, new CrossHostChainsRequest
				{
					MaxRows = 1,
					RuleId = "RDP_LATERAL_MOVEMENT",
					IncludeAcknowledged = false,
				});

			Assert.Equal(2, list.TotalMatching);
			Assert.Equal(1, list.AppliedLimit);
			CrossHostChainDto single = Assert.Single(list.Chains);
			Assert.Equal("key-2", single.ChainKey);

			// IncludeAcknowledged=true surfaces the acknowledged chain too.
			CrossHostChainListDto withAck = await DispatchAsync<CrossHostChainListDto>(
				dispatcher, IpcCommand.ListCrossHostChains, new CrossHostChainsRequest
				{
					RuleId = "RDP_LATERAL_MOVEMENT",
					IncludeAcknowledged = true,
				});
			Assert.Equal(3, withAck.TotalMatching);
			Assert.Equal("key-4", withAck.Chains[0].ChainKey);
			Assert.True(withAck.Chains[0].IsAcknowledged);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetCrossHostChainDetails_ExistingChain_ReturnsOrderedLinks_AndUnknownIdIsInvalidRequest()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long chainId = SeedChain(factory, "key-1", "RDP_LATERAL_MOVEMENT", DateTime.UtcNow);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			CrossHostChainDetailsDto details = await DispatchAsync<CrossHostChainDetailsDto>(
				dispatcher, IpcCommand.GetCrossHostChainDetails, new CrossHostChainDetailsRequest { ChainId = chainId });

			Assert.Equal(IpcResultStatus.Success, details.Status);
			Assert.Equal(chainId, details.Id);
			Assert.Equal("key-1", details.ChainKey);
			Assert.Equal("attacker", details.NormalizedUserName);
			Assert.Equal(3, details.Links.Count);
			Assert.Collection(details.Links,
				l => Assert.Equal("SRV-A", l.HostName),
				l => Assert.Equal("SRV-B", l.HostName),
				l => Assert.Equal("SRV-C", l.HostName));
			Assert.Equal(0, details.Links[0].Ordinal);
			Assert.Equal(4672, details.Links[2].EventId);

			CrossHostChainDetailsDto missing = await DispatchAsync<CrossHostChainDetailsDto>(
				dispatcher, IpcCommand.GetCrossHostChainDetails, new CrossHostChainDetailsRequest { ChainId = 999999 });
			Assert.Equal(IpcResultStatus.InvalidRequest, missing.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AcknowledgeCrossHostChain_ValidChain_FlagsChainAndClearsLinkedAlert()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long alertId;
			using (AuditDbContext db = factory.CreateDbContext())
			{
				Alert alert = new()
				{
					RuleId = CrossHostChainAlertFactory.RuleId,
					Severity = AlertSeverity.Critical,
					TimeUtc = DateTime.UtcNow,
					UserName = "attacker",
					Message = "chain",
					Acknowledged = false,
				};
				db.Alerts.Add(alert);
				db.SaveChanges();
				alertId = alert.Id;
			}

			long chainId = SeedChain(factory, "key-1", "RDP_LATERAL_MOVEMENT", DateTime.UtcNow, alertId: alertId);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			CrossHostChainAckResultDto result = await DispatchAsync<CrossHostChainAckResultDto>(
				dispatcher, IpcCommand.AcknowledgeCrossHostChain, new CrossHostChainAckRequest { ChainId = chainId });

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(chainId, result.ChainId);

			using (AuditDbContext verify = factory.CreateDbContext())
			{
				CrossHostChain chain = await verify.CrossHostChains.SingleAsync();
				Assert.True(chain.IsAcknowledged);
				Alert alert = await verify.Alerts.SingleAsync();
				Assert.True(alert.Acknowledged);
			}

			CrossHostChainAckResultDto missing = await DispatchAsync<CrossHostChainAckResultDto>(
				dispatcher, IpcCommand.AcknowledgeCrossHostChain, new CrossHostChainAckRequest { ChainId = 999999 });
			Assert.Equal(IpcResultStatus.InvalidRequest, missing.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
