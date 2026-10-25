// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStageIpDTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for Stage IP-D: ListConnectionFacts (40),
//          GetConnectionFactsForIp (41), Attack Statistics fact augmentation, and Remote RDP
//          Clients historical-context enrichment. Seeds an in-memory SQLite database, drives the
//          dispatcher directly, and asserts DTO shape, limit clamping, filter behaviour and
//          aggregate counters.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
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

public class IpcDispatcherStageIpDTests
{
	private static readonly DateTime Now = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);

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
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task SeedConnectionFactsAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();

		// Three facts for attacker IP, scattered timeline.
		db.RdpConnectionFacts.Add(new RdpConnectionFact
		{
			Ip = "203.0.113.7",
			UserName = "administrator",
			Domain = "ACME",
			LogonId = "0x1001",
			FirstSeenUtc = Now.AddHours(-3),
			LastSeenUtc = Now.AddHours(-2),
			FailedLogons = 5,
			SuccessfulLogons = 0,
			ObservedEventIds = "4625",
			UserNamesAttempted = "administrator",
			IsActive = false,
		});
		db.RdpConnectionFacts.Add(new RdpConnectionFact
		{
			Ip = "203.0.113.7",
			UserName = "root",
			LogonId = "0x1002",
			FirstSeenUtc = Now.AddHours(-1),
			LastSeenUtc = Now,
			FailedLogons = 7,
			SuccessfulLogons = 0,
			ObservedEventIds = "4625",
			UserNamesAttempted = "root,administrator",
			IsActive = true,
		});

		// One unrelated fact for a benign IP.
		db.RdpConnectionFacts.Add(new RdpConnectionFact
		{
			Ip = "10.0.0.7",
			UserName = "alice",
			LogonId = "0x2001",
			FirstSeenUtc = Now.AddHours(-6),
			LastSeenUtc = Now.AddHours(-5),
			SuccessfulLogons = 1,
			ObservedEventIds = "4624",
			UserNamesAttempted = "alice",
			IsActive = true,
		});

		// v3 invariant (Detect_Attack_Strategy_v3.md §8.1, §17.14): Fact Failed / Fact Success
		// counters derive from AuthAttemptFact, not from RdpConnectionFacts. Mirror the seeded
		// connection-fact tally as AuthAttemptFact rows so the IPC aggregation can find them.
		for (int i = 0; i < 5; i++)
		{
			db.AuthAttemptFacts.Add(MakeFailureFact("203.0.113.7", "administrator", Now.AddHours(-3).AddMinutes(i)));
		}

		for (int i = 0; i < 7; i++)
		{
			db.AuthAttemptFacts.Add(MakeFailureFact("203.0.113.7", "root", Now.AddHours(-1).AddMinutes(i)));
		}

		db.AuthAttemptFacts.Add(MakeSuccessFact("10.0.0.7", "alice", Now.AddHours(-6)));

		await db.SaveChangesAsync();
	}

	private static AuthAttemptFact MakeFailureFact(string ip, string user, DateTime utc) => new()
	{
		TimeUtc = utc,
		SourceIp = ip,
		TargetUser = user,
		NormalizedUserName = user.ToLowerInvariant(),
		Outcome = AuthAttemptOutcome.Failed,
		EvidenceChannel = "Security",
		EvidenceEventId = 4625,
		EnrichmentSource = "DirectXml",
		EnrichmentConfidence = "High",
		IngestedUtc = utc,
	};

	private static AuthAttemptFact MakeSuccessFact(string ip, string user, DateTime utc) => new()
	{
		TimeUtc = utc,
		SourceIp = ip,
		TargetUser = user,
		NormalizedUserName = user.ToLowerInvariant(),
		Outcome = AuthAttemptOutcome.Succeeded,
		EvidenceChannel = "Security",
		EvidenceEventId = 4624,
		EnrichmentSource = "DirectXml",
		EnrichmentConfidence = "High",
		IngestedUtc = utc,
	};

	private static async Task<T> CallAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest req = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	[Fact]
	public async Task ListConnectionFacts_OrdersByLastSeenDesc_AndAppliesDefaultLimit()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts, new ConnectionFactsRequest());

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal(3, dto.TotalMatching);
			Assert.Equal(3, dto.Facts.Count);
			Assert.True(dto.Facts[0].LastSeenUtc >= dto.Facts[^1].LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_FiltersByIpSubstring()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { IpQuery = "203.0.113" });

			Assert.Equal(2, dto.TotalMatching);
			Assert.All(dto.Facts, f => Assert.StartsWith("203.0.113", f.Ip));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_FiltersByUserSubstring()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { UserQuery = "admin" });

			Assert.Equal(1, dto.TotalMatching);
			Assert.Equal("administrator", dto.Facts[0].UserName);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_TreatsLikeWildcardsInUserQueryLiterally()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			// A lone "%" would match every row if wildcards were honoured; with escaping it is a
			// literal percent sign that matches none of the seeded user names.
			ConnectionFactsDto wildcard = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { UserQuery = "%" });
			Assert.Equal(0, wildcard.TotalMatching);

			// "_oot" would match "root" under wildcard semantics; literally it matches nothing.
			ConnectionFactsDto underscore = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { UserQuery = "_oot" });
			Assert.Equal(0, underscore.TotalMatching);

			// A hostile SQL/CRLF login is harmless literal text and simply matches nothing.
			ConnectionFactsDto hostile = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { UserQuery = "root' OR 1=1 --" });
			Assert.Equal(0, hostile.TotalMatching);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_ClampsRequestedLimitToMax()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { Limit = 100_000 });

			// The server clamps to the hard upper bound (1000) — but with only 3 rows seeded the
			// AppliedLimit should still report the clamped value and Facts.Count should match all rows.
			Assert.Equal(1000, dto.AppliedLimit);
			Assert.Equal(3, dto.Facts.Count);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_OnlyActive_RestrictsToActiveRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts,
				new ConnectionFactsRequest { OnlyActive = true });

			Assert.Equal(2, dto.TotalMatching);
			Assert.All(dto.Facts, f => Assert.True(f.IsActive));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetConnectionFactsForIp_AggregatesCountersAndOrdersFacts()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsForIpDto dto = await CallAsync<ConnectionFactsForIpDto>(dispatcher,
				IpcCommand.GetConnectionFactsForIp,
				new ConnectionFactsForIpRequest { Ip = "203.0.113.7" });

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal("203.0.113.7", dto.Ip);
			Assert.Equal(2, dto.TotalMatching);
			Assert.Equal(2, dto.Facts.Count);
			Assert.Equal(12, dto.FailedLogons);
			Assert.Equal(0, dto.SuccessfulLogons);
			Assert.True(dto.HasActiveFact);
			Assert.Equal(Now.AddHours(-3), dto.FirstSeenUtc);
			Assert.Equal(Now, dto.LastSeenUtc);
			Assert.True(dto.Facts[0].LastSeenUtc >= dto.Facts[^1].LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetConnectionFactsForIp_ResponsesDoNotCarryRawXml()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			IpcRequest req = new()
			{
				Command = IpcCommand.GetConnectionFactsForIp,
				Payload = JsonSerializer.Serialize(new ConnectionFactsForIpRequest { Ip = "203.0.113.7" }, JsonOptions.Default),
			};
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			// Sanity check: a fact response must never embed event XML markup. The DTO has no XML
			// member, so the payload shouldn't contain "<Event" anywhere.
			Assert.DoesNotContain("<Event", response.Payload!, StringComparison.Ordinal);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetConnectionFactsForIp_NoMatch_ReturnsEmptyButSuccess()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			ConnectionFactsForIpDto dto = await CallAsync<ConnectionFactsForIpDto>(dispatcher,
				IpcCommand.GetConnectionFactsForIp,
				new ConnectionFactsForIpRequest { Ip = "203.0.113.99" });

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal(0, dto.TotalMatching);
			Assert.Empty(dto.Facts);
			Assert.Null(dto.FirstSeenUtc);
			Assert.False(dto.HasActiveFact);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetConnectionFactsForIp_RejectsInvalidIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			IpcRequest req = new()
			{
				Command = IpcCommand.GetConnectionFactsForIp,
				Payload = JsonSerializer.Serialize(new ConnectionFactsForIpRequest { Ip = "garbage" }, JsonOptions.Default),
			};
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.False(response.Success);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_AugmentsRowsWithFactAggregates()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.7",
					TotalAttempts = 12,
					Failed = 12,
					Successful = 0,
					FirstSeenUtc = Now.AddHours(-3),
					LastSeenUtc = Now,
					DurationSeconds = 3 * 3600,
					ThreatScore = 80,
					IsBlocked = false,
					LastUpdatedUtc = Now,
				});
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);

			AttackStatsDto dto = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			AttackStatEntryDto entry = Assert.Single(dto.Entries);

			// AttackStat data preserved verbatim.
			Assert.Equal(12, entry.Failed);
			Assert.Equal(12, entry.TotalAttempts);

			// Fact-derived augmentation populated.
			Assert.True(entry.HasActiveConnectionFact);
			Assert.Equal(12, entry.FactFailedLogons);
			Assert.Equal(0, entry.FactSuccessfulLogons);
			Assert.NotNull(entry.FactFirstSeenUtc);
			Assert.NotNull(entry.FactLastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_FlagsUnresolvedSentinelRow_AndSeparatesCounters()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// A genuine public attacker IP.
				db.AttackStats.Add(new AttackStat
				{
					Ip = "77.37.192.246",
					TotalAttempts = 8,
					Failed = 8,
					Successful = 0,
					FirstSeenUtc = Now.AddHours(-1),
					LastSeenUtc = Now,
					ThreatScore = 70,
					Top10AttemptedLogins = "[]",
					LastUpdatedUtc = Now,
				});
				// The unresolved-IP sentinel aggregate row (0.0.0.0). Must never look like a real attacker.
				db.AttackStats.Add(new AttackStat
				{
					Ip = AttackStatsAggregator.SentinelUnresolvedIp,
					TotalAttempts = 4,
					Failed = 4,
					Successful = 0,
					FirstSeenUtc = Now.AddHours(-2),
					LastSeenUtc = Now.AddMinutes(-1),
					ThreatScore = 30,
					Top10AttemptedLogins = "[]",
					LastUpdatedUtc = Now,
				});

				// Window summary derives from AuthAttemptFacts: 3 failures with a real IP, 2 with none.
				for (int i = 0; i < 3; i++)
				{
					db.AuthAttemptFacts.Add(MakeFailureFact("77.37.192.246", "admin", Now.AddMinutes(-i)));
				}
				for (int i = 0; i < 2; i++)
				{
					AuthAttemptFact f = MakeFailureFact("", "admin", Now.AddMinutes(-10 - i));
					f.SourceIp = string.Empty;
					db.AuthAttemptFacts.Add(f);
				}
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			AttackStatsDto dto = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats,
				new AttackStatsRequest { SinceUtc = Now.AddDays(-1), UntilUtc = Now.AddMinutes(1) });

			AttackStatEntryDto real = dto.Entries.Single(e => e.Ip == "77.37.192.246");
			Assert.False(real.IsUnresolved);
			Assert.Equal("Public", real.Classification);
			Assert.Equal("77.37.192.246", real.DisplayIp);

			AttackStatEntryDto sentinel = dto.Entries.Single(e => e.Ip == AttackStatsAggregator.SentinelUnresolvedIp);
			Assert.True(sentinel.IsUnresolved);
			Assert.Equal("Unresolved", sentinel.Classification);
			Assert.Equal(AttackStatsAggregator.SentinelDisplayLabel, sentinel.DisplayIp);

			// Debug counters: 2 unresolved failures, and the resolved-IP population excludes the sentinel.
			Assert.Equal(2, dto.UnresolvedFailedLogons);
			Assert.Equal(5, dto.FailedLogons);
			Assert.Equal(1, dto.DistinctResolvedSourceIps);
			Assert.Equal(2, dto.DistinctSourceIps);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task EnrichSessionsHistoricalContext_FillsCountersAndAttemptedNames()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedConnectionFactsAsync(factory);

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto
				{
					SessionId = 3,
					UserName = "root",
					ClientAddress = "198.51.100.42",  // live IP must not be overwritten
				},
			};

			await using AuditDbContext db = factory.CreateDbContext();
			await IpcDispatcher.EnrichSessionsHistoricalContextAsync(db, sessions, CancellationToken.None);

			Assert.Equal("198.51.100.42", sessions[0].ClientAddress);
			Assert.Equal(Now.AddHours(-1), sessions[0].HistoricalFirstSeenUtc);
			Assert.Equal(Now, sessions[0].HistoricalLastSeenUtc);
			Assert.Equal(7, sessions[0].HistoricalFailedLogons);
			Assert.Equal(0, sessions[0].HistoricalSuccessfulLogons);
			Assert.False(string.IsNullOrEmpty(sessions[0].HistoricalUserNamesAttempted));
			Assert.Contains("root", sessions[0].HistoricalUserNamesAttempted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private static RdpConnectionFact MakeFact(string ip, DateTime lastSeenUtc) => new()
	{
		Ip = ip,
		UserName = "tester",
		LogonId = "0x9000",
		FirstSeenUtc = lastSeenUtc.AddMinutes(-5),
		LastSeenUtc = lastSeenUtc,
		FailedLogons = 1,
		ObservedEventIds = "4625",
		UserNamesAttempted = "tester",
		IsActive = false,
	};

	[Fact]
	public async Task ListConnectionFacts_PopulatesReportabilityClassification()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RdpConnectionFacts.Add(MakeFact("77.37.192.246", Now));
				db.RdpConnectionFacts.Add(MakeFact("192.168.1.50", Now.AddMinutes(-1)));
				db.RdpConnectionFacts.Add(MakeFact("fe80::1ff:fe23:4567:890a", Now.AddMinutes(-2)));
				db.RdpConnectionFacts.Add(MakeFact("8.8.8.8", Now.AddMinutes(-3)));
				db.WhitelistEntries.Add(new WhitelistEntry
				{
					Ip = "8.8.8.8",
					AddedUtc = Now,
				});
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts, new ConnectionFactsRequest());

			ConnectionFactDto pub = dto.Facts.Single(f => f.Ip == "77.37.192.246");
			Assert.True(pub.IsPublic);
			Assert.False(pub.IsWhitelisted);
			Assert.True(pub.IsReportableToAbuseIPDB);
			Assert.True(pub.IsEligibleForAutoBlock);

			ConnectionFactDto priv = dto.Facts.Single(f => f.Ip == "192.168.1.50");
			Assert.False(priv.IsPublic);
			Assert.False(priv.IsReportableToAbuseIPDB);
			Assert.False(priv.IsEligibleForAutoBlock);

			ConnectionFactDto link = dto.Facts.Single(f => f.Ip == "fe80::1ff:fe23:4567:890a");
			Assert.False(link.IsPublic);
			Assert.False(link.IsReportableToAbuseIPDB);
			Assert.False(link.IsEligibleForAutoBlock);

			ConnectionFactDto white = dto.Facts.Single(f => f.Ip == "8.8.8.8");
			Assert.True(white.IsWhitelisted);
			Assert.False(white.IsReportableToAbuseIPDB);
			Assert.False(white.IsEligibleForAutoBlock);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetConnectionFactsForIp_PopulatesReportabilityForPublicIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RdpConnectionFacts.Add(MakeFact("77.37.192.246", Now));
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			ConnectionFactsForIpDto dto = await CallAsync<ConnectionFactsForIpDto>(dispatcher,
				IpcCommand.GetConnectionFactsForIp,
				new ConnectionFactsForIpRequest { Ip = "77.37.192.246" });

			ConnectionFactDto fact = Assert.Single(dto.Facts);
			Assert.True(fact.IsPublic);
			Assert.True(fact.IsReportableToAbuseIPDB);
			Assert.True(fact.IsEligibleForAutoBlock);
			Assert.False(fact.IsWhitelisted);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task EnrichSessionsHistoricalContext_NoFacts_LeavesSessionUntouched()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto
				{
					SessionId = 1,
					UserName = "nobody",
					ClientAddress = "198.51.100.7",
				},
			};

			await using AuditDbContext db = factory.CreateDbContext();
			await IpcDispatcher.EnrichSessionsHistoricalContextAsync(db, sessions, CancellationToken.None);

			Assert.Equal("198.51.100.7", sessions[0].ClientAddress);
			Assert.Null(sessions[0].HistoricalFirstSeenUtc);
			Assert.Equal(0, sessions[0].HistoricalFailedLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
