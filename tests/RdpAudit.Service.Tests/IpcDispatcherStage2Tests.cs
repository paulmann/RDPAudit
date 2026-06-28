// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage2Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 2 visibility coverage — unresolved-IP sentinel rows in Attack Statistics, classifier-
//          based window summary counters (TS-RCM 1149 / TS-LSM 21 successes counted, 4625 failures
//          counted), and per-IP historical aggregation feeding the Remote RDP Clients tab.
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
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Stage 2 — visibility regressions on the read side of the IPC dispatcher.</summary>
public class IpcDispatcherStage2Tests
{
	private static readonly DateTime Now = DateTime.UtcNow;

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

	[Fact]
	public async Task AttackStatsRefreshWorker_IncludesUnresolved4625UnderSentinelIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				for (int i = 0; i < 3; i++)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = AttackStatsAggregator.EventIdLogonFailure,
						Channel = "Security",
						TimeUtc = Now.AddSeconds(-10 + i),
						SourceIp = null,
						SourceIpUnresolved = true,
						UserName = "administrator",
						LogonType = 10,
					});
				}

				TestAuthAttemptFactHelper.SynthesizeFactsFromRawEvents(db);
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			int upserts = await worker.RefreshOnceAsync(CancellationToken.None);

			Assert.True(upserts >= 1);

			await using AuditDbContext check = factory.CreateDbContext();
			AttackStat? sentinel = await check.AttackStats
				.FirstOrDefaultAsync(s => s.Ip == AttackStatsAggregator.SentinelUnresolvedIp);

			Assert.NotNull(sentinel);
			Assert.True(sentinel!.Failed >= 3);
			Assert.Equal(0, sentinel.Successful);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_WindowSummary_DerivesFromAuthAttemptFacts()
	{
		// Stage 4 (telemetry restoration): the IPC window summary MUST derive its Failed /
		// Successful / DistinctSourceIps counters from AuthAttemptFacts only. RDP/Operational,
		// RdpCoreTS and TerminalServices events are context/enrichment, not outcome carriers —
		// Detect_Attack_Strategy_v3.md §8.1, §6.3 rule 3. This test pins the new contract: the
		// same fixture that used to score TS-RCM 1149 + TS-LSM 21 as 2 successes now scores 0
		// because no AuthAttemptFact rows back them; only the AuthAttemptFact rows we seed for
		// 4624 / 4625 move the counters.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Context-only RawEvents — must NOT shift counters.
				db.RawEvents.Add(new RawEvent
				{
					EventId = 1149,
					Channel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
					TimeUtc = Now.AddSeconds(-30),
					SourceIp = "203.0.113.20",
					UserName = "alice",
				});
				db.RawEvents.Add(new RawEvent
				{
					EventId = 21,
					Channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
					TimeUtc = Now.AddSeconds(-20),
					SourceIp = "203.0.113.21",
					UserName = "bob",
					LogonType = 10,
				});

				// Authoritative facts — the only thing the counters now see.
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now.AddSeconds(-25),
					Outcome = AuthAttemptOutcome.Succeeded,
					EvidenceEventId = 4624,
					EvidenceChannel = "Security",
					SourceIp = "203.0.113.30",
					TargetUser = "diana",
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now.AddSeconds(-10),
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceEventId = 4625,
					EvidenceChannel = "Security",
					SourceIp = null, // NLA-stripped — should still land in the unresolved sentinel bucket
					TargetUser = "carol",
				});

				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			IpcRequest req = new()
			{
				Command = IpcCommand.GetAttackStats,
				Payload = JsonSerializer.Serialize(new AttackStatsRequest(), JsonOptions.Default),
			};
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.True(response.Success, response.Error);
			AttackStatsDto dto = JsonSerializer.Deserialize<AttackStatsDto>(response.Payload!, JsonOptions.Default)!;

			Assert.Equal(1, dto.SuccessfulLogons);
			Assert.Equal(1, dto.FailedLogons);
			// Real IP from the success fact + unresolved sentinel from the IP-stripped failure.
			Assert.Equal(2, dto.DistinctSourceIps);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task EnrichSessionsHistoricalByIpAsync_FillsCountersFromRdpConnectionFacts()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					Ip = "203.0.113.50",
					UserName = "alice",
					FirstSeenUtc = nowUtc.AddHours(-3),
					LastSeenUtc = nowUtc.AddHours(-2),
					FailedLogons = 3,
					SuccessfulLogons = 1,
					IsActive = false,
				});
				db.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					Ip = "203.0.113.50",
					UserName = "bob",
					FirstSeenUtc = nowUtc.AddHours(-1),
					LastSeenUtc = nowUtc,
					FailedLogons = 4,
					SuccessfulLogons = 0,
					IsActive = true,
				});
				db.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					Ip = "198.51.100.99",
					UserName = "carol",
					FirstSeenUtc = nowUtc.AddDays(-1),
					LastSeenUtc = nowUtc.AddHours(-12),
					FailedLogons = 1,
					SuccessfulLogons = 0,
					IsActive = false,
				});

				await db.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 1, UserName = "alice", ClientAddress = "203.0.113.50", IsActive = true },
				new RdpSessionDto { SessionId = 2, UserName = "noip", ClientAddress = null, IsActive = false },
				new RdpSessionDto { SessionId = 3, UserName = "fresh", ClientAddress = "10.0.0.10", IsActive = true },
			};

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				await IpcDispatcher.EnrichSessionsHistoricalByIpAsync(db, sessions, CancellationToken.None);
			}

			// Session 1 has a matching IP with two facts — totals: failed=7, successful=1, users=alice,bob.
			Assert.Equal(7L, sessions[0].HistoricalFailedLogonsByIp);
			Assert.Equal(1L, sessions[0].HistoricalSuccessfulLogonsByIp);
			Assert.NotNull(sessions[0].HistoricalUsersAttemptedFromIp);
			Assert.Contains("alice", sessions[0].HistoricalUsersAttemptedFromIp!);
			Assert.Contains("bob", sessions[0].HistoricalUsersAttemptedFromIp!);
			Assert.Equal(nowUtc.AddHours(-3), sessions[0].HistoricalFirstSeenByIpUtc);
			Assert.Equal(nowUtc, sessions[0].HistoricalLastSeenByIpUtc);

			// Session 2 has no IP — the *ByIp fields must stay null so the UI renders blank.
			Assert.Null(sessions[1].HistoricalFailedLogonsByIp);
			Assert.Null(sessions[1].HistoricalSuccessfulLogonsByIp);
			Assert.Null(sessions[1].HistoricalUsersAttemptedFromIp);
			Assert.Null(sessions[1].HistoricalFirstSeenByIpUtc);
			Assert.Null(sessions[1].HistoricalLastSeenByIpUtc);

			// Session 3 has an IP but no facts — counters land on 0 (known IP, no history) and
			// timestamps stay null.
			Assert.Equal(0L, sessions[2].HistoricalFailedLogonsByIp);
			Assert.Equal(0L, sessions[2].HistoricalSuccessfulLogonsByIp);
			Assert.Null(sessions[2].HistoricalFirstSeenByIpUtc);
			Assert.Null(sessions[2].HistoricalLastSeenByIpUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_IncludesSentinelRowWithBlockedFalse()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				for (int i = 0; i < 4; i++)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = AttackStatsAggregator.EventIdLogonFailure,
						Channel = "Security",
						TimeUtc = Now.AddSeconds(-30 + i),
						SourceIp = null,
						SourceIpUnresolved = true,
						UserName = "administrator",
						LogonType = 10,
					});
				}

				TestAuthAttemptFactHelper.SynthesizeFactsFromRawEvents(db);
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			IpcRequest req = new()
			{
				Command = IpcCommand.GetAttackStats,
				Payload = JsonSerializer.Serialize(new AttackStatsRequest(), JsonOptions.Default),
			};
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.True(response.Success, response.Error);
			AttackStatsDto dto = JsonSerializer.Deserialize<AttackStatsDto>(response.Payload!, JsonOptions.Default)!;

			AttackStatEntryDto sentinel = Assert.Single(dto.Entries,
				e => e.Ip == AttackStatsAggregator.SentinelUnresolvedIp);
			Assert.True(sentinel.Failed >= 4);
			Assert.False(sentinel.IsBlocked);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
