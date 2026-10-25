/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostCorrelationWorkerTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Unit and integration coverage for CrossHostCorrelationWorker: happy-path chain
//          correlation over three faked agent hosts, fail-closed handling of unavailable hosts
//          (no facts invented, no chains correlated, host state recorded), idempotent fact
//          deduplication across repeated polls, cancellation mid-poll, and a SQLITE_BUSY retry
//          on fact persistence. Uses the real worker against an in-memory SQLite AuditDbContext.
// Depends: CrossHostCorrelationWorker, FakeHostFactSource, Microsoft.Data.Sqlite, EF Core
// Extends: Add a multi-rule catalogue test when the P4-18 rule set grows beyond the default.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class CrossHostCorrelationWorkerTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
			=> Task.FromResult(new AuditDbContext(_options));
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	/// <summary>In-memory IHostFactSource: deterministic facts per host, optional forced status.</summary>
	private sealed class FakeHostFactSource : IHostFactSource
	{
		private readonly string _hostName;
		private readonly List<CrossHostFactDto> _facts;
		private IpcResultStatus? _forcedStatus;
		private string? _forcedMessage;

		public FakeHostFactSource(string hostName, List<CrossHostFactDto> facts)
		{
			_hostName = hostName;
			_facts = facts;
		}

		public FakeHostFactSource(string hostName, IpcResultStatus status, string message)
		{
			_hostName = hostName;
			_facts = new List<CrossHostFactDto>();
			_forcedStatus = status;
			_forcedMessage = message;
		}

		public string HostName => _hostName;

		public TaskCompletionSource? Gate { get; set; }

		public int Pulls { get; private set; }

		public async Task<CrossHostFactsDto> PullFactsAsync(DateTime? sinceUtc, int maxFacts, string? requestId, CancellationToken ct)
		{
			Pulls++;
			TaskCompletionSource? gate = Gate;
			if (gate is not null)
			{
				await gate.Task.WaitAsync(ct).ConfigureAwait(false);
			}

			return BuildResult();
		}

		private CrossHostFactsDto BuildResult()
		{
			if (_forcedStatus is not null)
			{
				return new CrossHostFactsDto
				{
					Status = _forcedStatus.Value,
					QueriedUtc = DateTime.UtcNow,
					LatestFactUtc = null,
					Message = _forcedMessage,
				};
			}

			DateTime? latest = _facts.Count > 0 ? _facts[^1].TimeUtc : null;
			return new CrossHostFactsDto
			{
				Status = IpcResultStatus.Success,
				QueriedUtc = DateTime.UtcNow,
				LatestFactUtc = latest,
				Facts = new List<CrossHostFactDto>(_facts),
			};
		}
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

	private static CrossHostOptions EnabledOptions(params string[] hostNames)
	{
		CrossHostOptions crossHost = new()
		{
			Enabled = true,
			PollIntervalSeconds = CrossHostOptions.MinPollIntervalSeconds,
			Hosts = hostNames.Select(h => new CrossHostHostOptions { HostName = h }).ToList(),
		};
		return crossHost;
	}

	private static RdpAuditOptions OptionsWith(CrossHostOptions crossHost)
	{
		RdpAuditOptions options = new() { CrossHost = crossHost };
		return options;
	}

	private static CrossHostFactDto BuildFact(
		string host,
		DateTime timeUtc,
		CrossHostFactKind kind,
		int eventId,
		string user,
		string? sourceIp = null)
	{
		string normalized = user.ToLowerInvariant();
		CrossHostFactProjection projection = new()
		{
			HostName = host,
			TimeUtc = DateTime.SpecifyKind(timeUtc, DateTimeKind.Utc),
			UserName = user,
			NormalizedUserName = normalized,
			SourceIp = sourceIp,
			Kind = kind,
			EventId = eventId,
		};

		return new CrossHostFactDto
		{
			HostName = host,
			TimeUtc = DateTime.SpecifyKind(timeUtc, DateTimeKind.Utc),
			UserName = user,
			NormalizedUserName = normalized,
			SourceIp = sourceIp,
			Kind = kind,
			EventId = eventId,
			DedupKey = projection.BuildDedupKey(),
		};
	}

	private static CrossHostCorrelationWorker BuildWorker(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions options,
		Dictionary<string, FakeHostFactSource> sources)
	{
		return new CrossHostCorrelationWorker(
			factory,
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<CrossHostCorrelationWorker>.Instance,
			sourceFactory: host => sources[host.HostName]);
	}

	[Fact]
	public async Task RunOnce_HappyPath_PersistsFactsChainAndHostStates()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			DateTime t0 = now.AddMinutes(-30);

			// 3 failed 4625 on SRV-A, then 4624 on SRV-B, then 4672 on SRV-C: the documented
			// lateral-movement template of the default rule.
			List<CrossHostFactDto> hostAFacts = new();
			for (int i = 0; i < 3; i++)
			{
				hostAFacts.Add(BuildFact("SRV-A", t0.AddSeconds(i), CrossHostFactKind.FailedLogon, 4625, "attacker"));
			}

			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-A"] = new FakeHostFactSource("SRV-A", hostAFacts),
				["SRV-B"] = new FakeHostFactSource("SRV-B", new List<CrossHostFactDto>
				{
					BuildFact("SRV-B", t0.AddMinutes(1), CrossHostFactKind.SuccessfulLogon, 4624, "attacker"),
				}),
				["SRV-C"] = new FakeHostFactSource("SRV-C", new List<CrossHostFactDto>
				{
					BuildFact("SRV-C", t0.AddMinutes(20), CrossHostFactKind.PrivilegedLogon, 4672, "attacker"),
				}),
			};

			CrossHostCorrelationWorker worker = BuildWorker(factory, OptionsWith(EnabledOptions("SRV-A", "SRV-B", "SRV-C")), sources);
			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(5, await db.CrossHostFacts.CountAsync());

			List<CrossHostChain> chains = await db.CrossHostChains.ToListAsync();
			Assert.Single(chains);
			CrossHostChain chain = chains[0];
			Assert.Equal("RDP_LATERAL_MOVEMENT", chain.RuleId);
			Assert.Equal("attacker", chain.NormalizedUserName);
			Assert.True(chain.Score > 0);

			List<CrossHostLink> links = await db.CrossHostLinks.OrderBy(l => l.Ordinal).ToListAsync();
			Assert.Equal(3, links.Count);
			Assert.Collection(links,
				l => Assert.Equal("SRV-A", l.HostName),
				l => Assert.Equal("SRV-B", l.HostName),
				l => Assert.Equal("SRV-C", l.HostName));

			List<CrossHostHostState> states = await db.CrossHostHostStates.OrderBy(s => s.HostName).ToListAsync();
			Assert.Equal(3, states.Count);
			Assert.All(states, s => Assert.Equal(CrossHostAvailability.Available, s.Availability));
			Assert.All(states, s => Assert.True(s.LastPolledUtc >= now.AddMinutes(-5)));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnce_UnavailableHost_NoFactsInventedNoChainPersistedHostMarkedUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			DateTime t0 = now.AddMinutes(-30);

			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-A"] = new FakeHostFactSource("SRV-A", IpcResultStatus.Unavailable, "agent pipe timeout"),
				["SRV-B"] = new FakeHostFactSource("SRV-B", new List<CrossHostFactDto>()),
				["SRV-C"] = new FakeHostFactSource("SRV-C", new List<CrossHostFactDto>()),
			};

			CrossHostCorrelationWorker worker = BuildWorker(factory, OptionsWith(EnabledOptions("SRV-A", "SRV-B", "SRV-C")), sources);
			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.CrossHostFacts.CountAsync());
			Assert.Equal(0, await db.CrossHostChains.CountAsync());
			Assert.Equal(0, await db.CrossHostLinks.CountAsync());

			CrossHostHostState stateA = Assert.Single(await db.CrossHostHostStates.Where(s => s.HostName == "SRV-A").ToListAsync());
			Assert.Equal(CrossHostAvailability.Unavailable, stateA.Availability);
			Assert.NotNull(stateA.LastError);
			Assert.Contains("agent pipe timeout", stateA.LastError);
			Assert.Null(stateA.LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnce_RepeatedPoll_SameFactsDeduplicated_ChainPersistedExactlyOnce()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			DateTime t0 = now.AddMinutes(-30);

			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-A"] = new FakeHostFactSource("SRV-A", new List<CrossHostFactDto>
				{
					BuildFact("SRV-A", t0, CrossHostFactKind.FailedLogon, 4625, "attacker"),
					BuildFact("SRV-A", t0.AddSeconds(1), CrossHostFactKind.FailedLogon, 4625, "attacker"),
					BuildFact("SRV-A", t0.AddSeconds(2), CrossHostFactKind.FailedLogon, 4625, "attacker"),
				}),
				["SRV-B"] = new FakeHostFactSource("SRV-B", new List<CrossHostFactDto>
				{
					BuildFact("SRV-B", t0.AddMinutes(1), CrossHostFactKind.SuccessfulLogon, 4624, "attacker"),
				}),
				["SRV-C"] = new FakeHostFactSource("SRV-C", new List<CrossHostFactDto>
				{
					BuildFact("SRV-C", t0.AddMinutes(2), CrossHostFactKind.PrivilegedLogon, 4672, "attacker"),
				}),
			};

			CrossHostCorrelationWorker worker = BuildWorker(factory, OptionsWith(EnabledOptions("SRV-A", "SRV-B", "SRV-C")), sources);
			await worker.RunOnceAsync(CancellationToken.None);
			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(5, await db.CrossHostFacts.CountAsync());
			Assert.Equal(1, await db.CrossHostChains.CountAsync());
			Assert.Equal(3, await db.CrossHostLinks.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnce_Disabled_SkipsPolling_NoDbWrites()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			FakeHostFactSource sourceA = new("SRV-A", new List<CrossHostFactDto>());
			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-A"] = sourceA,
			};

			RdpAuditOptions options = OptionsWith(new CrossHostOptions
			{
				Enabled = false,
				Hosts = new List<CrossHostHostOptions> { new() { HostName = "SRV-A" } },
			});

			CrossHostCorrelationWorker worker = BuildWorker(factory, options, sources);
			await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, sourceA.Pulls);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.CrossHostFacts.CountAsync());
			Assert.Equal(0, await db.CrossHostHostStates.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnce_CancellationMidPoll_ThrowsOperationCanceled()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			FakeHostFactSource blocked = new("SRV-A", new List<CrossHostFactDto>())
			{
				Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
			};
			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-A"] = blocked,
			};

			CrossHostCorrelationWorker worker = BuildWorker(factory, OptionsWith(EnabledOptions("SRV-A")), sources);
			CancellationTokenSource cts = new();

			Task run = worker.RunOnceAsync(cts.Token);
			// Wait until the worker reached the gated pull, then cancel.
			DateTime deadline = DateTime.UtcNow.AddSeconds(5);
			while (blocked.Pulls == 0 && DateTime.UtcNow < deadline)
			{
				await Task.Delay(10);
			}

			Assert.Equal(1, blocked.Pulls);
			cts.Cancel();
			await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await run);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.CrossHostHostStates.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnce_SqliteBusyOnFirstSave_RetriesAndPersists()
	{
		string dbPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.IO.Path.GetRandomFileName() + ".db");
		try
		{
			DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
				.UseSqlite(new SqliteConnectionStringBuilder
				{
					DataSource = dbPath,
					Mode = SqliteOpenMode.ReadWriteCreate,
				}.ToString())
				.Options;
			TestDbContextFactory factory = new(options);
			await using (AuditDbContext init = factory.CreateDbContext())
			{
				await init.Database.EnsureCreatedAsync();
			}

			DateTime now = DateTime.UtcNow;
			DateTime t0 = now.AddMinutes(-25);

			Dictionary<string, FakeHostFactSource> sources = new(StringComparer.OrdinalIgnoreCase)
			{
				["SRV-B"] = new FakeHostFactSource("SRV-B", new List<CrossHostFactDto>
				{
					BuildFact("SRV-B", t0, CrossHostFactKind.SuccessfulLogon, 4624, "u"),
				}),
			};

			CrossHostCorrelationWorker worker = BuildWorker(factory, OptionsWith(EnabledOptions("SRV-B")), sources);

			// Deterministic SQLITE_BUSY injection: a second connection starts an IMMEDIATE
			// transaction (RESERVED lock) so the worker's first SaveChanges hits the file lock;
			// it releases mid-backoff, letting a later retry (25+50+100+200ms) succeed.
			TaskCompletionSource lockStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
			Task holdLock = Task.Run(async () =>
			{
				await using SqliteConnection hold = new(new SqliteConnectionStringBuilder
				{
					DataSource = dbPath,
					Mode = SqliteOpenMode.ReadWrite,
				}.ToString());
				await hold.OpenAsync();
				await using SqliteTransaction tx = (SqliteTransaction)await hold.BeginTransactionAsync();
				SqliteCommand insert = hold.CreateCommand();
				insert.Transaction = tx;
				insert.CommandText = "INSERT INTO CrossHostHostStates (HostName, Availability, LastPolledUtc) VALUES ('locker', 0, '2026-01-01');";
				await insert.ExecuteNonQueryAsync();
				lockStarted.TrySetResult();
				await Task.Delay(300);
				await tx.RollbackAsync();
			});

			await lockStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
			await worker.RunOnceAsync(CancellationToken.None);
			await holdLock;

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(1, await db.CrossHostFacts.CountAsync());
		}
		finally
		{
			try
			{
				System.IO.File.Delete(dbPath);
			}
			catch (System.IO.IOException)
			{
			}
			catch (System.UnauthorizedAccessException)
			{
			}
		}
	}

	[Fact]
	public async Task PersistChains_StaleExistingChain_IsRefreshedAndReAlerts()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.CrossHostChains.Add(new CrossHostChain
				{
					ChainKey = "chain-key-refresh",
					RuleId = "RDP_LATERAL_MOVEMENT",
					NormalizedUserName = "victim",
					FirstSeenUtc = now.AddDays(-3),
					LastSeenUtc = now.AddDays(-3),
					Score = 40,
					FailedAttemptCount = 2,
					DetectedUtc = now.AddDays(-3),
					IsAcknowledged = true,
				});
				await seed.SaveChangesAsync();
			}

			CrossHostCorrelationWorker worker = new(
				factory,
				new StaticOptionsMonitor<RdpAuditOptions>(new RdpAuditOptions()),
				NullLogger<CrossHostCorrelationWorker>.Instance);

			CrossHostChainCandidate candidate = new()
			{
				RuleId = "RDP_LATERAL_MOVEMENT",
				ChainKey = "chain-key-refresh",
				NormalizedUserName = "victim",
				FirstSeenUtc = now.AddMinutes(-30),
				LastSeenUtc = now.AddMinutes(-1),
				Score = 85,
				FailedAttemptCount = 3,
			};
			candidate.Links.Add(new CrossHostChainLinkCandidate { HostName = "SRV-A", Kind = CrossHostFactKind.FailedLogon, EventId = 4625, TimeUtc = now.AddMinutes(-30) });
			candidate.Links.Add(new CrossHostChainLinkCandidate { HostName = "SRV-B", Kind = CrossHostFactKind.SuccessfulLogon, EventId = 4624, TimeUtc = now.AddMinutes(-10) });
			candidate.Links.Add(new CrossHostChainLinkCandidate { HostName = "SRV-C", Kind = CrossHostFactKind.PrivilegedLogon, EventId = 4672, TimeUtc = now.AddMinutes(-1) });

			// The engine only emits a stale key again, so this exercises the refresh path.
			int touched = await worker.PersistChainsAsync(new List<CrossHostChainCandidate> { candidate }, now, CancellationToken.None);
			Assert.Equal(1, touched);

			using (AuditDbContext verify = factory.CreateDbContext())
			{
				CrossHostChain stored = await verify.CrossHostChains.SingleAsync();
				Assert.Equal("chain-key-refresh", stored.ChainKey);
				Assert.False(stored.IsAcknowledged);
				Assert.Null(stored.AlertId);
				Assert.Equal(85, stored.Score);
				Assert.True(stored.LastSeenUtc > now.AddHours(-2));
			}

			// Clearing the alert gate makes the alert processor raise a NEW alert for the recurrence.
			using (AuditDbContext alertDb = factory.CreateDbContext())
			{
				int raised = await CrossHostChainAlertProcessor.ProcessAsync(alertDb, NullLogger.Instance, CancellationToken.None);
				await alertDb.SaveChangesAsync();
				Assert.Equal(1, raised);
			}
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
