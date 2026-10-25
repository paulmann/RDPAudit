/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionWorkerTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Drives the information-density retention worker against real SQLite databases and asserts
//          the guarantees an operator depends on: an anchor that is byte-identical to the original
//          first record after repeated overfill passes, deletion confined to the interior with the
//          anchor and the protected tail alive, non-regressing IpEventSummary / IpEventTypeCounter
//          counters, a ledger that accounts for exactly the deleted rows and window, rare and
//          protected codes left alone, no writes at all when no trigger fires, stability under a
//          second pass, legal hold stopping deletion, protection for rows an alert fact references,
//          a per-address anchor under the PerCodeAndIp scope, and consistency when a pass is
//          cancelled mid-way - the cancellation case is driven DETERMINISTICALLY from the engine's
//          AfterBatchCommitted hook (cancel as soon as one batch is durable) and asserts the resulting
//          state, so it can neither hang nor pass by luck of timing.
// Depends: InformationDensityRetentionWorker, InformationDensityRetentionEngine (hook), AuditDbContext,
//          RetentionPolicyOptions, Xunit
// Extends: Add a scenario per new pressure trigger, protection rule and ledger field.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class InformationDensityRetentionWorkerTests : IDisposable
{
	private readonly string _directory;
	private readonly string _databasePath;
	private readonly string _connectionString;
	private readonly TestDbContextFactory _factory;
	private readonly ServiceMetrics _metrics;

	public InformationDensityRetentionWorkerTests()
	{
		_directory = Path.Combine(Path.GetTempPath(), "rdpaudit-idr-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_directory);
		_databasePath = Path.Combine(_directory, "audit.db");
		_connectionString = "Data Source=" + _databasePath + ";Cache=Shared";

		using (SqliteConnection bootstrap = new(_connectionString))
		{
			bootstrap.Open();
			using SqliteCommand command = bootstrap.CreateCommand();
			command.CommandText = "PRAGMA journal_mode=WAL;";
			command.ExecuteNonQuery();
		}

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connectionString)
			.Options;
		using (AuditDbContext init = new(options))
		{
			init.Database.EnsureCreated();
		}

		_factory = new TestDbContextFactory(options);
		_metrics = new ServiceMetrics();
	}

	public void Dispose()
	{
		SqliteConnection.ClearAllPools();
		try
		{
			Directory.Delete(_directory, recursive: true);
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;

		public T CurrentValue { get; }

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	/// <summary>Builds a policy that fires the row-count trigger and is otherwise conservative, then
	/// lets the caller override whatever the scenario needs.</summary>
	private RdpAuditOptions BuildOptions(Action<RetentionPolicyOptions>? configure = null)
	{
		RetentionPolicyOptions policy = new()
		{
			Enabled = true,
			TailKeepPerCode = 5,
			CandidateMinRows = 100,
			MinAgeDays = 7,
			MaxRowsPerPass = 1_000,
			MaxWriterLockMs = 60_000,
			DeleteBatchRows = 1_000,
			MaxRawEventRows = 1,
		};
		configure?.Invoke(policy);
		return new RdpAuditOptions
		{
			Storage = new StorageOptions
			{
				DatabasePath = _databasePath,
				RetentionPolicy = policy,
			},
		};
	}

	private InformationDensityRetentionWorker BuildWorker(IOptionsMonitor<RdpAuditOptions> monitor)
	{
		DbOperationLogWriter operationLog = new(_factory, monitor, NullLogger<DbOperationLogWriter>.Instance);
		return new InformationDensityRetentionWorker(
			_factory,
			monitor,
			operationLog,
			_metrics,
			NullLogger<InformationDensityRetentionWorker>.Instance);
	}

	private async Task<InformationDensityRetentionWorker.RetentionPassOutcome> RunOnceAsync(
		RdpAuditOptions options,
		CancellationToken cancellationToken = default)
		=> await BuildWorker(new StaticOptionsMonitor<RdpAuditOptions>(options))
			.RunOnceAsync(cancellationToken);

	/// <summary>Seeds <paramref name="count"/> rows of one code, one minute apart, starting
	/// <paramref name="startOffsetDays"/> days before now, so every row clears a 7-day age floor.</summary>
	private List<long> SeedCode(
		int eventId,
		string channel,
		int count,
		int startOffsetDays = 60,
		byte[]? sourceIpBinary = null,
		string? sourceIp = null)
	{
		DateTime startUtc = DateTime.UtcNow.AddDays(-startOffsetDays);
		using AuditDbContext db = _factory.CreateDbContext();
		db.ChangeTracker.AutoDetectChangesEnabled = false;
		List<RawEvent> rows = new(count);
		for (int index = 0; index < count; index++)
		{
			rows.Add(new RawEvent
			{
				EventId = eventId,
				Channel = channel,
				TimeUtc = startUtc.AddMinutes(index),
				SourceIpBinary = sourceIpBinary,
				SourceIp = sourceIp,
			});
		}

		db.RawEvents.AddRange(rows);
		db.SaveChanges();
		return [.. rows.Select(row => row.Id)];
	}

	private void AddAuthAttemptFact(long rawEventId, DateTime timeUtc)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.AuthAttemptFacts.Add(new AuthAttemptFact
		{
			TimeUtc = timeUtc,
			Outcome = AuthAttemptOutcome.Failed,
			EvidenceEventId = 4625,
			EvidenceRawEventId = rawEventId,
			EvidenceChannel = "Security",
			IngestedUtc = DateTime.UtcNow,
		});
		db.SaveChanges();
	}

	private async Task<long> CountRawEventsAsync(int eventId)
	{
		await using AuditDbContext db = _factory.CreateDbContext();
		return await db.RawEvents.LongCountAsync(row => row.EventId == eventId);
	}

	private List<RawEvent> ReadCode(int eventId)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return [.. db.RawEvents.AsNoTracking()
			.Where(row => row.EventId == eventId)
			.OrderBy(row => row.TimeUtc)
			.ThenBy(row => row.Id)];
	}

	private List<EventDeletionLedger> ReadLedger()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return [.. db.EventDeletionLedger.AsNoTracking().OrderBy(row => row.Id)];
	}

	private RawEvent Anchor(int eventId, byte[]? ip = null)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.RawEvents.AsNoTracking()
			.Where(row => row.EventId == eventId && (ip == null || row.SourceIpBinary == ip))
			.OrderBy(row => row.TimeUtc)
			.ThenBy(row => row.Id)
			.First();
	}

	private int CountRawEventsForIp(int eventId, byte[] ip)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.RawEvents.Count(row => row.EventId == eventId && row.SourceIpBinary == ip);
	}

	private static void AssertRowUnchanged(RawEvent before, RawEvent after)
	{
		Assert.Equal(before.Id, after.Id);
		Assert.Equal(before.EventId, after.EventId);
		Assert.Equal(before.Channel, after.Channel);
		Assert.Equal(before.TimeUtc, after.TimeUtc);
		Assert.Equal(before.IngestionSequence, after.IngestionSequence);
		Assert.Equal(before.EventLayer, after.EventLayer);
		Assert.Equal(before.SourceIp, after.SourceIp);
		Assert.Equal(before.SourceIpBinary, after.SourceIpBinary);
		Assert.Equal(before.SourceIpDerived, after.SourceIpDerived);
		Assert.Equal(before.SourceIpUnresolved, after.SourceIpUnresolved);
		Assert.Equal(before.UserName, after.UserName);
		Assert.Equal(before.Domain, after.Domain);
		Assert.Equal(before.SessionId, after.SessionId);
		Assert.Equal(before.LogonType, after.LogonType);
		Assert.Equal(before.LogonId, after.LogonId);
		Assert.Equal(before.AuthPackage, after.AuthPackage);
		Assert.Equal(before.Status, after.Status);
		Assert.Equal(before.ProcessName, after.ProcessName);
		Assert.Equal(before.CommandLine, after.CommandLine);
		Assert.Equal(before.ObjectName, after.ObjectName);
		Assert.Equal(before.AccessMask, after.AccessMask);
		Assert.Equal(before.Details, after.Details);
		Assert.Equal(before.Processed, after.Processed);
		Assert.Equal(before.AddressId, after.AddressId);
		Assert.Equal(before.SessionRefId, after.SessionRefId);
	}

	// ── Posture: nothing happens until a trigger fires ───────────────────────────

	[Fact]
	public async Task RunOnceAsync_PolicyDisabled_DoesNoWorkAndWritesNothing()
	{
		SeedCode(4625, "Security", 500);
		RdpAuditOptions options = BuildOptions(policy => policy.Enabled = false);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.True(outcome.PolicyDisabled);
		Assert.True(outcome.DeletedNothing);
		Assert.Equal(500, await CountRawEventsAsync(4625));
		Assert.Empty(ReadLedger());
	}

	[Fact]
	public async Task RunOnceAsync_NoTriggerFires_WritesNothing()
	{
		SeedCode(4625, "Security", 500);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRawEventRows = 0;
			policy.MaxDatabaseBytes = 0;
			policy.MinFreeDiskBytes = 0;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(EventDeletionTrigger.Unknown, outcome.Trigger);
		Assert.True(outcome.DeletedNothing);
		Assert.Equal(500, await CountRawEventsAsync(4625));
		Assert.Empty(ReadLedger());
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Empty(db.OperationLogs);
	}

	[Fact]
	public async Task RunOnceAsync_NoEligibleCode_WritesNoLedgerRowButReportsAnHonestSkip()
	{
		// 200 rows of a protected class only: the trigger fires, but nothing may be deleted.
		SeedCode(4720, "Security", 200);
		RdpAuditOptions options = BuildOptions();

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(EventDeletionTrigger.RawEventRows, outcome.Trigger);
		Assert.True(outcome.DeletedNothing);
		Assert.Equal(200, await CountRawEventsAsync(4720));
		Assert.Empty(ReadLedger());
		Assert.Equal(1L, _metrics.InformationDensitySkippedPasses);
	}

	// ── Triggers ─────────────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_DatabaseBytesTrigger_IsRecordedInTheLedger()
	{
		SeedCode(4625, "Security", 200);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRawEventRows = 0;
			policy.MaxDatabaseBytes = 1;
			policy.MaxRowsPerPass = 50;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(EventDeletionTrigger.DatabaseBytes, outcome.Trigger);
		Assert.Equal(50L, outcome.RowsDeleted);
		Assert.All(ReadLedger(), row => Assert.Equal(EventDeletionTrigger.DatabaseBytes, row.Trigger));
	}

	[Fact]
	public async Task RunOnceAsync_FreeDiskBytesTrigger_IsRecordedInTheLedger()
	{
		SeedCode(4625, "Security", 200);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRawEventRows = 0;
			policy.MinFreeDiskBytes = long.MaxValue;
			policy.MaxRowsPerPass = 40;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(EventDeletionTrigger.FreeDiskBytes, outcome.Trigger);
		Assert.Equal(40L, outcome.RowsDeleted);
		Assert.All(ReadLedger(), row => Assert.Equal(EventDeletionTrigger.FreeDiskBytes, row.Trigger));
	}

	[Fact]
	public async Task RunOnceAsync_RawEventRowsTrigger_IsRecordedInTheLedger()
	{
		SeedCode(4625, "Security", 200);
		RdpAuditOptions options = BuildOptions(policy => policy.MaxRowsPerPass = 30);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(EventDeletionTrigger.RawEventRows, outcome.Trigger);
		Assert.Equal(30L, outcome.RowsDeleted);
		Assert.All(ReadLedger(), row => Assert.Equal(EventDeletionTrigger.RawEventRows, row.Trigger));
	}

	// ── Anchor and tail ──────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_TenOverfillPasses_KeepEveryAnchorByteIdentical()
	{
		SeedCode(4625, "Security", 300);
		SeedCode(4624, "Security", 300, startOffsetDays: 70);
		RawEvent anchor4625 = Anchor(4625);
		RawEvent anchor4624 = Anchor(4624);

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRowsPerPass = 25;
			policy.DeleteBatchRows = 100;
		});

		long totalDeleted = 0;
		for (int pass = 0; pass < 10; pass++)
		{
			InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);
			totalDeleted += outcome.RowsDeleted;
			AssertRowUnchanged(anchor4625, Anchor(4625));
			AssertRowUnchanged(anchor4624, Anchor(4624));
		}

		// Ten passes of a 25-row budget: a density tie sends every pass to the lower event id first.
		Assert.Equal(250L, totalDeleted);
		Assert.Equal(250L, ReadLedger().Sum(row => row.RowsDeleted));
		Assert.Equal(anchor4625.TimeUtc, ReadCode(4625)[0].TimeUtc);
		Assert.Equal(anchor4624.TimeUtc, ReadCode(4624)[0].TimeUtc);
	}

	[Fact]
	public async Task RunOnceAsync_DeletesOnlyTheInterior_AnchorAndTailSurvive()
	{
		SeedCode(4625, "Security", 200);
		List<RawEvent> before = ReadCode(4625);
		RawEvent anchor = before[0];

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.TailKeepPerCode = 5;
			policy.MaxRowsPerPass = 10_000;
			policy.DeleteBatchRows = 1_000;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(194L, outcome.RowsDeleted);
		List<RawEvent> survivors = ReadCode(4625);
		Assert.Equal(6, survivors.Count);
		AssertRowUnchanged(anchor, survivors[0]);
		Assert.Equal(before[^5..].Select(row => row.Id), survivors.Skip(1).Select(row => row.Id));

		EventDeletionLedger entry = Assert.Single(ReadLedger());
		Assert.Equal(194L, entry.RowsDeleted);
		Assert.Equal(4625, entry.EventCode);
		Assert.Equal(EventDeletionScope.Global, entry.Scope);
		Assert.Null(entry.IpBinary16);
		Assert.Equal(RetentionRuleVersion.Current, entry.RuleVersion);
		Assert.Equal("Service", entry.InitiatedBy);
		Assert.Contains("Security/4625", entry.Reason);
		Assert.Equal(before[1].TimeUtc, entry.WindowStartUtc);
		Assert.Equal(before[194].TimeUtc, entry.WindowEndUtc);
		Assert.True(entry.WindowStartUtc > anchor.TimeUtc);
	}

	// ── Ledger accuracy ──────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_LedgerAccountsForExactlyTheDeletedRowsAndWindow()
	{
		SeedCode(4625, "Security", 500);
		List<RawEvent> before = ReadCode(4625);

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.TailKeepPerCode = 5;
			policy.MaxRowsPerPass = 150;
			// Clamped up to the 100-row floor, so the pass runs two batches.
			policy.DeleteBatchRows = 40;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(150L, outcome.RowsDeleted);
		List<EventDeletionLedger> ledger = ReadLedger();

		// Two batches of 100 and 50: one append-only ledger row per batch, annotated with the same
		// trigger, rule version and initiator, so the pass is reconstructable by grouping.
		Assert.Equal([100L, 50L], ledger.Select(row => row.RowsDeleted).ToArray());
		Assert.Equal(150L, ledger.Sum(row => row.RowsDeleted));
		Assert.Equal(before[1].TimeUtc, ledger[0].WindowStartUtc);
		Assert.Equal(before[150].TimeUtc, ledger[^1].WindowEndUtc);
		Assert.All(ledger, row =>
		{
			Assert.Equal(4625, row.EventCode);
			Assert.Equal(EventDeletionTrigger.RawEventRows, row.Trigger);
			Assert.Equal(RetentionRuleVersion.Current, row.RuleVersion);
			Assert.Equal("Service", row.InitiatedBy);
			Assert.Contains("IDR-1", row.Reason);
			Assert.True(row.WindowStartUtc <= row.WindowEndUtc);
		});

		List<RawEvent> survivors = ReadCode(4625);
		Assert.Equal(350, survivors.Count);
		Assert.Equal(before[151].Id, survivors[1].Id);
	}

	// ── Counters ─────────────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_IpCountersNeverRegress()
	{
		byte[] ip = [0x0A, 0x00, 0x00, 0x2A];
		const string IpText = "10.0.0.42";
		SeedCode(4625, "Security", 300, sourceIpBinary: ip, sourceIp: IpText);

		using (AuditDbContext db = _factory.CreateDbContext())
		{
			db.IpEventSummaries.Add(new IpEventSummary
			{
				IpBinary16 = ip,
				IpText = IpText,
				AddressFamily = 4,
				FirstEventUtc = DateTime.UtcNow.AddDays(-60).Ticks,
				FirstEventId = 4625,
				FirstEventSequence = 1,
				FirstEventSnapshot = [1, 2, 3],
				LastEventUtc = DateTime.UtcNow.Ticks,
				LastEventId = 4625,
				LastEventSequence = 300,
				LastEventSnapshot = [4, 5, 6],
				TotalEventCount = 300,
				SuccessCount = 0,
				FailureCount = 300,
			});
			db.IpEventTypeCounters.Add(new IpEventTypeCounter
			{
				IpBinary16 = ip,
				EventId = 4625,
				Count = 300,
				FirstUtc = DateTime.UtcNow.AddDays(-60).Ticks,
				LastUtc = DateTime.UtcNow.Ticks,
			});
			db.SaveChanges();
		}

		CounterSnapshot before = ReadCounters(ip);
		RdpAuditOptions options = BuildOptions(policy => policy.MaxRowsPerPass = 200);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.Equal(200L, outcome.RowsDeleted);
		CounterSnapshot after = ReadCounters(ip);
		Assert.Equal(before, after);
		Assert.True(after.Total >= before.Total);
		Assert.True(after.Success >= before.Success);
		Assert.True(after.Failure >= before.Failure);
		Assert.True(after.FirstEventUtc <= before.FirstEventUtc);
		Assert.True(after.LastEventUtc >= before.LastEventUtc);
		Assert.True(after.PerTypeCount >= before.PerTypeCount);
		Assert.Equal(IpText, after.IpText);
	}

	// ── Protection ───────────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_RareAndProtectedCodesAreUntouched()
	{
		SeedCode(4625, "Security", 300);
		SeedCode(4720, "Security", 300);
		SeedCode(9999, "Application", 200);
		RawEvent anchor4625 = Anchor(4625);
		RawEvent anchor4720 = Anchor(4720);
		RawEvent anchor9999 = Anchor(9999);

		RdpAuditOptions options = BuildOptions(policy =>
		{
			// 194 eligible rows is below this ceiling, so the rare code stays out of scope while the
			// 294-row dense code is still eligible.
			policy.CandidateMinRows = 250;
			policy.MaxRowsPerPass = 1_000;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		// Only the dense, unprotected code is a candidate: 300 rows - anchor - 5 tail = 294.
		Assert.Equal(294L, outcome.RowsDeleted);
		Assert.Equal(6, await CountRawEventsAsync(4625));
		AssertRowUnchanged(anchor4625, Anchor(4625));
		Assert.Equal(300, await CountRawEventsAsync(4720));
		AssertRowUnchanged(anchor4720, Anchor(4720));
		Assert.Equal(200, await CountRawEventsAsync(9999));
		AssertRowUnchanged(anchor9999, Anchor(9999));
		Assert.All(ReadLedger(), row => Assert.Equal(4625, row.EventCode));
	}

	[Fact]
	public async Task RunOnceAsync_ProtectedCodesNeverAppearInTheLedger()
	{
		SeedCode(4625, "Security", 300);
		SeedCode(7045, "System", 300);
		SeedCode(4771, "Security", 300);

		RdpAuditOptions options = BuildOptions(policy => policy.MaxRowsPerPass = 1_000);

		await RunOnceAsync(options);

		Assert.NotEmpty(ReadLedger());
		Assert.All(ReadLedger(), row => Assert.Equal(4625, row.EventCode));
		Assert.Equal(300, await CountRawEventsAsync(7045));
		Assert.Equal(300, await CountRawEventsAsync(4771));
	}

	[Fact]
	public async Task RunOnceAsync_RowReferencedByAnAuthAttemptFact_IsNeverDeleted()
	{
		SeedCode(4625, "Security", 300);
		List<RawEvent> rows = ReadCode(4625);

		// The 20th persisted row is referenced by an authentication fact: it must survive even though
		// it sits squarely inside the interior.
		RawEvent referenced = rows[19];
		AddAuthAttemptFact(referenced.Id, referenced.TimeUtc);

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRowsPerPass = 10_000;
			policy.DeleteBatchRows = 100;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		// 300 rows - anchor - 5 tail - 1 referenced = 293.
		Assert.Equal(293L, outcome.RowsDeleted);
		Assert.True(outcome.RowsProtectedByLinkedEvidence >= 1);
		List<RawEvent> survivors = ReadCode(4625);
		Assert.Equal(7, survivors.Count);
		Assert.Contains(survivors, row => row.Id == referenced.Id);
		AssertRowUnchanged(referenced, survivors.Single(row => row.Id == referenced.Id));
	}

	[Fact]
	public async Task RunOnceAsync_PerCodeAndIpScope_KeepsAnAnchorPerAddress()
	{
		byte[] attackerA = [0x0A, 0x00, 0x00, 0x01];
		byte[] attackerB = [0x0A, 0x00, 0x00, 0x02];
		SeedCode(4625, "Security", 300, sourceIpBinary: attackerA, sourceIp: "10.0.0.1");
		SeedCode(4625, "Security", 300, startOffsetDays: 70, sourceIpBinary: attackerB, sourceIp: "10.0.0.2");
		RawEvent anchorA = Anchor(4625, attackerA);
		RawEvent anchorB = Anchor(4625, attackerB);

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.AnchorScope = RetentionAnchorScope.PerCodeAndIp;
			policy.MaxRowsPerPass = 1_000;
			policy.DeleteBatchRows = 100;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		// Each address keeps its own anchor and its own five-row tail: 300 - 6 = 294 per address.
		Assert.Equal(588L, outcome.RowsDeleted);
		AssertRowUnchanged(anchorA, Anchor(4625, attackerA));
		AssertRowUnchanged(anchorB, Anchor(4625, attackerB));
		Assert.Equal(6, CountRawEventsForIp(4625, attackerA));
		Assert.Equal(6, CountRawEventsForIp(4625, attackerB));

		List<EventDeletionLedger> ledger = ReadLedger();
		Assert.All(ledger, row =>
		{
			Assert.Equal(EventDeletionScope.PerIp, row.Scope);
			Assert.NotNull(row.IpBinary16);
		});
		Assert.Equal(2, ledger.Select(row => Convert.ToHexString(row.IpBinary16!)).Distinct().Count());
	}

	// ── Idempotency and legal hold ───────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_SecondPassWithTheSameTriggerDeletesNothingExtra()
	{
		SeedCode(4625, "Security", 200);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRowsPerPass = 10_000;
			policy.DeleteBatchRows = 100;
		});

		InformationDensityRetentionWorker.RetentionPassOutcome first = await RunOnceAsync(options);
		Assert.Equal(194L, first.RowsDeleted);
		int ledgerCountAfterFirst = ReadLedger().Count;
		List<RawEvent> survivors = ReadCode(4625);

		InformationDensityRetentionWorker.RetentionPassOutcome second = await RunOnceAsync(options);

		Assert.True(second.DeletedNothing);
		Assert.Equal(0, second.StepsPlanned);
		Assert.Equal(ledgerCountAfterFirst, ReadLedger().Count);
		Assert.Equal(survivors.Select(row => row.Id), ReadCode(4625).Select(row => row.Id));
		Assert.Equal(194L, ReadLedger().Sum(row => row.RowsDeleted));
	}

	[Fact]
	public async Task RunOnceAsync_LegalHoldStopsDeletionEvenWithAFiredTrigger()
	{
		SeedCode(4625, "Security", 500);
		RdpAuditOptions options = BuildOptions(policy => policy.LegalHold = true);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome = await RunOnceAsync(options);

		Assert.True(outcome.LegalHold);
		Assert.True(outcome.DeletedNothing);
		Assert.Equal(500, await CountRawEventsAsync(4625));
		Assert.Empty(ReadLedger());
	}

	[Fact]
	public async Task RunOnceAsync_LegalHoldRemoved_DeletionResumes()
	{
		SeedCode(4625, "Security", 200);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.LegalHold = true;
			policy.MaxRowsPerPass = 10_000;
		});
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(options);
		InformationDensityRetentionWorker worker = BuildWorker(monitor);

		Assert.True((await worker.RunOnceAsync(CancellationToken.None)).DeletedNothing);
		Assert.Equal(200, await CountRawEventsAsync(4625));

		options.Storage.RetentionPolicy.LegalHold = false;
		InformationDensityRetentionWorker.RetentionPassOutcome resumed =
			await worker.RunOnceAsync(CancellationToken.None);

		Assert.Equal(194L, resumed.RowsDeleted);
	}

	// ── Cancellation ─────────────────────────────────────────────────────────────

	[Fact]
	public async Task RunOnceAsync_CancelledMidPass_LeavesAnchorTailAndLedgerConsistent()
	{
		const int Seeded = 4_000;

		// 4000 rows - anchor - 5-row tail is what a complete pass would delete; the pass below must stop
		// well short of it, and the assertions are about STATE (anchor, tail, ledger accounting), never
		// about the exact number of rows a cancelled pass happens to have removed.
		const int FullyEligible = Seeded - 6;

		SeedCode(4625, "Security", Seeded);
		List<RawEvent> before = ReadCode(4625);
		RawEvent anchor = before[0];
		long[] newestFive = [.. before.TakeLast(5).Select(row => row.Id)];

		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRowsPerPass = Seeded;
			policy.DeleteBatchRows = 100;
		});
		InformationDensityRetentionWorker worker = BuildWorker(new StaticOptionsMonitor<RdpAuditOptions>(options));

		using CancellationTokenSource cancellation = new();
		bool cancellationIssued = false;

		// Deterministic cancellation: the engine calls this hook right AFTER the first batch COMMITTED,
		// so the cancel is issued from inside the pass. The previous version of this test polled the
		// ledger from another thread and cancelled whatever it found - if the pass finished first, the
		// test failed on its own timing rather than on the product. Here the hook fires before the pass
		// can reach its next cancellation check, so the outcome is fixed by construction.
		worker.Engine.AfterBatchCommitted = _ =>
		{
			cancellationIssued = true;
			cancellation.Cancel();
		};

		bool reportedCancelled = false;
		try
		{
			InformationDensityRetentionWorker.RetentionPassOutcome outcome =
				await worker.RunOnceAsync(cancellation.Token);
			reportedCancelled = outcome.Cancelled;
			Assert.False(
				outcome.WriterLockBudgetExhausted,
				"The pass stopped on the writer-lock budget instead of the cancellation, so this test no "
					+ "longer exercises the cancellation path.");
		}
		catch (OperationCanceledException)
		{
			// Observed shape on this host: the pass returns normally with Cancelled = true, because the
			// passive WAL checkpoint and the summary write tolerate the cancelled token. This branch is the
			// tolerance for the other legitimate shape - the cancellation surfacing as the exception out of
			// that post-pass work - so the test pins "the pass observed the cancellation" without depending
			// on which of the two shapes it takes.
			reportedCancelled = true;
		}

		Assert.True(cancellationIssued, "the batch hook never fired - the pass never committed a batch");

		// The guard against a regression: if the engine ever ignored the token again, it would delete the
		// whole eligible interior and this flag (and the deletion bound below) would fail.
		Assert.True(reportedCancelled, "the pass reported completion although its token was cancelled mid-pass");

		List<RawEvent> survivors = ReadCode(4625);
		long deleted = Seeded - survivors.Count;
		Assert.InRange(deleted, 1, FullyEligible - 1);

		// Consistency, not a specific count: the anchor survives unchanged, the newest five rows
		// survive, the ledger accounts for exactly the rows that are gone, and no ledger row covers a
		// window another ledger row already covers.
		AssertRowUnchanged(anchor, survivors[0]);
		Assert.Equal(newestFive, survivors.TakeLast(5).Select(row => row.Id).ToArray());
		List<EventDeletionLedger> ledger = ReadLedger();
		Assert.NotEmpty(ledger);
		Assert.Equal(deleted, ledger.Sum(row => row.RowsDeleted));
		Assert.Equal(
			ledger.Count,
			ledger.Select(row => (row.WindowStartUtc, row.WindowEndUtc)).Distinct().Count());
		Assert.All(ledger, row =>
		{
			Assert.Equal(4625, row.EventCode);
			Assert.InRange(row.RowsDeleted, 1L, 100L);
		});
		Assert.Equal(0L, survivors.Count(row => row.Id == anchor.Id && row.TimeUtc != anchor.TimeUtc));
	}

	// ── Counter projection ───────────────────────────────────────────────────────

	private readonly record struct CounterSnapshot(
		string IpText,
		long Total,
		long Success,
		long Failure,
		long FirstEventUtc,
		long LastEventUtc,
		long PerTypeCount);

	private CounterSnapshot ReadCounters(byte[] ip)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		IpEventSummary summary = db.IpEventSummaries.AsNoTracking().Single(row => row.IpBinary16 == ip);
		IpEventTypeCounter counter = db.IpEventTypeCounters.AsNoTracking()
			.Single(row => row.IpBinary16 == ip && row.EventId == 4625);
		return new CounterSnapshot(
			summary.IpText,
			summary.TotalEventCount,
			summary.SuccessCount,
			summary.FailureCount,
			summary.FirstEventUtc,
			summary.LastEventUtc,
			counter.Count);
	}
}
