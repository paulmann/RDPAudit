/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionPreviewTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Proves the contract the Database tab depends on: the dry run and the real pass are the
//          same computation. Both drive InformationDensityRetentionEngine, so the preview's
//          per-code row counts and step windows must equal the ledger the real pass writes on the
//          same state - asserted code by code, not just in total. Also proves the preview is
//          read-only (no row, no ledger entry, no operation-log entry) and that it still reports
//          the codes that are protected and why.
// Depends: InformationDensityRetentionWorker, RetentionPreviewService, AuditDbContext, xUnit
// Extends: Add an assertion here whenever the preview or the pass gains a planning input.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Preview/dry-run equals execution.</summary>
public sealed class InformationDensityRetentionPreviewTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int DenseCode = 4625;
	private const int SparseCode = 4624;
	private const int ProtectedCode = 4720;
	private const string SecurityChannel = "Security";

	private readonly string _directory;
	private readonly string _databasePath;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ServiceMetrics _metrics;

	public InformationDensityRetentionPreviewTests()
	{
		_directory = Path.Combine(Path.GetTempPath(), "rdpaudit-idr-preview-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_directory);
		_databasePath = Path.Combine(_directory, "audit.db");
		string connectionString = "Data Source=" + _databasePath + ";Cache=Shared";

		using (SqliteConnection bootstrap = new(connectionString))
		{
			bootstrap.Open();
			using SqliteCommand command = bootstrap.CreateCommand();
			command.CommandText = "PRAGMA journal_mode=WAL;";
			command.ExecuteNonQuery();
		}

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connectionString)
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

	private IOptionsMonitor<RdpAuditOptions> Monitor(RdpAuditOptions options) => new StaticOptionsMonitor<RdpAuditOptions>(options);

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

	private RetentionPreviewService BuildPreview(IOptionsMonitor<RdpAuditOptions> monitor)
		=> new(_factory, monitor, NullLogger<RetentionPreviewService>.Instance);

	private void SeedCode(int eventId, int count, string channel = SecurityChannel)
	{
		DateTime startUtc = DateTime.UtcNow.AddDays(-60);
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
			});
		}

		db.RawEvents.AddRange(rows);
		db.SaveChanges();
	}

	private Task<long> CountRawEventsAsync(int eventId)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return Task.FromResult(db.RawEvents.AsNoTracking().LongCount(row => row.EventId == eventId));
	}

	private List<EventDeletionLedger> ReadLedger()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return [.. db.EventDeletionLedger.AsNoTracking().OrderBy(row => row.Id)];
	}

	private long CountOperationLogs()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.OperationLogs.AsNoTracking().LongCount();
	}

	// ── Read-only guarantee ──────────────────────────────────────────────────────

	/// <summary>Given a store that is over every ceiling, when the operator opens the dry run, then
	/// nothing is deleted, no ledger entry appears and no operation-log row is written: a preview
	/// must be inspectable without consequences.</summary>
	[Fact]
	public async Task Preview_IsReadOnly_AndDeletesNothing()
	{
		SeedCode(DenseCode, 300);
		RdpAuditOptions options = BuildOptions();
		long rawBefore = await CountRawEventsAsync(DenseCode);

		RetentionPreviewDto preview = await BuildPreview(Monitor(options)).PreviewAsync(CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, preview.Status);
		Assert.True(preview.WouldDeleteRows > 0);
		Assert.Equal(rawBefore, await CountRawEventsAsync(DenseCode));
		Assert.Empty(ReadLedger());
		Assert.Equal(0, CountOperationLogs());
	}

	// ── The headline contract ────────────────────────────────────────────────────

	/// <summary>
	/// Given one dense code, when the preview is taken and then the real pass runs on the same state,
	/// then the pass deletes exactly the rows the preview predicted - same total, same per-code
	/// count, same covered window - and a second preview afterwards reports that nothing is left.
	/// </summary>
	[Fact]
	public async Task Preview_ReportsExactlyTheRowsAndWindowTheRealPassDeletes()
	{
		SeedCode(DenseCode, 300);
		RdpAuditOptions options = BuildOptions();
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		// Anchor survives, the newest TailKeepPerCode rows survive, the interior does not.
		Assert.Equal(300L - 1L - 5L, preview.WouldDeleteRows);
		RetentionPreviewStepDto step = Assert.Single(preview.Steps);
		Assert.Equal(DenseCode, step.EventId);
		Assert.Equal(294, step.Rows);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome =
			await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);

		Assert.Equal(preview.Trigger, outcome.Trigger);
		Assert.Equal(preview.WouldDeleteRows, outcome.RowsDeleted);
		Assert.Equal(preview.Steps.Count, outcome.StepsCompleted);

		List<EventDeletionLedger> ledger = ReadLedger();
		long deletedByLedger = 0;
		DateTime ledgerWindowStart = DateTime.MaxValue;
		DateTime ledgerWindowEnd = DateTime.MinValue;
		foreach (EventDeletionLedger entry in ledger)
		{
			Assert.Equal(DenseCode, entry.EventCode);
			deletedByLedger += entry.RowsDeleted;
			ledgerWindowStart = entry.WindowStartUtc < ledgerWindowStart ? entry.WindowStartUtc : ledgerWindowStart;
			ledgerWindowEnd = entry.WindowEndUtc > ledgerWindowEnd ? entry.WindowEndUtc : ledgerWindowEnd;
		}

		Assert.Equal(step.Rows, deletedByLedger);
		Assert.Equal(step.WindowStartUtc, ledgerWindowStart);
		Assert.Equal(step.WindowEndUtc, ledgerWindowEnd);
		Assert.Equal(1L + 5L, await CountRawEventsAsync(DenseCode));

		RetentionPreviewDto second = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);
		Assert.Equal(0, second.WouldDeleteRows);
		Assert.Empty(second.Steps);
	}

	/// <summary>
	/// Given two codes of different density and a per-pass budget that cannot cover both, when the
	/// preview and the pass run on the same state, then both spend the budget the same way: the
	/// densest code first, the remainder on the next, and the ledger matches the preview step by
	/// step - including the partial code.
	/// </summary>
	[Fact]
	public async Task Preview_MatchesThePass_AcrossCodesAndABudgetSplit()
	{
		SeedCode(DenseCode, 300);
		SeedCode(SparseCode, 200);
		RdpAuditOptions options = BuildOptions(policy => policy.MaxRowsPerPass = 300);
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		Assert.Equal(300, preview.WouldDeleteRows);
		Assert.Equal(2, preview.Steps.Count);
		// Densest first: the 300-row code is compressed before the 200-row one.
		Assert.Equal(DenseCode, preview.Steps[0].EventId);
		Assert.Equal(294, preview.Steps[0].Rows);
		Assert.Equal(SparseCode, preview.Steps[1].EventId);
		Assert.Equal(6, preview.Steps[1].Rows);
		Assert.Equal(0, preview.Steps[0].Order);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome =
			await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);
		Assert.Equal(preview.WouldDeleteRows, outcome.RowsDeleted);

		Dictionary<int, long> deletedByCode = new();
		foreach (EventDeletionLedger entry in ReadLedger())
		{
			deletedByCode[entry.EventCode] = deletedByCode.GetValueOrDefault(entry.EventCode) + entry.RowsDeleted;
		}

		foreach (RetentionPreviewStepDto step in preview.Steps)
		{
			Assert.Equal(step.Rows, deletedByCode.GetValueOrDefault(step.EventId));
		}
	}

	/// <summary>Given a protected code mixed in with a compressible one, when the preview runs, then
	/// it names the protected code and says why it is out of scope, and never plans a row for it -
	/// and the pass agrees and leaves every protected row in place.</summary>
	[Fact]
	public async Task Preview_ExplainsProtectedCodes_AndThePassLeavesThemAlone()
	{
		SeedCode(DenseCode, 300);
		SeedCode(ProtectedCode, 300);
		RdpAuditOptions options = BuildOptions();
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		RetentionPreviewCodeDto protectedCode = Assert.Single(
			preview.Codes, code => code.EventId == ProtectedCode);
		Assert.Equal(300, protectedCode.Count);
		Assert.Equal(0, protectedCode.PlannedRows);
		Assert.Equal(RetentionSkipReason.ProtectedEventCode, protectedCode.SkipReason);
		Assert.Contains("ProtectedEventIds", protectedCode.Explanation, StringComparison.Ordinal);
		Assert.DoesNotContain(preview.Steps, step => step.EventId == ProtectedCode);
		// The protected code has no step, so it counts as left alone.
		Assert.Equal(preview.Codes.Count - preview.Steps.Count, preview.SkippedCodeCount);

		await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);

		Assert.Equal(300, await CountRawEventsAsync(ProtectedCode));
		Assert.All(ReadLedger(), entry => Assert.Equal(DenseCode, entry.EventCode));
	}

	/// <summary>Given a legal hold, when the preview runs, then the ceiling the hold is covering is
	/// still named, no trigger is reported as actionable, every code is reported as held, nothing is
	/// planned - and the pass deletes nothing at all.</summary>
	[Fact]
	public async Task Preview_ReportsLegalHold_AndThePassDeletesNothing()
	{
		SeedCode(DenseCode, 300);
		RdpAuditOptions options = BuildOptions(policy => policy.LegalHold = true);
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		Assert.True(preview.LegalHold);
		Assert.True(preview.PolicyEnabled);
		Assert.False(preview.TriggerWouldFire);
		Assert.Equal(EventDeletionTrigger.RawEventRows, preview.Trigger);
		Assert.Equal(0, preview.WouldDeleteRows);
		Assert.Empty(preview.Steps);
		Assert.All(preview.Codes, code => Assert.Equal(RetentionSkipReason.LegalHold, code.SkipReason));

		InformationDensityRetentionWorker.RetentionPassOutcome outcome =
			await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);
		Assert.True(outcome.LegalHold);
		Assert.True(outcome.DeletedNothing);
		Assert.Equal(300, await CountRawEventsAsync(DenseCode));
		Assert.Empty(ReadLedger());
	}

	/// <summary>Given the default posture (policy disabled), when the preview runs, then it says so
	/// and predicts nothing, and the pass stays inert.</summary>
	[Fact]
	public async Task Preview_WithDisabledPolicy_ReportsNothingToDelete()
	{
		SeedCode(DenseCode, 300);
		RdpAuditOptions options = BuildOptions(policy => policy.Enabled = false);
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		Assert.False(preview.PolicyEnabled);
		Assert.Equal(0, preview.WouldDeleteRows);
		Assert.Empty(preview.Steps);
		Assert.Empty(preview.Codes);
		Assert.Contains("disabled", preview.Message!, StringComparison.OrdinalIgnoreCase);

		InformationDensityRetentionWorker.RetentionPassOutcome outcome =
			await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);
		Assert.True(outcome.PolicyDisabled);
		Assert.Equal(300, await CountRawEventsAsync(DenseCode));
	}

	/// <summary>
	/// Given a store that is over no configured ceiling but would be compressible if one fired, when
	/// the preview runs, then it still reports the latent plan and says that no trigger fires - which
	/// is exactly the information an operator needs when choosing a ceiling, and the one thing the
	/// real pass deliberately does not compute.
	/// </summary>
	[Fact]
	public async Task Preview_WithoutATrigger_StillReportsTheLatentPlan()
	{
		SeedCode(DenseCode, 300);
		RdpAuditOptions options = BuildOptions(policy =>
		{
			policy.MaxRawEventRows = 0;
			policy.MaxDatabaseBytes = 0;
			policy.MinFreeDiskBytes = 0;
		});
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		Assert.False(preview.TriggerWouldFire);
		Assert.Equal(EventDeletionTrigger.Unknown, preview.Trigger);
		Assert.Equal(294, preview.WouldDeleteRows);
		Assert.Single(preview.Steps);
		Assert.Contains("no trigger", preview.Message!, StringComparison.OrdinalIgnoreCase);

		// The pass, by contrast, must do nothing: no ceiling is breached.
		InformationDensityRetentionWorker.RetentionPassOutcome outcome =
			await BuildWorker(monitor).RunOnceAsync(CancellationToken.None);
		Assert.Equal(EventDeletionTrigger.Unknown, outcome.Trigger);
		Assert.True(outcome.DeletedNothing);
		Assert.Empty(ReadLedger());
		Assert.Equal(300, await CountRawEventsAsync(DenseCode));
	}

	/// <summary>Given a code that clears the row threshold but whose interior cannot reach the
	/// eligibility threshold, when the preview runs, then it names the threshold as the reason rather
	/// than claiming the code has no interior.</summary>
	[Fact]
	public async Task Preview_ReportsBelowThreshold_WithItsOwnReason()
	{
		SeedCode(DenseCode, 300);
		// 102 rows clears the "at least CandidateMinRows rows" scan filter (100) while its interior
		// capacity - 102 minus the anchor minus the 5-row tail - is 96, below the threshold.
		SeedCode(SparseCode, 102);
		RdpAuditOptions options = BuildOptions();
		IOptionsMonitor<RdpAuditOptions> monitor = Monitor(options);

		RetentionPreviewDto preview = await BuildPreview(monitor).PreviewAsync(CancellationToken.None);

		RetentionPreviewCodeDto sparse = Assert.Single(preview.Codes, code => code.EventId == SparseCode);
		Assert.Equal(0, sparse.PlannedRows);
		Assert.Equal(RetentionSkipReason.BelowCandidateMinRows, sparse.SkipReason);
		Assert.Equal(102, sparse.Count);
		Assert.Contains("CandidateMinRows", sparse.Explanation, StringComparison.Ordinal);
		Assert.DoesNotContain(preview.Steps, step => step.EventId == SparseCode);
	}

	// ── Test doubles ─────────────────────────────────────────────────────────────

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
}
