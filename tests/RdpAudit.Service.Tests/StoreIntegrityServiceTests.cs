/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreIntegrityServiceTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Drives the durable store fingerprint and the scheduled integrity checks against a real SQLite
//          file (Requirement R23). The two halves that matter are both covered end to end:
//          (1) tamper detection - a store that loses rows between a clean shutdown and the next start is
//              reported, and a store that simply restarts without changing is NOT (the false-positive guard
//              that keeps the alarm meaningful);
//          (2) the scheduled checks - every enabled check runs, is bounded, is journaled with its honest
//              outcome, and the expensive full check only ever starts inside the configured window.
// Depends: StoreIntegrityService, StoreFingerprintStore, AuditDbContextOptionsFactory, xUnit
// Extends: Add a scenario here for every new scheduled check and every new fingerprint field.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class StoreIntegrityServiceTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _databasePath;
	private readonly string _fingerprintPath;
	private readonly string _anomalyMarkerPath;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly RdpAuditOptions _options = new();

	public StoreIntegrityServiceTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-integrity-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_root);
		_databasePath = Path.Combine(_root, "rdpaudit.db");
		_fingerprintPath = Path.Combine(_root, "integrity", "store-fingerprint.json");
		_anomalyMarkerPath = Path.Combine(_root, "integrity", "store-anomaly.json");

		DbContextOptions<AuditDbContext> dbOptions = AuditDbContextOptionsFactory.Create(_databasePath);
		using (AuditDbContext init = new(dbOptions))
		{
			init.Database.EnsureCreated();
		}

		_factory = new FileDbContextFactory(dbOptions);
	}

	public void Dispose()
	{
		SqliteConnection.ClearAllPools();
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Fingerprint round trip ───────────────────────────────────────────────────

	/// <summary>Given a clean-shutdown fingerprint, when the service starts against an unchanged store, then
	/// nothing is reported - and a second start is still silent, so the periodic fingerprint written by the
	/// first comparison does not become a source of noise.</summary>
	[Fact]
	public async Task CompareOnStartup_OnAnUnchangedStore_ReportsNothingTwice()
	{
		SeedRawEvents(20);
		StoreIntegrityService service = CreateService();

		await service.CaptureAtShutdownAsync(CancellationToken.None);

		StoreIntegrityReport first = await service.CompareOnStartupAsync(CancellationToken.None);
		StoreIntegrityReport second = await service.CompareOnStartupAsync(CancellationToken.None);

		Assert.True(first.Compared);
		Assert.True(first.BaselineWasCleanShutdown);
		Assert.False(first.HasAnomalies);
		Assert.False(second.HasAnomalies);
		Assert.False(File.Exists(_anomalyMarkerPath));
	}

	/// <summary>Given a clean shutdown, when rows disappear before the next start, then the comparison reports
	/// it as a Strong anomaly, writes the marker, and the marker survives for the operator to read.</summary>
	[Fact]
	public async Task CompareOnStartup_WhenRowsDisappearedWhileStopped_ReportsAndMarksIt()
	{
		SeedRawEvents(20);
		StoreIntegrityService service = CreateService();
		await service.CaptureAtShutdownAsync(CancellationToken.None);

		await using (AuditDbContext db = _factory.CreateDbContext())
		{
			await db.RawEvents.Where(row => row.Id > 5).ExecuteDeleteAsync();
		}

		StoreIntegrityReport report = await service.CompareOnStartupAsync(CancellationToken.None);

		Assert.True(report.HasStrongAnomalies);
		Assert.Contains(report.Anomalies, entry => entry.Kind == "RowsRemovedWhileStopped");
		Assert.True(File.Exists(_anomalyMarkerPath));
		string marker = await File.ReadAllTextAsync(_anomalyMarkerPath, CancellationToken.None);
		Assert.Contains("RowsRemovedWhileStopped", marker, StringComparison.Ordinal);

		// The report is also audited, so the observation outlives the marker file.
		await using AuditDbContext verify = _factory.CreateDbContext();
		OperationLog audit = await verify.OperationLogs.SingleAsync();
		Assert.Equal("StoreIntegrityAnomaly", audit.Operation);
		Assert.Equal(OperationLogSeverity.Error, audit.Severity);
	}

	/// <summary>Given a clean shutdown without any change, when the shutdown fingerprint is captured again,
	/// then the anomaly marker from an earlier incident is cleared: a verified clean stop supersedes it.</summary>
	[Fact]
	public async Task CaptureAtShutdown_ClearsAPreviousAnomalyMarker()
	{
		SeedRawEvents(5);
		Directory.CreateDirectory(Path.GetDirectoryName(_anomalyMarkerPath)!);
		await File.WriteAllTextAsync(_anomalyMarkerPath, "{\"stale\":true}", CancellationToken.None);
		StoreIntegrityService service = CreateService();

		await service.CaptureAtShutdownAsync(CancellationToken.None);

		Assert.False(File.Exists(_anomalyMarkerPath));
		StoreFingerprintDocument document = service.Fingerprints.Read();
		Assert.NotNull(document.LastCleanShutdown);
		Assert.True(document.LastCleanShutdown!.CleanShutdown);
		Assert.Equal(5L, document.LastCleanShutdown.TableRowCounts["RawEvents"]);
	}

	/// <summary>Given a capture that was interrupted between appending its chain entry and re-sealing the tip,
	/// when the service compares at start-up, then the interruption reaches the operator through the ordinary
	/// store-integrity signals - the report, the anomaly marker and the audit row - and it is a Warning rather
	/// than an accusation of tampering. B24 removes the false tamper alarm; it does not remove the alarm.
	/// <para>
	/// The test then keeps the I/O problem in place for a second start, because that is the case the recoverable
	/// state has to survive: a capture that cannot seal its tip must not append another entry, or the tip falls
	/// further and further behind and the state stops being recoverable at all - the store would drift from
	/// "interrupted" into "rolled back or replaced", a false tamper alarm produced by a full disk. With the
	/// problem removed, one ordinary start repairs the store without an operator doing anything.
	/// </para>
	/// </summary>
	[Fact]
	public async Task CompareOnStartup_AfterAnInterruptedCapture_ReportsAWarningAndSurvivesARecurrence()
	{
		SeedRawEvents(20);
		StoreIntegrityService service = CreateService();
		await service.CaptureAtShutdownAsync(CancellationToken.None);

		string tipPath = service.Fingerprints.SealedTipPath;
		Directory.CreateDirectory(tipPath + ".tmp");
		await service.CaptureAtShutdownAsync(CancellationToken.None);

		StoreIntegrityReport report = await service.CompareOnStartupAsync(CancellationToken.None);

		StoreIntegrityAnomaly anomaly = Assert.Single(
			report.Anomalies,
			entry => entry.Kind.StartsWith("FingerprintChain", StringComparison.Ordinal));
		Assert.Equal("FingerprintChainInterrupted", anomaly.Kind);
		Assert.Equal(StoreIntegritySeverity.Warning, anomaly.Severity);
		Assert.False(report.HasStrongAnomalies);
		Assert.True(File.Exists(_anomalyMarkerPath));
		Assert.Contains("Interrupted", await File.ReadAllTextAsync(_anomalyMarkerPath, CancellationToken.None), StringComparison.Ordinal);

		await using AuditDbContext verify = _factory.CreateDbContext();
		OperationLog audit = await verify.OperationLogs.SingleAsync();
		Assert.Equal(OperationLogSeverity.Warning, audit.Severity);

		// The problem persists: the next start reports the interruption again - and NOT ChainBroken, which is what
		// a second unsealed append would have produced.
		StoreIntegrityReport again = await service.CompareOnStartupAsync(CancellationToken.None);
		Assert.Contains(again.Anomalies, entry => entry.Kind == "FingerprintChainInterrupted");
		Assert.DoesNotContain(again.Anomalies, entry => entry.Kind == "FingerprintChainChainBroken");

		// The transient problem is gone; the next ordinary capture seals the tip over the whole chain.
		Directory.Delete(tipPath + ".tmp");
		await service.CompareOnStartupAsync(CancellationToken.None);

		Assert.Equal(StoreFingerprintChainState.Ok, service.Fingerprints.ReadAndVerify().State);
		Assert.False(File.Exists(service.Fingerprints.WriteIntentPath));
	}

	// ── Scheduled checks ─────────────────────────────────────────────────────────

	/// <summary>Given the default cadence, when the scheduled pass runs outside any window, then the two cheap
	/// checks and the ledger-chain verification are journaled as Ok and the expensive full check is not run -
	/// because it is disabled by default.</summary>
	[Fact]
	public async Task RunScheduledChecks_WithDefaults_JournalsTheCheapChecksOnly()
	{
		StoreIntegrityService service = CreateService();

		IReadOnlyList<DatabaseIntegrityCheckResult> results =
			await service.RunScheduledChecksAsync(new DateTime(2026, 9, 15, 14, 0, 0, DateTimeKind.Local), CancellationToken.None);

		Assert.Contains(results, row => row.Kind == DatabaseIntegrityCheckKind.QuickCheck);
		Assert.Contains(results, row => row.Kind == DatabaseIntegrityCheckKind.ForeignKeyCheck);
		Assert.Contains(results, row => row.Kind == DatabaseIntegrityCheckKind.LedgerChainVerify);
		Assert.DoesNotContain(results, row => row.Kind == DatabaseIntegrityCheckKind.FullIntegrityCheck);
		Assert.All(results, row => Assert.Equal(DatabaseIntegrityOutcome.Ok, row.Outcome));
		Assert.All(results, row => Assert.Equal(StoreIntegrityService.ScheduleActor, row.InitiatedBy));

		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(results.Count, await db.DatabaseIntegrityCheckResults.CountAsync());
	}

	/// <summary>Given the full check is enabled, when the pass runs outside the maintenance window, then it is
	/// skipped; inside the window it runs and is journaled. This is the bound that keeps a page-by-page read of
	/// a multi-gigabyte store inside the hours the operator chose.</summary>
	[Fact]
	public async Task RunScheduledChecks_RunsTheFullCheckOnlyInsideTheMaintenanceWindow()
	{
		_options.Storage.Integrity.FullCheckEnabled = true;
		_options.Storage.Integrity.MaintenanceWindowStartHourLocal = 3;
		_options.Storage.Integrity.MaintenanceWindowDurationHours = 4;
		StoreIntegrityService service = CreateService();

		IReadOnlyList<DatabaseIntegrityCheckResult> outside =
			await service.RunScheduledChecksAsync(new DateTime(2026, 9, 15, 14, 0, 0, DateTimeKind.Local), CancellationToken.None);
		Assert.DoesNotContain(outside, row => row.Kind == DatabaseIntegrityCheckKind.FullIntegrityCheck);

		IReadOnlyList<DatabaseIntegrityCheckResult> inside =
			await service.RunScheduledChecksAsync(new DateTime(2026, 9, 15, 4, 0, 0, DateTimeKind.Local), CancellationToken.None);
		DatabaseIntegrityCheckResult full = Assert.Single(
			inside,
			row => row.Kind == DatabaseIntegrityCheckKind.FullIntegrityCheck);
		Assert.Equal(DatabaseIntegrityOutcome.Ok, full.Outcome);
	}

	/// <summary>Given the feature is switched off, when the scheduled pass runs, then it journals nothing at
	/// all: a disabled feature must not leave rows behind that imply it ran.</summary>
	[Fact]
	public async Task RunScheduledChecks_WhenDisabled_DoesNothing()
	{
		_options.Storage.Integrity.Enabled = false;
		StoreIntegrityService service = CreateService();

		IReadOnlyList<DatabaseIntegrityCheckResult> results =
			await service.RunScheduledChecksAsync(DateTime.Now, CancellationToken.None);

		Assert.Empty(results);
		await using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(0, await db.DatabaseIntegrityCheckResults.CountAsync());
	}

	/// <summary>Given a tampered deletion ledger, when the ledger-chain check runs, then it is journaled as
	/// Failed rather than as a warning: a broken chain is corruption of the accountability record.</summary>
	[Fact]
	public async Task RunScheduledChecks_WhenTheLedgerChainIsBroken_JournalAFailure()
	{
		await SeedLedgerRowAsync(reason: "IDR-1 original");
		await ExecuteAsync("UPDATE \"EventDeletionLedger\" SET \"Reason\" = 'IDR-1 edited' WHERE \"Id\" = 1;");
		StoreIntegrityService service = CreateService();

		IReadOnlyList<DatabaseIntegrityCheckResult> results =
			await service.RunScheduledChecksAsync(DateTime.Now, CancellationToken.None);

		DatabaseIntegrityCheckResult chain = Assert.Single(
			results,
			row => row.Kind == DatabaseIntegrityCheckKind.LedgerChainVerify);
		Assert.Equal(DatabaseIntegrityOutcome.Failed, chain.Outcome);
		Assert.Contains("BROKEN", chain.Detail, StringComparison.Ordinal);
	}

	/// <summary>Given the ledger holds an intact chain, when the ledger-chain check runs, then it passes and
	/// reports how many entries it verified.</summary>
	[Fact]
	public async Task RunScheduledChecks_WhenTheLedgerChainIsIntact_PassesAndReportsTheCount()
	{
		await SeedLedgerRowAsync(reason: "IDR-1 original");
		StoreIntegrityService service = CreateService();

		IReadOnlyList<DatabaseIntegrityCheckResult> results =
			await service.RunScheduledChecksAsync(DateTime.Now, CancellationToken.None);

		DatabaseIntegrityCheckResult chain = Assert.Single(
			results,
			row => row.Kind == DatabaseIntegrityCheckKind.LedgerChainVerify);
		Assert.Equal(DatabaseIntegrityOutcome.Ok, chain.Outcome);
		Assert.Contains("intact", chain.Detail, StringComparison.OrdinalIgnoreCase);
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private sealed class FileDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public FileDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;

		public T CurrentValue { get; }

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private StoreIntegrityService CreateService()
	{
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(_options);
		StoreFingerprintStore store = new(
			_fingerprintPath,
			_anomalyMarkerPath,
			NullLogger<StoreFingerprintStore>.Instance);
		return new StoreIntegrityService(
			_factory,
			monitor,
			store,
			NullLogger<StoreIntegrityService>.Instance,
			opLog: new DbOperationLogWriter(_factory, monitor, NullLogger<DbOperationLogWriter>.Instance));
	}

	private void SeedRawEvents(int count)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		for (int index = 0; index < count; index++)
		{
			db.RawEvents.Add(new RawEvent
			{
				Channel = "Security",
				EventId = 4625,
				TimeUtc = DateTime.UtcNow.AddSeconds(-index),
			});
		}

		db.SaveChanges();
	}

	/// <summary>Seeds one properly chained ledger row, so the chain check has something real to verify.</summary>
	private async Task SeedLedgerRowAsync(string reason)
	{
		await using SqliteConnection connection = new("Data Source=" + _databasePath);
		await connection.OpenAsync();
		LedgerChainEntry entry = new(
			EventCode: 4625,
			Scope: 0,
			IpBinary16: null,
			WindowStartUtc: new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc),
			WindowEndUtc: new DateTime(2026, 9, 8, 0, 0, 0, DateTimeKind.Utc),
			RowsDeleted: 1_000,
			Trigger: 1,
			RuleVersion: 1,
			Reason: reason,
			InitiatedBy: "Service",
			CreatedUtc: new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc));
		string hash = LedgerChainHasher.ComputeEntryHash(LedgerChainHasher.GenesisPreviousHash, entry);
		await using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"INSERT INTO \"EventDeletionLedger\" (\"EventCode\", \"Scope\", \"IpBinary16\", \"WindowStartUtc\", "
			+ "\"WindowEndUtc\", \"RowsDeleted\", \"Trigger\", \"RuleVersion\", \"Reason\", \"InitiatedBy\", "
			+ "\"CreatedUtc\", \"PreviousHash\", \"EntryHash\") VALUES ($eventCode, $scope, NULL, $windowStart, "
			+ "$windowEnd, $rowsDeleted, $trigger, $ruleVersion, $reason, $initiatedBy, $createdUtc, $previous, $hash);";
		command.Parameters.AddWithValue("$eventCode", entry.EventCode);
		command.Parameters.AddWithValue("$scope", entry.Scope);
		command.Parameters.AddWithValue("$windowStart", entry.WindowStartUtc);
		command.Parameters.AddWithValue("$windowEnd", entry.WindowEndUtc);
		command.Parameters.AddWithValue("$rowsDeleted", entry.RowsDeleted);
		command.Parameters.AddWithValue("$trigger", entry.Trigger);
		command.Parameters.AddWithValue("$ruleVersion", entry.RuleVersion);
		command.Parameters.AddWithValue("$reason", entry.Reason);
		command.Parameters.AddWithValue("$initiatedBy", entry.InitiatedBy);
		command.Parameters.AddWithValue("$createdUtc", entry.CreatedUtc);
		command.Parameters.AddWithValue("$previous", LedgerChainHasher.GenesisPreviousHash);
		command.Parameters.AddWithValue("$hash", hash);
		await command.ExecuteNonQueryAsync();
	}

	private async Task ExecuteAsync(string sql)
	{
		await using SqliteConnection connection = new("Data Source=" + _databasePath);
		await connection.OpenAsync();
		await using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: the test composes the statement from its own literals only.
		command.CommandText = sql;
#pragma warning restore CA2100
		await command.ExecuteNonQueryAsync();
	}
}
