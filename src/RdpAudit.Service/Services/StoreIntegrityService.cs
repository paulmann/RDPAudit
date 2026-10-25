// File:    src/RdpAudit.Service/Services/StoreIntegrityService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Captures the durable store fingerprint, compares it against the stored baseline at start-up, and
//          runs the scheduled integrity checks (Requirement R23).
//          It is a SINGLETON and holds no state between calls: the worker that captures on shutdown, the
//          worker that captures periodically and the initializer that compares at start-up all resolve the
//          same instance, so they cannot disagree about where the fingerprint lives or what it contains.
//          Every path here is observational. Nothing is repaired, truncated or rebuilt from a check result:
//          a detected problem is reported (OperationLog + marker) and the operator decides. The one write
//          this service performs is the integrity-check journal row, which records that a check ran and what
//          it returned.
//          The checks themselves are bounded: each PRAGMA runs with a row cap on its result so a corrupt
//              store cannot produce an unbounded report, and the caller decides whether a full pass is
//          allowed (maintenance window) before it is even attempted.
// Extends: System.Object

using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Service.Security;

namespace RdpAudit.Service.Services;

/// <summary>Captures store fingerprints, detects offline modification, and journals scheduled integrity
/// checks.</summary>
public sealed class StoreIntegrityService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Tables the fingerprint watches. The set is deliberately the same shape as the backup
	/// manifest's counted tables plus the two summary projections: it covers every table whose row count
	/// would move if evidence were removed, and nothing whose count changes for benign reasons unrelated to
	/// evidence (log rotation, for example).</summary>
	internal static readonly string[] CountedTables =
	[
		"RawEvents",
		"AuthAttemptFacts",
		"RdpConnectionFacts",
		"IpEventSummary",
		"IpEventTypeCounter",
		"Alerts",
		"Sessions",
		"SessionIpCorrelations",
		"AttackStats",
		"Addresses",
		"AbuseReports",
		"CrossHostFacts",
		"ProcessObservations",
		"EventDeletionLedger",
	];

	/// <summary>Maximum stored report lines from a check. A corrupt multi-page store can emit one line per
	/// page; the journal row must stay bounded.</summary>
	internal const int MaxCheckResultLines = 200;

	/// <summary>Marker actor recorded for a check nobody asked for.</summary>
	internal const string ScheduleActor = "Schedule";

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly StoreFingerprintStore _fingerprints;
	private readonly IOperationLogWriter? _opLog;
	private readonly ILogger<StoreIntegrityService> _logger;
	private readonly Security.StorageAclEnforcer? _acl;
	private readonly IRdpAuditPathsProvider? _paths;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory, the live options, the fingerprint store and
	/// the operation-log writer.</summary>
	public StoreIntegrityService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		StoreFingerprintStore fingerprints,
		ILogger<StoreIntegrityService> logger,
		IOperationLogWriter? opLog = null,
		Security.StorageAclEnforcer? acl = null,
		IRdpAuditPathsProvider? paths = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(fingerprints);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_fingerprints = fingerprints;
		_logger = logger;
		_opLog = opLog;
		_acl = acl;
		_paths = paths;
	}

	/// <summary>The most recent ACL assessment (null when the enforcer is not registered or has not run
	/// yet). Read by the Database-tab overview, which shows the current state rather than a stored one.</summary>
	public StorageAclStatus? LastAclStatus { get; private set; }

	/// <summary>Inspects the ACL of the evidence tree and records the result for the overview. Never throws:
	/// an unreadable ACL is an observation, not a failure.</summary>
	public StorageAclStatus? InspectStorageAcl()
	{
		if (_acl is null || _paths is null)
		{
			return null;
		}

		try
		{
			LastAclStatus = _acl.Inspect(_paths.Paths.ProgramDataDirectory);
			return LastAclStatus;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The storage ACL could not be inspected");
			return LastAclStatus;
		}
	}

	/// <summary>The fingerprint store this service writes to, exposed for the Configurator-visible status.</summary>
	public StoreFingerprintStore Fingerprints => _fingerprints;

	// ── Startup comparison ───────────────────────────────────────────────────────

	/// <summary>
	/// Compares the store against the stored baseline and reports anomalies. Called once at start-up, after
	/// migrations have been applied, because the migration history is part of what is compared.
	/// <para>
	/// The authoritative baseline is the last CLEAN-SHUTDOWN fingerprint; when none exists the comparison
	/// falls back to the periodic one and the report says so, because a periodic baseline cannot support a
	/// conclusion about rows that disappeared. A fingerprint is written for the current state in either case,
	/// so the next start compares against this one.
	/// </para>
	/// </summary>
	public async Task<StoreIntegrityReport> CompareOnStartupAsync(CancellationToken cancellationToken)
	{
		StorageIntegrityOptions integrity = _options.CurrentValue.Storage.Integrity;
		if (!integrity.Enabled)
		{
			return new StoreIntegrityReport(
				Compared: false,
				BaselineWasCleanShutdown: false,
				BaselineCapturedUtc: null,
				Anomalies: [],
				LedgerChainIntact: true,
				Message: "Store-integrity verification is disabled (RdpAudit:Storage:Integrity:Enabled=false).");
		}

		StoreFingerprint current = await CaptureAsync(ScheduleActor, cleanShutdown: false, cancellationToken)
			.ConfigureAwait(false);

		// The chain is verified BEFORE the baseline is taken from it (B19): a deleted tail or a broken linkage
		// means the baseline itself cannot be trusted, and that has to be said rather than quietly compared away.
		StoreFingerprintChainVerification chain = _fingerprints.ReadAndVerify();
		StoreFingerprint? baseline = chain.Baseline;

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);
		report = AppendChainFindings(report, chain);
		report = AppendAclFindings(report);

		if (!report.Compared)
		{
			_logger.LogInformation("Store-integrity comparison skipped: {Message}", report.Message);
		}
		else if (!report.HasAnomalies)
		{
			_logger.LogInformation("Store-integrity comparison clean: {Message}", report.Message);
		}
		else
		{
			// An operator signal in three places, deliberately: the structured log, the durable audit row and
			// a marker file the Configurator's diagnostics can show without reading the log.
			_logger.LogWarning("Store-integrity anomaly detected ({Severity}): {Message}",
				report.HasStrongAnomalies ? "strong" : "warning",
				report.Message);
			_fingerprints.WriteAnomalyMarker(report);
			await WriteAnomalyAuditAsync(report, cancellationToken).ConfigureAwait(false);
		}

		// The current state becomes the periodic baseline. It is NOT promoted to the clean-shutdown slot: only
		// a shutdown proves that no writer remained.
		_fingerprints.Write(current, cleanShutdown: false);
		return report;
	}

	/// <summary>Turns a non-Ok fingerprint-chain verdict into a loud anomaly (B19). This is the whole point of
	/// the chain: a deleted entry, a broken linkage or an unreadable tip must reach the same three operator
	/// signals as every other store-integrity observation (log, audit row, marker) instead of dissolving into
	/// "there is no baseline yet".
	/// <para>
	/// The severity is Strong for every state that accuses the store of having been changed, which is safe
	/// because those states cannot occur on a fresh install: <c>Missing</c> requires a sealed tip that accounts
	/// for entries which are not on disk, and a first run has neither chain nor tip (it is <c>Ok</c> with zero
	/// entries). Every one of them therefore means something that used to be recorded is gone or was altered.
	/// </para>
	/// <para>
	/// <c>Interrupted</c> is the one exception, and it is a Warning rather than a Strong anomaly on purpose
	/// (B24): it is reported - same method, same signals, nothing silent about it - but its meaning is "a
	/// capture was cut short", not "the store was tampered with", and it is admitted only when a durable write
	/// intent corroborates the on-disk shape fact for fact. Keeping it Strong would restore exactly the false
	/// tamper alarm that B24 exists to remove; treating it as silence would hide a real interruption. The
	/// evidence for interference is the SAME shape WITHOUT a matching intent, which is still ChainBroken and
	/// still Strong.
	/// </para>
	/// </summary>
	private static StoreIntegrityReport AppendChainFindings(
		StoreIntegrityReport report,
		StoreFingerprintChainVerification chain)
	{
		if (!chain.IsAlarming)
		{
			return report;
		}

		StoreIntegritySeverity severity = chain.State == StoreFingerprintChainState.Interrupted
			? StoreIntegritySeverity.Warning
			: StoreIntegritySeverity.Strong;

		StoreIntegrityAnomaly anomaly = new(
			severity,
			"FingerprintChain" + chain.State,
			chain.Message);

		List<StoreIntegrityAnomaly> anomalies = [.. report.Anomalies, anomaly];
		string message = string.Create(
			CultureInfo.InvariantCulture,
			$"{anomalies.Count} store-integrity observation(s): {string.Join(", ", anomalies.Select(entry => entry.Kind))}");
		return report with { Anomalies = anomalies, Message = message };
	}

	/// <summary>Adds the storage-ACL assessment to a fingerprint report. ACL drift is a store-integrity
	/// observation like any other: the same report, the same audit row, the same marker. An ACL that could
	/// not be read at all produces an Information entry rather than an alarm, because a policy that forbids
	/// reading ACLs is not evidence of tampering.</summary>
	private StoreIntegrityReport AppendAclFindings(StoreIntegrityReport report)
	{
		StorageAclStatus? acl = InspectStorageAcl();
		if (acl is null || !acl.Supported)
		{
			return report;
		}

		StoreIntegrityAnomaly? anomaly = null;
		if (acl.IsUnverifiable)
		{
			anomaly = new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Information,
				"StorageAclUnverifiable",
				acl.Message);
		}
		else if (!acl.Compliant)
		{
			anomaly = new StoreIntegrityAnomaly(
				StoreIntegritySeverity.Warning,
				"StorageAclDrift",
				acl.Message + " Expected: " + StorageAclPolicy.DescribeExpected()
					+ " Re-assert the ACL with install.ps1 (or the Configurator's installation repair) on the "
					+ "evidence tree.");
		}

		if (anomaly is null)
		{
			return report;
		}

		List<StoreIntegrityAnomaly> anomalies = [.. report.Anomalies, anomaly];
		string message = string.Create(
			CultureInfo.InvariantCulture,
			$"{anomalies.Count} store-integrity observation(s): {string.Join(", ", anomalies.Select(entry => entry.Kind))}");
		return report with { Anomalies = anomalies, Message = message };
	}

	// ── Fingerprint capture ──────────────────────────────────────────────────────
	/// <summary>Captures the store's fingerprint. Never throws for a store it cannot fully read: the missing
	/// parts are recorded as -1/empty, which the comparer treats as "no observation" rather than as a value
	/// that happens to be zero.</summary>
	public async Task<StoreFingerprint> CaptureAsync(
		string capturedBy,
		bool cleanShutdown,
		CancellationToken cancellationToken)
	{
		string databasePath = Path.GetFullPath(_options.CurrentValue.Storage.ResolveDatabasePath());
		Dictionary<string, long> counts = new(StringComparer.Ordinal);
		long lastSequence = 0;
		List<string> appliedMigrations = [];
		long chained = 0;
		long unchained = 0;
		string chainHead = LedgerChainHasher.GenesisPreviousHash;
		bool chainIntact = true;

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();

			foreach (string table in CountedTables)
			{
				cancellationToken.ThrowIfCancellationRequested();
				long? count = await CountTableAsync(connection, table, cancellationToken).ConfigureAwait(false);
				if (count is not null)
				{
					counts[table] = count.Value;
				}
			}

			lastSequence = await ReadLastIngestionSequenceAsync(connection, cancellationToken).ConfigureAwait(false);

			LedgerChainVerification verification =
				await LedgerChainVerifier.VerifyAsync(connection, cancellationToken).ConfigureAwait(false);
			chained = verification.ChainedRows;
			unchained = verification.UnchainedRows;
			chainIntact = verification.IsIntact;
			chainHead = await ReadChainHeadAsync(connection, cancellationToken).ConfigureAwait(false);

			foreach (string migration in db.Database.GetAppliedMigrations())
			{
				appliedMigrations.Add(migration);
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The store fingerprint could not be captured completely");
		}

		return new StoreFingerprint
		{
			CapturedUtc = DateTime.UtcNow,
			CleanShutdown = cleanShutdown,
			CapturedBy = capturedBy,
			DatabaseBytes = ReadFileLength(databasePath),
			WalBytes = ReadFileLength(databasePath + "-wal"),
			DatabaseLastWriteUtc = ReadLastWriteUtc(databasePath),
			LastIngestionSequence = lastSequence,
			TableRowCounts = counts,
			AppliedMigrations = appliedMigrations,
			LedgerChainedRows = chained,
			LedgerUnchainedRows = unchained,
			LedgerChainHead = chainHead,
			LedgerChainIntact = chainIntact,
		};
	}

	/// <summary>Captures the fingerprint and stores it in the clean-shutdown slot. Called from the worker
	/// whose StopAsync runs last, so every writer has already stopped.</summary>
	public async Task CaptureAtShutdownAsync(CancellationToken cancellationToken)
	{
		if (!_options.CurrentValue.Storage.Integrity.Enabled)
		{
			return;
		}

		StoreFingerprint fingerprint = await CaptureAsync("Shutdown", cleanShutdown: true, cancellationToken)
			.ConfigureAwait(false);
		_fingerprints.Write(fingerprint, cleanShutdown: true);
		_logger.LogInformation(
			"Store fingerprint captured at shutdown: dbBytes={DatabaseBytes} rows={Tables} ledgerChained={Chained} chainIntact={Intact}",
			fingerprint.DatabaseBytes,
			fingerprint.TableRowCounts.Count,
			fingerprint.LedgerChainedRows,
			fingerprint.LedgerChainIntact);
	}

	// ── Scheduled checks ─────────────────────────────────────────────────────────

	/// <summary>
	/// Runs the scheduled checks and journals each one. <paramref name="localNow"/> decides whether the full
	/// integrity check is allowed: it only ever starts inside the configured maintenance window, so a
	/// page-by-page read of the whole store lands where the operator chose.
	/// </summary>
	public async Task<IReadOnlyList<DatabaseIntegrityCheckResult>> RunScheduledChecksAsync(
		DateTime localNow,
		CancellationToken cancellationToken)
	{
		StorageIntegrityOptions integrity = _options.CurrentValue.Storage.Integrity;
		List<DatabaseIntegrityCheckResult> results = [];
		if (!integrity.Enabled)
		{
			return results;
		}

		if (integrity.QuickCheckEnabled)
		{
			results.Add(await RunCheckAsync(
				DatabaseIntegrityCheckKind.QuickCheck,
				"PRAGMA quick_check;",
				ScheduleActor,
				cancellationToken).ConfigureAwait(false));
		}

		if (integrity.ForeignKeyCheckEnabled)
		{
			results.Add(await RunCheckAsync(
				DatabaseIntegrityCheckKind.ForeignKeyCheck,
				"PRAGMA foreign_key_check;",
				ScheduleActor,
				cancellationToken).ConfigureAwait(false));
		}

		if (integrity.FullCheckEnabled && integrity.IsInsideMaintenanceWindow(localNow) && await IsFullCheckDueAsync(
			integrity.ResolveFullCheckIntervalDays(),
			cancellationToken).ConfigureAwait(false))
		{
			results.Add(await RunCheckAsync(
				DatabaseIntegrityCheckKind.FullIntegrityCheck,
				"PRAGMA integrity_check;",
				ScheduleActor,
				cancellationToken).ConfigureAwait(false));
		}

		List<DatabaseIntegrityCheckResult> ledgerResults = [];
		ledgerResults.Add(await RunLedgerChainCheckAsync(ScheduleActor, cancellationToken).ConfigureAwait(false));
		results.AddRange(ledgerResults);

		return results;
	}

	/// <summary>True when no full check has been journaled inside the configured interval.</summary>
	private async Task<bool> IsFullCheckDueAsync(int intervalDays, CancellationToken cancellationToken)
	{
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			DatabaseIntegrityCheckKind kind = DatabaseIntegrityCheckKind.FullIntegrityCheck;
			DatabaseIntegrityCheckResult? newest = await db.DatabaseIntegrityCheckResults
				.AsNoTracking()
				.Where(row => row.Kind == kind)
				.OrderByDescending(row => row.CompletedUtc)
				.FirstOrDefaultAsync(cancellationToken)
				.ConfigureAwait(false);
			if (newest is null)
			{
				return true;
			}

			return DateTime.UtcNow - newest.CompletedUtc >= TimeSpan.FromDays(intervalDays);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			// Without the journal the cadence cannot be honoured; skipping is the safe reading, because the
			// alternative is a full check on every pass.
			_logger.LogWarning(ex, "The full-integrity-check cadence could not be read; skipping this pass");
			return false;
		}
	}

	/// <summary>Runs one PRAGMA check bounded by <see cref="MaxCheckResultLines"/> and journals the result.</summary>
	public async Task<DatabaseIntegrityCheckResult> RunCheckAsync(
		DatabaseIntegrityCheckKind kind,
		string pragmaSql,
		string initiatedBy,
		CancellationToken cancellationToken)
	{
		DateTime startedUtc = DateTime.UtcNow;
		DatabaseIntegrityOutcome outcome = DatabaseIntegrityOutcome.Warning;
		string detail;
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
			List<string> lines = await ExecuteScalarListAsync(connection, pragmaSql, cancellationToken).ConfigureAwait(false);
			outcome = ClassifyCheckResult(lines);
			detail = Truncate(string.Join(" | ", lines));
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			// A check that could not run is a Warning, never an Ok: "we could not look" must not read as
			// "we looked and it was fine".
			outcome = DatabaseIntegrityOutcome.Warning;
			detail = Truncate(ex.GetType().Name + " - " + ex.Message);
		}

		return await JournalAsync(kind, startedUtc, outcome, detail, initiatedBy, cancellationToken)
			.ConfigureAwait(false);
	}

	/// <summary>Runs the deletion-ledger hash-chain verification and journals it as a check of its own, so a
	/// broken chain is visible in the same place as a failed page check.</summary>
	public async Task<DatabaseIntegrityCheckResult> RunLedgerChainCheckAsync(
		string initiatedBy,
		CancellationToken cancellationToken)
	{
		DateTime startedUtc = DateTime.UtcNow;
		DatabaseIntegrityOutcome outcome = DatabaseIntegrityOutcome.Warning;
		string detail;
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
			LedgerChainVerification verification =
				await LedgerChainVerifier.VerifyAsync(connection, cancellationToken).ConfigureAwait(false);
			outcome = verification.IsIntact ? DatabaseIntegrityOutcome.Ok : DatabaseIntegrityOutcome.Failed;
			detail = Truncate(verification.Message);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			detail = Truncate(ex.GetType().Name + " - " + ex.Message);
		}

		return await JournalAsync(
			DatabaseIntegrityCheckKind.LedgerChainVerify,
			startedUtc,
			outcome,
			detail,
			initiatedBy,
			cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Writes one journal row. Best effort with respect to the caller's flow - a check that ran is
	/// still reported to the caller even when the row cannot be written - but the failure is logged, because
	/// an unrecorded check is a check nobody can audit.</summary>
	private async Task<DatabaseIntegrityCheckResult> JournalAsync(
		DatabaseIntegrityCheckKind kind,
		DateTime startedUtc,
		DatabaseIntegrityOutcome outcome,
		string detail,
		string initiatedBy,
		CancellationToken cancellationToken)
	{
		DateTime completedUtc = DateTime.UtcNow;
		DatabaseIntegrityCheckResult row = new()
		{
			Kind = kind,
			StartedUtc = startedUtc,
			CompletedUtc = completedUtc,
			Outcome = outcome,
			Detail = detail,
			DurationMs = (long)(completedUtc - startedUtc).TotalMilliseconds,
			InitiatedBy = initiatedBy,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			db.DatabaseIntegrityCheckResults.Add(row);
			await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The integrity-check journal row for {Kind} could not be written", kind);
		}

		if (outcome != DatabaseIntegrityOutcome.Ok)
		{
			_logger.LogWarning("Integrity check {Kind} reported {Outcome}: {Detail}", kind, outcome, detail);
		}
		else
		{
			_logger.LogInformation("Integrity check {Kind} passed in {DurationMs} ms", kind, row.DurationMs);
		}

		return row;
	}

	// ── Check helpers ────────────────────────────────────────────────────────────

	/// <summary>Classifies a check's output. SQLite returns exactly "ok" for a clean page check and no rows
	/// at all for a clean foreign-key check, so both are Ok; anything else is corruption and therefore
	/// <see cref="DatabaseIntegrityOutcome.Failed"/>, because a page-level complaint is not a warning.</summary>
	internal static DatabaseIntegrityOutcome ClassifyCheckResult(IReadOnlyList<string> lines)
	{
		if (lines.Count == 0)
		{
			return DatabaseIntegrityOutcome.Ok;
		}

		if (lines.Count == 1 && string.Equals(lines[0], "ok", StringComparison.OrdinalIgnoreCase))
		{
			return DatabaseIntegrityOutcome.Ok;
		}

		return DatabaseIntegrityOutcome.Failed;
	}

	private static async Task<List<string>> ExecuteScalarListAsync(
		SqliteConnection connection,
		string pragmaSql,
		CancellationToken cancellationToken)
	{
		List<string> lines = [];
		await using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: the callers pass constant pragma literals; no operator input reaches SQL.
		command.CommandText = pragmaSql;
#pragma warning restore CA2100
		await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			lines.Add(reader.IsDBNull(0) ? string.Empty : reader.GetValue(0).ToString() ?? string.Empty);
			if (lines.Count >= MaxCheckResultLines)
			{
				lines.Add("...(report truncated at " + MaxCheckResultLines.ToString(CultureInfo.InvariantCulture) + " lines)");
				break;
			}
		}

		return lines;
	}

	private static async Task<long?> CountTableAsync(
		SqliteConnection connection,
		string table,
		CancellationToken cancellationToken)
	{
		if (!await TableExistsAsync(connection, table, cancellationToken).ConfigureAwait(false))
		{
			return null;
		}

		await using SqliteCommand command = connection.CreateCommand();
		SetTableCommandText(command, "SELECT COUNT(*) FROM \"" + table + "\";");
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is long count ? count : 0L;
	}

	private static async Task<bool> TableExistsAsync(
		SqliteConnection connection,
		string table,
		CancellationToken cancellationToken)
	{
		await using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name;";
		command.Parameters.AddWithValue("$name", table);
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is long count && count > 0;
	}

	/// <summary>Highest durable ingestion sequence in the store, or 0 when there is none. Read from the
	/// sequence allocator rather than from RawEvents, because the allocator's value is monotonic even after
	/// every raw event behind it has been deleted by retention.</summary>
	private static async Task<long> ReadLastIngestionSequenceAsync(
		SqliteConnection connection,
		CancellationToken cancellationToken)
	{
		if (!await TableExistsAsync(connection, "IngestionSequence", cancellationToken).ConfigureAwait(false))
		{
			return 0L;
		}

		await using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT MAX(\"NextValue\") FROM \"IngestionSequence\";";
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is long sequence ? sequence : 0L;
	}

	private static async Task<string> ReadChainHeadAsync(
		SqliteConnection connection,
		CancellationToken cancellationToken)
	{
		await using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"SELECT \"EntryHash\" FROM \"EventDeletionLedger\" WHERE \"EntryHash\" IS NOT NULL "
			+ "ORDER BY \"Id\" DESC LIMIT 1;";
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is string hash ? hash : LedgerChainHasher.GenesisPreviousHash;
	}

	private static void SetTableCommandText(SqliteCommand command, string sql)
	{
#pragma warning disable CA2100 // Reviewed: composed from a constant and a table name taken from CountedTables; no operator input reaches SQL.
		command.CommandText = sql;
#pragma warning restore CA2100
	}

	private static string Truncate(string value)
		=> value.Length <= 4000 ? value : value[..4000];

	private static long ReadFileLength(string path)
	{
		try
		{
			FileInfo info = new(path);
			return info.Exists ? info.Length : -1L;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
		{
			return -1L;
		}
	}

	private static DateTime? ReadLastWriteUtc(string path)
	{
		try
		{
			FileInfo info = new(path);
			return info.Exists ? info.LastWriteTimeUtc : null;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
		{
			return null;
		}
	}

	private async Task WriteAnomalyAuditAsync(StoreIntegrityReport report, CancellationToken cancellationToken)
	{
		if (_opLog is null)
		{
			return;
		}

		try
		{
			StringBuilder details = new();
			foreach (StoreIntegrityAnomaly anomaly in report.Anomalies)
			{
				details.Append(anomaly.Severity).Append(": ").Append(anomaly.Kind).Append(": ")
					.Append(anomaly.Detail).Append('\n');
			}

			await _opLog.WriteAsync(
				new OperationLogEntry
				{
					Severity = report.HasStrongAnomalies ? OperationLogSeverity.Error : OperationLogSeverity.Warning,
					Source = "Storage",
					Operation = "StoreIntegrityAnomaly",
					Message = Truncate(report.Message),
					DetailsJson = details.Length > 0 ? Truncate(details.ToString()) : null,
					Actor = "Service",
				},
				cancellationToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The store-integrity anomaly could not be written to the operation log");
		}
	}
}
