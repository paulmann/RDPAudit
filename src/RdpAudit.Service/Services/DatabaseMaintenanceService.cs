// File:    src/RdpAudit.Service/Services/DatabaseMaintenanceService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Executes ONE safe, operator-triggered maintenance action for the Database tab's
//          Maintenance section (IPC ordinal 89) and reports it as structured steps plus a
//          monospace ResultText. Every action is read-safe: the three checks are pure reads,
//          a WAL checkpoint only moves committed frames, incremental_vacuum only hands already
//          freed pages back to the filesystem (bounded, like the daily maintenance worker), and
//          PRAGMA optimize is the SQLite-recommended statistics maintenance. A FULL VACUUM does
//          not exist in this surface - the kind enum has no such member and the validator refuses
//          anything outside the defined set, because a full VACUUM rewrites the whole file and can
//          hold the writer lock for minutes on a live evidence store (docs/88 states the policy).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Services;

/// <summary>Runs bounded, read-safe maintenance actions and reports them structurally.</summary>
public sealed class DatabaseMaintenanceService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Free pages one incremental vacuum may release, mirroring the daily
	/// MaintenanceWorker's bound so a manual pass can never hold the writer longer.</summary>
	internal const int DefaultIncrementalVacuumPages = 5000;

	/// <summary>Upper bound on the requested page budget.</summary>
	internal const int MaxIncrementalVacuumPages = 5000;

	/// <summary>The <c>PRAGMA auto_vacuum</c> value for INCREMENTAL mode: the only mode in which
	/// <c>PRAGMA incremental_vacuum(N)</c> returns a page to the filesystem at all (B27).</summary>
	private const int IncrementalAutoVacuumMode = 2;

	/// <summary>Maximum result lines kept from a check. A corrupt multi-page store can produce one
	/// report line per page; the report must stay bounded, so the rest is summarised.</summary>
	internal const int MaxCheckResultLines = 100;

	/// <summary>Wall-clock budget of one step. A check that exceeds it reports TimedOut instead of
	/// hanging the IPC round-trip past the client's own deadline.</summary>
	private const int StepTimeoutMs = 30_000;

	private const string VacuumRefusalNote =
		"Full VACUUM is deliberately not offered on the live evidence store: it rewrites the entire "
		+ "database file and can hold the SQLite writer lock for minutes, which the no-freeze rule "
		+ "forbids. Space already freed by deletions is reclaimed with 'Incremental vacuum' (bounded) "
		+ "WHEN the store's auto-vacuum mode is INCREMENTAL; on a store that is not, that statement "
		+ "releases nothing and only the offline compaction (Database tab -> Danger Zone) returns the "
		+ "space - the Database tab overview reports the mode and the free pages. See "
		+ "docs/88-database-backup-and-restore.md.";

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<DatabaseMaintenanceService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory and the live options monitor.</summary>
	public DatabaseMaintenanceService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<DatabaseMaintenanceService> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Runs the requested action. Never throws for an operational failure: a refused kind is an
	/// <see cref="IpcResultStatus.InvalidRequest"/> report, a failing or timing-out step is reported
	/// as such in the steps and the result is downgraded to <see cref="IpcResultStatus.Unavailable"/>,
	/// so the operator always gets a document that says what happened.
	/// </summary>
	public async Task<DatabaseMaintenanceReportDto> RunAsync(DatabaseMaintenanceRequest? request, CancellationToken cancellationToken)
	{
		DateTime startedUtc = DateTime.UtcNow;
		DatabaseMaintenanceKind kind = request?.Kind ?? DatabaseMaintenanceKind.Unknown;

		DatabaseMaintenanceReportDto report = new()
		{
			QueriedUtc = startedUtc,
			Kind = kind,
			KindName = kind.ToString(),
		};

		if (!Enum.IsDefined(kind) || kind == DatabaseMaintenanceKind.Unknown)
		{
			report.Status = IpcResultStatus.InvalidRequest;
			report.Message = string.Format(
				CultureInfo.InvariantCulture,
				"RunDatabaseMaintenance requires a valid maintenance action. Supported kinds: {0}. {1}",
				DescribeSupportedKinds(),
				VacuumRefusalNote);
			report.ResultText = Render(report);
			return report;
		}

		string databasePath = SafeFullPath(_options.CurrentValue.Storage.ResolveDatabasePath());
		int vacuumPages = Math.Clamp(
			request?.IncrementalVacuumPages ?? DefaultIncrementalVacuumPages,
			1,
			MaxIncrementalVacuumPages);

		Stopwatch watch = Stopwatch.StartNew();
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();

			switch (kind)
			{
				case DatabaseMaintenanceKind.QuickCheck:
					await RunCheckStepAsync(connection, report, "PRAGMA quick_check", MaxCheckResultLines, cancellationToken)
						.ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.FullIntegrityCheck:
					await RunCheckStepAsync(connection, report, "PRAGMA integrity_check", MaxCheckResultLines, cancellationToken)
						.ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.ForeignKeyCheck:
					await RunCheckStepAsync(connection, report, "PRAGMA foreign_key_check", MaxCheckResultLines, cancellationToken)
						.ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.WalCheckpointPassive:
					await RunCheckpointStepAsync(connection, report, "PASSIVE", cancellationToken).ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.WalCheckpointTruncate:
					await RunCheckpointStepAsync(connection, report, "TRUNCATE", cancellationToken).ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.IncrementalVacuum:
					await RunIncrementalVacuumStepAsync(connection, report, vacuumPages, cancellationToken).ConfigureAwait(false);
					break;
				case DatabaseMaintenanceKind.Optimize:
					await RunOptimizeStepAsync(connection, report, cancellationToken).ConfigureAwait(false);
					break;
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			report.Steps.Add(new DatabaseMaintenanceStepDto
			{
				Name = DescribeAction(kind),
				Outcome = "Failed",
				Detail = ex.GetType().Name + " - " + ex.Message,
				DurationMs = watch.ElapsedMilliseconds,
			});
			_logger.LogWarning(ex, "Database maintenance action {Kind} failed", kind);
		}
		finally
		{
			watch.Stop();
			report.DurationMs = watch.ElapsedMilliseconds;
		}

		bool degraded = report.Steps.Any(step => step.Outcome != "Completed");
		report.Status = degraded ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		report.ResultText = Render(report);
		report.Message = BuildMessage(report, databasePath);
		return report;
	}

	// ── Steps ────────────────────────────────────────────────────────────────────

	/// <summary>Runs a row-returning check pragma and records the bounded result.</summary>
	private async Task RunCheckStepAsync(
		SqliteConnection connection,
		DatabaseMaintenanceReportDto report,
		string pragma,
		int maxLines,
		CancellationToken cancellationToken)
	{
		Stopwatch watch = Stopwatch.StartNew();
		DatabaseMaintenanceStepDto step = new() { Name = pragma };
		try
		{
			using CancellationTokenSource stepCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			stepCts.CancelAfter(StepTimeoutMs);
			List<string> lines = await ExecuteScalarListAsync(connection, pragma, MaxCheckResultLines, stepCts.Token).ConfigureAwait(false);

			// quick_check / integrity_check answer exactly "ok" (or the first problems);
			// foreign_key_check answers no rows when every reference holds.
			bool ok = pragma.Contains("foreign_key_check", StringComparison.Ordinal)
				? lines.Count == 0
				: lines.Count == 1 && string.Equals(lines[0], "ok", StringComparison.OrdinalIgnoreCase);
			step.Outcome = "Completed";
			step.Detail = ok
				? "ok"
				: string.Format(
					CultureInfo.InvariantCulture,
					"{0} problem line(s) reported{1}: {2}",
					lines.Count,
					lines.Count >= maxLines ? " (bounded)" : string.Empty,
					string.Join(" | ", lines.Take(maxLines)));
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			step.Outcome = "TimedOut";
			step.Detail = string.Format(CultureInfo.InvariantCulture, "The check exceeded its {0} ms budget.", StepTimeoutMs);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			step.Outcome = "Failed";
			step.Detail = ex.GetType().Name + " - " + ex.Message;
		}
		finally
		{
			watch.Stop();
			step.DurationMs = watch.ElapsedMilliseconds;
		}

		report.Steps.Add(step);
	}

	/// <summary>Runs <c>PRAGMA wal_checkpoint(&lt;mode&gt;)</c> and records the three returned counts.</summary>
	private async Task RunCheckpointStepAsync(
		SqliteConnection connection,
		DatabaseMaintenanceReportDto report,
		string mode,
		CancellationToken cancellationToken)
	{
		string pragma = "PRAGMA wal_checkpoint(" + mode + ")";
		Stopwatch watch = Stopwatch.StartNew();
		DatabaseMaintenanceStepDto step = new() { Name = pragma };
		try
		{
			using CancellationTokenSource stepCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			stepCts.CancelAfter(StepTimeoutMs);
			List<string> values = await ExecuteScalarListAsync(connection, pragma, MaxCheckResultLines, stepCts.Token).ConfigureAwait(false);
			step.Outcome = "Completed";
			step.Detail = values.Count >= 3
				? string.Format(
					CultureInfo.InvariantCulture,
					"busy={0} walFrames={1} checkpointedFrames={2}",
					values[0], values[1], values[2])
				: "The checkpoint returned no counts" + (values.Count == 0 ? " (nothing to checkpoint)." : ".");
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			step.Outcome = "TimedOut";
			step.Detail = string.Format(CultureInfo.InvariantCulture, "The checkpoint exceeded its {0} ms budget.", StepTimeoutMs);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			step.Outcome = "Failed";
			step.Detail = ex.GetType().Name + " - " + ex.Message;
		}
		finally
		{
			watch.Stop();
			step.DurationMs = watch.ElapsedMilliseconds;
		}

		report.Steps.Add(step);
	}

	/// <summary>
	/// Runs the bounded <c>PRAGMA incremental_vacuum(N)</c> and reports what it actually did.
	/// <para>
	/// The statement's own result set cannot answer that: measured on SQLite 3.41.2,
	/// <c>PRAGMA incremental_vacuum(N)</c> returns ZERO rows whether it released nothing or thousands of
	/// pages (<c>PRAGMA wal_checkpoint</c>, by contrast, returns one row). Reporting the freed-page count
	/// from those rows would therefore tell the operator "no free pages to release" on a store where pages
	/// were released. The step measures the freelist depth before and after instead - the same reading the
	/// application-data purge uses - and reads <c>PRAGMA auto_vacuum</c>, so that "released nothing" can
	/// name its cause: on a store that is not in INCREMENTAL mode the statement is a documented no-op
	/// (B27), and only an offline rewrite returns that space.
	/// </para>
	/// </summary>
	private async Task RunIncrementalVacuumStepAsync(
		SqliteConnection connection,
		DatabaseMaintenanceReportDto report,
		int pages,
		CancellationToken cancellationToken)
	{
		string pragma = "PRAGMA incremental_vacuum(" + pages.ToString(CultureInfo.InvariantCulture) + ")";
		Stopwatch watch = Stopwatch.StartNew();
		DatabaseMaintenanceStepDto step = new() { Name = pragma };
		try
		{
			using CancellationTokenSource stepCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			stepCts.CancelAfter(StepTimeoutMs);
			long? freePagesBefore = await ReadPragmaLongAsync(connection, "PRAGMA freelist_count;", stepCts.Token)
				.ConfigureAwait(false);
			int? autoVacuumMode = await ReadPragmaIntAsync(connection, "PRAGMA auto_vacuum;", stepCts.Token)
				.ConfigureAwait(false);
			await ExecuteNonQueryAsync(connection, pragma, stepCts.Token).ConfigureAwait(false);
			long? freePagesAfter = await ReadPragmaLongAsync(connection, "PRAGMA freelist_count;", stepCts.Token)
				.ConfigureAwait(false);
			step.Outcome = "Completed";
			step.Detail = DescribeIncrementalVacuumOutcome(freePagesBefore, freePagesAfter, autoVacuumMode, pages);
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			step.Outcome = "TimedOut";
			step.Detail = string.Format(CultureInfo.InvariantCulture, "The vacuum exceeded its {0} ms budget.", StepTimeoutMs);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			step.Outcome = "Failed";
			step.Detail = ex.GetType().Name + " - " + ex.Message;
		}
		finally
		{
			watch.Stop();
			step.DurationMs = watch.ElapsedMilliseconds;
		}

		report.Steps.Add(step);
	}

	/// <summary>Runs <c>PRAGMA optimize</c>, which writes only statistics-side data.</summary>
	private async Task RunOptimizeStepAsync(
		SqliteConnection connection,
		DatabaseMaintenanceReportDto report,
		CancellationToken cancellationToken)
	{
		const string pragma = "PRAGMA optimize";
		Stopwatch watch = Stopwatch.StartNew();
		DatabaseMaintenanceStepDto step = new() { Name = pragma };
		try
		{
			using CancellationTokenSource stepCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			stepCts.CancelAfter(StepTimeoutMs);
			await using (SqliteCommand command = connection.CreateCommand())
			{
				command.CommandText = pragma;
				await command.ExecuteNonQueryAsync(stepCts.Token).ConfigureAwait(false);
			}

			step.Outcome = "Completed";
			step.Detail = "Statistics maintenance completed; query-planner data updated where SQLite judged it necessary.";
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			step.Outcome = "TimedOut";
			step.Detail = string.Format(CultureInfo.InvariantCulture, "The optimize exceeded its {0} ms budget.", StepTimeoutMs);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			step.Outcome = "Failed";
			step.Detail = ex.GetType().Name + " - " + ex.Message;
		}
		finally
		{
			watch.Stop();
			step.DurationMs = watch.ElapsedMilliseconds;
		}

		report.Steps.Add(step);
	}

	// ── Rendering ────────────────────────────────────────────────────────────────

	/// <summary>States what the incremental vacuum did, from the two freelist readings. "Released nothing"
	/// is only ever reported together with its cause, because on a store that is not in INCREMENTAL mode it
	/// is the expected outcome (B27) and not a failed step.</summary>
	private static string DescribeIncrementalVacuumOutcome(long? freePagesBefore, long? freePagesAfter, int? autoVacuumMode, int budget)
	{
		if (freePagesBefore is not { } before || freePagesAfter is not { } after)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"The freelist depth could not be read, so the number of released pages is unknown (budget {0}).",
				budget);
		}

		long released = before > after ? before - after : 0;
		if (released > 0)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"freedPages={0} (freelist {1} -> {2}, budget {3})",
				released,
				before,
				after,
				budget);
		}

		if (after == 0)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"The freelist is empty, so there was nothing to release (budget {0}).",
				budget);
		}

		if (autoVacuumMode != IncrementalAutoVacuumMode)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"Released nothing although {0} free page(s) are inside the file: this store's auto-vacuum mode "
				+ "is {1}, not INCREMENTAL, so this statement cannot return them. Only the offline compaction "
				+ "returns that space - Database tab, Danger Zone, 'Compact database (offline)' with the service "
				+ "stopped - and it rewrites the store into INCREMENTAL mode, after which this action works. The "
				+ "Database tab overview reports the mode and the free pages (budget {2}).",
				before,
				autoVacuumMode?.ToString(CultureInfo.InvariantCulture) ?? "unknown",
				budget);
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"Released nothing although {0} free page(s) are inside the file and the mode is INCREMENTAL; a "
			+ "concurrent writer or the page budget ({1}) explains that. Run the action again.",
			before,
			budget);
	}

	/// <summary>Renders the monospace report the Configurator displays verbatim.</summary>
	private static string Render(DatabaseMaintenanceReportDto report)
	{
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit database maintenance");
		sb.AppendLine("=============================");
		sb.AppendLine("Started (UTC):  " + report.QueriedUtc.ToString("O", CultureInfo.InvariantCulture));
		sb.AppendLine("Action:         " + report.KindName);
		sb.AppendLine();
		if (report.Steps.Count == 0)
		{
			sb.AppendLine("No step was executed.");
		}

		foreach (DatabaseMaintenanceStepDto step in report.Steps)
		{
			sb.AppendLine(step.Name + "  ->  " + step.Outcome + " (" + step.DurationMs.ToString(CultureInfo.InvariantCulture) + " ms)");
			sb.AppendLine("  " + step.Detail);
		}

		sb.AppendLine();
		sb.AppendLine(report.Message ?? string.Empty);
		return sb.ToString();
	}

	private static string BuildMessage(DatabaseMaintenanceReportDto report, string databasePath)
	{
		if (report.Status == IpcResultStatus.InvalidRequest)
		{
			return report.Message ?? string.Empty;
		}

		string firstDetail = report.Steps.Count > 0 ? report.Steps[0].Detail : "no step executed";
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0}: {1}. Database: {2}. No evidence row was deleted and no OperationLog row was written (read-safe action).",
			report.KindName,
			firstDetail,
			databasePath);
	}

	private static string DescribeSupportedKinds() => string.Join(
		", ",
		Enum.GetValues<DatabaseMaintenanceKind>()
			.Where(kind => kind is not DatabaseMaintenanceKind.Unknown)
			.Select(kind => kind.ToString()));

	private static string DescribeAction(DatabaseMaintenanceKind kind) => kind switch
	{
		DatabaseMaintenanceKind.QuickCheck => "PRAGMA quick_check",
		DatabaseMaintenanceKind.FullIntegrityCheck => "PRAGMA integrity_check",
		DatabaseMaintenanceKind.ForeignKeyCheck => "PRAGMA foreign_key_check",
		DatabaseMaintenanceKind.WalCheckpointPassive => "PRAGMA wal_checkpoint(PASSIVE)",
		DatabaseMaintenanceKind.WalCheckpointTruncate => "PRAGMA wal_checkpoint(TRUNCATE)",
		DatabaseMaintenanceKind.IncrementalVacuum => "PRAGMA incremental_vacuum",
		DatabaseMaintenanceKind.Optimize => "PRAGMA optimize",
		_ => kind.ToString(),
	};

	// ── Helpers ──────────────────────────────────────────────────────────────────

	/// <summary>Executes a row-returning pragma and returns the first column of every row, capped
	/// at <paramref name="maxLines"/>. The pragma text is composed only from compile-time constants
	/// and an integer - never from operator input - so there is nothing to parameterize; the single
	/// reviewed CA2100 site mirrors the retention engine's justification.</summary>
	private static async Task<List<string>> ExecuteScalarListAsync(
		SqliteConnection connection,
		string pragma,
		int maxLines,
		CancellationToken cancellationToken)
	{
		List<string> lines = new();
		await using (SqliteCommand command = connection.CreateCommand())
		{
#pragma warning disable CA2100 // Reviewed: composed from constant fragments and an integer only; no operator input reaches SQL.
			command.CommandText = pragma;
#pragma warning restore CA2100
			await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				lines.Add(reader.IsDBNull(0) ? string.Empty : reader.GetValue(0).ToString() ?? string.Empty);
				if (lines.Count >= maxLines)
				{
					break;
				}
			}
		}

		return lines;
	}

	/// <summary>Executes a write statement (a PRAGMA the step issues) and returns nothing; used where the
	/// statement has no useful result set - <c>incremental_vacuum</c> returns none even when it works.</summary>
	private static async Task ExecuteNonQueryAsync(
		SqliteConnection connection,
		string statement,
		CancellationToken cancellationToken)
	{
		await using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: composed from constant fragments and an integer only; no operator input reaches SQL.
		command.CommandText = statement;
#pragma warning restore CA2100
		await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Reads a scalar PRAGMA as a nullable long, so an unreadable value is reported as unknown
	/// instead of being read as zero.</summary>
	private static async Task<long?> ReadPragmaLongAsync(
		SqliteConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		object? value = await ReadPragmaAsync(connection, pragma, cancellationToken).ConfigureAwait(false);
		return value is null or DBNull ? null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
	}

	/// <summary>Reads a scalar PRAGMA as a nullable int.</summary>
	private static async Task<int?> ReadPragmaIntAsync(
		SqliteConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		object? value = await ReadPragmaAsync(connection, pragma, cancellationToken).ConfigureAwait(false);
		return value is null or DBNull ? null : Convert.ToInt32(value, CultureInfo.InvariantCulture);
	}

	private static async Task<object?> ReadPragmaAsync(
		SqliteConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		await using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: every caller passes a literal PRAGMA statement defined in this file.
		command.CommandText = pragma;
#pragma warning restore CA2100
		return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Full path of a configured location, or the raw value when the path is unusable.</summary>
	private static string SafeFullPath(string? path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return string.Empty;
		}

		try
		{
			return Path.GetFullPath(path);
		}
		catch (ArgumentException)
		{
			return path;
		}
		catch (NotSupportedException)
		{
			return path;
		}
	}
}
