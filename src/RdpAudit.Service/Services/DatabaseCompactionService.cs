// File:    src/RdpAudit.Service/Services/DatabaseCompactionService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Answers IpcCommand.CompactDatabase (ordinal 93). It refuses, on purpose, and the refusal is
//          the feature: a full VACUUM rewrites the entire database file inside one write transaction, so
//          on a multi-gigabyte evidence store it can hold the single SQLite writer for minutes and stall
//          ingestion - the freeze the no-freeze rule forbids. The service that would have to hold that
//          lock is the very service answering the call, which is why the command can never succeed in
//          process: the correct shape of this operation is offline, from the Configurator, with the
//          service stopped (DatabaseCompactService in RdpAudit.Configurator).
//          What the command DOES do is make the refusal actionable rather than merely negative: it reads
//          SQLite's own page accounting from the live store (page size, page count, freelist depth) and
//          reports how many bytes are currently allocated to freed pages, so the operator can decide
//          whether an offline compaction is worth a service restart. Those reads are read-only PRAGMAs on
//          a short-lived connection; nothing here writes a byte of evidence.
// Extends: System.Object

using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Services;

/// <summary>Refuses an online full VACUUM and reports what an offline compaction would reclaim. Read-only:
/// the only statements it executes are page-accounting PRAGMAs.</summary>
public sealed class DatabaseCompactionService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Policy note carried in every answer, so the reason survives outside this source file.</summary>
	internal const string PolicyNote =
		"A full VACUUM is never run against the live evidence store. Deletions are followed by a WAL "
		+ "checkpoint and a bounded PRAGMA incremental_vacuum, which returns already-freed pages to the "
		+ "filesystem without rewriting the file - but only when the store's auto-vacuum mode is "
		+ "INCREMENTAL, which is the mode this product's own stores are created in (see "
		+ "docs/88-database-backup-and-restore.md and docs/41-data-model.md). Shrinking the file itself is "
		+ "an offline operation: the Configurator compacts through VACUUM INTO into a verified copy, "
		+ "normalises that copy to INCREMENTAL mode, and swaps it in atomically while the service is "
		+ "stopped - which is also the only way a store created by an older build becomes reclaimable "
		+ "online again.";

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<DatabaseCompactionService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory and the live options monitor.</summary>
	public DatabaseCompactionService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<DatabaseCompactionService> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Answers a compaction request. The status is always
	/// <see cref="IpcResultStatus.Refused"/>: performing the work here is precisely what must not happen.
	/// The answer still carries the store's page accounting so the operator can judge the offline pass.</summary>
	public async Task<DatabaseCompactionDto> RunAsync(
		DatabaseCompactionRequest? request,
		CancellationToken cancellationToken)
	{
		string databasePath = SafeFullPath(_options.CurrentValue.Storage.ResolveDatabasePath());

		DatabaseCompactionDto dto = new()
		{
			Status = IpcResultStatus.Refused,
			QueriedUtc = DateTime.UtcNow,
			ServiceRunning = true,
			Refused = true,
			DatabasePath = databasePath,
			PolicyNote = PolicyNote,
			Message =
				"Online compaction refused by design. A full VACUUM rewrites the whole database file inside "
				+ "one write transaction; on a multi-gigabyte evidence store it can hold the SQLite writer "
				+ "for minutes and stall ingestion. This command is answered BY the running service, so the "
				+ "service is demonstrably running and the rewrite cannot be permitted here."
				+ (request?.OfflineRequested == true
					? " The request was flagged as offline, but a service that answers an IPC call cannot be "
						+ "stopped; stop it for real and use the Configurator."
					: string.Empty),
			Procedure =
			[
				"1. Stop the RdpAudit service (the Configurator does this itself: Services ▸ Stop).",
				"2. Open the Configurator ▸ Database ▸ Danger Zone (needs DEBUG mode + elevation).",
				"3. Run 'Compact database (offline)…' and type the confirmation phrase.",
				"4. The Configurator checkpoints the WAL, writes a VACUUM INTO copy, verifies quick_check, "
					+ "per-table row counts, the migration history and foreign keys, rewrites that copy into "
					+ "auto-vacuum mode INCREMENTAL (so online reclamation works on the store afterwards), then "
					+ "swaps the copy in atomically and restarts the service.",
				"5. The pre-compaction file is kept next to the store as a timestamped .bak until you delete it.",
			],
		};

		await PopulatePageAccountingAsync(dto, databasePath, cancellationToken).ConfigureAwait(false);

		_logger.LogInformation(
			"Online database compaction refused (expected): database={DatabasePath} reclaimableBytes={ReclaimableBytes} "
			+ "freelistPages={FreeListPages}",
			dto.DatabasePath,
			dto.ReclaimableBytes,
			dto.FreeListPages);

		return dto;
	}

	// ── Page accounting ──────────────────────────────────────────────────────────

	/// <summary>Reads the live store's page accounting. Read-only, best effort and never fatal: a store
	/// that cannot be measured still gets an explanation of the refusal, which is the point of the
	/// command.</summary>
	private async Task PopulatePageAccountingAsync(
		DatabaseCompactionDto dto,
		string databasePath,
		CancellationToken cancellationToken)
	{
		dto.DatabaseBytes = ReadFileLength(databasePath);
		dto.WalBytes = ReadFileLength(databasePath + "-wal");
		dto.ShmBytes = ReadFileLength(databasePath + "-shm");

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();

			dto.PageSize = ReadPragma(connection, "PRAGMA page_size;");
			dto.PageCount = ReadPragma(connection, "PRAGMA page_count;");
			dto.FreeListPages = ReadPragma(connection, "PRAGMA freelist_count;");
			dto.AutoVacuumMode = ReadPragma(connection, "PRAGMA auto_vacuum;");
			if (dto.PageSize > 0 && dto.FreeListPages > 0)
			{
				dto.ReclaimableBytes = dto.PageSize * dto.FreeListPages;
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			// The refusal is still correct and still useful without the forecast; say the numbers are
			// missing rather than reporting zeros as if the store were full.
			_logger.LogWarning(ex, "Database compaction forecast could not read the page accounting");
			dto.PolicyNote = PolicyNote + " (The page accounting could not be read for this store.)";
		}
	}

	/// <summary>Executes a constant, row-returning PRAGMA and returns its first column as an integer, or
	/// -1 when it cannot be read. The pragma text is a compile-time literal supplied by this class - no
	/// operator input reaches SQL.</summary>
	private static long ReadPragma(SqliteConnection connection, string pragmaSql)
	{
		try
		{
			using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: the caller passes a constant pragma literal; no operator input reaches SQL.
			command.CommandText = pragmaSql;
#pragma warning restore CA2100
			object? value = command.ExecuteScalar();
			return value is null or DBNull
				? -1L
				: Convert.ToInt64(value, CultureInfo.InvariantCulture);
		}
		catch (Exception ex) when (ex is SqliteException or InvalidOperationException)
		{
			return -1L;
		}
	}

	/// <summary>Length of a store file in bytes, or -1 when it does not exist or cannot be read.</summary>
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
		catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
		{
			return path;
		}
	}
}
