/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseOverviewService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Assembles the Database tab's Overview snapshot with bounded, independently failable
//          sections: database file family sizes, volume free space, the shard-tree footprint,
//          key-table row counts, size growth and projected time-to-cap from
//          DbSizeGrowthCalculator, applied vs pending migrations, the migration-failure marker,
//          the effective retention switches and the aggregated deletion-ledger totals. A section
//          that times out or throws degrades the snapshot to partial and is named in Warnings -
//          it never fails the whole command, exactly like GetDiagnostics.
// Depends: AuditDbContext, RdpAuditOptions, DbSizeGrowthCalculator, DatabaseMigrationFailureMarker,
//          DatabaseOverviewDto
// Extends: Add a section by adding one RunSectionAsync call and its DatabaseOverviewDto fields.

using System.Data.Common;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Core.Util;
using RdpAudit.Service.Security;

namespace RdpAudit.Service.Services;

/// <summary>Collects the bounded, sectioned evidence-store snapshot for the Database tab.</summary>
public sealed class DatabaseOverviewService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Per-section wall-clock budget. A section that exceeds it is reported as
	/// <c>TimedOut</c> and the snapshot becomes partial rather than the command failing.</summary>
	private const int SectionTimeoutMs = 8000;

	/// <summary>The <c>PRAGMA auto_vacuum</c> value for INCREMENTAL mode - the only mode in which the
	/// online path can return free pages to the filesystem at all (B27). A store in any other mode keeps
	/// them inside the file until an offline rewrite.</summary>
	private const int IncrementalAutoVacuumMode = 2;

	/// <summary>Upper bound on the shard-tree walk so a pathological directory cannot turn an
	/// overview read into an unbounded enumeration. Reaching it marks the section truncated.</summary>
	private const int MaxShardTreeFilesScanned = 200_000;

	/// <summary>Key evidence tables the Overview reports row counts for, in display order.</summary>
	private static readonly string[] CountedTables =
	[
		"RawEvents",
		"AuthAttemptFacts",
		"RdpConnectionFacts",
		"IpEventSummaries",
		"IpEventTypeCounters",
		"Alerts",
		"ActiveBlocks",
		"AttackStats",
		"AbuseReports",
		"OperationLogs",
		"CrossHostFacts",
		"ProcessObservations",
		"EventDeletionLedger",
	];

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IRdpAuditPathsProvider? _paths;
	private readonly ILogger<DatabaseOverviewService> _logger;
	private readonly DatabaseBackupService? _backups;
	private readonly Storage.ShardIngestionSink? _shardSink;
	private readonly Security.StorageAclEnforcer? _acl;
	private readonly StoreFingerprintStore? _fingerprints;
	private readonly ServiceMetrics? _metrics;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory and the live options monitor.
	/// <paramref name="backups"/> is optional: a host without the snapshot engine still answers the
	/// overview, and the snapshot section says so instead of reporting an empty backup folder.
	/// <paramref name="shardSink"/> is optional for the same reason: without it the shard capacity
	/// section is reported as absent instead of as healthy.</summary>
	public DatabaseOverviewService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<DatabaseOverviewService> logger,
		IRdpAuditPathsProvider? paths = null,
		DatabaseBackupService? backups = null,
		Storage.ShardIngestionSink? shardSink = null,
		Security.StorageAclEnforcer? acl = null,
		StoreFingerprintStore? fingerprints = null,
		ServiceMetrics? metrics = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
		_paths = paths;
		_backups = backups;
		_shardSink = shardSink;
		_acl = acl;
		_fingerprints = fingerprints;
		_metrics = metrics;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Builds the overview snapshot. Never throws for a section failure; a total failure
	/// still returns a DTO whose <c>IsPartial</c> flag and section list explain what happened.</summary>
	public async Task<DatabaseOverviewDto> BuildAsync(CancellationToken cancellationToken)
	{
		DateTime nowUtc = DateTime.UtcNow;
		RdpAuditOptions options = _options.CurrentValue;
		StorageOptions storage = options.Storage;
		RetentionPolicyOptions policy = storage.RetentionPolicy;

		string databasePath = SafeFullPath(storage.ResolveDatabasePath());
		string actionsRoot = SafeFullPath(options.Sharding.ResolveActionsRoot());

		DatabaseOverviewDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			DatabasePath = databasePath,
			ActionsRoot = actionsRoot,
			RetentionPolicyEnabled = policy.Enabled,
			LegalHold = policy.LegalHold,
			MaxDatabaseBytes = policy.ResolveMaxDatabaseBytes(),
			MaxRawEventRows = policy.ResolveMaxRawEventRows(),
			MinFreeDiskBytes = policy.ResolveMinFreeDiskBytes(),
			ShardingEnabled = options.Sharding.Enabled,
			MaxShardFiles = options.Sharding.MaxShardFiles,
			// Null - not "healthy" - when this host has no shard sink: the absence of a refusal is only
			// meaningful when something is there to refuse.
			ShardCapacityStatus = _shardSink?.GetCapacityStatus(),
			// -1 rather than 0 when this host registered no metrics: "no counter" and "no failed batch"
			// must not render the same way - the whole point of the counters is to make a silent
			// persistence stall visible.
			PersistBatchRetainedCount = _metrics?.PersistBatchRetainedCount ?? -1,
			PersistBatchStalledCount = _metrics?.PersistBatchStalledCount ?? -1,
		};

		await RunSectionAsync(dto, "DbFiles", _ => PopulateFileSizes(dto, databasePath, actionsRoot), cancellationToken)
			.ConfigureAwait(false);
		await RunSectionAsync(dto, "ShardTree", sct =>
		{
			PopulateShardTree(dto, actionsRoot, sct);
			return Task.CompletedTask;
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "DbCounts", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateRowCountsAsync(db, dto, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Growth", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateGrowthAsync(db, dto, nowUtc, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "StorePages", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateStorePageAccountingAsync(db, dto, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Schema", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateSchemaAsync(db, dto, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Ledger", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateLedgerAggregateAsync(db, dto, sct).ConfigureAwait(false);
			await PopulateLedgerChainAsync(db, dto, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Integrity", async sct =>
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(sct).ConfigureAwait(false);
			await PopulateIntegrityStateAsync(db, dto, sct).ConfigureAwait(false);
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "StorageAcl", _ =>
		{
			PopulateStorageAcl(dto);
			return Task.CompletedTask;
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Fingerprint", _ =>
		{
			PopulateFingerprintState(dto);
			return Task.CompletedTask;
		}, cancellationToken).ConfigureAwait(false);
		dto.IntegrityCadence = storage.Integrity.Describe();
		dto.EncryptionMode = storage.Encryption.Describe();

		await RunSectionAsync(dto, "MigrationMarker", _ =>
		{
			PopulateMigrationFailureMarker(dto);
			return Task.CompletedTask;
		}, cancellationToken).ConfigureAwait(false);
		await RunSectionAsync(dto, "Backups", _ =>
		{
			PopulateBackups(dto);
			return Task.CompletedTask;
		}, cancellationToken).ConfigureAwait(false);

		if (dto.IsPartial)
		{
			// The snapshot is usable but incomplete: say so in the status so a client cannot present
			// partial capacity numbers as the whole truth.
			dto.Status = IpcResultStatus.Unavailable;
		}

		dto.Message = string.Format(
			CultureInfo.InvariantCulture,
			"dbBytes={0} walBytes={1} actionsBytes={2} shards={3} ledgerEntries={4} removedRows={5} appliedMigrations={6} pendingMigrations={7} policyEnabled={8} legalHold={9} sharding={10} partial={11}",
			dto.DatabaseBytes,
			dto.WalBytes,
			dto.ActionsBytes,
			dto.ShardCount,
			dto.LedgerEntryCount,
			dto.LedgerRowsDeleted,
			dto.AppliedMigrations.Count,
			dto.PendingMigrations.Count,
			dto.RetentionPolicyEnabled,
			dto.LegalHold,
			dto.ShardingEnabled,
			dto.IsPartial);

		return dto;
	}

	// ── Section runner ───────────────────────────────────────────────────────────

	/// <summary>
	/// Runs one bounded section. A section that times out or throws marks the snapshot partial and
	/// is recorded with its duration and error, so a client can show which numbers are missing and
	/// why instead of silently reading zeros. Cancellation of the caller always propagates.
	/// </summary>
	private async Task RunSectionAsync(
		DatabaseOverviewDto dto,
		string section,
		Func<CancellationToken, Task> body,
		CancellationToken cancellationToken)
	{
		Stopwatch watch = Stopwatch.StartNew();
		using CancellationTokenSource sectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		sectionCts.CancelAfter(SectionTimeoutMs);
		string status;
		string? error = null;
		try
		{
			await body(sectionCts.Token).ConfigureAwait(false);
			status = "Completed";
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (OperationCanceledException)
		{
			status = "TimedOut";
			error = string.Format(
				CultureInfo.InvariantCulture,
				"Section '{0}' exceeded its {1} ms budget.",
				section,
				SectionTimeoutMs);
			Degrade(dto, error);
		}
		catch (Exception ex)
		{
			status = "Failed";
			error = ex.GetType().Name + " - " + ex.Message;
			Degrade(
				dto,
				string.Format(CultureInfo.InvariantCulture, "Database overview section '{0}' failed: {1}", section, error));
			_logger.LogWarning(ex, "Database overview section {Section} failed", section);
		}

		watch.Stop();
		dto.Sections.Add(new DatabaseOverviewSectionDto
		{
			Section = section,
			DurationMs = watch.ElapsedMilliseconds,
			Status = status,
			Error = error,
		});
	}

	private static void Degrade(DatabaseOverviewDto dto, string warning)
	{
		dto.IsPartial = true;
		dto.Warnings.Add(warning);
	}

	// ── File sizes and volumes ───────────────────────────────────────────────────

	private static Task PopulateFileSizes(DatabaseOverviewDto dto, string databasePath, string actionsRoot)
	{
		dto.DatabaseBytes = ReadFileSize(databasePath);
		dto.WalBytes = ReadFileSize(databasePath + "-wal");
		dto.ShmBytes = ReadFileSize(databasePath + "-shm");
		dto.TotalDatabaseFamilyBytes = dto.DatabaseBytes < 0 || dto.WalBytes < 0 || dto.ShmBytes < 0
			? -1
			: dto.DatabaseBytes + dto.WalBytes + dto.ShmBytes;

		(dto.DatabaseVolumeRoot, dto.DatabaseVolumeFreeBytes, dto.DatabaseVolumeTotalBytes) =
			ReadVolume(databasePath);
		(dto.ActionsVolumeRoot, dto.ActionsVolumeFreeBytes, dto.ActionsVolumeTotalBytes) =
			ReadVolume(actionsRoot);
		return Task.CompletedTask;
	}

	/// <summary>Reads a file size. Zero means the file does not exist yet (or the configured path is
	/// empty, which is the shipped default); <c>-1</c> means it exists but could not be read, so the
	/// caller never confuses "empty" with "unreadable".</summary>
	private static long ReadFileSize(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return 0L;
		}

		try
		{
			FileInfo info = new(path);
			return info.Exists ? info.Length : 0L;
		}
		catch (IOException)
		{
			return -1L;
		}
		catch (UnauthorizedAccessException)
		{
			return -1L;
		}
		catch (ArgumentException)
		{
			return 0L;
		}
	}

	private static (string Root, long? FreeBytes, long? TotalBytes) ReadVolume(string path)
	{
		try
		{
			string? root = Path.GetPathRoot(Path.GetFullPath(path));
			if (string.IsNullOrEmpty(root))
			{
				return (string.Empty, null, null);
			}

			DriveInfo drive = new(root);
			return drive.IsReady
				? (root, drive.AvailableFreeSpace, drive.TotalSize)
				: (root, null, null);
		}
		catch (IOException)
		{
			return (string.Empty, null, null);
		}
		catch (UnauthorizedAccessException)
		{
			return (string.Empty, null, null);
		}
		catch (ArgumentException)
		{
			return (string.Empty, null, null);
		}
	}

	// ── Store page accounting and auto-vacuum mode ───────────────────────────────

	/// <summary>
	/// Reads the two facts that decide whether the online space-reclamation path can work at all:
	/// <c>PRAGMA auto_vacuum</c> (only INCREMENTAL lets a bounded <c>incremental_vacuum</c> return pages to
	/// the filesystem) and the freelist depth (how much is waiting inside the file). Reported together
	/// because neither alone tells the operator anything actionable - "released nothing" is a bug only when
	/// there was something to release and the mode allowed it.
	/// <para>
	/// Every value is nullable: a pragma that could not be read is reported as unknown, and the note is
	/// omitted rather than derived from it. A store that cannot state its mode must not be presented with a
	/// sentence about what its mode permits.
	/// </para>
	/// </summary>
	private static async Task PopulateStorePageAccountingAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
		DbConnection connection = db.Database.GetDbConnection();

		dto.AutoVacuumMode = await ReadPragmaIntAsync(connection, "PRAGMA auto_vacuum;", cancellationToken)
			.ConfigureAwait(false);
		dto.JournalMode = await ReadPragmaTextAsync(connection, "PRAGMA journal_mode;", cancellationToken)
			.ConfigureAwait(false);
		dto.PageSize = await ReadPragmaIntAsync(connection, "PRAGMA page_size;", cancellationToken)
			.ConfigureAwait(false);
		dto.PageCount = await ReadPragmaLongAsync(connection, "PRAGMA page_count;", cancellationToken)
			.ConfigureAwait(false);
		dto.FreeListPages = await ReadPragmaLongAsync(connection, "PRAGMA freelist_count;", cancellationToken)
			.ConfigureAwait(false);

		dto.ReclaimableBytes = dto.PageSize is { } pageSize && dto.FreeListPages is { } freePages
			? pageSize * freePages
			: null;

		dto.SpaceReclamationNote = DescribeSpaceReclamationMode(dto);
	}

	/// <summary>The one sentence the mode and the freelist add up to for this store. It says what can happen
	/// now, and - on a store that is not in INCREMENTAL mode - that free pages already inside the file will
	/// only leave it through an offline rewrite, so "released nothing" is a property of the store's header
	/// and not a defect the operator should keep retrying.</summary>
	private static string? DescribeSpaceReclamationMode(DatabaseOverviewDto dto)
	{
		if (dto.AutoVacuumMode is not { } mode)
		{
			return null;
		}

		long freePages = dto.FreeListPages ?? -1;
		if (mode == IncrementalAutoVacuumMode)
		{
			return freePages > 0
				? string.Format(
					CultureInfo.InvariantCulture,
					"Online reclamation is available: {0} free page(s) are waiting inside the file and a bounded "
					+ "incremental vacuum (purge or maintenance) returns them to the filesystem.",
					freePages)
				: "Online reclamation is available: this store's auto-vacuum mode is INCREMENTAL, so free pages "
					+ "left by deletions are returned to the filesystem by the bounded incremental vacuum.";
		}

		return freePages > 0
			? string.Format(
				CultureInfo.InvariantCulture,
				"ONLINE RELEASE IS NOT POSSIBLE on this store: its auto-vacuum mode is {0}, so the bounded "
				+ "incremental vacuum of the purge and the maintenance surface releases nothing, and the {1} "
				+ "free page(s) inside the file stay there. Only the offline rewrite can return that space - "
				+ "Database tab, Danger Zone, 'Compact database (offline)' with the service stopped. That "
				+ "compaction also rewrites the store into INCREMENTAL mode, after which online reclamation "
				+ "works.",
				mode,
				freePages)
			: string.Format(
				CultureInfo.InvariantCulture,
				"This store's auto-vacuum mode is {0}, not INCREMENTAL: it holds no free pages right now, but "
				+ "once deletions leave some, online reclamation cannot return them and only the offline "
				+ "compaction (Database tab, Danger Zone) will.",
				mode);
	}

	// ── Pragma readers ───────────────────────────────────────────────────────────

	private static async Task<int?> ReadPragmaIntAsync(
		DbConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		object? value = await ReadPragmaAsync(connection, pragma, cancellationToken).ConfigureAwait(false);
		return value is null or DBNull ? null : Convert.ToInt32(value, CultureInfo.InvariantCulture);
	}

	private static async Task<long?> ReadPragmaLongAsync(
		DbConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		object? value = await ReadPragmaAsync(connection, pragma, cancellationToken).ConfigureAwait(false);
		return value is null or DBNull ? null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
	}

	private static async Task<string?> ReadPragmaTextAsync(
		DbConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		object? value = await ReadPragmaAsync(connection, pragma, cancellationToken).ConfigureAwait(false);
		return value is null or DBNull ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
	}

	private static async Task<object?> ReadPragmaAsync(
		DbConnection connection,
		string pragma,
		CancellationToken cancellationToken)
	{
		await using DbCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Reviewed: every caller passes a literal PRAGMA statement defined in this file.
		command.CommandText = pragma;
#pragma warning restore CA2100
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value;
	}

	// ── Shard tree ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Walks the shard tree once and reports its total size, its file count and its shard count. The
	/// walk is bounded, skips reparse points so it can never follow a junction out of the tree, and
	/// ignores inaccessible directories instead of failing the section.
	/// </summary>
	private static void PopulateShardTree(
		DatabaseOverviewDto dto,
		string actionsRoot,
		CancellationToken cancellationToken)
	{
		dto.ActionsBytes = 0;
		dto.ActionsFileCount = 0;
		dto.ShardCount = 0;

		if (string.IsNullOrWhiteSpace(actionsRoot) || !Directory.Exists(actionsRoot))
		{
			// No shard tree yet is an honest zero, not an error.
			return;
		}

		EnumerationOptions enumerationOptions = new()
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.ReparsePoint,
		};

		foreach (string file in Directory.EnumerateFiles(actionsRoot, "*", enumerationOptions))
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (dto.ActionsFileCount >= MaxShardTreeFilesScanned)
			{
				dto.ActionsScanTruncated = true;
				break;
			}

			dto.ActionsFileCount++;
			if (file.EndsWith(ShardPath.ShardExtension, StringComparison.OrdinalIgnoreCase))
			{
				dto.ShardCount++;
			}

			try
			{
				FileInfo info = new(file);
				if (info.Exists)
				{
					dto.ActionsBytes += info.Length;
				}
			}
			catch (IOException)
			{
				// A file that vanished or is unreadable mid-walk is skipped; the totals stay lower
				// bounds and ActionsScanTruncated tells the client the numbers are not exhaustive.
			}
			catch (UnauthorizedAccessException)
			{
			}
		}
	}

	// ── Row counts ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Counts the key evidence tables, isolating a failure to the table it belongs to: one
	/// unreadable table reports <c>RowCount = -1</c> with its error instead of discarding the counts
	/// that did succeed.
	/// </summary>
	private static async Task PopulateRowCountsAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		foreach (string table in CountedTables)
		{
			DatabaseTableRowCountDto row = new() { Table = table };
			try
			{
				row.RowCount = await CountTableAsync(db, table, cancellationToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception ex)
			{
				row.RowCount = -1;
				row.Error = ex.GetType().Name + " - " + ex.Message;
			}

			dto.TableRowCounts.Add(row);
		}
	}

	private static Task<long> CountTableAsync(AuditDbContext db, string table, CancellationToken cancellationToken)
		=> table switch
		{
			"RawEvents" => db.RawEvents.AsNoTracking().LongCountAsync(cancellationToken),
			"AuthAttemptFacts" => db.AuthAttemptFacts.AsNoTracking().LongCountAsync(cancellationToken),
			"RdpConnectionFacts" => db.RdpConnectionFacts.AsNoTracking().LongCountAsync(cancellationToken),
			"IpEventSummaries" => db.IpEventSummaries.AsNoTracking().LongCountAsync(cancellationToken),
			"IpEventTypeCounters" => db.IpEventTypeCounters.AsNoTracking().LongCountAsync(cancellationToken),
			"Alerts" => db.Alerts.AsNoTracking().LongCountAsync(cancellationToken),
			"ActiveBlocks" => db.ActiveBlocks.AsNoTracking().LongCountAsync(cancellationToken),
			"AttackStats" => db.AttackStats.AsNoTracking().LongCountAsync(cancellationToken),
			"AbuseReports" => db.AbuseReports.AsNoTracking().LongCountAsync(cancellationToken),
			"OperationLogs" => db.OperationLogs.AsNoTracking().LongCountAsync(cancellationToken),
			"CrossHostFacts" => db.CrossHostFacts.AsNoTracking().LongCountAsync(cancellationToken),
			"ProcessObservations" => db.ProcessObservations.AsNoTracking().LongCountAsync(cancellationToken),
			"EventDeletionLedger" => db.EventDeletionLedger.AsNoTracking().LongCountAsync(cancellationToken),
			_ => throw new ArgumentOutOfRangeException(nameof(table), table, "Unknown overview table."),
		};

	// ── Growth and projection ────────────────────────────────────────────────────

	/// <summary>
	/// Derives the growth trend from the daily size snapshots and projects the whole days left
	/// before the database family reaches <c>MaxDatabaseBytes</c>. The monthly rate is used because
	/// it is the least noisy of the three windows; the projection is stated with its basis so an
	/// operator can see it is a trend, not a measurement.
	/// </summary>
	private static async Task PopulateGrowthAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		DateTime nowUtc,
		CancellationToken cancellationToken)
	{
		List<DbProp> snapshots = await db.DbProps.AsNoTracking()
			.Where(p => p.Key.StartsWith(DbSizeGrowthCalculator.SnapshotKeyPrefix))
			.ToListAsync(cancellationToken).ConfigureAwait(false);

		long currentSizeBytes = dto.TotalDatabaseFamilyBytes >= 0
			? dto.TotalDatabaseFamilyBytes
			: dto.DatabaseBytes;
		if (currentSizeBytes < 0)
		{
			dto.GrowthNote = "The database size could not be measured, so no growth trend is available.";
			return;
		}

		List<DbSizeSnapshot> parsed = new(snapshots.Count);
		foreach (DbProp prop in snapshots)
		{
			if (DbSizeGrowthCalculator.IsSnapshotKey(prop.Key)
				&& DbSizeGrowthCalculator.TryDecode(prop.Value, out DbSizeSnapshot snapshot))
			{
				parsed.Add(snapshot);
			}
		}

		DbSizeGrowth growth = DbSizeGrowthCalculator.Compute(parsed, currentSizeBytes, nowUtc);
		dto.GrowthBytesDay = growth.GrowthBytesDay;
		dto.GrowthBytesWeek = growth.GrowthBytesWeek;
		dto.GrowthBytesMonth = growth.GrowthBytesMonth;
		dto.ProjectedDaysToCap = ProjectDaysToCap(dto, out string? note);
		dto.GrowthNote = note;
	}

	/// <summary>
	/// Whole days until the database family reaches the configured ceiling. Null with an explanation
	/// whenever a projection would be dishonest: no ceiling, no measurable size, the ceiling is
	/// already exceeded, or no positive growth rate is known.
	/// </summary>
	private static long? ProjectDaysToCap(DatabaseOverviewDto dto, out string? note)
	{
		long cap = dto.MaxDatabaseBytes;
		long current = dto.TotalDatabaseFamilyBytes >= 0 ? dto.TotalDatabaseFamilyBytes : dto.DatabaseBytes;
		if (cap <= 0)
		{
			note = "No database-size ceiling is configured (MaxDatabaseBytes = 0), so there is no cap to project against.";
			return null;
		}

		if (current < 0)
		{
			note = "The database size could not be measured.";
			return null;
		}

		if (current >= cap)
		{
			note = "The database already reaches or exceeds MaxDatabaseBytes; the next pass fires the DatabaseBytes trigger.";
			return null;
		}

		long? growthMonth = dto.GrowthBytesMonth;
		if (growthMonth is not > 0)
		{
			note = "No positive month-over-month growth is known from the recorded size snapshots, so no projection is possible.";
			return null;
		}

		double bytesPerDay = growthMonth.Value / 30.0;
		double days = (cap - current) / bytesPerDay;
		note = string.Format(
			CultureInfo.InvariantCulture,
			"Projected from the month-over-month growth of {0} bytes over 30 days.",
			growthMonth.Value);
		return days >= long.MaxValue ? long.MaxValue : (long)days;
	}

	// ── Schema state ─────────────────────────────────────────────────────────────

	private static async Task PopulateSchemaAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		IEnumerable<string> applied = await db.Database.GetAppliedMigrationsAsync(cancellationToken)
			.ConfigureAwait(false);
		dto.AppliedMigrations.AddRange(applied);

		IEnumerable<string> pending = await db.Database.GetPendingMigrationsAsync(cancellationToken)
			.ConfigureAwait(false);
		dto.PendingMigrations.AddRange(pending);
	}

	/// <summary>
	/// Reads the migration-failure marker. It lives next to appsettings.json in the ProgramData
	/// root, not next to the database file, so the path comes from the layout provider rather than
	/// from the configured database path.
	/// </summary>
	private void PopulateMigrationFailureMarker(DatabaseOverviewDto dto)
	{
		string programDataDirectory = (_paths?.Paths ?? RdpAuditPaths.Default).ProgramDataDirectory;
		MigrationFailureMarkerPayload? marker = DatabaseMigrationFailureMarker.TryRead(programDataDirectory);
		if (marker is null)
		{
			dto.MigrationFailureMarkerPresent = false;
			return;
		}

		dto.MigrationFailureMarkerPresent = true;
		dto.MigrationFailureUtc = marker.TimestampUtc;
		dto.MigrationFailureMessage = marker.ExceptionMessage ?? marker.ExceptionType;
		dto.MigrationFailurePendingMigrations.AddRange(marker.PendingMigrations);
	}

	// ── Database snapshots ───────────────────────────────────────────────────────

	/// <summary>
	/// Reports the snapshot state the operator needs before trusting a recovery plan: whether the
	/// surface is enabled, whether a pre-migration snapshot is required, where snapshots live, how many
	/// there are and which is newest. A host without the snapshot engine reports -1 snapshots and a note
	/// that says so, rather than an empty folder that reads as "no backups exist".
	/// </summary>
	private void PopulateBackups(DatabaseOverviewDto dto)
	{
		if (_backups is null)
		{
			dto.BackupSnapshotCount = -1;
			dto.BackupNote = "The database backup service is not available in this host, so no snapshot state could be read.";
			return;
		}

		DatabaseBackupStatus status = _backups.GetStatus(CancellationToken.None);
		dto.BackupEnabled = status.Enabled;
		dto.PreMigrationBackupEnabled = status.PreMigrationBackupEnabled;
		dto.BackupDirectory = status.BackupDirectory;
		dto.BackupSnapshotCount = status.SnapshotCount;
		dto.BackupRetentionCopies = status.RetentionCopies;
		dto.BackupLastCreatedUtc = status.LastCreatedUtc;
		dto.BackupLastSnapshotDirectory = status.LastSnapshotDirectory;
		dto.BackupLastSnapshotSha256 = status.LastSnapshotSha256;
		if (status.LastSnapshotDirectory is null)
		{
			dto.BackupNote = status.PreMigrationBackupEnabled
				? "No database snapshot exists yet. A snapshot will be taken automatically before the next schema migration."
				: "No database snapshot exists yet, and pre-migration snapshots are disabled (Storage:Backup:PreMigrationBackupEnabled is false), so a schema upgrade has no rollback point.";
		}
	}

	// ── Deletion-ledger aggregate ────────────────────────────────────────────────

	private static async Task PopulateLedgerAggregateAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		dto.LedgerEntryCount = await db.EventDeletionLedger.AsNoTracking()
			.LongCountAsync(cancellationToken).ConfigureAwait(false);
		dto.LedgerRowsDeleted = await db.EventDeletionLedger.AsNoTracking()
			.SumAsync(row => (long?)row.RowsDeleted, cancellationToken).ConfigureAwait(false) ?? 0L;
		dto.LedgerLastCreatedUtc = await db.EventDeletionLedger.AsNoTracking()
			.OrderByDescending(row => row.CreatedUtc)
			.ThenByDescending(row => row.Id)
			.Select(row => (DateTime?)row.CreatedUtc)
			.FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
	}

	// ── Store integrity and tamper evidence (Stage 5) ────────────────────────────

	/// <summary>Verifies the deletion-ledger hash chain and reports it. The ledger holds one row per deletion
	/// pass and code, so this is a small scan rather than a table walk; a broken chain is the one integrity
	/// signal that a reader of the ledger cannot see for themselves.
	/// <para>
	/// The connection is opened here because the verifier takes a raw <c>SqliteConnection</c> and issues its own
	/// command. EF closes a connection it opened itself once the last EF query finishes, so the aggregate query
	/// just above leaves it closed, and the verifier would fail with "ExecuteReader can only be called when the
	/// connection is open" - which is exactly what the end-to-end smoke test found: the whole Ledger section
	/// reported Failed and the overview came back partial on a healthy store. Test containers that hand EF an
	/// already-open connection never saw it. The connection is closed again only when this method opened it.
	/// </para>
	/// </summary>
	private async Task PopulateLedgerChainAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		Microsoft.Data.Sqlite.SqliteConnection connection =
			(Microsoft.Data.Sqlite.SqliteConnection)db.Database.GetDbConnection();
		bool openedHere = connection.State != System.Data.ConnectionState.Open;
		if (openedHere)
		{
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
		}

		try
		{
			LedgerChainVerification verification =
				await LedgerChainVerifier.VerifyAsync(connection, cancellationToken).ConfigureAwait(false);
			dto.LedgerChainIntact = verification.IsIntact;
			dto.LedgerChainedRows = verification.ChainedRows;
			dto.LedgerUnchainedRows = verification.UnchainedRows;
			dto.LedgerChainMessage = verification.Message;
		}
		finally
		{
			if (openedHere)
			{
				await db.Database.CloseConnectionAsync().ConfigureAwait(false);
			}
		}
	}

	/// <summary>Reports the newest journaled outcome of each integrity check, the fingerprint timestamps and
	/// whether an anomaly marker is present. Every value is a recorded observation; nothing here runs a
	/// check, so opening the tab cannot impose a page scan on the store.</summary>
	private async Task PopulateIntegrityStateAsync(
		AuditDbContext db,
		DatabaseOverviewDto dto,
		CancellationToken cancellationToken)
	{
		foreach (DatabaseIntegrityCheckKind kind in new[]
		{
			DatabaseIntegrityCheckKind.QuickCheck,
			DatabaseIntegrityCheckKind.FullIntegrityCheck,
			DatabaseIntegrityCheckKind.ForeignKeyCheck,
			DatabaseIntegrityCheckKind.LedgerChainVerify,
		})
		{
			DatabaseIntegrityCheckResult? row = await db.DatabaseIntegrityCheckResults
				.AsNoTracking()
				.Where(entry => entry.Kind == kind)
				.OrderByDescending(entry => entry.CompletedUtc)
				.ThenByDescending(entry => entry.Id)
				.FirstOrDefaultAsync(cancellationToken)
				.ConfigureAwait(false);
			if (row is null)
			{
				continue;
			}

			DatabaseIntegrityCheckRowDto projected = new()
			{
				Kind = row.Kind.ToString(),
				Outcome = row.Outcome.ToString(),
				CompletedUtc = row.CompletedUtc,
				DurationMs = row.DurationMs,
				InitiatedBy = row.InitiatedBy,
				Detail = row.Detail,
			};
			switch (kind)
			{
				case DatabaseIntegrityCheckKind.QuickCheck:
					dto.LastQuickCheck = projected;
					break;
				case DatabaseIntegrityCheckKind.FullIntegrityCheck:
					dto.LastFullIntegrityCheck = projected;
					break;
				case DatabaseIntegrityCheckKind.ForeignKeyCheck:
					dto.LastForeignKeyCheck = projected;
					break;
				default:
					dto.LastLedgerChainCheck = projected;
					break;
			}
		}
	}

	/// <summary>Reads the stored fingerprint chain and the anomaly marker. The marker is a file, not a
	/// database row, because it must survive exactly the situation it reports: a store that was changed while
	/// the service was not running. The chain state is reported as its own field (B19) so "no baseline yet",
	/// "entries were deleted" and "the chain was edited" are three different things on screen.
	/// <para>
	/// The read itself lives in <see cref="StoreFingerprintVerdictReader"/> because the Diagnostic tab shows
	/// the same verdict (B25); sharing the read is what keeps the two tabs from disagreeing.</para>
	/// </summary>
	private void PopulateFingerprintState(DatabaseOverviewDto dto)
	{
		if (_paths is null)
		{
			return;
		}

		try
		{
			StoreFingerprintVerdictRead read = StoreFingerprintVerdictReader.Read(
				_paths.Paths.StoreFingerprintPath,
				_paths.Paths.StoreIntegrityAnomalyMarkerPath,
				_fingerprints);
			dto.FingerprintChainState = read.ChainState;
			dto.FingerprintChainEntryCount = read.ChainEntryCount;
			dto.FingerprintChainMessage = read.ChainMessage;
			dto.FingerprintChainMirrorAvailable = read.MirrorAvailable;
			dto.FingerprintCleanShutdownUtc = read.CleanShutdownUtc;
			dto.FingerprintPeriodicUtc = read.PeriodicUtc;
			dto.IntegrityAnomalyMarkerPresent = read.AnomalyMarkerPresent;
			dto.IntegrityAnomalyDetail = read.AnomalyDetail;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
			or JsonException or ArgumentException)
		{
			Degrade(dto, "Fingerprint: " + ex.GetType().Name + " - " + ex.Message);
		}
	}

	/// <summary>Assesses the ACL of the evidence tree and reports it. The assessment is a live read of the
	/// current DACLs - a few syscalls - so the operator sees the state now rather than a remembered one; the
	/// start-up verification records its own outcome in the OperationLog.</summary>
	private void PopulateStorageAcl(DatabaseOverviewDto dto)
	{
		if (_paths is null || _acl is null)
		{
			return;
		}

		try
		{
			StorageAclStatus status = _acl.Inspect(_paths.Paths.ProgramDataDirectory);
			dto.StorageAclCompliant = status.Supported ? status.Compliant : null;
			dto.StorageAclMessage = status.Message;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
		{
			Degrade(dto, "StorageAcl: " + ex.GetType().Name + " - " + ex.Message);
		}
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

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
		catch (PathTooLongException)
		{
			return path;
		}
	}
}
