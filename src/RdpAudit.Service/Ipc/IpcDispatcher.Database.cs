// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.Database.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: IPC handlers for the Database tab's server surface (ordinals 80-94). GetDatabaseOverview,
//          GetRetentionPolicy, PreviewRetention, GetDeletionLedger, ListDatabaseBackups,
//          VerifyDatabaseBackup, GetShardInventory and CompactDatabase are strictly read-only and delegate
//          to a data service; RunDatabaseMaintenance is read-safe (its action set contains no destructive
//          operation); SaveRetentionPolicy, CreateDatabaseBackup, RestoreDatabaseBackupToDirectory,
//          SaveShardingPolicy, CollectShardGarbage and PurgeBySubject are the mutating commands here and
//          are the only ones that write an OperationLog row - carrying what changed and the invoking
//          Windows identity. CollectShardGarbage and PurgeBySubject both default to a dry run, so an
//          omitted payload deletes nothing. CompactDatabase always answers Refused - the offline-only
//          compaction contract - and records the refusal as a Warning audit row, because an operator asked
//          for a destructive operation and the answer belongs in the trail.
//          No handler in this file touches SQLite or the shard tree itself: every query is bounded and
//          owned by the service that answers it, so a slow store degrades its own section instead of
//          the dispatcher.
// Extends: IpcDispatcher (partial)
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Ipc;

/// <summary>Database-tab IPC handlers of the dispatcher (commands 80-90).</summary>
public sealed partial class IpcDispatcher
{
	// ── Read-only handlers ───────────────────────────────────────────────────────

	/// <summary>Returns the sectioned evidence-store overview. A host that did not register the
	/// service answers with a typed Unavailable instead of throwing, so a stale Configurator can
	/// always render an explanation.</summary>
	private async Task<DatabaseOverviewDto> GetDatabaseOverviewAsync(CancellationToken ct)
	{
		if (_databaseOverview is null)
		{
			return new DatabaseOverviewDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The database overview service is not available in this host.",
			};
		}

		return await _databaseOverview.BuildAsync(ct).ConfigureAwait(false);
	}

	/// <summary>Returns the effective retention policy: global windows, per-event overrides and the
	/// information-density block with configured and clamped values.</summary>
	private async Task<RetentionPolicyDto> GetRetentionPolicyAsync(CancellationToken ct)
	{
		if (_retentionPolicy is null)
		{
			return new RetentionPolicyDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The retention policy service is not available in this host.",
			};
		}

		return await _retentionPolicy.GetAsync(ct).ConfigureAwait(false);
	}

	/// <summary>Dry-runs the information-density retention pass. Composed by the same engine the
	/// background worker executes, so the predicted per-code counts equal what a real pass deletes.</summary>
	private async Task<RetentionPreviewDto> PreviewRetentionAsync(CancellationToken ct)
	{
		if (_retentionPreview is null)
		{
			return new RetentionPreviewDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The retention preview service is not available in this host.",
			};
		}

		return await _retentionPreview.PreviewAsync(ct).ConfigureAwait(false);
	}

	/// <summary>Returns one page of the append-only deletion ledger, newest first. An absent payload
	/// means "first page, no filters"; a malformed one is refused as invalid input.</summary>
	private async Task<DeletionLedgerPageDto> GetDeletionLedgerAsync(string? payload, CancellationToken ct)
	{
		if (_deletionLedger is null)
		{
			return new DeletionLedgerPageDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The deletion ledger service is not available in this host.",
			};
		}

		DeletionLedgerQueryRequest request = string.IsNullOrWhiteSpace(payload)
			? new DeletionLedgerQueryRequest()
			: ParsePayload<DeletionLedgerQueryRequest>(payload, "GetDeletionLedger");
		return await _deletionLedger.QueryAsync(request, ct).ConfigureAwait(false);
	}

	/// <summary>Returns the bounded shard-tree inventory cross-referenced with the per-IP summaries.
	/// Read-only: it never writes, moves, quarantines or deletes a shard file, so a client polling
	/// the inventory cannot degrade the tree.</summary>
	private async Task<ShardInventoryDto> GetShardInventoryAsync(CancellationToken ct)
	{
		if (_shardInventory is null)
		{
			return new ShardInventoryDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The shard inventory service is not available in this host.",
			};
		}

		return await _shardInventory.BuildAsync(ct).ConfigureAwait(false);
	}

	/// <summary>Writes the whole shard capacity policy. The service validates and clamps the request in
	/// full before anything is written, so an invalid request leaves no partial change; on success it
	/// writes one OperationLog row carrying the invoking identity and the old and new policy, and the
	/// live options monitor picks the new document up without a service restart.</summary>
	private async Task<ShardingPolicyDto> SaveShardingPolicyAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_shardingPolicy is null)
		{
			throw new IpcException("SaveShardingPolicy is not available in this host.");
		}

		ShardingPolicyMutationRequest request = ParsePayload<ShardingPolicyMutationRequest>(payload, "SaveShardingPolicy");
		return await _shardingPolicy.SaveAsync(request, ResolveInvokedBy(callerIdentity), ct).ConfigureAwait(false);
	}

	/// <summary>Runs one orphan-shard collection pass. <c>DryRun=true</c> deletes nothing and returns the
	/// candidate list; an apply pass re-validates every candidate against the live summary table, the
	/// live writer pool and the grace period, and audits every removed file with its own OperationLog
	/// row.</summary>
	private async Task<ShardGarbageCollectionReportDto> CollectShardGarbageAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_shardGarbageCollector is null)
		{
			throw new IpcException("CollectShardGarbage is not available in this host.");
		}

		CollectShardGarbageRequest request = string.IsNullOrWhiteSpace(payload)
			? new CollectShardGarbageRequest()
			: ParsePayload<CollectShardGarbageRequest>(payload, "CollectShardGarbage");
		return await _shardGarbageCollector.CollectAsync(request, ResolveInvokedBy(callerIdentity), ct).ConfigureAwait(false);
	}

	/// <summary>Runs one read-safe maintenance action named by the request's kind. The service-side
	/// validator refuses any kind outside the defined set - a full VACUUM does not exist in this
	/// surface, so a hand-crafted payload cannot smuggle one in - and the report names what ran,
	/// what it returned and how long it took.</summary>
	private async Task<DatabaseMaintenanceReportDto> RunDatabaseMaintenanceAsync(string? payload, CancellationToken ct)
	{
		if (_databaseMaintenance is null)
		{
			return new DatabaseMaintenanceReportDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The database maintenance service is not available in this host.",
			};
		}

		DatabaseMaintenanceRequest request = string.IsNullOrWhiteSpace(payload)
			? new DatabaseMaintenanceRequest()
			: ParsePayload<DatabaseMaintenanceRequest>(payload, "RunDatabaseMaintenance");
		return await _databaseMaintenance.RunAsync(request, ct).ConfigureAwait(false);
	}

	// ── Read-only snapshot handlers ──────────────────────────────────────────────

	/// <summary>Returns the newest-first snapshot inventory. Read-only: it never creates, verifies or
	/// removes a snapshot, so a client polling the list cannot degrade the store.</summary>
	private async Task<DatabaseBackupListDto> ListDatabaseBackupsAsync(CancellationToken ct)
	{
		if (_databaseBackups is null)
		{
			return new DatabaseBackupListDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The database backup service is not available in this host.",
			};
		}

		return await _databaseBackups.ListAsync(ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Verifies one snapshot, or the newest when the request names none. The migrations of the running
	/// binaries are supplied so the check can refuse a snapshot whose schema is ahead of this build -
	/// restoring that snapshot would install a downgrade and the next start would refuse it anyway.
	/// </summary>
	private async Task<DatabaseBackupVerificationDto> VerifyDatabaseBackupAsync(string? payload, CancellationToken ct)
	{
		if (_databaseBackups is null)
		{
			return new DatabaseBackupVerificationDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Message = "The database backup service is not available in this host.",
			};
		}

		VerifyDatabaseBackupRequest request = string.IsNullOrWhiteSpace(payload)
			? new VerifyDatabaseBackupRequest()
			: ParsePayload<VerifyDatabaseBackupRequest>(payload, "VerifyDatabaseBackup");
		IReadOnlyList<string> knownMigrations = await GetKnownMigrationsAsync(ct).ConfigureAwait(false);
		return await _databaseBackups.VerifyAsync(request.Name, knownMigrations, ct).ConfigureAwait(false);
	}

	// ── Mutating handler ─────────────────────────────────────────────────────────

	/// <summary>
	/// Saves the retention policy. The request is validated and clamped in full before any write; the
	/// per-event overrides are staged inside a transaction that is committed only after the settings
	/// document has been written, so an invalid or unwritable request changes nothing. The single
	/// audited mutation of the Database surface.
	/// </summary>
	private async Task<RetentionPolicyDto> SaveRetentionPolicyAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_retentionPolicy is null)
		{
			throw new IpcException("SaveRetentionPolicy is not available in this host.");
		}

		RetentionPolicyMutationRequest request = ParsePayload<RetentionPolicyMutationRequest>(
			payload,
			"SaveRetentionPolicy");
		return await _retentionPolicy.SaveAsync(request, ResolveInvokedBy(callerIdentity), ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Creates one database snapshot and audits it. Refused - without an audit row, because nothing
	/// happened - when the snapshot feature is switched off or the snapshot itself could not be taken;
	/// on success the OperationLog entry carries the invoking identity, how many snapshots existed
	/// before and after, and the absolute path of the artifact.
	/// </summary>
	private async Task<DatabaseBackupCreationDto> CreateDatabaseBackupAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_databaseBackups is null)
		{
			throw new IpcException("CreateDatabaseBackup is not available in this host.");
		}

		CreateDatabaseBackupRequest request = string.IsNullOrWhiteSpace(payload)
			? new CreateDatabaseBackupRequest()
			: ParsePayload<CreateDatabaseBackupRequest>(payload, "CreateDatabaseBackup");

		StorageOptions storage = _options.CurrentValue.Storage;
		BackupOptions backup = storage.Backup;
		if (!backup.Enabled)
		{
			return new DatabaseBackupCreationDto
			{
				Status = IpcResultStatus.Refused,
				QueriedUtc = DateTime.UtcNow,
				Kind = DatabaseBackupKind.Manual,
				Message = "Database snapshots are disabled in this deployment. Set RdpAudit:Storage:Backup:Enabled to true in appsettings.json and restart the service to allow operators to take snapshots. (Backup.PreMigrationBackupEnabled is independent of this switch and still protects schema upgrades.)",
			};
		}

		bool includeShards = request.IncludeShards ?? backup.IncludeShards;
		string databasePath = Path.GetFullPath(storage.ResolveDatabasePath());
		string invokedBy = ResolveInvokedBy(callerIdentity);
		int snapshotsBefore = _databaseBackups.GetStatus(ct).SnapshotCount;

		DatabaseBackupCreationDto result = await _databaseBackups.CreateSnapshotAsync(
			databasePath,
			includeShards,
			DatabaseBackupKind.Manual,
			ct).ConfigureAwait(false);

		if (result.Status != IpcResultStatus.Success)
		{
			// A refused snapshot changed nothing on disk, so there is nothing to audit beyond the
			// service log already written by the backup service.
			return result;
		}

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"CreateDatabaseBackup completed by {0}; snapshotsBefore={1}; snapshotsAfter={2}; snapshot={3}; path={4}; bytes={5}; sha256={6}; shardsIncluded={7}; retentionDeleted={8}",
			invokedBy,
			snapshotsBefore,
			result.SnapshotCountAfter,
			result.SnapshotName,
			result.SnapshotDirectory,
			result.DatabaseBytes,
			result.DatabaseSha256,
			result.ShardsIncluded,
			result.RetentionDeleted.Count);

		string detailsJson = JsonSerializer.Serialize(
			new
			{
				invokedBy,
				snapshotsBefore,
				snapshotsAfter = result.SnapshotCountAfter,
				snapshotName = result.SnapshotName,
				snapshotDirectory = result.SnapshotDirectory,
				databaseBytes = result.DatabaseBytes,
				databaseSha256 = result.DatabaseSha256,
				shardsIncluded = result.ShardsIncluded,
				retentionDeleted = result.RetentionDeleted,
				retentionSkipped = result.RetentionSkipped,
			},
			JsonOptions.Default);

		bool audited = await WriteDatabaseAuditAsync("CreateDatabaseBackup", invokedBy, message, detailsJson, ct).ConfigureAwait(false);
		if (!audited)
		{
			// The snapshot is durable; failing to record it is a compliance problem, so say so rather
			// than returning a clean success.
			result.Status = IpcResultStatus.Unavailable;
			result.Message = (result.Message ?? string.Empty)
				+ " The snapshot was written, but the audit entry could not be written. See the service log.";
		}

		return result;
	}

	/// <summary>
	/// Restores one snapshot into an operator-chosen scratch directory. The snapshot is verified
	/// before a byte is written and the live store is never touched, so this is the safe restore
	/// path; replacing the live database is the Configurator's DatabaseRestoreService flow, which
	/// stops the service first and stays out of IPC. The target directory is validated (absolute,
	/// well-formed, not a drive root), and the outcome is audited with the invoking identity because
	/// the command writes files to disk at an operator-supplied location.
	/// </summary>
	/// <summary>Refuses a restore target inside a system directory or an autostart folder.</summary>
	/// <remarks>
	/// The restore writes its files with the service's identity, so the target is not a purely
	/// cosmetic choice: a snapshot copied next to system binaries, or into a Startup folder, would be
	/// a way to place content where Windows executes it. Both the path and the configured roots go
	/// through <see cref="Path.GetFullPath(string)"/>, so a trailing separator, a relative segment or a
	/// different casing cannot slip past the comparison.
	/// </remarks>
	private static string? DescribeForbiddenRestoreTarget(string target)
	{
		foreach ((string root, string label) in ForbiddenRestoreRoots())
		{
			if (string.IsNullOrWhiteSpace(root))
			{
				continue;
			}

			string canonicalRoot;
			try
			{
				canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
			}
			catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
			{
				continue;
			}

			if (IsSamePathOrBelow(target, canonicalRoot))
			{
				return "The restore target is inside " + label + " (" + canonicalRoot
					+ "). Choose a scratch directory that is not a system or autostart location.";
			}
		}

		return null;
	}

	/// <summary>The directories a restore target must stay out of, with a label for the refusal.</summary>
	private static IEnumerable<(string Root, string Label)> ForbiddenRestoreRoots()
	{
		yield return (Environment.GetFolderPath(Environment.SpecialFolder.Windows), "the Windows directory");
		yield return (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Program Files");
		yield return (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Program Files (x86)");
		yield return (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "the Startup folder");
		yield return (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "the shared Startup folder");
	}

	/// <summary>True when the candidate is the root itself or lies underneath it.</summary>
	private static bool IsSamePathOrBelow(string candidate, string root)
	{
		if (string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		return candidate.Length > root.Length
			&& candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase)
			&& (candidate[root.Length] == Path.DirectorySeparatorChar
				|| candidate[root.Length] == Path.AltDirectorySeparatorChar);
	}

	private async Task<DatabaseBackupRestoreReportDto> RestoreDatabaseBackupToDirectoryAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_databaseBackups is null)
		{
			throw new IpcException("RestoreDatabaseBackupToDirectory is not available in this host.");
		}

		RestoreDatabaseBackupToDirectoryRequest request = ParsePayload<RestoreDatabaseBackupToDirectoryRequest>(
			payload,
			"RestoreDatabaseBackupToDirectory");

		// Validate the target before the service resolves anything, so a malformed or hostile path is
		// refused with a specific reason instead of surfacing as a filesystem exception mid-copy.
		string target;
		try
		{
			target = Path.GetFullPath(request.TargetDirectory?.Trim() ?? string.Empty);
		}
		catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
		{
			return new DatabaseBackupRestoreReportDto
			{
				Status = IpcResultStatus.InvalidRequest,
				QueriedUtc = DateTime.UtcNow,
				SnapshotName = request.Name ?? string.Empty,
				Message = "The restore target directory is not a usable path: " + ex.Message,
			};
		}

		if (!Path.IsPathRooted(target) || string.Equals(Path.GetPathRoot(target), target, StringComparison.OrdinalIgnoreCase))
		{
			return new DatabaseBackupRestoreReportDto
			{
				Status = IpcResultStatus.InvalidRequest,
				QueriedUtc = DateTime.UtcNow,
				SnapshotName = request.Name ?? string.Empty,
				Message = "The restore target must be an absolute subdirectory, not a drive root.",
			};
		}

		string? forbiddenTarget = DescribeForbiddenRestoreTarget(target);
		if (forbiddenTarget is not null)
		{
			return new DatabaseBackupRestoreReportDto
			{
				Status = IpcResultStatus.InvalidRequest,
				QueriedUtc = DateTime.UtcNow,
				SnapshotName = request.Name ?? string.Empty,
				Message = forbiddenTarget,
			};
		}

		string invokedBy = ResolveInvokedBy(callerIdentity);
		IReadOnlyList<string> knownMigrations = await GetKnownMigrationsAsync(ct).ConfigureAwait(false);
		DatabaseBackupRestoreReportDto report = await _databaseBackups.RestoreToDirectoryAsync(
			request.Name ?? string.Empty,
			target,
			knownMigrations,
			ct).ConfigureAwait(false);

		if (report.Status != IpcResultStatus.Success)
		{
			// A refused restore copied nothing, so there is nothing to audit beyond the service log.
			return report;
		}

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"RestoreDatabaseBackupToDirectory by {0}; status={1}; snapshot={2}; target={3}; bytesCopied={4}",
			invokedBy,
			report.Status,
			report.SnapshotName,
			report.TargetDatabasePath ?? target,
			report.DatabaseBytesCopied);

		string detailsJson = JsonSerializer.Serialize(
			new
			{
				invokedBy,
				status = report.Status.ToString(),
				snapshotName = report.SnapshotName,
				targetDirectory = target,
				targetDatabasePath = report.TargetDatabasePath,
				databaseBytesCopied = report.DatabaseBytesCopied,
				shardsRestored = report.ShardsRestored,
				shardFilesRestored = report.ShardFilesRestored,
			},
			JsonOptions.Default);

		await WriteDatabaseAuditAsync("RestoreDatabaseBackupToDirectory", invokedBy, message, detailsJson, ct).ConfigureAwait(false);
		return report;
	}

	// ── Stage 5 handlers: offline-compaction refusal and subject purge ───────────

	/// <summary>
	/// Answers a compaction request. The answer is a refusal, and it is the contract rather than a
	/// limitation: a full VACUUM rewrites the whole file and can hold the writer lock for minutes, and a
	/// service that answers an IPC call is by definition running. The refusal still carries the store's
	/// read-only page accounting, so the operator can judge whether an offline compaction is worth
	/// stopping the service for. The refusal is audited (Warning) with the invoking identity because an
	/// operator asked for a destructive operation and the record of the answer is part of the trail.
	/// </summary>
	private async Task<DatabaseCompactionDto> CompactDatabaseAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_databaseCompaction is null)
		{
			return new DatabaseCompactionDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				Refused = true,
				Message = "The database compaction service is not available in this host.",
			};
		}

		DatabaseCompactionRequest request = string.IsNullOrWhiteSpace(payload)
			? new DatabaseCompactionRequest()
			: ParsePayload<DatabaseCompactionRequest>(payload, "CompactDatabase");
		DatabaseCompactionDto report = await _databaseCompaction.RunAsync(request, ct).ConfigureAwait(false);

		string invokedBy = ResolveInvokedBy(callerIdentity);
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"CompactDatabase refused by {0}; database={1}; reclaimableBytes={2}; freelistPages={3}",
			invokedBy,
			report.DatabasePath,
			report.ReclaimableBytes,
			report.FreeListPages);
		string detailsJson = JsonSerializer.Serialize(
			new
			{
				invokedBy,
				refused = report.Refused,
				offlineRequested = request.OfflineRequested,
				databasePath = report.DatabasePath,
				databaseBytes = report.DatabaseBytes,
				reclaimableBytes = report.ReclaimableBytes,
				freelistPages = report.FreeListPages,
			},
			JsonOptions.Default);
		await WriteDatabaseRefusalAuditAsync("CompactDatabase", invokedBy, message, detailsJson, ct)
			.ConfigureAwait(false);

		return report;
	}

	/// <summary>
	/// Previews or applies a subject purge. An omitted payload is the strictest possible interpretation -
	/// a dry run with no subject - and is therefore an invalid request rather than a full wipe. The typed
	/// phrase and the legal hold are both re-validated inside the service, so a client that skips its own
	/// confirmation dialog cannot delete anything; an applied pass is audited with the invoking identity,
	/// the subject, the window and the per-table counts.
	/// </summary>
	private async Task<PurgeBySubjectReportDto> PurgeBySubjectAsync(
		string? payload,
		string? callerIdentity,
		CancellationToken ct)
	{
		if (_purgeBySubject is null)
		{
			return new PurgeBySubjectReportDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				DryRun = true,
				Message = "The subject-purge service is not available in this host.",
			};
		}

		PurgeBySubjectRequest request = string.IsNullOrWhiteSpace(payload)
			? new PurgeBySubjectRequest()
			: ParsePayload<PurgeBySubjectRequest>(payload, "PurgeBySubject");
		string invokedBy = ResolveInvokedBy(callerIdentity);
		PurgeBySubjectReportDto report = await _purgeBySubject
			.RunAsync(request, invokedBy, ct)
			.ConfigureAwait(false);

		if (!report.Applied)
		{
			// A dry run and a refusal both changed nothing, so there is nothing to account for beyond the
			// service log.
			return report;
		}

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"PurgeBySubject applied by {0}; kind={1}; subject={2}; window={3}..{4}; matched={5}; deleted={6}; "
				+ "ledgerEntries={7}",
			invokedBy,
			report.Kind,
			report.Subject,
			report.WindowStartUtc,
			report.WindowEndUtc,
			report.TotalRowsMatched,
			report.TotalRowsDeleted,
			report.LedgerEntriesWritten);
		string detailsJson = JsonSerializer.Serialize(
			new
			{
				invokedBy,
				kind = report.Kind.ToString(),
				subject = report.Subject,
				windowStartUtc = report.WindowStartUtc,
				windowEndUtc = report.WindowEndUtc,
				totalRowsMatched = report.TotalRowsMatched,
				totalRowsDeleted = report.TotalRowsDeleted,
				ledgerEntriesWritten = report.LedgerEntriesWritten,
				ledgerChainHead = report.LedgerChainHead,
				tables = report.Tables.Select(table => new
				{
					table = table.Table,
					rowsMatched = table.RowsMatched,
					rowsDeleted = table.RowsDeleted,
					ledgerWritten = table.LedgerWritten,
				}),
				preserved = report.Preserved,
			},
			JsonOptions.Default);

		bool audited = await WriteDatabaseAuditAsync("PurgeBySubject", invokedBy, message, detailsJson, ct)
			.ConfigureAwait(false);
		if (!audited)
		{
			report.Status = IpcResultStatus.Unavailable;
			report.Message = report.Message
				+ " The purge ran, but the audit entry could not be written. See the service log.";
		}

		return report;
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	/// <summary>Migrations the running binaries define. EF reads them from the assembly's migration
	/// types, so this is an in-memory enumeration and never touches the database.</summary>
	private async Task<IReadOnlyList<string>> GetKnownMigrationsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<string> known = [];
		foreach (string migration in db.Database.GetMigrations())
		{
			known.Add(migration);
		}

		return known;
	}

	/// <summary>Writes the SOC2 audit row for a database-surface mutation. Returns false when the row
	/// could not be written, so the caller can report an unaudited action instead of a clean success.</summary>
	private async Task<bool> WriteDatabaseAuditAsync(
		string operation,
		string invokedBy,
		string message,
		string detailsJson,
		CancellationToken ct)
		=> await WriteDatabaseAuditRowAsync(
			OperationLogSeverity.Information,
			operation,
			invokedBy,
			message,
			detailsJson,
			ct).ConfigureAwait(false);

	/// <summary>Writes the audit row for a destructive database action the service REFUSED. It is recorded
	/// as a Warning rather than dropped: an operator asked for something the product forbids, and the fact
	/// that it was asked for - and answered - belongs in the trail next to the actions that ran.</summary>
	private async Task<bool> WriteDatabaseRefusalAuditAsync(
		string operation,
		string invokedBy,
		string message,
		string detailsJson,
		CancellationToken ct)
		=> await WriteDatabaseAuditRowAsync(
			OperationLogSeverity.Warning,
			operation,
			invokedBy,
			message,
			detailsJson,
			ct).ConfigureAwait(false);

	private async Task<bool> WriteDatabaseAuditRowAsync(
		OperationLogSeverity severity,
		string operation,
		string invokedBy,
		string message,
		string detailsJson,
		CancellationToken ct)
	{
		if (_opLog is null)
		{
			return false;
		}

		try
		{
			await _opLog.WriteAsync(
				new OperationLogEntry
				{
					Severity = severity,
					Source = "Database",
					Operation = operation,
					Message = message,
					DetailsJson = detailsJson,
					Actor = invokedBy,
				},
				ct).ConfigureAwait(false);
			return true;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Database {Operation} audit entry could not be written", operation);
			return false;
		}
	}

	// ── Caller identity ──────────────────────────────────────────────────────────

	/// <summary>
	/// Names the invoker for the audit trail. With a pipe-resolved identity the row says
	/// <c>Operator:&lt;account&gt;</c>; without one (in-process caller, or a pipe that could not
	/// report the peer) it says <c>Service:&lt;process account&gt;</c> rather than inventing an
	/// identity. The prefix is never omitted, so a reader can always tell a self-asserted operator
	/// action from one the service performed on its own initiative.
	/// </summary>
	private static string ResolveInvokedBy(string? callerIdentity)
		=> string.IsNullOrWhiteSpace(callerIdentity)
			? "Service:" + ResolveProcessIdentity()
			: "Operator:" + callerIdentity;

	private static string ResolveProcessIdentity()
	{
		try
		{
			if (OperatingSystem.IsWindows())
			{
				using System.Security.Principal.WindowsIdentity current =
					System.Security.Principal.WindowsIdentity.GetCurrent();
				return current.Name ?? "(unknown)";
			}
		}
		catch (Exception)
		{
			// Best effort - identity is observational.
		}

		return Environment.UserDomainName + "\\" + Environment.UserName;
	}
}
