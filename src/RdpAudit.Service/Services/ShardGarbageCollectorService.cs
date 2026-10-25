/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardGarbageCollectorService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Collects orphan shard files - .rdpshard artifacts no IpEventSummary row names any more -
//          once they have been untouched for at least the configured orphan grace period. Until this
//          stage those files were never reclaimable: actions\ grew monotonically and a retired source's
//          evidence stayed on disk forever.
//          Safety properties, in order of importance:
//          1. A dry run deletes nothing. It is the only way to see the candidate list before applying.
//          2. Every candidate is re-validated immediately before its deletion: it must still be
//             unreferenced (re-read from IpEventSummary with the inventory's own normalization), must
//             not be open in any live shard writer, must still be older than the grace period, and must
//             resolve inside the configured actions root.
//          3. A candidate whose last-write time cannot be read is never eligible: nothing is deleted on
//             a guess.
//          4. Every deletion writes its own OperationLog row naming the path, the bytes, the retained
//             records and the age, so a removal is auditable exactly.
//          5. The whole pass is bounded by MaxDeletionsPerRun, so one command can never mass-delete a
//             tree; the remainder is reported as a spent budget rather than silently skipped.
//          Deliberately NOT written to EventDeletionLedger: that ledger accounts for deleted event
//          ROWS by (EventCode, Scope, window) and requires fields a file removal cannot fill truthfully
//          - a shard carries no event code and no per-row window, and inventing them would make the
//          ledger lie. Shard-file removals are audited through OperationLog, and the per-shard eviction
//          accounting stays in IpEventSummary, exactly as the shard evidence model already defines it.
// Depends: ShardInventoryService, ShardingOptions, ShardIngestionSink, IOperationLogWriter
// Extends: Add a safety rule as a ShardGarbageDisposition member plus its check below; never delete a
//          file the pass cannot prove is unreferenced, old enough and closed.

using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Storage;

namespace RdpAudit.Service.Services;

/// <summary>Collects shard files that no summary row references and that are past the orphan grace
/// period.</summary>
public sealed class ShardGarbageCollectorService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Upper bound on the files one apply pass may delete. A collection pass is an explicit
	/// operator action on a small, rare set; the cap means a mistake or a hostile request cannot turn
	/// one command into a mass deletion, and the report says when it was reached.</summary>
	internal const int MaxDeletionsPerRun = 200;

	/// <summary>Logical OperationLog source for shard collection.</summary>
	internal const string OperationLogSource = "Sharding";

	/// <summary>Logical OperationLog operation name for one deleted shard file.</summary>
	internal const string OperationLogOperation = "CollectShardGarbage";

	private readonly ShardInventoryService _inventory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<ShardGarbageCollectorService> _logger;
	private readonly ShardIngestionSink? _sink;
	private readonly IOperationLogWriter? _operationLog;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the collector over the inventory, the live options monitor and the optional live
	/// shard sink (whose open-writer set is one of the deletion guards).</summary>
	public ShardGarbageCollectorService(
		ShardInventoryService inventory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardGarbageCollectorService> logger,
		ShardIngestionSink? sink = null,
		IOperationLogWriter? operationLog = null)
	{
		ArgumentNullException.ThrowIfNull(inventory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_inventory = inventory;
		_options = options;
		_logger = logger;
		_sink = sink;
		_operationLog = operationLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Runs one collection pass. With <see cref="CollectShardGarbageRequest.DryRun"/> nothing is
	/// deleted and the report lists every candidate with its disposition.</summary>
	public async Task<ShardGarbageCollectionReportDto> CollectAsync(
		CollectShardGarbageRequest request,
		string invokedBy,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(request);

		ShardingOptions sharding = _options.CurrentValue.Sharding;
		int graceDays = sharding.ResolveOrphanGraceDays();
		ShardInventoryDto inventory = await _inventory.BuildAsync(cancellationToken).ConfigureAwait(false);

		ShardGarbageCollectionReportDto report = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = inventory.QueriedUtc,
			DryRun = request.DryRun,
			ActionsRoot = inventory.ActionsRoot,
			OrphanGraceDays = graceDays,
			CandidateListTruncated = inventory.Summary.Truncated,
		};
		report.Warnings.AddRange(inventory.Warnings);

		if (string.IsNullOrWhiteSpace(inventory.ActionsRoot) || !Directory.Exists(inventory.ActionsRoot))
		{
			report.Status = IpcResultStatus.Unavailable;
			report.Message = "There is no shard tree to collect from; nothing was examined and nothing was deleted.";
			return report;
		}

		DateTime nowUtc = DateTime.UtcNow;
		List<ShardGarbageCandidateDto> candidates = BuildCandidates(inventory, nowUtc, graceDays);

		if (request.DryRun)
		{
			report.Candidates.AddRange(candidates);
			report.Message = Describe(report, eligible: CountEligible(candidates), applied: false);
			return report;
		}

		// Re-validated against the live database immediately before any deletion: the inventory's own
		// normalization is reused so the two views can never disagree about what a path means.
		HashSet<string> referencedNow = await _inventory.LoadReferencedPathSetAsync(cancellationToken)
			.ConfigureAwait(false);

		int deletions = 0;
		bool auditFailed = false;
		foreach (ShardGarbageCandidateDto candidate in candidates)
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (candidate.Disposition != ShardGarbageDisposition.Eligible)
			{
				report.Candidates.Add(candidate);
				continue;
			}

			if (referencedNow.Contains(candidate.RelativePath))
			{
				candidate.Disposition = ShardGarbageDisposition.BecameReferenced;
				candidate.Note = "An IpEventSummary row names this file again; it is live evidence and was kept.";
				report.Candidates.Add(candidate);
				continue;
			}

			if (_sink?.IsShardOpen(candidate.AbsolutePath) == true)
			{
				candidate.Disposition = ShardGarbageDisposition.OpenInWriter;
				candidate.Note = "A live shard writer holds this file open; it was kept.";
				report.Candidates.Add(candidate);
				continue;
			}

			if (deletions >= MaxDeletionsPerRun)
			{
				candidate.Disposition = ShardGarbageDisposition.DeletionBudgetSpent;
				candidate.Note = string.Format(
					CultureInfo.InvariantCulture,
					"The per-run deletion budget of {0} files is spent; run the collection again to continue.",
					MaxDeletionsPerRun);
				report.DeletionBudgetReached = true;
				report.Candidates.Add(candidate);
				continue;
			}

			// The file may have been written since the walk; re-read its age from the filesystem so a shard
			// that became active again is not removed.
			DateTime? lastWriteUtc = TryReadLastWriteUtc(candidate.AbsolutePath);
			if (lastWriteUtc is null)
			{
				candidate.Disposition = ShardGarbageDisposition.LastActivityUnknown;
				candidate.Note = "The file's last-write time disappeared before the delete; it was kept.";
				report.Candidates.Add(candidate);
				continue;
			}

			double ageDays = (nowUtc - lastWriteUtc.Value).TotalDays;
			if (ageDays < graceDays)
			{
				candidate.Disposition = ShardGarbageDisposition.YoungerThanGracePeriod;
				candidate.LastWriteUtc = lastWriteUtc;
				candidate.AgeDays = ageDays;
				candidate.Note = "The shard was written again while the pass was running; it was kept.";
				report.Candidates.Add(candidate);
				continue;
			}

			candidate.LastWriteUtc = lastWriteUtc;
			candidate.AgeDays = ageDays;

			if (!File.Exists(candidate.AbsolutePath))
			{
				candidate.Disposition = ShardGarbageDisposition.VanishedBeforeDeletion;
				candidate.Note = "The file was already gone when the delete ran; nothing was removed.";
				report.Candidates.Add(candidate);
				continue;
			}

			try
			{
				File.Delete(candidate.AbsolutePath);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				candidate.Disposition = ShardGarbageDisposition.DeletionFailed;
				candidate.Note = "The delete failed: " + ex.GetType().Name + ". Nothing was removed.";
				_logger.LogWarning(ex, "Orphan shard {ShardPath} could not be deleted", candidate.AbsolutePath);
				report.Candidates.Add(candidate);
				continue;
			}

			candidate.Disposition = ShardGarbageDisposition.Eligible;
			candidate.Note = "Deleted.";
			report.Candidates.Add(candidate);
			report.DeletedPaths.Add(candidate.RelativePath);
			deletions++;
			if (candidate.Bytes > 0)
			{
				report.DeletedBytes += candidate.Bytes;
			}

			if (candidate.Records > 0)
			{
				report.DeletedRecords += candidate.Records;
			}

			if (!await WriteAuditAsync(invokedBy, candidate, ageDays, cancellationToken).ConfigureAwait(false))
			{
				auditFailed = true;
			}
		}

		report.DeletedFileCount = report.DeletedPaths.Count;
		report.Message = Describe(report, CountEligible(candidates), applied: true);
		if (auditFailed)
		{
			report.Status = IpcResultStatus.Unavailable;
			report.Message = "Some shard files were deleted, but at least one audit entry could not be written. See the service log. "
				+ report.Message;
		}

		return report;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Turns the inventory's orphan entries into candidates and applies every rule that does not
	/// need a re-read: containment, the sink's open-writer set and the grace period.</summary>
	private List<ShardGarbageCandidateDto> BuildCandidates(ShardInventoryDto inventory, DateTime nowUtc, int graceDays)
	{
		List<ShardGarbageCandidateDto> candidates = new();
		foreach (ShardInventoryEntryDto entry in inventory.Entries)
		{
			if (!entry.IsOrphan)
			{
				continue;
			}

			ShardGarbageCandidateDto candidate = new()
			{
				RelativePath = entry.RelativePath,
				IpText = entry.IpText,
				IsSubnetAggregate = entry.IsSubnetAggregate,
				Bytes = entry.Bytes,
				Records = entry.Records,
				Evicted = entry.Evicted,
				LastWriteUtc = entry.LastWriteUtc,
			};

			if (entry.LastWriteUtc is DateTime lastWrite)
			{
				candidate.AgeDays = (nowUtc - lastWrite).TotalDays;
			}

			string absolute;
			try
			{
				absolute = Path.GetFullPath(Path.Combine(
					inventory.ActionsRoot,
					entry.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
			}
			catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
			{
				candidate.Disposition = ShardGarbageDisposition.OutsideActionsRoot;
				candidate.Note = "The relative path could not be resolved: " + ex.GetType().Name + ".";
				candidates.Add(candidate);
				continue;
			}

			candidate.AbsolutePath = absolute;
			if (!ShardPath.IsContainedUnder(inventory.ActionsRoot, absolute))
			{
				candidate.Disposition = ShardGarbageDisposition.OutsideActionsRoot;
				candidate.Note = "The resolved path is outside the actions root, so it is never deleted.";
				candidates.Add(candidate);
				continue;
			}

			if (_sink?.IsShardOpen(absolute) == true)
			{
				candidate.Disposition = ShardGarbageDisposition.OpenInWriter;
				candidate.Note = "A live shard writer holds this file open; it was kept.";
				candidates.Add(candidate);
				continue;
			}

			if (entry.LastWriteUtc is null)
			{
				candidate.Disposition = ShardGarbageDisposition.LastActivityUnknown;
				candidate.Note = "The file's last-write time could not be read, so its age is unknown; an unknown age is never old enough.";
				candidates.Add(candidate);
				continue;
			}

			if (candidate.AgeDays is double age && age < graceDays)
			{
				candidate.Disposition = ShardGarbageDisposition.YoungerThanGracePeriod;
				candidate.Note = string.Format(
					CultureInfo.InvariantCulture,
					"The shard was last written {0:0.##} day(s) ago, inside the {1}-day grace period.",
					age,
					graceDays);
				candidates.Add(candidate);
				continue;
			}

			candidate.Disposition = ShardGarbageDisposition.Eligible;
			candidates.Add(candidate);
		}

		return candidates;
	}

	private static long CountEligible(List<ShardGarbageCandidateDto> candidates)
	{
		long eligible = 0;
		foreach (ShardGarbageCandidateDto candidate in candidates)
		{
			if (candidate.Disposition == ShardGarbageDisposition.Eligible)
			{
				eligible++;
			}
		}

		return eligible;
	}

	private static DateTime? TryReadLastWriteUtc(string absolutePath)
	{
		try
		{
			FileInfo info = new(absolutePath);
			return info.Exists ? info.LastWriteTimeUtc : null;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
		{
			return null;
		}
	}

	private static string Describe(ShardGarbageCollectionReportDto report, long eligible, bool applied)
		=> string.Format(
			CultureInfo.InvariantCulture,
			"{0}: orphanCandidates={1} eligible={2} deleted={3} deletedBytes={4} deletedRecords={5} graceDays={6} budgetReached={7} truncated={8}",
			applied ? "Collection applied" : "Collection dry run",
			report.Candidates.Count,
			eligible,
			report.DeletedFileCount,
			report.DeletedBytes,
			report.DeletedRecords,
			report.OrphanGraceDays,
			report.DeletionBudgetReached,
			report.CandidateListTruncated);

	// ── Audit ────────────────────────────────────────────────────────────────────

	/// <summary>Writes one audit row for one deleted shard file, naming the path, its size, the records
	/// it retained and its age. Returns false when the row could not be written.</summary>
	private async Task<bool> WriteAuditAsync(
		string invokedBy,
		ShardGarbageCandidateDto candidate,
		double ageDays,
		CancellationToken cancellationToken)
	{
		if (_operationLog is null)
		{
			return true;
		}

		string actor = string.IsNullOrWhiteSpace(invokedBy) ? "Operator" : invokedBy;
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"Orphan shard {0} deleted by {1}; bytes={2} records={3} lastWriteUtc={4} ageDays={5:0.##}",
			candidate.RelativePath,
			actor,
			candidate.Bytes,
			candidate.Records,
			candidate.LastWriteUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "unknown",
			ageDays);
		string detailsJson = JsonSerializer.Serialize(new
		{
			invokedBy = actor,
			relativePath = candidate.RelativePath,
			absolutePath = candidate.AbsolutePath,
			bytes = candidate.Bytes,
			records = candidate.Records,
			evicted = candidate.Evicted,
			lastWriteUtc = candidate.LastWriteUtc,
			ageDays,
			isSubnetAggregate = candidate.IsSubnetAggregate,
		});

		try
		{
			await _operationLog.WriteAsync(new OperationLogEntry
			{
				Severity = OperationLogSeverity.Warning,
				Source = OperationLogSource,
				Operation = OperationLogOperation,
				Message = message,
				DetailsJson = detailsJson,
				Actor = actor,
			}, cancellationToken).ConfigureAwait(false);
			return true;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Orphan shard deletion audit entry could not be written");
			return false;
		}
	}
}
