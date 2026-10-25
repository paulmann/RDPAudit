/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPreviewService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Dry run of the information-density retention pass for the Database tab. It produces its
//          answer through InformationDensityRetentionEngine - the very component the real worker
//          uses - so the trigger it reports, the per-code row counts it predicts and the step order
//          it lists are exactly what a subsequent real pass deletes on the same state. It never
//          deletes a row, never writes a ledger entry and never mutates configuration; the only
//          thing it writes is nothing at all.
// Depends: InformationDensityRetentionEngine, RetentionPreviewDto, RetentionSkipReason
// Extends: Add a field to RetentionPreviewDto and populate it here when the preview must explain
//          a new planning input.

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;

namespace RdpAudit.Service.Services;

/// <summary>Produces the retention dry run the Database tab shows before anything is deleted.</summary>
public sealed class RetentionPreviewService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Explains why no byte figure accompanies the preview.</summary>
	private const string ReclaimedBytesNote =
		"Not estimated. A SQLite delete returns pages to the file's own freelist; the file only shrinks "
		+ "after an incremental vacuum or a VACUUM, and the page-granular yield depends on page occupancy. "
		+ "The exact figure that is known is the number of rows the pass would remove.";

	private readonly InformationDensityRetentionEngine _engine;
	private readonly ILogger<RetentionPreviewService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service; the engine is built from the same collaborators the worker uses,
	/// so both see identical rules and identical option snapshots.</summary>
	public RetentionPreviewService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<RetentionPreviewService> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_engine = new InformationDensityRetentionEngine(factory, options);
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Builds the dry run. A failure to examine the store returns a DTO whose status is
	/// <see cref="IpcResultStatus.Unavailable"/> rather than throwing, so the caller always gets an
	/// explanation.</summary>
	public async Task<RetentionPreviewDto> PreviewAsync(CancellationToken cancellationToken)
	{
		DateTime nowUtc = DateTime.UtcNow;
		try
		{
			RetentionEvaluation evaluation = await _engine.EvaluateForPreviewAsync(nowUtc, cancellationToken)
				.ConfigureAwait(false);
			return Build(evaluation);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Retention preview failed");
			return new RetentionPreviewDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = nowUtc,
				ReclaimedBytesNote = ReclaimedBytesNote,
				Message = "The store could not be examined; no preview is available. See the service log.",
			};
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static RetentionPreviewDto Build(RetentionEvaluation evaluation)
	{
		RetentionPlan plan = evaluation.Plan;
		Dictionary<string, RetentionSkipReason> prefiltered = BuildPrefilterMap(evaluation.Prefiltered);
		Dictionary<string, RetentionCodeState> states = BuildStateMap(evaluation.States);

		RetentionPreviewDto dto = new()
		{
			Status = IpcResultStatus.Success,
			PolicyEnabled = evaluation.PolicyEnabled,
			LegalHold = evaluation.LegalHold,
			Trigger = evaluation.Trigger,
			// A ceiling can be breached while a legal hold is in force, and naming which one is still
			// useful - but a real pass would not act, so TriggerWouldFire says so.
			TriggerWouldFire = evaluation.Trigger != EventDeletionTrigger.Unknown && !evaluation.LegalHold,
			WouldDeleteRows = plan.PlannedRows,
			EstimatedReclaimedBytes = null,
			ReclaimedBytesNote = ReclaimedBytesNote,
			RuleVersion = plan.RuleVersion,
			MinAgeCutoffUtc = evaluation.MinAgeCutoffUtc,
			TailKeepPerCode = evaluation.TailKeepPerCode,
			MaxRowsPerPass = evaluation.MaxRowsPerPass,
			QueriedUtc = evaluation.NowUtc,
		};

		// Codes that would be compressed, in the exact order the pass would process them. The plan's
		// step list is the pass's own work list, so this ordering cannot drift from the execution.
		foreach (RetentionPlanStep step in plan.Steps)
		{
			dto.Codes.Add(new RetentionPreviewCodeDto
			{
				EventId = step.Key.EventId,
				Channel = step.Key.Channel,
				IpHex = step.Key.IpHex,
				PerIp = step.Key.IpBinary16 is not null,
				Count = CountOf(states, step.Key),
				EligibleInteriorRows = DensityOf(states, step.Key),
				PlannedRows = step.Rows,
				SkipReason = null,
				Explanation = "Would be compressed: the oldest interior rows go first, densest codes first.",
				OldestRetainedUtc = step.AnchorTimeUtc,
				OldestDeletedUtc = step.WindowStartUtc,
				NewestDeletedUtc = step.WindowEndUtc,
			});
		}

		// Codes the planner rejected, in the planner's own order, with the reason it recorded.
		foreach (RetentionPlanSkip skip in plan.Skipped)
		{
			string key = ComposeKey(skip.Key);
			bool shortCircuited = prefiltered.TryGetValue(key, out RetentionSkipReason prefilterReason);
			RetentionSkipReason reason = shortCircuited ? prefilterReason : skip.Reason;
			dto.Codes.Add(new RetentionPreviewCodeDto
			{
				EventId = skip.Key.EventId,
				Channel = skip.Key.Channel,
				IpHex = skip.Key.IpHex,
				PerIp = skip.Key.IpBinary16 is not null,
				Count = CountOf(states, skip.Key),
				EligibleInteriorRows = shortCircuited ? 0L : DensityOf(states, skip.Key),
				PlannedRows = 0,
				SkipReason = reason,
				Explanation = Explain(reason),
				// The scan short-circuited before measuring the anchor, so its timestamp is unknown;
				// the placeholder is never presented as evidence.
				OldestRetainedUtc = shortCircuited ? null : AnchorOf(states, skip.Key),
				OldestDeletedUtc = null,
				NewestDeletedUtc = null,
			});
		}

		// Codes that are protected by policy. The eligibility scan excludes them, so they never reach
		// the planner; the preview names them explicitly, because "which codes are protected and why"
		// is part of what a dry run owes the operator.
		foreach (RetentionProtectedCode protectedCode in evaluation.ProtectedCodes)
		{
			dto.Codes.Add(new RetentionPreviewCodeDto
			{
				EventId = protectedCode.Key.EventId,
				Channel = protectedCode.Key.Channel,
				IpHex = protectedCode.Key.IpHex,
				PerIp = protectedCode.Key.IpBinary16 is not null,
				Count = protectedCode.TotalRows,
				EligibleInteriorRows = 0,
				PlannedRows = 0,
				SkipReason = RetentionSkipReason.ProtectedEventCode,
				Explanation = Explain(RetentionSkipReason.ProtectedEventCode),
				OldestRetainedUtc = null,
				OldestDeletedUtc = null,
				NewestDeletedUtc = null,
			});
		}

		for (int index = 0; index < plan.Steps.Count; index++)
		{
			RetentionPlanStep step = plan.Steps[index];
			dto.Steps.Add(new RetentionPreviewStepDto
			{
				Order = index,
				EventId = step.Key.EventId,
				Channel = step.Key.Channel,
				IpHex = step.Key.IpHex,
				Rows = step.Rows,
				AnchorRowId = step.AnchorRowId,
				AnchorTimeUtc = step.AnchorTimeUtc,
				TailBoundaryRowId = step.TailBoundaryRowId,
				TailBoundaryTimeUtc = step.TailBoundaryTimeUtc,
				WindowStartUtc = step.WindowStartUtc,
				WindowEndUtc = step.WindowEndUtc,
			});
		}

		// Every code entry that carries no step is, by construction, a code the preview reports as
		// left alone - so the count below can never disagree with the Codes list.
		dto.SkippedCodeCount = dto.Codes.Count - plan.Steps.Count;
		dto.Message = Describe(dto, plan.Steps.Count);
		return dto;
	}

	/// <summary>
	/// Operator-facing summary of the dry run. Written to be read aloud: it states the trigger that
	/// would fire, the rows that would go and the codes that are protected, so a dry run is never a
	/// silent "0".
	/// </summary>
	private static string Describe(RetentionPreviewDto dto, int stepCount)
	{
		if (!dto.PolicyEnabled)
		{
			return "Information-density retention is disabled, so a pass would delete nothing.";
		}

		if (dto.LegalHold)
		{
			return "Information-density retention is enabled but a legal hold is in force: every pressure rule is inert and a pass would delete nothing.";
		}

		string trigger = dto.TriggerWouldFire
			? "trigger " + dto.Trigger.ToString()
			: "no trigger (the store is inside every configured ceiling)";
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0}; a pass would delete {1} row(s) across {2} code(s) and would leave {3} code(s) untouched.",
			trigger,
			dto.WouldDeleteRows,
			stepCount,
			dto.SkippedCodeCount);
	}

	private static string Explain(RetentionSkipReason reason)
		=> reason switch
		{
			RetentionSkipReason.LegalHold =>
				"A legal hold is in force, so no pressure rule may delete this code.",
			RetentionSkipReason.ProtectedEventCode =>
				"The event code is in ProtectedEventIds and is never a pressure candidate.",
			RetentionSkipReason.BelowCandidateMinRows =>
				"The code holds fewer eligible interior rows than CandidateMinRows inside the deletion window.",
			RetentionSkipReason.NoInteriorRows =>
				"Everything the code holds is its anchor, its protected tail or fresh evidence, so it has no interior.",
			RetentionSkipReason.BudgetExhausted =>
				"The per-pass row budget was already spent by denser codes, so this code is deferred to the next pass.",
			_ => "The code produced no deletion step.",
		};

	// ── Snapshot lookups ─────────────────────────────────────────────────────────

	/// <summary>
	/// Identity of a code for dictionary lookups. <c>RetentionCodeKey</c> is a record whose
	/// <c>byte[]</c> member compares by reference, so the composed string form (which encodes the
	/// address content through <c>IpHex</c>) is the only safe lookup key here.
	/// </summary>
	private static string ComposeKey(RetentionCodeKey key)
		=> key.EventId.ToString(CultureInfo.InvariantCulture) + "|" + key.Channel + "|" + key.IpHex;

	private static Dictionary<string, RetentionSkipReason> BuildPrefilterMap(List<RetentionPrefilteredCode> prefiltered)
	{
		Dictionary<string, RetentionSkipReason> map = new(prefiltered.Count, StringComparer.Ordinal);
		foreach (RetentionPrefilteredCode code in prefiltered)
		{
			map[ComposeKey(code.Key)] = code.Reason;
		}

		return map;
	}

	private static Dictionary<string, RetentionCodeState> BuildStateMap(List<RetentionCodeState> states)
	{
		Dictionary<string, RetentionCodeState> map = new(states.Count, StringComparer.Ordinal);
		foreach (RetentionCodeState state in states)
		{
			map[ComposeKey(state.Key)] = state;
		}

		return map;
	}

	private static long CountOf(Dictionary<string, RetentionCodeState> states, RetentionCodeKey key)
		=> states.TryGetValue(ComposeKey(key), out RetentionCodeState? state) ? state.TotalRows : 0L;

	private static long DensityOf(Dictionary<string, RetentionCodeState> states, RetentionCodeKey key)
		=> states.TryGetValue(ComposeKey(key), out RetentionCodeState? state) ? state.EligibleInteriorRows : 0L;

	/// <summary>UTC timestamp of a code's anchor, measured by the scan.</summary>
	private static DateTime AnchorOf(Dictionary<string, RetentionCodeState> states, RetentionCodeKey key)
		=> states.TryGetValue(ComposeKey(key), out RetentionCodeState? state)
			? state.Anchor.TimeUtc
			: DateTime.UnixEpoch;
}
