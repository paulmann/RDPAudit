/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Schedules the information-density retention pass. On every tick it asks
//          InformationDensityRetentionEngine whether anything should happen and, only when a
//          pressure trigger fires, applies the plan the engine returns in short, cancellable,
//          transactional batches - one DELETE plus one ledger row per batch - so removed evidence
//          is accounted for exactly once even when a pass is interrupted. Anchors, protected tails,
//          fresh rows, protected event classes and rows referenced by alert evidence are never
//          candidates. Disabled policy means no work and no writes at all.
//          This worker owns scheduling, metrics and the operator-facing pass summary ONLY: the
//          trigger rules, the statistics snapshot, the planner call, the delete predicate and the
//          ledger pairing all live in InformationDensityRetentionEngine, so the dry-run preview
//          and the real pass can never disagree.
// Depends: InformationDensityRetentionEngine, RdpAuditOptions, IOperationLogWriter, ServiceMetrics
// Extends: Add a pressure trigger in InformationDensityRetentionEngine plus EventDeletionTrigger;
//          add operator-facing reporting here.

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Applies the optional information-density retention policy under explicit pressure triggers.</summary>
public sealed class InformationDensityRetentionWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);

	/// <summary>Logical OperationLog source for the pass summary.</summary>
	private const string OperationLogSource = "Retention";

	/// <summary>Logical OperationLog operation name for the pass summary.</summary>
	private const string OperationLogOperation = "InformationDensityRetention";

	/// <summary>Maximum length of an operation-log summary message.</summary>
	private const int OperationLogMessageLimit = 1800;

	private readonly InformationDensityRetentionEngine _engine;
	private readonly IOperationLogWriter _operationLog;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<InformationDensityRetentionWorker> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the worker with database, configuration, audit and diagnostic dependencies.</summary>
	public InformationDensityRetentionWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IOperationLogWriter operationLog,
		ServiceMetrics metrics,
		ILogger<InformationDensityRetentionWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(operationLog);
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(logger);
		_engine = new InformationDensityRetentionEngine(factory, options);
		_operationLog = operationLog;
		_metrics = metrics;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>The pass engine this worker drives. Exposed internally so an integration test can
	/// install <see cref="InformationDensityRetentionEngine.AfterBatchCommitted"/> and cancel a pass at
	/// a deterministic point; production neither reads nor replaces it.</summary>
	internal InformationDensityRetentionEngine Engine => _engine;

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(InformationDensityRetentionWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await RunOnceAsync(stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception exception)
				{
					_metrics.RecordInformationDensityError(exception.GetType().Name + ": " + exception.Message);
					_logger.LogError(
						exception,
						"Information-density retention pass failed; will retry after {Interval}",
						TickInterval);
				}

				await Task.Delay(TickInterval, stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(InformationDensityRetentionWorker));
		}
	}

	// ── Pass outcome ─────────────────────────────────────────────────────────────

	/// <summary>
	/// Outcome of one tick. Exposed internally so integration tests can assert the exact effect of a
	/// pass without inspecting private state.
	/// </summary>
	internal readonly record struct RetentionPassOutcome(
		bool PolicyDisabled,
		bool LegalHold,
		EventDeletionTrigger Trigger,
		long RowsDeleted,
		int StepsPlanned,
		int StepsCompleted,
		int CodesSkipped,
		long RowsProtectedByLinkedEvidence,
		bool WriterLockBudgetExhausted,
		bool Cancelled)
	{
		/// <summary>True when the pass deleted nothing at all.</summary>
		public bool DeletedNothing => RowsDeleted == 0;
	}

	/// <summary>Everything the pass-summary writer needs after the database scope has closed.</summary>
	private readonly record struct PassSummary(
		EventDeletionTrigger Trigger,
		long RowsDeleted,
		int StepsPlanned,
		int StepsCompleted,
		int CodesSkipped,
		string State,
		bool HonestSkip);

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Runs one bounded information-density retention pass. Exposed internally for worker integration
	/// tests. Returns without reading or writing anything when the policy is disabled, when a legal hold
	/// is in force, or when no pressure trigger fires.
	/// </summary>
	internal async Task<RetentionPassOutcome> RunOnceAsync(CancellationToken cancellationToken)
	{
		DateTime nowUtc = DateTime.UtcNow;
		RetentionEvaluation evaluation = await _engine.EvaluateForPassAsync(nowUtc, cancellationToken)
			.ConfigureAwait(false);

		if (!evaluation.PolicyEnabled)
		{
			// Default posture: an installation that never opted in does no work and writes nothing.
			return EmptyOutcome(policyDisabled: true, legalHold: false);
		}

		if (evaluation.LegalHold)
		{
			// The engine stops before any trigger probe or statistics read, so nothing was touched.
			_metrics.RecordInformationDensitySkip();
			_logger.LogInformation(
				"Information-density retention is enabled but a legal hold is in force; no pressure rule ran.");
			return EmptyOutcome(policyDisabled: false, legalHold: true);
		}

		if (evaluation.Trigger == EventDeletionTrigger.Unknown)
		{
			// No trigger fired: no row is read from or written to the database beyond the cheap ceiling
			// probes, and neither a ledger row nor an operation-log entry is produced.
			_metrics.RecordInformationDensitySkip();
			return EmptyOutcome(policyDisabled: false, legalHold: false);
		}

		RetentionPlan plan = evaluation.Plan;
		RetentionPassOutcome outcome;
		PassSummary summary;
		if (plan.IsEmpty)
		{
			// Honest skip: the trigger fired, but no code carries compressible, information-poor
			// rows. This is reported, never silent.
			summary = new PassSummary(
				evaluation.Trigger,
				RowsDeleted: 0,
				StepsPlanned: 0,
				StepsCompleted: 0,
				CodesSkipped: plan.Skipped.Count,
				State: evaluation.States.Count == 0
					? "no code reached the eligibility threshold"
					: "every eligible code is fully protected by its anchor, tail or age floor",
				HonestSkip: true);
			outcome = new RetentionPassOutcome(
				PolicyDisabled: false,
				LegalHold: false,
				Trigger: evaluation.Trigger,
				RowsDeleted: 0,
				StepsPlanned: 0,
				StepsCompleted: 0,
				CodesSkipped: plan.Skipped.Count,
				RowsProtectedByLinkedEvidence: 0,
				WriterLockBudgetExhausted: false,
				Cancelled: false);
		}
		else
		{
			RetentionExecutionResult execution = await _engine.ExecutePlanAsync(
				plan,
				evaluation.Trigger,
				evaluation.MinAgeCutoffUtc,
				evaluation.DeleteBatchRows,
				evaluation.MaxWriterLockMs,
				cancellationToken).ConfigureAwait(false);

			summary = new PassSummary(
				evaluation.Trigger,
				execution.RowsDeleted,
				plan.Steps.Count,
				execution.StepsCompleted,
				plan.Skipped.Count,
				DescribeExecution(execution),
				HonestSkip: false);
			outcome = new RetentionPassOutcome(
				PolicyDisabled: false,
				LegalHold: false,
				Trigger: evaluation.Trigger,
				RowsDeleted: execution.RowsDeleted,
				StepsPlanned: plan.Steps.Count,
				StepsCompleted: execution.StepsCompleted,
				CodesSkipped: plan.Skipped.Count,
				RowsProtectedByLinkedEvidence: execution.RowsProtectedByLinkedEvidence,
				WriterLockBudgetExhausted: execution.WriterLockBudgetExhausted,
				Cancelled: execution.Cancelled);
		}

		if (summary.HonestSkip)
		{
			_metrics.RecordInformationDensitySkip();
			_logger.LogInformation(
				"Information-density retention evaluated the store for trigger {Trigger} and honestly deleted nothing: {State}",
				summary.Trigger,
				summary.State);
		}
		else if (outcome.RowsDeleted > 0)
		{
			_metrics.RecordInformationDensityPass(outcome.RowsDeleted, summary.Trigger.ToString(), nowUtc);
		}

		await WriteSummaryAsync(summary, cancellationToken).ConfigureAwait(false);
		return outcome;
	}

	private static RetentionPassOutcome EmptyOutcome(bool policyDisabled, bool legalHold)
		=> new(
			PolicyDisabled: policyDisabled,
			LegalHold: legalHold,
			Trigger: EventDeletionTrigger.Unknown,
			RowsDeleted: 0,
			StepsPlanned: 0,
			StepsCompleted: 0,
			CodesSkipped: 0,
			RowsProtectedByLinkedEvidence: 0,
			WriterLockBudgetExhausted: false,
			Cancelled: false);

	// ── Operation-log reporting ──────────────────────────────────────────────────

	private static string DescribeExecution(RetentionExecutionResult execution)
	{
		if (execution.Cancelled)
		{
			return "cancelled mid-pass; anchors, tails and the ledger remain consistent";
		}

		if (execution.WriterLockBudgetExhausted)
		{
			return "writer-lock budget reached; remainder deferred to the next tick";
		}

		return "complete";
	}

	private Task WriteSummaryAsync(PassSummary summary, CancellationToken cancellationToken)
	{
		string message = summary.HonestSkip
			? "Information-density retention deleted nothing; trigger=" + summary.Trigger.ToString() +
				"; state=" + summary.State
			: "Information-density retention removed " + summary.RowsDeleted.ToString(CultureInfo.InvariantCulture) +
				" row(s) across " + summary.StepsCompleted.ToString(CultureInfo.InvariantCulture) + " of " +
				summary.StepsPlanned.ToString(CultureInfo.InvariantCulture) + " planned code(s); trigger=" +
				summary.Trigger.ToString() + "; skippedCodes=" +
				summary.CodesSkipped.ToString(CultureInfo.InvariantCulture) + "; state=" + summary.State;
		if (message.Length > OperationLogMessageLimit)
		{
			message = message[..OperationLogMessageLimit];
		}

		_logger.LogInformation(
			"Information-density retention pass: trigger={Trigger}, deleted={Rows}, planned={Planned}, completed={Completed}, skipped={Skipped}, state={State}",
			summary.Trigger,
			summary.RowsDeleted,
			summary.StepsPlanned,
			summary.StepsCompleted,
			summary.CodesSkipped,
			summary.State);

		return _operationLog.WriteAsync(
			new OperationLogEntry
			{
				Severity = OperationLogSeverity.Information,
				Source = OperationLogSource,
				Operation = OperationLogOperation,
				Message = message,
				Actor = InformationDensityRetentionEngine.ServiceActor,
			},
			cancellationToken);
	}
}
