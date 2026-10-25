/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionEngine.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: The single implementation of "what would the information-density retention pass do?"
//          - trigger enumeration, the bounded statistics snapshot, the deterministic plan and the
//          batched delete-plus-ledger execution. Both InformationDensityRetentionWorker (the real
//          pass) and RetentionPreviewService (the dry run) call this class, so a preview cannot
//          drift from the pass it predicts: same ceilings, same code ordering, same eligibility
//          rules, same age floor, same delete predicate. Nothing here reads the clock on its own -
//          the caller supplies nowUtc - and nothing here reports; that is the callers' concern.
// Depends: AuditDbContext, RetentionPolicyOptions, InformationDensityRetentionPlanner,
//          EventDeletionLedger, Microsoft.Data.Sqlite
// Extends: Add a pressure trigger by extending EvaluateTriggerAsync plus EventDeletionTrigger; add
//          a linked-evidence guard by extending LinkedEvidenceExistsFragment.

using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;

namespace RdpAudit.Service.Services;

/// <summary>One code that the statistics scan short-circuited before its interior was measured,
/// with the reason. Reported so a dry run can explain the skip instead of dropping the code.</summary>
internal sealed record RetentionPrefilteredCode(RetentionCodeKey Key, long TotalRows, RetentionSkipReason Reason);

/// <summary>One protected code that currently holds rows. The statistics scan deliberately skips
/// protected codes so the bounded code budget goes to genuinely eligible streams; a dry run still
/// has to name them, because "this code is protected and why" is part of what a preview owes the
/// operator.</summary>
internal sealed record RetentionProtectedCode(RetentionCodeKey Key, long TotalRows);

/// <summary>
/// The result of evaluating the policy once: which trigger (if any) fires, the deterministic plan
/// and the statistics snapshot the plan was derived from. When
/// <see cref="StatisticsCollected"/> is false no code state was read and <see cref="Plan"/> is
/// empty for that reason, not because the store is clean.
/// </summary>
internal sealed record RetentionEvaluation
{
	/// <summary>True when <c>RetentionPolicy.Enabled</c> is set.</summary>
	public required bool PolicyEnabled { get; init; }

	/// <summary>True when a legal hold is in force.</summary>
	public required bool LegalHold { get; init; }

	/// <summary>First pressure ceiling breached, or <see cref="EventDeletionTrigger.Unknown"/>.</summary>
	public required EventDeletionTrigger Trigger { get; init; }

	/// <summary>The deterministic plan.</summary>
	public required RetentionPlan Plan { get; init; }

	/// <summary>The code snapshot the plan was derived from; empty when statistics were not collected.</summary>
	public required List<RetentionCodeState> States { get; init; }

	/// <summary>Codes the scan short-circuited, with the reason.</summary>
	public required List<RetentionPrefilteredCode> Prefiltered { get; init; }

	/// <summary>Protected codes that currently hold rows. Populated for a preview only, because the
	/// pass has no reason to enumerate codes it will never touch.</summary>
	public required List<RetentionProtectedCode> ProtectedCodes { get; init; }

	/// <summary>True when the statistics snapshot was taken.</summary>
	public required bool StatisticsCollected { get; init; }

	/// <summary>The instant the evaluation was made against.</summary>
	public required DateTime NowUtc { get; init; }

	/// <summary>Age floor applied to candidates.</summary>
	public required DateTime MinAgeCutoffUtc { get; init; }

	/// <summary>Effective protected-tail length.</summary>
	public required int TailKeepPerCode { get; init; }

	/// <summary>Effective per-pass row budget.</summary>
	public required int MaxRowsPerPass { get; init; }

	/// <summary>Effective rows per delete statement.</summary>
	public required int DeleteBatchRows { get; init; }

	/// <summary>Effective writer-lock budget in milliseconds.</summary>
	public required int MaxWriterLockMs { get; init; }
}

/// <summary>Aggregate outcome of applying a plan.</summary>
internal readonly record struct RetentionExecutionResult(
	long RowsDeleted,
	int StepsCompleted,
	long RowsProtectedByLinkedEvidence,
	bool WriterLockBudgetExhausted,
	bool Cancelled);

/// <summary>Result of one transactional batch.</summary>
internal readonly record struct RetentionBatchResult(long RowsDeleted, long RowsProtectedByLinkedEvidence);

/// <summary>
/// The measured cost of one committed batch: how much it removed and how long it held the writer. The
/// span covers the whole batch transaction - the DELETE, the ledger append and the commit - which is
/// exactly the interval <see cref="RetentionPolicyOptions.MaxWriterLockMs"/> bounds.
/// </summary>
internal readonly record struct RetentionBatchTelemetry(
	int RowsDeleted,
	long RowsProtectedByLinkedEvidence,
	long ElapsedMs);

/// <summary>
/// Shared information-density retention evaluation and execution engine. Stateless apart from its
/// two collaborators, so it can be constructed per consumer without coordination.
/// </summary>
internal sealed class InformationDensityRetentionEngine
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Hard bound on the number of distinct codes examined by one evaluation, so a
	/// pathological code population cannot turn a single pass into thousands of round trips.</summary>
	internal const int MaxCodesExaminedPerPass = 256;

	/// <summary>Actor recorded in the ledger when the service itself runs the pass.</summary>
	internal const string ServiceActor = "Service";

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	/// <summary>Optional progress observer, invoked with the newly deleted row count immediately AFTER
	/// a batch has committed (and before the next cancellation check of the pass). It exists so an
	/// integration test can drive a mid-pass cancellation DETERMINISTICALLY - "cancel as soon as the
	/// first batch is durable" - instead of racing the pass from another thread and hoping the cancel
	/// lands while rows are still being deleted. Production never sets it: the property is
	/// <c>internal</c> (visible to the test assembly only) and stays null on every code path the
	/// service itself creates, so a pass behaves exactly as before.</summary>
	internal Action<long>? AfterBatchCommitted { get; set; }

	/// <summary>Optional per-batch telemetry observer, invoked with the measured cost of a batch right
	/// after it committed and after the same hook above has run. It exists for the same reason and under
	/// the same rule: production never sets it, so it is null on every code path the service creates and
	/// a pass behaves exactly as before. It carries the batch's elapsed milliseconds - the writer-lock
	/// hold the engine otherwise computes and discards - so a storage benchmark can size DeleteBatchRows
	/// and MaxWriterLockMs from measured numbers instead of a guess. Only batches that deleted rows are
	/// reported, matching <see cref="AfterBatchCommitted"/>.</summary>
	internal Action<RetentionBatchTelemetry>? BatchCompleted { get; set; }

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the engine over the database factory and the live options monitor.</summary>
	public InformationDensityRetentionEngine(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		_factory = factory;
		_options = options;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Evaluates the policy with pass semantics: when the policy is disabled, a legal hold is in
	/// force or no pressure ceiling is breached, no code state is read at all and the returned plan
	/// is empty. This is the "do not pay for a pass that cannot run" contract the worker relies on.
	/// </summary>
	public Task<RetentionEvaluation> EvaluateForPassAsync(DateTime nowUtc, CancellationToken cancellationToken)
		=> EvaluateCoreAsync(nowUtc, forPreview: false, cancellationToken);

	/// <summary>
	/// Evaluates the policy with preview semantics: whenever the policy is enabled the full
	/// statistics snapshot, the plan and the inventory of protected codes are produced even if no
	/// ceiling is breached, so an operator can see exactly which rows the next real pass would remove
	/// and which codes are protected and why. The pass itself is unchanged by this mode: it never
	/// collects the protected inventory, and it still stops before any statistics read when no
	/// trigger fires.
	/// </summary>
	public Task<RetentionEvaluation> EvaluateForPreviewAsync(DateTime nowUtc, CancellationToken cancellationToken)
		=> EvaluateCoreAsync(nowUtc, forPreview: true, cancellationToken);

	/// <summary>
	/// Applies a plan in short, cancellable, transactional batches - one DELETE plus one ledger row
	/// per batch inside one transaction - so removed evidence is accounted for exactly once even when
	/// a pass is interrupted. Yields when a batch exceeds the writer-lock budget. A passive WAL
	/// checkpoint follows a pass that actually removed rows; no full VACUUM ever runs on the live
	/// store.
	/// </summary>
	public async Task<RetentionExecutionResult> ExecutePlanAsync(
		RetentionPlan plan,
		EventDeletionTrigger trigger,
		DateTime minAgeCutoffUtc,
		int batchRows,
		int writerLockBudgetMs,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(plan);

		long rowsDeleted = 0;
		long rowsProtected = 0;
		int stepsCompleted = 0;
		bool writerLockBudgetExhausted = false;
		bool cancelled = false;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
		bool openedHere = connection.State != ConnectionState.Open;
		if (openedHere)
		{
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
		}

		try
		{
			foreach (RetentionPlanStep step in plan.Steps)
			{
				if (cancellationToken.IsCancellationRequested)
				{
					cancelled = true;
					break;
				}

				string ledgerReason = BuildLedgerReason(step, trigger);
				int remaining = step.Rows;
				while (remaining > 0)
				{
					if (cancellationToken.IsCancellationRequested)
					{
						cancelled = true;
						break;
					}

					int batch = Math.Min(batchRows, remaining);
					Stopwatch batchWatch = Stopwatch.StartNew();
					RetentionBatchResult batchResult = await ExecuteBatchAsync(
						db,
						connection,
						step,
						batch,
						minAgeCutoffUtc,
						trigger,
						ledgerReason,
						cancellationToken).ConfigureAwait(false);
					batchWatch.Stop();

					rowsProtected += batchResult.RowsProtectedByLinkedEvidence;
					if (batchResult.RowsDeleted == 0)
					{
						// Nothing left to delete for this step; the ledger already accounts for whatever
						// was removed, so stopping here cannot lose evidence.
						break;
					}

					rowsDeleted += batchResult.RowsDeleted;
					remaining -= (int)batchResult.RowsDeleted;

					// The batch is committed, so a test hook can now cancel the token and be certain that
					// exactly this much work is durable. The next iteration's cancellation check then reports
					// the pass as cancelled - no timing, no polling from another thread.
					AfterBatchCommitted?.Invoke(batchResult.RowsDeleted);

					// The batch is durable and its writer-lock span has been measured; hand both to anyone
					// observing the pass. Null on every production path.
					BatchCompleted?.Invoke(new RetentionBatchTelemetry(
						(int)batchResult.RowsDeleted,
						batchResult.RowsProtectedByLinkedEvidence,
						batchWatch.ElapsedMilliseconds));

					if (batchWatch.ElapsedMilliseconds > writerLockBudgetMs)
					{
						// Yield to ingestion: the remaining rows are deferred to the next tick.
						writerLockBudgetExhausted = true;
						break;
					}
				}

				if (writerLockBudgetExhausted || cancelled)
				{
					break;
				}

				stepsCompleted++;
			}

			if (rowsDeleted > 0)
			{
				// Never a full VACUUM on the live store: a passive checkpoint returns committed WAL
				// pages to the main file without rewriting it and without taking the writer.
				await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(PASSIVE);", cancellationToken)
					.ConfigureAwait(false);
			}
		}
		finally
		{
			if (openedHere)
			{
				await db.Database.CloseConnectionAsync().ConfigureAwait(false);
			}
		}

		return new RetentionExecutionResult(rowsDeleted, stepsCompleted, rowsProtected, writerLockBudgetExhausted, cancelled);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>
	/// The shared evaluation path. Both public entry points funnel through here, so the trigger
	/// enumeration, the statistics snapshot and the planner invocation exist exactly once.
	/// </summary>
	private async Task<RetentionEvaluation> EvaluateCoreAsync(
		DateTime nowUtc,
		bool forPreview,
		CancellationToken cancellationToken)
	{
		RdpAuditOptions options = _options.CurrentValue;
		RetentionPolicyOptions policy = options.Storage.RetentionPolicy;

		if (!policy.Enabled)
		{
			// Default posture: an installation that never opted in does no work and writes nothing.
			return EmptyEvaluation(nowUtc, policy, policyEnabled: false, legalHold: false, EventDeletionTrigger.Unknown);
		}

		if (policy.LegalHold && !forPreview)
		{
			// Pass semantics: a legal hold stops the pass before any ceiling probe and before any
			// statistics read, which is the behaviour the policy has always had. Preview semantics
			// deliberately continue, so an operator can still see which codes the hold protects.
			return EmptyEvaluation(nowUtc, policy, policyEnabled: true, legalHold: true, EventDeletionTrigger.Unknown);
		}

		string databasePath = Path.GetFullPath(options.Storage.ResolveDatabasePath());
		EventDeletionTrigger trigger = await EvaluateTriggerAsync(policy, options, databasePath, cancellationToken)
			.ConfigureAwait(false);

		if (trigger == EventDeletionTrigger.Unknown && !forPreview)
		{
			return EmptyEvaluation(nowUtc, policy, policyEnabled: true, legalHold: policy.LegalHold, trigger);
		}

		int tailKeep = policy.ResolveTailKeepPerCode();
		int budget = policy.ResolveMaxRowsPerPass();
		DateTime minAgeCutoffUtc = nowUtc.AddDays(-policy.ResolveMinAgeDays());

		List<RetentionCodeState> states;
		List<RetentionPrefilteredCode> prefiltered = [];
		List<RetentionProtectedCode> protectedCodes = [];
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false))
		{
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
			bool openedHere = connection.State != ConnectionState.Open;
			if (openedHere)
			{
				await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			}

			try
			{
				states = await CollectCodeStatesAsync(
					connection,
					policy,
					minAgeCutoffUtc,
					tailKeep,
					budget,
					prefiltered,
					cancellationToken).ConfigureAwait(false);
				if (forPreview)
				{
					protectedCodes = await CollectProtectedCodesAsync(connection, policy, cancellationToken)
						.ConfigureAwait(false);
				}
			}
			finally
			{
				if (openedHere)
				{
					await db.Database.CloseConnectionAsync().ConfigureAwait(false);
				}
			}
		}

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(nowUtc, policy, states);

		return new RetentionEvaluation
		{
			PolicyEnabled = true,
			LegalHold = policy.LegalHold,
			Trigger = trigger,
			Plan = plan,
			States = states,
			Prefiltered = prefiltered,
			ProtectedCodes = protectedCodes,
			StatisticsCollected = true,
			NowUtc = nowUtc,
			MinAgeCutoffUtc = minAgeCutoffUtc,
			TailKeepPerCode = tailKeep,
			MaxRowsPerPass = budget,
			DeleteBatchRows = policy.ResolveDeleteBatchRows(),
			MaxWriterLockMs = policy.ResolveMaxWriterLockMs(),
		};
	}

	private static RetentionEvaluation EmptyEvaluation(
		DateTime nowUtc,
		RetentionPolicyOptions policy,
		bool policyEnabled,
		bool legalHold,
		EventDeletionTrigger trigger)
		=> new()
		{
			PolicyEnabled = policyEnabled,
			LegalHold = legalHold,
			Trigger = trigger,
			Plan = new RetentionPlan { Steps = [], Skipped = [], RuleVersion = RetentionRuleVersion.Current },
			States = [],
			Prefiltered = [],
			ProtectedCodes = [],
			StatisticsCollected = false,
			NowUtc = nowUtc,
			MinAgeCutoffUtc = nowUtc.AddDays(-policy.ResolveMinAgeDays()),
			TailKeepPerCode = policy.ResolveTailKeepPerCode(),
			MaxRowsPerPass = policy.ResolveMaxRowsPerPass(),
			DeleteBatchRows = policy.ResolveDeleteBatchRows(),
			MaxWriterLockMs = policy.ResolveMaxWriterLockMs(),
		};

	// ── Trigger evaluation ───────────────────────────────────────────────────────

	/// <summary>
	/// Evaluates the three pressure triggers in a fixed order and returns the first one that fires, or
	/// <see cref="EventDeletionTrigger.Unknown"/> when the store is inside every configured ceiling. The
	/// order is part of the contract, so the recorded trigger is deterministic when several ceilings are
	/// breached at once. A ceiling of zero disables its trigger.
	/// </summary>
	private async Task<EventDeletionTrigger> EvaluateTriggerAsync(
		RetentionPolicyOptions policy,
		RdpAuditOptions options,
		string databasePath,
		CancellationToken cancellationToken)
	{
		long maxDatabaseBytes = policy.ResolveMaxDatabaseBytes();
		if (maxDatabaseBytes > 0 && ReadDatabaseFootprintBytes(databasePath) > maxDatabaseBytes)
		{
			return EventDeletionTrigger.DatabaseBytes;
		}

		long minFreeDiskBytes = policy.ResolveMinFreeDiskBytes();
		if (minFreeDiskBytes > 0
			&& ReadLowestAvailableFreeBytes(options, databasePath) is { } freeBytes
			&& freeBytes < minFreeDiskBytes)
		{
			return EventDeletionTrigger.FreeDiskBytes;
		}

		long maxRawEventRows = policy.ResolveMaxRawEventRows();
		if (maxRawEventRows > 0)
		{
			await using AuditDbContext db =
				await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			if (await db.RawEvents.LongCountAsync(cancellationToken).ConfigureAwait(false) > maxRawEventRows)
			{
				return EventDeletionTrigger.RawEventRows;
			}
		}

		return EventDeletionTrigger.Unknown;
	}

	/// <summary>Reads the on-disk size of the database family (database, write-ahead log, shared-memory
	/// file). A missing file contributes zero, so a not-yet-created database cannot look oversized.</summary>
	private static long ReadDatabaseFootprintBytes(string databasePath)
		=> ReadFileLength(databasePath)
			+ ReadFileLength(databasePath + "-wal")
			+ ReadFileLength(databasePath + "-shm");

	private static long ReadFileLength(string path)
	{
		try
		{
			FileInfo info = new(path);
			return info.Exists ? info.Length : 0L;
		}
		catch (IOException)
		{
			return 0L;
		}
		catch (UnauthorizedAccessException)
		{
			return 0L;
		}
	}

	/// <summary>Lowest available free space across the volumes hosting the database and the shard tree,
	/// or null when neither volume can be inspected.</summary>
	private static long? ReadLowestAvailableFreeBytes(RdpAuditOptions options, string databasePath)
	{
		long? lowest = TryReadAvailableFreeBytes(databasePath);
		string actionsRoot = options.Sharding.ResolveActionsRoot();
		if (!string.IsNullOrWhiteSpace(actionsRoot)
			&& TryReadAvailableFreeBytes(actionsRoot) is { } actionsFree
			&& (lowest is null || actionsFree < lowest.Value))
		{
			lowest = actionsFree;
		}

		return lowest;
	}

	private static long? TryReadAvailableFreeBytes(string path)
	{
		try
		{
			string? root = Path.GetPathRoot(Path.GetFullPath(path));
			if (string.IsNullOrEmpty(root))
			{
				return null;
			}

			DriveInfo drive = new(root);
			return drive.IsReady ? drive.AvailableFreeSpace : null;
		}
		catch (IOException)
		{
			return null;
		}
		catch (UnauthorizedAccessException)
		{
			return null;
		}
		catch (ArgumentException)
		{
			return null;
		}
	}

	// ── Statistics collection ────────────────────────────────────────────────────

	/// <summary>
	/// Builds the per-code snapshot the planner reasons about: one bounded GROUP BY over the raw-event
	/// table, then an anchor lookup, a tail-boundary lookup, an exact density count and one bounded
	/// candidate fetch per code. Codes that cannot physically reach the eligibility threshold are never
	/// queried further. The planner re-applies the exact eligibility, protection and age rules on top
	/// of what this returns.
	/// </summary>
	private static async Task<List<RetentionCodeState>> CollectCodeStatesAsync(
		SqliteConnection connection,
		RetentionPolicyOptions policy,
		DateTime minAgeCutoffUtc,
		int tailKeep,
		int budget,
		List<RetentionPrefilteredCode> prefiltered,
		CancellationToken cancellationToken)
	{
		bool perIp = policy.ResolveAnchorScope() == RetentionAnchorScope.PerCodeAndIp;
		int candidateMinRows = policy.ResolveCandidateMinRows();
		List<CodeStatistic> statistics = await ReadCodeStatisticsAsync(
			connection,
			policy,
			perIp,
			minAgeCutoffUtc,
			cancellationToken).ConfigureAwait(false);

		List<RetentionCodeState> states = [];
		long remainingBudget = budget;
		foreach (CodeStatistic statistic in statistics)
		{
			cancellationToken.ThrowIfCancellationRequested();
			RetentionCodeKey key = statistic.Key;
			long interiorCapacity = statistic.TotalRows - 1L - tailKeep;
			if (interiorCapacity < candidateMinRows || remainingBudget <= 0)
			{
				// Either the code cannot expose enough rows to matter, or the row budget this tick is
				// allowed to look at is already spent. The state is reported so the planner can explain
				// the skip, and the reason is recorded separately because the two causes are different.
				prefiltered.Add(new RetentionPrefilteredCode(
					key,
					statistic.TotalRows,
					remainingBudget <= 0 ? RetentionSkipReason.BudgetExhausted : RetentionSkipReason.BelowCandidateMinRows));
				states.Add(new RetentionCodeState
				{
					Key = key,
					TotalRows = statistic.TotalRows,
					Anchor = new RetentionRow(statistic.LowestRowId, DateTime.UnixEpoch),
					TailBoundary = null,
					EligibleInteriorRows = 0,
					LowestRowId = statistic.LowestRowId,
					HighestRowId = statistic.HighestRowId,
					CandidateRows = [],
				});
				continue;
			}

			RetentionRow? anchor = await ReadAnchorAsync(connection, key, perIp, cancellationToken)
				.ConfigureAwait(false);
			RetentionRow? tailBoundary = anchor is null
				? null
				: await ReadTailBoundaryAsync(connection, key, perIp, tailKeep, cancellationToken)
					.ConfigureAwait(false);
			if (anchor is not { } anchorRow || tailBoundary is not { } tailRow)
			{
				states.Add(new RetentionCodeState
				{
					Key = key,
					TotalRows = statistic.TotalRows,
					Anchor = anchor ?? new RetentionRow(statistic.LowestRowId, DateTime.UnixEpoch),
					TailBoundary = null,
					EligibleInteriorRows = 0,
					LowestRowId = statistic.LowestRowId,
					HighestRowId = statistic.HighestRowId,
					CandidateRows = [],
				});
				continue;
			}

			// The eligibility threshold and the priority order are measured against the density inside
			// the deletion window, which the fetch budget must not distort: count it exactly.
			long density = await CountCandidateRowsAsync(
				connection,
				key,
				perIp,
				anchorRow,
				tailRow,
				statistic.LowestRowId,
				statistic.HighestRowId,
				minAgeCutoffUtc,
				cancellationToken).ConfigureAwait(false);

			int limit = (int)Math.Min(remainingBudget, Math.Min(density, interiorCapacity));
			List<RetentionRow> candidates = limit <= 0
				? []
				: await ReadCandidateRowsAsync(
					connection,
					key,
					perIp,
					anchorRow,
					tailRow,
					statistic.LowestRowId,
					statistic.HighestRowId,
					minAgeCutoffUtc,
					limit,
					cancellationToken).ConfigureAwait(false);
			remainingBudget -= candidates.Count;

			states.Add(new RetentionCodeState
			{
				Key = key,
				TotalRows = statistic.TotalRows,
				Anchor = anchorRow,
				TailBoundary = tailRow,
				EligibleInteriorRows = density,
				LowestRowId = statistic.LowestRowId,
				HighestRowId = statistic.HighestRowId,
				CandidateRows = candidates,
			});
		}

		return states;
	}

	/// <summary>
	/// Lists the protected codes that currently hold rows, so a dry run can name them and say why
	/// they are out of scope. This is deliberately a separate, bounded question from the eligibility
	/// scan - the scan excludes protected codes so its bounded code budget is spent on streams that
	/// could actually be compressed - and it is only asked by the preview, never by the pass.
	/// </summary>
	private static async Task<List<RetentionProtectedCode>> CollectProtectedCodesAsync(
		SqliteConnection connection,
		RetentionPolicyOptions policy,
		CancellationToken cancellationToken)
	{
		List<int> protectedCodes = [.. policy.ResolveProtectedEventIds()];
		if (protectedCodes.Count == 0)
		{
			return [];
		}

		protectedCodes.Sort();
		using SqliteCommand command = connection.CreateCommand();
		StringBuilder builder = new("SELECT re.\"EventId\", re.\"Channel\", COUNT(*) AS \"TotalRows\"" +
			" FROM \"RawEvents\" AS re WHERE re.\"EventId\" IN (");
		for (int index = 0; index < protectedCodes.Count; index++)
		{
			if (index > 0)
			{
				builder.Append(',');
			}

			string name = "$protectedInventory" + index.ToString(CultureInfo.InvariantCulture);
			builder.Append(name);
			command.Parameters.AddWithValue(name, protectedCodes[index]);
		}

		builder.Append(") GROUP BY re.\"EventId\", re.\"Channel\"" +
			" ORDER BY \"TotalRows\" DESC, re.\"EventId\" ASC, re.\"Channel\" ASC LIMIT $maxCodes;");
		command.Parameters.AddWithValue("$maxCodes", MaxCodesExaminedPerPass);
		SetCommandText(command, builder.ToString());

		List<RetentionProtectedCode> inventory = [];
		await using SqliteDataReader reader =
			await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			int eventId = reader.GetInt32(0);
			inventory.Add(new RetentionProtectedCode(
				new RetentionCodeKey
				{
					EventId = eventId,
					Channel = reader.GetString(1),
					IpBinary16 = null,
				},
				reader.GetInt64(2)));
		}

		return inventory;
	}

	private static async Task<List<CodeStatistic>> ReadCodeStatisticsAsync(
		SqliteConnection connection,
		RetentionPolicyOptions policy,
		bool perIp,
		DateTime minAgeCutoffUtc,
		CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		string ipSelect = perIp ? ", re.\"SourceIpBinary\" AS \"IpBinary16\"" : string.Empty;
		string ipGroup = perIp ? ", re.\"SourceIpBinary\"" : string.Empty;
		SetCommandText(command,
			"SELECT re.\"EventId\" AS \"EventId\", re.\"Channel\" AS \"Channel\"" + ipSelect +
			", COUNT(*) AS \"TotalRows\"" +
			", MIN(re.\"Id\") AS \"LowestRowId\"" +
			", MAX(re.\"Id\") AS \"HighestRowId\"" +
			", SUM(CASE WHEN re.\"TimeUtc\" < $minAgeCutoff THEN 1 ELSE 0 END) AS \"WindowRows\"" +
			" FROM \"RawEvents\" AS re" +
			BuildProtectedCodeFilter(policy, command) +
			" GROUP BY re.\"EventId\", re.\"Channel\"" + ipGroup +
			" HAVING COUNT(*) >= $candidateMinRows" +
			" ORDER BY \"WindowRows\" DESC, \"TotalRows\" DESC, \"EventId\" ASC, \"Channel\" ASC" +
			" LIMIT $maxCodes;");
		command.Parameters.AddWithValue("$minAgeCutoff", minAgeCutoffUtc);
		command.Parameters.AddWithValue("$candidateMinRows", policy.ResolveCandidateMinRows());
		command.Parameters.AddWithValue("$maxCodes", MaxCodesExaminedPerPass);

		List<CodeStatistic> statistics = [];
		await using SqliteDataReader reader =
			await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			int eventId = reader.GetInt32(0);
			string channel = reader.GetString(1);
			int offset = 2;
			byte[]? ipBinary16 = null;
			if (perIp)
			{
				ipBinary16 = reader.IsDBNull(offset) ? null : (byte[])reader.GetValue(offset);
				offset++;
			}

			statistics.Add(new CodeStatistic(
				new RetentionCodeKey { EventId = eventId, Channel = channel, IpBinary16 = ipBinary16 },
				TotalRows: reader.GetInt64(offset),
				LowestRowId: reader.GetInt64(offset + 1),
				HighestRowId: reader.GetInt64(offset + 2)));
		}

		return statistics;
	}

	/// <summary>
	/// Adds a <c>WHERE</c> clause removing protected event codes from the statistics scan, so the bounded
	/// code budget is spent on genuinely eligible streams. The planner re-applies the same rule.
	/// </summary>
	private static string BuildProtectedCodeFilter(RetentionPolicyOptions policy, SqliteCommand command)
	{
		List<int> protectedCodes = [.. policy.ResolveProtectedEventIds()];
		if (protectedCodes.Count == 0)
		{
			return string.Empty;
		}

		protectedCodes.Sort();
		StringBuilder builder = new(" WHERE re.\"EventId\" NOT IN (");
		for (int index = 0; index < protectedCodes.Count; index++)
		{
			if (index > 0)
			{
				builder.Append(',');
			}

			string name = "$protectedCode" + index.ToString(CultureInfo.InvariantCulture);
			builder.Append(name);
			command.Parameters.AddWithValue(name, protectedCodes[index]);
		}

		builder.Append(')');
		return builder.ToString();
	}

	private static Task<RetentionRow?> ReadAnchorAsync(
		SqliteConnection connection,
		RetentionCodeKey key,
		bool perIp,
		CancellationToken cancellationToken)
		=> ReadSingleRowAsync(
			connection,
			"SELECT re.\"Id\", re.\"TimeUtc\" FROM \"RawEvents\" AS re" +
			BuildCodeWhere(perIp) +
			" ORDER BY re.\"TimeUtc\", re.\"Id\" LIMIT 1;",
			key,
			perIp,
			cancellationToken);

	private static Task<RetentionRow?> ReadTailBoundaryAsync(
		SqliteConnection connection,
		RetentionCodeKey key,
		bool perIp,
		int tailKeep,
		CancellationToken cancellationToken)
		=> ReadSingleRowAsync(
			connection,
			"SELECT re.\"Id\", re.\"TimeUtc\" FROM \"RawEvents\" AS re" +
			BuildCodeWhere(perIp) +
			" ORDER BY re.\"TimeUtc\" DESC, re.\"Id\" DESC LIMIT 1 OFFSET $tailOffset;",
			key,
			perIp,
			cancellationToken,
			// Offset tailKeep - 1 in descending order lands on the OLDEST row of the protected tail, so
			// "strictly older than the boundary" describes exactly the deletable interior.
			Math.Max(0, tailKeep - 1));

	private static async Task<RetentionRow?> ReadSingleRowAsync(
		SqliteConnection connection,
		string sql,
		RetentionCodeKey key,
		bool perIp,
		CancellationToken cancellationToken,
		int? tailOffset = null)
	{
		using SqliteCommand command = connection.CreateCommand();
		SetCommandText(command, sql);
		BindCodeParameters(command, key, perIp);
		if (tailOffset is { } offset)
		{
			command.Parameters.AddWithValue("$tailOffset", offset);
		}

		await using SqliteDataReader reader =
			await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			return null;
		}

		return new RetentionRow(reader.GetInt64(0), reader.GetDateTime(1));
	}

	/// <summary>
	/// Counts exactly how many rows of the code are deletable interior rows: older than the age floor,
	/// strictly newer than the anchor, strictly older than the tail boundary and not referenced by alert
	/// evidence. This is the density <c>d(c)</c> the eligibility threshold and the priority order use.
	/// </summary>
	private static async Task<long> CountCandidateRowsAsync(
		SqliteConnection connection,
		RetentionCodeKey key,
		bool perIp,
		RetentionRow anchor,
		RetentionRow tailBoundary,
		long lowestRowId,
		long highestRowId,
		DateTime minAgeCutoffUtc,
		CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		SetCommandText(
			command,
			"SELECT COUNT(*) FROM \"RawEvents\" AS re" +
			BuildCandidatePredicate(perIp) + ";");
		BindCandidateParameters(
			command,
			key,
			perIp,
			anchor,
			tailBoundary,
			lowestRowId,
			highestRowId,
			minAgeCutoffUtc);
		object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return result is long count ? count : 0L;
	}

	/// <summary>
	/// Reads the bounded interior candidate set: rows of the code older than the age floor, strictly
	/// newer than the anchor, strictly older than the tail boundary, and not referenced by alert
	/// evidence - oldest first, so the planner's slice is the oldest interior slice.
	/// </summary>
	private static async Task<List<RetentionRow>> ReadCandidateRowsAsync(
		SqliteConnection connection,
		RetentionCodeKey key,
		bool perIp,
		RetentionRow anchor,
		RetentionRow tailBoundary,
		long lowestRowId,
		long highestRowId,
		DateTime minAgeCutoffUtc,
		int limit,
		CancellationToken cancellationToken)
	{
		if (limit <= 0)
		{
			return [];
		}

		using SqliteCommand command = connection.CreateCommand();
		SetCommandText(
			command,
			"SELECT re.\"Id\", re.\"TimeUtc\" FROM \"RawEvents\" AS re" +
			BuildCandidatePredicate(perIp) +
			" ORDER BY re.\"TimeUtc\", re.\"Id\" LIMIT $limit;");
		BindCandidateParameters(
			command,
			key,
			perIp,
			anchor,
			tailBoundary,
			lowestRowId,
			highestRowId,
			minAgeCutoffUtc);
		command.Parameters.AddWithValue("$limit", limit);

		List<RetentionRow> rows = [];
		await using SqliteDataReader reader =
			await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			rows.Add(new RetentionRow(reader.GetInt64(0), reader.GetDateTime(1)));
		}

		return rows;
	}

	// ── Batch execution ──────────────────────────────────────────────────────────

	/// <summary>
	/// Deletes at most <paramref name="batch"/> rows of one step inside a single transaction and writes
	/// the matching ledger row in the same transaction. The pairing is what makes the ledger exact: a
	/// batch either commits both the deletion and its tombstone, or commits neither.
	/// </summary>
	private static async Task<RetentionBatchResult> ExecuteBatchAsync(
		AuditDbContext db,
		SqliteConnection connection,
		RetentionPlanStep step,
		int batch,
		DateTime minAgeCutoffUtc,
		EventDeletionTrigger trigger,
		string ledgerReason,
		CancellationToken cancellationToken)
	{
		bool perIp = step.Key.IpBinary16 is not null;
		await using IDbContextTransaction transaction =
			await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		try
		{
			using SqliteCommand delete = connection.CreateCommand();
			delete.Transaction = (SqliteTransaction)transaction.GetDbTransaction();
			SetCommandText(delete, BuildDeleteSql(perIp));
			BindCandidateParameters(
				delete,
				step.Key,
				perIp,
				new RetentionRow(step.AnchorRowId, step.AnchorTimeUtc),
				new RetentionRow(step.TailBoundaryRowId, step.TailBoundaryTimeUtc),
				step.LowestRowId,
				step.HighestRowId,
				minAgeCutoffUtc);
			delete.Parameters.AddWithValue("$batch", batch);

			long deleted = 0;
			DateTime windowStartUtc = default;
			DateTime windowEndUtc = default;
			await using (SqliteDataReader reader =
				await delete.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
			{
				while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
				{
					DateTime timeUtc = reader.GetDateTime(0);
					if (deleted == 0 || timeUtc < windowStartUtc)
					{
						windowStartUtc = timeUtc;
					}

					if (deleted == 0 || timeUtc > windowEndUtc)
					{
						windowEndUtc = timeUtc;
					}

					deleted++;
				}
			}

			if (deleted == 0)
			{
				await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
				return new RetentionBatchResult(0, 0);
			}

			long protectedRows = await CountLinkedEvidenceRowsInWindowAsync(
				connection,
				transaction,
				step,
				perIp,
				windowStartUtc,
				windowEndUtc,
				cancellationToken).ConfigureAwait(false);

			DateTime createdUtc = DateTime.UtcNow;
			LedgerChainEntry ledgerEntry = new(
				step.Key.EventId,
				(int)(perIp ? EventDeletionScope.PerIp : EventDeletionScope.Global),
				step.Key.IpBinary16,
				windowStartUtc,
				windowEndUtc,
				deleted,
				(int)trigger,
				RetentionRuleVersion.Current,
				ledgerReason,
				ServiceActor,
				createdUtc);

			// The chain link is read inside the same transaction as the delete, so two concurrent passes
			// cannot both extend the chain from the same head: the second one either sees the committed
			// hash or blocks behind this transaction.
			SqliteTransaction sqliteTransaction = (SqliteTransaction)transaction.GetDbTransaction();
			string previousHash = await EventDeletionLedgerWriter
				.ReadChainHeadAsync(connection, sqliteTransaction, cancellationToken)
				.ConfigureAwait(false);
			await EventDeletionLedgerWriter
				.AppendAsync(connection, sqliteTransaction, ledgerEntry, previousHash, cancellationToken)
				.ConfigureAwait(false);

			await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
			return new RetentionBatchResult(deleted, protectedRows);
		}
		catch
		{
			await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
			throw;
		}
	}

	/// <summary>Counts rows still present in the just-processed window that alert evidence references, so
	/// an operator can see that the linked-evidence guard actually withheld something.</summary>
	private static async Task<long> CountLinkedEvidenceRowsInWindowAsync(
		SqliteConnection connection,
		IDbContextTransaction transaction,
		RetentionPlanStep step,
		bool perIp,
		DateTime windowStartUtc,
		DateTime windowEndUtc,
		CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.Transaction = (SqliteTransaction)transaction.GetDbTransaction();
		SetCommandText(command,
			"SELECT COUNT(*) FROM \"RawEvents\" AS re" +
			BuildCodeWhere(perIp) +
			" AND re.\"TimeUtc\" >= $windowStart AND re.\"TimeUtc\" <= $windowEnd" +
			" AND (" + LinkedEvidenceExists + ");");
		BindCodeParameters(command, step.Key, perIp);
		command.Parameters.AddWithValue("$windowStart", windowStartUtc);
		command.Parameters.AddWithValue("$windowEnd", windowEndUtc);
		command.Parameters.AddWithValue("$lowestRowId", step.LowestRowId);
		command.Parameters.AddWithValue("$highestRowId", step.HighestRowId);
		object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return result is long count ? count : 0L;
	}

	// ── SQL composition ──────────────────────────────────────────────────────────

	/// <summary>
	/// Existence test for alert evidence that references a raw-event row. Two tables hold a real
	/// reference to <c>RawEvents.Id</c> - <c>AuthAttemptFacts.EvidenceRawEventId</c> and
	/// <c>ProcessObservations.RawEventId</c> - so both are honoured, bounded by the code's surrogate-key
	/// span so the subquery can only see rows that could point into this code. The tables that hold no
	/// row-level reference (alerts, active blocks, cross-host chains, process alert responses) are
	/// matched by the code and the deletion window instead; see the retention runbook for the limits of
	/// that approximation.
	/// </summary>
	private const string LinkedEvidenceExists =
		"EXISTS (SELECT 1 FROM \"AuthAttemptFacts\" AS f" +
		" WHERE f.\"EvidenceRawEventId\" = re.\"Id\"" +
		" AND f.\"EvidenceRawEventId\" BETWEEN $lowestRowId AND $highestRowId)" +
		" OR EXISTS (SELECT 1 FROM \"ProcessObservations\" AS o" +
		" WHERE o.\"RawEventId\" = re.\"Id\"" +
		" AND o.\"RawEventId\" BETWEEN $lowestRowId AND $highestRowId)";

	private const string LinkedEvidenceGuard = " AND NOT (" + LinkedEvidenceExists + ")";

	private static string BuildCodeWhere(bool perIp)
		=> perIp
			? " WHERE re.\"EventId\" = $eventId AND re.\"Channel\" = $channel AND re.\"SourceIpBinary\" = $ipBinary"
			: " WHERE re.\"EventId\" = $eventId AND re.\"Channel\" = $channel";

	/// <summary>
	/// The exact definition of a deletable interior row, shared by the density count, the candidate
	/// fetch and the delete statement so the three can never drift apart: the code, an age floor, an
	/// exclusive lower bound at the anchor, an exclusive upper bound at the oldest protected tail row,
	/// and no reference from alert evidence.
	/// </summary>
	private static string BuildCandidatePredicate(bool perIp)
		=> BuildCodeWhere(perIp) +
			" AND re.\"TimeUtc\" < $minAgeCutoff" +
			" AND (re.\"TimeUtc\" > $anchorTime OR (re.\"TimeUtc\" = $anchorTime AND re.\"Id\" > $anchorId))" +
			" AND (re.\"TimeUtc\" < $tailTime OR (re.\"TimeUtc\" = $tailTime AND re.\"Id\" < $tailId))" +
			LinkedEvidenceGuard;

	private static string BuildDeleteSql(bool perIp)
		=> "DELETE FROM \"RawEvents\" WHERE \"Id\" IN (" +
			"SELECT re.\"Id\" FROM \"RawEvents\" AS re" +
			BuildCandidatePredicate(perIp) +
			" ORDER BY re.\"TimeUtc\", re.\"Id\" LIMIT $batch" +
			") RETURNING \"TimeUtc\";";

	private static void BindCodeParameters(SqliteCommand command, RetentionCodeKey key, bool perIp)
	{
		command.Parameters.AddWithValue("$eventId", key.EventId);
		command.Parameters.AddWithValue("$channel", key.Channel);
		if (perIp)
		{
			command.Parameters.Add(new SqliteParameter("$ipBinary", (object?)key.IpBinary16 ?? DBNull.Value));
		}
	}

	private static void BindCandidateParameters(
		SqliteCommand command,
		RetentionCodeKey key,
		bool perIp,
		RetentionRow anchor,
		RetentionRow tailBoundary,
		long lowestRowId,
		long highestRowId,
		DateTime minAgeCutoffUtc)
	{
		BindCodeParameters(command, key, perIp);
		command.Parameters.AddWithValue("$minAgeCutoff", minAgeCutoffUtc);
		command.Parameters.AddWithValue("$anchorTime", anchor.TimeUtc);
		command.Parameters.AddWithValue("$anchorId", anchor.Id);
		command.Parameters.AddWithValue("$tailTime", tailBoundary.TimeUtc);
		command.Parameters.AddWithValue("$tailId", tailBoundary.Id);
		command.Parameters.AddWithValue("$lowestRowId", lowestRowId);
		command.Parameters.AddWithValue("$highestRowId", highestRowId);
	}

	private static string BuildLedgerReason(RetentionPlanStep step, EventDeletionTrigger trigger)
		=> "IDR-" + RetentionRuleVersion.Current.ToString(CultureInfo.InvariantCulture) +
			" information-density retention; trigger=" + trigger.ToString() +
			"; code=" + step.Key.Describe();

	/// <summary>
	/// Assigns a composed statement to a command. The statements this engine composes are built
	/// exclusively from constant fragments: no identifier and no literal ever comes from configuration,
	/// from an event payload or from an operator, and every value - code, timestamp, row bound, batch
	/// size - travels as a bound parameter. The CA2100 review therefore resolves to "not injectable",
	/// and the single reviewed site is kept here rather than scattered over six call sites.
	/// </summary>
	private static void SetCommandText(SqliteCommand command, string sql)
	{
#pragma warning disable CA2100 // Reviewed: composed from constant fragments only; all values are bound parameters.
		command.CommandText = sql;
#pragma warning restore CA2100
	}

	// ── Internal model ───────────────────────────────────────────────────────────

	/// <summary>One eligible code as reported by the GROUP BY statistics query.</summary>
	private readonly record struct CodeStatistic(
		RetentionCodeKey Key,
		long TotalRows,
		long LowestRowId,
		long HighestRowId);
}
