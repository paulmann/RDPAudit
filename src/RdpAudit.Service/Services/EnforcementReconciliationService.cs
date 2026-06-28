// File:    src/RdpAudit.Service/Services/EnforcementReconciliationService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Orchestrates live enforcement reconciliation. Reads the database-intended blocks
//          (ActiveBlock rows that are Active / Pending / Failed), live-scans the real backend
//          (Windows Firewall via IFirewallRuleScanner), feeds both into the pure
//          EnforcementReconciler, and projects the result into IPC DTOs. Also implements the two
//          mutating operations the operator can trigger from the result: repairing one block by
//          re-installing its missing/mismatched rule through the owning provider, and the emergency
//          "remove all RdpAudit enforcement" cleanup that deletes every RdpAudit-created firewall
//          rule (and marks the corresponding rows Removed) while never touching unrelated admin
//          rules. RdpAudit never reports an IP as actively blocked unless this reconciliation finds
//          a matching backend object — so the Configurator builds the Active Blocks view from the
//          reconciled DTOs, not from raw DB rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Firewall;

namespace RdpAudit.Service.Services;

/// <summary>Orchestrates live enforcement reconciliation, repair, and emergency cleanup.</summary>
public sealed class EnforcementReconciliationService
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly IFirewallRuleScanner _scanner;
	private readonly ILogger<EnforcementReconciliationService> _logger;
	private readonly TimeProvider _time;

	public EnforcementReconciliationService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IEnumerable<IFirewallProvider> providers,
		IFirewallRuleScanner scanner,
		ILogger<EnforcementReconciliationService> logger,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(providers);
		ArgumentNullException.ThrowIfNull(scanner);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_providers = providers;
		_scanner = scanner;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	/// <summary>Runs one reconciliation pass and returns the aggregate report DTO.</summary>
	public async Task<ReconciliationReportDto> ReconcileAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.Status == ActiveBlockStatus.Active
				|| b.Status == ActiveBlockStatus.Pending
				|| b.Status == ActiveBlockStatus.Failed)
			.OrderByDescending(b => b.CreatedUtc)
			.Take(5000)
			.ToListAsync(ct).ConfigureAwait(false);

		ReconciliationReport report = await BuildReportAsync(rows, cfg, rulePrefix, nowUtc, ct).ConfigureAwait(false);
		ReconciliationReportDto dto = MapReport(report);

		// Join the persisted per-attempt backend detail back onto each reconciled block by id so the
		// diagnostics report can show exactly what the last block attempt ran (never a bare Failed/Failed).
		Dictionary<long, ActiveBlock> rowsById = new();
		foreach (ActiveBlock row in rows)
		{
			rowsById[row.Id] = row;
		}

		foreach (ReconciledBlockDto block in dto.Blocks)
		{
			if (rowsById.TryGetValue(block.ActiveBlockId, out ActiveBlock? row))
			{
				EnrichWithPersistedDetail(block, row);
			}
		}

		return dto;
	}

	/// <summary>Copies the persisted per-attempt backend diagnostics from an ActiveBlock row onto its
	/// reconciled DTO so callers (diagnostics report, Repair grid) see the last attempt's detail.</summary>
	private static void EnrichWithPersistedDetail(ReconciledBlockDto block, ActiveBlock row)
	{
		block.LastError ??= row.LastError;
		block.LastAttemptUtc ??= row.LastAttemptUtc;
		block.BackendCommand ??= row.BackendCommand;
		block.BackendStdoutPreview ??= row.BackendStdoutPreview;
		block.BackendStderrPreview ??= row.BackendStderrPreview;
		block.ExitCode ??= row.ExitCode;
		block.TimedOut ??= row.TimedOut;
		block.DurationMs ??= row.DurationMs;
		block.RuleHandle ??= row.RuleHandle;
		block.ScannerBackend ??= row.ScannerBackend;
		block.VerifierReason ??= row.VerifierReason;
	}

	/// <summary>Reconciles the supplied rows and returns the full reconciled set as ActiveBlockDto so
	/// the Active Blocks view is built from reconciliation results, not raw DB rows.</summary>
	public async Task<List<ActiveBlockDto>> ReconcileToActiveBlockDtosAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		// Only Active/Pending/Failed rows are reconciled against the live scan; Removed/AuditOnly
		// rows are surfaced as-is so the operator still sees their history without a false claim.
		List<ActiveBlock> reconcilable = rows.FindAll(b =>
			b.Status is ActiveBlockStatus.Active or ActiveBlockStatus.Pending or ActiveBlockStatus.Failed);

		ReconciliationReport report = await BuildReportAsync(reconcilable, cfg, rulePrefix, nowUtc, ct).ConfigureAwait(false);

		Dictionary<long, ReconciledBlock> byId = new();
		foreach (ReconciledBlock rb in report.Blocks)
		{
			byId[rb.ActiveBlockId] = rb;
		}

		List<ActiveBlockDto> dtos = new(rows.Count);
		foreach (ActiveBlock row in rows)
		{
			ActiveBlockDto dto = new()
			{
				Id = row.Id,
				Ip = row.Ip,
				Provider = row.Provider,
				RuleHandle = row.RuleHandle,
				CreatedUtc = row.CreatedUtc,
				ExpiresUtc = row.ExpiresUtc,
				Reason = row.Reason,
				Status = row.Status,
				LastError = row.LastError,
				LastAttemptUtc = row.LastAttemptUtc,
				BackendCommand = row.BackendCommand,
				BackendStdoutPreview = row.BackendStdoutPreview,
				BackendStderrPreview = row.BackendStderrPreview,
				ExitCode = row.ExitCode,
				TimedOut = row.TimedOut,
				DurationMs = row.DurationMs,
				ScannerBackend = row.ScannerBackend,
				VerifierReason = row.VerifierReason,
			};

			if (byId.TryGetValue(row.Id, out ReconciledBlock? rb))
			{
				dto.EnforcementBackend = rb.Backend;
				dto.EnforcementObjectId = rb.EnforcementObjectId;
				dto.EnforcementStatus = rb.Status;
				dto.EnforcementConfidence = rb.Confidence;
				dto.LastVerifiedUtc = report.GeneratedUtc;
				dto.RecommendedAction = rb.RecommendedAction;
			}
			else
			{
				// Not reconciled (Removed / AuditOnly): report unknown enforcement, no false claim.
				dto.EnforcementBackend = ResolveBackend(cfg, row.Provider);
				dto.EnforcementStatus = EnforcementStatus.EffectiveUnknown;
				dto.EnforcementConfidence = EnforcementConfidence.Unknown;
				dto.RecommendedAction = "No reconciliation performed for this row state.";
			}

			dtos.Add(dto);
		}

		return dtos;
	}

	/// <summary>Repairs one ActiveBlock row by id: re-installs the missing/mismatched rule through the
	/// owning provider, then re-reconciles and returns the post-repair reconciled row (or a Failed
	/// row when the provider could not re-install it).</summary>
	public async Task<ReconciledBlockDto> RepairAsync(long activeBlockId, CancellationToken ct)
	{
		if (activeBlockId <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(activeBlockId), "ActiveBlock id must be positive.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ActiveBlock? row = await db.ActiveBlocks.FirstOrDefaultAsync(b => b.Id == activeBlockId, ct).ConfigureAwait(false);
		if (row is null)
		{
			return new ReconciledBlockDto
			{
				ActiveBlockId = activeBlockId,
				Status = EnforcementStatus.Failed,
				Confidence = EnforcementConfidence.Failed,
				Detail = "ActiveBlock row not found.",
				RecommendedAction = "Refresh the Active Blocks list; the row may have been removed.",
			};
		}

		// No-op fast path: if the row already reconciles as verifiably Active there is nothing to repair.
		// Skip the backend mutation entirely so Repair (and Repair All) never re-runs New-NetFirewallRule
		// against an already-enforced IP. Confidence ExistsButProviderMayBypass is treated as enforced
		// here because the matching backend rule does exist; a re-block would not improve that.
		DateTime preCheckUtc = _time.GetUtcNow().UtcDateTime;
		ReconciliationReport preCheck = await BuildReportAsync(new List<ActiveBlock> { row }, cfg, rulePrefix, preCheckUtc, ct)
			.ConfigureAwait(false);
		if (preCheck.Blocks.Count > 0
			&& preCheck.Blocks[0].Status == EnforcementStatus.Active
			&& preCheck.Blocks[0].Confidence is EnforcementConfidence.Verified or EnforcementConfidence.ExistsButProviderMayBypass)
		{
			ReconciledBlockDto verified = MapBlock(preCheck.Blocks[0]);
			verified.Detail = "Already verified; no repair required.";
			verified.RecommendedAction = string.IsNullOrEmpty(verified.RecommendedAction)
				? "No action needed; the firewall rule is present and verified."
				: verified.RecommendedAction;
			EnrichWithPersistedDetail(verified, row);
			return verified;
		}

		IFirewallProvider? provider = ResolveProvider(cfg, row.Provider);
		string? repairError = null;
		FirewallActionResult? lastAction = null;
		if (provider is null)
		{
			repairError = "No firewall provider is registered for this block's backend.";
			row.LastAttemptUtc = _time.GetUtcNow().UtcDateTime;
			row.LastError = repairError;
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
		else
		{
			FirewallBlockRequest request = new(row.Ip, cfg.BlockRuleName) { Reason = row.Reason };
			FirewallActionResult action = await provider.BlockAsync(request, ct).ConfigureAwait(false);
			lastAction = action;
			if (action.Status == FirewallActionStatus.Success)
			{
				row.Status = ActiveBlockStatus.Active;
				row.RuleHandle = action.RuleHandle ?? action.RuleId ?? row.RuleHandle;
				row.LastError = null;
			}
			else
			{
				row.Status = ActiveBlockStatus.Failed;
				row.LastError = action.Message ?? action.Status.ToString();
				repairError = action.Message ?? ("Provider returned " + action.Status + ".");
			}

			PersistBackendAttempt(row, action);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		// Re-reconcile just this row so the caller sees verified vs still-missing.
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		ReconciliationReport report = await BuildReportAsync(new List<ActiveBlock> { row }, cfg, rulePrefix, nowUtc, ct)
			.ConfigureAwait(false);

		ReconciledBlock reconciled = report.Blocks.Count > 0
			? report.Blocks[0]
			: new ReconciledBlock(row.Id, row.Ip, row.Provider, ResolveBackend(cfg, row.Provider),
				EnforcementStatus.Failed, EnforcementConfidence.Failed, null, row.ExpiresUtc,
				repairError ?? "Repair did not produce a reconciled row.", "Inspect service logs.");

		ReconciledBlockDto dto = MapBlock(reconciled);
		if (repairError is not null && dto.Detail is null)
		{
			dto.Detail = repairError;
		}

		// Carry the persisted per-IP backend detail so the Repair grid never shows a bare Failed/Failed.
		dto.LastError = row.LastError;
		dto.LastAttemptUtc = row.LastAttemptUtc;
		dto.BackendCommand = row.BackendCommand;
		dto.BackendStdoutPreview = row.BackendStdoutPreview;
		dto.BackendStderrPreview = row.BackendStderrPreview;
		dto.ExitCode = row.ExitCode;
		dto.TimedOut = row.TimedOut;
		dto.DurationMs = row.DurationMs;
		dto.RuleHandle = row.RuleHandle;
		dto.ScannerBackend = row.ScannerBackend;
		dto.VerifierReason = row.VerifierReason;
		if (lastAction is not null)
		{
			dto.RuleName = lastAction.RuleId;
			dto.RuleHandle ??= lastAction.RuleHandle;
			dto.VerifierReason ??= lastAction.VerifierReason;
		}

		return dto;
	}

	/// <summary>Persists the backend-command detail of one block attempt onto the ActiveBlock row so
	/// per-IP diagnostics survive across reconciliation passes. When the backend exited non-zero with an
	/// empty stderr the stdout preview is folded into LastError so a silent exit=1 still carries detail.</summary>
	private void PersistBackendAttempt(ActiveBlock row, FirewallActionResult action)
	{
		row.LastAttemptUtc = _time.GetUtcNow().UtcDateTime;
		row.VerifierReason = action.VerifierReason;

		BackendCommandAttempt? attempt = action.BackendAttempt;
		if (attempt is null)
		{
			row.BackendCommand = null;
			row.BackendStdoutPreview = null;
			row.BackendStderrPreview = null;
			row.ExitCode = null;
			row.TimedOut = null;
			row.DurationMs = null;
			row.ScannerBackend = null;
			return;
		}

		row.BackendCommand = Truncate(attempt.RenderCommandLine(), 2048);
		row.BackendStdoutPreview = Truncate(attempt.StdoutPreview, 1024);
		row.BackendStderrPreview = Truncate(attempt.StderrPreview, 1024);
		row.ExitCode = attempt.ExitCode;
		row.TimedOut = attempt.TimedOut;
		row.DurationMs = attempt.DurationMs;
		row.ScannerBackend = attempt.ScannerBackend;

		// exit=1 with empty stderr: the only failure signal is stdout — make sure LastError carries it.
		if (action.Status != FirewallActionStatus.Success
			&& attempt.StderrPreview.Length == 0
			&& attempt.StdoutPreview.Length > 0
			&& (string.IsNullOrEmpty(row.LastError) || !row.LastError!.Contains(attempt.StdoutPreview, StringComparison.Ordinal)))
		{
			string prefix = string.IsNullOrEmpty(row.LastError) ? string.Empty : row.LastError + " ";
			row.LastError = Truncate(prefix + "stdout: " + attempt.StdoutPreview, 2048);
		}
	}

	private static string? Truncate(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return value;
		}

		return value!.Length <= max ? value : value[..max];
	}

	/// <summary>
	/// Repairs enforcement for one enabled BlockList row: ensures a matching ActiveBlock exists for
	/// the row's IP (creating a Pending row routed to the configured provider when none is found),
	/// then delegates to <see cref="RepairAsync"/> which (re-)installs the backend rule and proves
	/// enforcement by re-reading the firewall. Returns the post-repair reconciled row so the caller
	/// sees verified vs still-missing — never a silent success.
	/// </summary>
	public async Task<ReconciledBlockDto> RepairBlocklistAsync(long blocklistId, CancellationToken ct)
	{
		if (blocklistId <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(blocklistId), "BlockList id must be positive.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;

		long activeBlockId;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			BlocklistEntry? entry = await db.BlocklistEntries
				.FirstOrDefaultAsync(b => b.Id == blocklistId, ct).ConfigureAwait(false);
			if (entry is null)
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row not found.",
					RecommendedAction = "Refresh the BlockList; the row may have been removed.",
				};
			}

			if (!entry.IsEnabled)
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Ip = entry.Ip ?? string.Empty,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row is disabled; enforcement is not expected for disabled rows.",
					RecommendedAction = "Re-enable the row before repairing its enforcement.",
				};
			}

			if (string.IsNullOrWhiteSpace(entry.Ip))
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row has no IP (login-only rule); firewall enforcement does not apply.",
					RecommendedAction = "Login-only rules are enforced by the auth pipeline, not the firewall.",
				};
			}

			activeBlockId = await EnsureActiveBlockAsync(db, entry, cfg, ct).ConfigureAwait(false);
		}

		return await RepairAsync(activeBlockId, ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Repairs enforcement for every enabled BlockList IP row in one pass and returns an aggregate
	/// report (attempted = Blocks.Count, VerifiedCount, UnenforcedCount). Never claims success when
	/// zero rules were installed: the per-row reconciled results carry the exact outcome.
	/// </summary>
	public async Task<ReconciliationReportDto> RepairAllEnabledBlocklistAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;

		List<long> ids;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			ids = await db.BlocklistEntries.AsNoTracking()
				.Where(b => b.IsEnabled && b.Ip != null && b.Ip != string.Empty)
				.OrderByDescending(b => b.AddedUtc)
				.Select(b => b.Id)
				.Take(5000)
				.ToListAsync(ct).ConfigureAwait(false);
		}

		ReconciliationReportDto report = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = _time.GetUtcNow().UtcDateTime,
		};

		foreach (long id in ids)
		{
			ct.ThrowIfCancellationRequested();
			ReconciledBlockDto rb;
			try
			{
				rb = await RepairBlocklistAsync(id, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				// One row's failure must not abort the batch or take the service down; record it as an
				// unenforced partial result and continue with the remaining rows.
				_logger.LogWarning(ex, "Repair All: BlockList row {Id} failed", id);
				rb = new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "Repair failed for this row: " + ex.GetType().Name + ".",
					RecommendedAction = "Inspect the service logs and retry this row individually.",
				};
			}

			report.Blocks.Add(rb);
			if (rb.Status == EnforcementStatus.Active)
			{
				report.VerifiedCount++;
			}
			else
			{
				report.UnenforcedCount++;
			}
		}

		report.Message = report.Blocks.Count == 0
			? "No enabled BlockList IP rows to repair."
			: string.Format(CultureInfo.InvariantCulture,
				"Repaired {0} enabled BlockList row(s): {1} verified enforced, {2} still unenforced.",
				report.Blocks.Count, report.VerifiedCount, report.UnenforcedCount);
		return report;
	}

	/// <summary>
	/// Finds an existing reconcilable ActiveBlock for the entry's IP, or creates a fresh Pending row
	/// routed to the configured provider. Returns the ActiveBlock id to repair. The actual rule
	/// install + verification is performed by <see cref="RepairAsync"/>.
	/// </summary>
	private async Task<long> EnsureActiveBlockAsync(
		AuditDbContext db, BlocklistEntry entry, FirewallOptions cfg, CancellationToken ct)
	{
		string ip = entry.Ip!;
		ActiveBlock? existing = await db.ActiveBlocks
			.Where(b => b.Ip == ip
				&& (b.Status == ActiveBlockStatus.Active
					|| b.Status == ActiveBlockStatus.Pending
					|| b.Status == ActiveBlockStatus.Failed))
			.OrderByDescending(b => b.CreatedUtc)
			.FirstOrDefaultAsync(ct).ConfigureAwait(false);

		if (existing is not null)
		{
			return existing.Id;
		}

		// Route to the configured provider; Both fans out to Windows for the local reconciler (the
		// MikroTik leg is owned by its own provider and reconciled separately).
		FirewallProviderKind target = cfg.Provider == FirewallProviderKind.Both
			? FirewallProviderKind.Windows
			: cfg.Provider;
		if (target == FirewallProviderKind.None)
		{
			target = FirewallProviderKind.Windows;
		}

		ActiveBlock created = new()
		{
			Ip = ip,
			Provider = target,
			CreatedUtc = _time.GetUtcNow().UtcDateTime,
			ExpiresUtc = entry.ExpiresUtc,
			Reason = string.IsNullOrWhiteSpace(entry.Reason) ? "BlockList repair" : entry.Reason,
			Status = ActiveBlockStatus.Pending,
		};
		db.ActiveBlocks.Add(created);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		_logger.LogInformation(
			"BlockList repair created Pending ActiveBlock {Id} for {Ip} via {Provider}",
			created.Id, ip, target);
		return created.Id;
	}

	/// <summary>Emergency cleanup: removes every RdpAudit-created firewall rule discovered live and
	/// marks the corresponding ActiveBlock rows Removed. Never deletes unrelated admin rules — only
	/// rules whose name carries the RdpAudit prefix are touched.</summary>
	public async Task<EnforcementCleanupResultDto> RemoveAllEnforcementAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		EnforcementCleanupResultDto result = new();

		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);

		if (!scan.Scannable)
		{
			result.Message = scan.Note ?? "Firewall could not be scanned; no enforcement objects removed.";
		}
		else if (windows is null)
		{
			result.Message = "Windows firewall provider is not registered; cannot remove rules.";
		}
		else
		{
			HashSet<string> removedIps = new(StringComparer.OrdinalIgnoreCase);
			foreach (DiscoveredBlockRule rule in scan.Rules)
			{
				string ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty;
				if (ip.Length == 0)
				{
					continue;
				}

				FirewallActionResult action;
				try
				{
					action = await windows.UnblockAsync(ip, cfg.BlockRuleName, ct).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception ex)
				{
					result.Failures++;
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Failed to remove rule {0}: {1}", rule.RuleName, ex.GetType().Name));
					_logger.LogWarning(ex, "Emergency cleanup failed to remove rule {RuleName}", rule.RuleName);
					continue;
				}

				if (action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound)
				{
					result.FirewallRulesRemoved++;
					removedIps.Add(ip);
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Removed firewall rule {0} ({1}).", rule.RuleName, ip));
				}
				else
				{
					result.Failures++;
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Provider returned {0} removing rule {1}.", action.Status, rule.RuleName));
				}
			}

			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			List<ActiveBlock> activeRows = await db.ActiveBlocks
				.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				.ToListAsync(ct).ConfigureAwait(false);
			foreach (ActiveBlock row in activeRows)
			{
				row.Status = ActiveBlockStatus.Removed;
				row.LastError = "Removed by emergency enforcement cleanup.";
				result.ActiveBlockRowsMarkedRemoved++;
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			result.Message = string.Format(CultureInfo.InvariantCulture,
				"Removed {0} RdpAudit firewall rule(s); marked {1} ActiveBlock row(s) Removed.",
				result.FirewallRulesRemoved,
				result.ActiveBlockRowsMarkedRemoved);
		}

		result.Status = result.Failures > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		_logger.LogInformation(
			"Emergency enforcement cleanup completed: rulesRemoved={Rules} rowsRemoved={Rows} failures={Failures}",
			result.FirewallRulesRemoved,
			result.ActiveBlockRowsMarkedRemoved,
			result.Failures);
		return result;
	}

	/// <summary>Full blacklist cleanup (Req A): soft-disables every currently-enabled BlocklistEntry
	/// (kept for audit, never hard-deleted), then synchronizes enforcement for every IP left without an
	/// enabled entry — marking its Active / Pending / Failed ActiveBlock rows Removed inside the same
	/// transaction, and after the DB state is durably committed removing the RdpAudit-created firewall
	/// rules that backed those IPs plus any safe RdpAudit-owned orphan rules. Only rules carrying the
	/// RdpAudit prefix are ever scanned or removed, so unrelated admin rules are never touched. Every step
	/// is recorded in <see cref="BlocklistClearResultDto.DebugLog"/>; per-step failures are counted and the
	/// pass continues best-effort so a single backend error never aborts the whole cleanup.</summary>
	public async Task<BlocklistClearResultDto> ClearAllBlocklistAsync(CancellationToken ct)
	{
		BlocklistClearResultDto result = new();
		System.Text.StringBuilder log = new();
		void Trace(string line) => log.Append('[')
			.Append(_time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture))
			.Append("] ").Append(line).Append('\n');

		FirewallOptions cfg = _options.CurrentValue.Firewall;
		HashSet<string> clearedIps = new(StringComparer.OrdinalIgnoreCase);

		Trace("ClearAllBlocklist starting.");

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx =
				await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);

			List<BlocklistEntry> enabled = await db.BlocklistEntries
				.Where(b => b.IsEnabled)
				.ToListAsync(ct).ConfigureAwait(false);
			Trace(string.Format(CultureInfo.InvariantCulture,
				"Found {0} enabled BlocklistEntry row(s).", enabled.Count));

			foreach (BlocklistEntry row in enabled)
			{
				row.IsEnabled = false;
				result.BlocklistRowsAffected++;
				if (!string.IsNullOrEmpty(row.Ip))
				{
					clearedIps.Add(row.Ip);
				}
			}

			Trace(string.Format(CultureInfo.InvariantCulture,
				"Soft-disabled {0} row(s) across {1} distinct IP(s).", result.BlocklistRowsAffected, clearedIps.Count));

			// For each cleared IP that has no remaining enabled row, mark its reconcilable ActiveBlock
			// rows Removed in the same transaction. (After the bulk disable above none remain enabled,
			// so every cleared IP qualifies.)
			if (clearedIps.Count > 0)
			{
				List<ActiveBlock> blocks = await db.ActiveBlocks
					.Where(b => clearedIps.Contains(b.Ip)
						&& (b.Status == ActiveBlockStatus.Active
							|| b.Status == ActiveBlockStatus.Pending
							|| b.Status == ActiveBlockStatus.Failed))
					.ToListAsync(ct).ConfigureAwait(false);
				foreach (ActiveBlock block in blocks)
				{
					block.Status = ActiveBlockStatus.Removed;
					block.LastError = "Removed by full blacklist cleanup.";
					result.ActiveBlocksRemoved++;
				}

				Trace(string.Format(CultureInfo.InvariantCulture,
					"Marked {0} ActiveBlock row(s) Removed.", result.ActiveBlocksRemoved));
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
			await tx.CommitAsync(ct).ConfigureAwait(false);
			Trace("DB transaction committed.");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "ClearAllBlocklist DB phase failed");
			result.Errors++;
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Database error while clearing the blacklist; no firewall change was made.";
			Trace("DB phase exception: " + ex.GetType().Name + ": " + ex.Message);
			result.DebugLog = log.ToString();
			return result;
		}

		result.IpsSynchronized = clearedIps.Count;

		// Firewall phase: remove the RdpAudit-created rules backing the cleared IPs plus safe orphans.
		// Runs after the DB state is durably committed so a backend failure cannot leave an enabled row
		// with no rule. A scan failure or per-rule failure is counted, never thrown.
		if (clearedIps.Count > 0)
		{
			try
			{
				await RemoveLiveFirewallForIpsAsync(clearedIps, cfg, result, Trace, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "ClearAllBlocklist firewall phase failed");
				result.Errors++;
				Trace("Firewall phase exception: " + ex.GetType().Name + ": " + ex.Message);
			}
		}

		result.Status = result.Errors > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		result.Message = string.Format(CultureInfo.InvariantCulture,
			"Disabled {0} blacklist row(s) across {1} IP(s); marked {2} active block(s) Removed; removed {3} firewall rule(s) and {4} orphan rule(s). Errors: {5}.",
			result.BlocklistRowsAffected, result.IpsSynchronized, result.ActiveBlocksRemoved,
			result.FirewallRulesRemoved, result.OrphanRulesRemoved, result.Errors);
		Trace("Result: " + result.Message);
		result.DebugLog = log.ToString();
		_logger.LogInformation(
			"ClearAllBlocklist completed: rows={Rows} ips={Ips} activeBlocks={Abr} firewall={Fwr} orphans={Orph} errors={Err}",
			result.BlocklistRowsAffected, result.IpsSynchronized, result.ActiveBlocksRemoved,
			result.FirewallRulesRemoved, result.OrphanRulesRemoved, result.Errors);
		return result;
	}

	/// <summary>DEBUG-gated full firewall cleanup (Req B): removes every RdpAudit-owned firewall rule
	/// discovered live (matched strictly by the RdpAudit prefix) and synchronizes the database by marking
	/// every Active / Pending / Failed ActiveBlock row Removed. Unrelated admin rules are never touched and
	/// the BlocklistEntry table is never modified. Per-rule failures are counted and the pass continues
	/// best-effort; each step is recorded in <see cref="FirewallClearResultDto.DebugLog"/>.</summary>
	public async Task<FirewallClearResultDto> ClearAllRdpAuditFirewallAsync(CancellationToken ct)
	{
		FirewallClearResultDto result = new();
		System.Text.StringBuilder log = new();
		void Trace(string line) => log.Append('[')
			.Append(_time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture))
			.Append("] ").Append(line).Append('\n');

		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		Trace("ClearAllRdpAuditFirewall starting; prefix=" + rulePrefix + ".");

		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);

		if (!scan.Scannable)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = scan.Note ?? "Firewall could not be scanned; no rules removed.";
			Trace("Firewall not scannable: " + result.Message);
			result.DebugLog = log.ToString();
			return result;
		}

		if (windows is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Windows firewall provider is not registered; cannot remove rules.";
			Trace(result.Message);
			result.DebugLog = log.ToString();
			return result;
		}

		result.FirewallRulesFound = scan.Rules.Count;
		Trace(string.Format(CultureInfo.InvariantCulture,
			"Scanned firewall ({0}); found {1} RdpAudit rule(s).", scan.Backend, result.FirewallRulesFound));

		foreach (DiscoveredBlockRule rule in scan.Rules)
		{
			ct.ThrowIfCancellationRequested();
			string ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty;
			if (ip.Length == 0)
			{
				Trace("Skipping rule " + rule.RuleName + " (no remote IP parsed).");
				continue;
			}

			try
			{
				FirewallActionResult action = await windows.UnblockAsync(ip, cfg.BlockRuleName, ct).ConfigureAwait(false);
				if (action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound)
				{
					result.FirewallRulesRemoved++;
					Trace(string.Format(CultureInfo.InvariantCulture,
						"Removed firewall rule {0} ({1}); status={2}.", rule.RuleName, ip, action.Status));
				}
				else
				{
					result.Errors++;
					Trace(string.Format(CultureInfo.InvariantCulture,
						"Provider returned {0} removing rule {1} ({2}).", action.Status, rule.RuleName, ip));
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				result.Errors++;
				Trace(string.Format(CultureInfo.InvariantCulture,
					"Failed to remove rule {0}: {1}.", rule.RuleName, ex.GetType().Name));
				_logger.LogWarning(ex, "ClearAllRdpAuditFirewall failed to remove rule {RuleName}", rule.RuleName);
			}
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			List<ActiveBlock> activeRows = await db.ActiveBlocks
				.Where(b => b.Status == ActiveBlockStatus.Active
					|| b.Status == ActiveBlockStatus.Pending
					|| b.Status == ActiveBlockStatus.Failed)
				.ToListAsync(ct).ConfigureAwait(false);
			foreach (ActiveBlock row in activeRows)
			{
				row.Status = ActiveBlockStatus.Removed;
				row.LastError = "Removed by full firewall cleanup.";
				result.ActiveBlocksUpdated++;
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
			Trace(string.Format(CultureInfo.InvariantCulture,
				"Marked {0} ActiveBlock row(s) Removed.", result.ActiveBlocksUpdated));
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			result.Errors++;
			Trace("ActiveBlock sync exception: " + ex.GetType().Name + ": " + ex.Message);
			_logger.LogWarning(ex, "ClearAllRdpAuditFirewall ActiveBlock sync failed");
		}

		result.Status = result.Errors > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		result.Message = string.Format(CultureInfo.InvariantCulture,
			"Found {0} RdpAudit firewall rule(s); removed {1}; marked {2} active block(s) Removed. Errors: {3}.",
			result.FirewallRulesFound, result.FirewallRulesRemoved, result.ActiveBlocksUpdated, result.Errors);
		Trace("Result: " + result.Message);
		result.DebugLog = log.ToString();
		_logger.LogInformation(
			"ClearAllRdpAuditFirewall completed: found={Found} removed={Removed} activeBlocks={Abr} errors={Err}",
			result.FirewallRulesFound, result.FirewallRulesRemoved, result.ActiveBlocksUpdated, result.Errors);
		return result;
	}

	/// <summary>Removes every live RdpAudit firewall rule whose remote IP is in <paramref name="ips"/>
	/// through the owning provider, counting the first removal per IP as a firewall rule and any further
	/// matches as orphan rules. Only RdpAudit-prefixed rules are scanned, so unrelated admin rules are
	/// never touched. Per-rule failures are counted into <see cref="BlocklistClearResultDto.Errors"/> and
	/// never thrown, so one bad rule cannot abort the whole cleanup.</summary>
	private async Task RemoveLiveFirewallForIpsAsync(
		HashSet<string> ips, FirewallOptions cfg, BlocklistClearResultDto result, Action<string> trace, CancellationToken ct)
	{
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);
		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		if (windows is null)
		{
			trace("Windows firewall provider not registered; skipping live rule removal.");
			return;
		}

		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);
		if (!scan.Scannable)
		{
			trace("Firewall not scannable (" + (scan.Note ?? "no detail") + "); skipping live rule removal.");
			return;
		}

		HashSet<string> firstRemovedForIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (DiscoveredBlockRule rule in scan.Rules)
		{
			ct.ThrowIfCancellationRequested();
			string? matchIp = rule.RemoteIps
				.FirstOrDefault(x => ips.Contains(x));
			if (matchIp is null)
			{
				continue;
			}

			try
			{
				FirewallActionResult action = await windows.UnblockAsync(matchIp, cfg.BlockRuleName, ct).ConfigureAwait(false);
				if (action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound)
				{
					if (firstRemovedForIp.Add(matchIp))
					{
						result.FirewallRulesRemoved++;
					}
					else
					{
						result.OrphanRulesRemoved++;
					}

					trace(string.Format(CultureInfo.InvariantCulture,
						"Removed firewall rule {0} for {1} (status={2}).", rule.RuleName, matchIp, action.Status));
				}
				else
				{
					result.Errors++;
					trace(string.Format(CultureInfo.InvariantCulture,
						"Provider returned {0} removing rule {1} for {2}.", action.Status, rule.RuleName, matchIp));
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				result.Errors++;
				trace(string.Format(CultureInfo.InvariantCulture,
					"Failed to remove rule {0} for {1}: {2}.", rule.RuleName, matchIp, ex.GetType().Name));
			}
		}
	}

	/// <summary>Removes exactly one selected BlockList row by its stable surrogate id and synchronizes
	/// the ActiveBlock / live firewall rule only when that row was the last enabled BlockList row for its
	/// IP. The row is soft-disabled (kept for audit, never hard-deleted). Behaviour:
	/// <list type="bullet">
	/// <item>Already-disabled row: re-affirm disabled, never touch the firewall, say so.</item>
	/// <item>Other enabled rows for the same IP remain: do not remove the ActiveBlock or firewall rule.</item>
	/// <item>Last enabled row removed: mark the IP's ActiveBlock row(s) Removed and remove the live
	/// firewall rule(s) through the owning provider; clean orphan rules for the IP.</item>
	/// </list>
	/// The DB mutation runs inside a transaction; the firewall mutation happens after the row state is
	/// durably committed so a backend failure cannot leave an enabled row with no rule silently. Every
	/// step is recorded in <see cref="BlocklistRemovalResultDto.DebugLog"/> for the Diagnostics DEBUG
	/// view. Per-IP exceptions are caught and surfaced as a structured failure; the service stays up.</summary>
	public async Task<BlocklistRemovalResultDto> RemoveBlocklistEntryAsync(
		long selectedId, string? addressHint, CancellationToken ct)
	{
		BlocklistRemovalResultDto result = new() { SelectedId = selectedId };
		System.Text.StringBuilder log = new();
		void Trace(string line) => log.Append('[')
			.Append(_time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture))
			.Append("] ").Append(line).Append('\n');

		Trace(string.Format(CultureInfo.InvariantCulture,
			"RemoveBlocklistEntry selectedId={0} addressHint='{1}'", selectedId, addressHint ?? string.Empty));

		if (selectedId <= 0)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Error = "A positive BlockList row id is required.";
			result.Message = result.Error;
			result.DebugLog = log.ToString();
			return result;
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string ip;
		bool lastEnabledRemoved;

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx =
				await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);

			BlocklistEntry? target = await db.BlocklistEntries
				.FirstOrDefaultAsync(b => b.Id == selectedId, ct).ConfigureAwait(false);
			if (target is null)
			{
				await tx.RollbackAsync(ct).ConfigureAwait(false);
				result.Status = IpcResultStatus.Unavailable;
				result.Error = string.Format(CultureInfo.InvariantCulture,
					"No BlockList row exists with Id={0}; the grid selection may be stale. Refresh and retry.", selectedId);
				result.Message = result.Error;
				Trace(result.Error);
				result.DebugLog = log.ToString();
				return result;
			}

			ip = target.Ip ?? string.Empty;
			result.Ip = ip;
			result.WasEnabled = target.IsEnabled;
			Trace(string.Format(CultureInfo.InvariantCulture,
				"Targeted row Id={0} ip='{1}' enabled={2} source={3}", target.Id, ip, target.IsEnabled, target.Source));

			if (!target.IsEnabled)
			{
				// Already disabled: do not touch the firewall. Re-affirm the disabled state for idempotency.
				await tx.CommitAsync(ct).ConfigureAwait(false);
				result.RowsAffected = 0;
				result.Status = IpcResultStatus.Success;
				result.Message = string.Format(CultureInfo.InvariantCulture,
					"Row Id={0} for {1} was already disabled; no firewall change was made.", selectedId, ip);
				Trace(result.Message);
				result.DebugLog = log.ToString();
				return result;
			}

			target.IsEnabled = false;
			result.RowsAffected = 1;
			Trace("Soft-disabled the selected row.");

			// Are there OTHER still-enabled BlockList rows for this IP? If so, enforcement must stay.
			bool otherEnabledForIp = !string.IsNullOrEmpty(ip)
				&& await db.BlocklistEntries
					.AnyAsync(b => b.Ip == ip && b.IsEnabled && b.Id != selectedId, ct).ConfigureAwait(false);
			lastEnabledRemoved = !otherEnabledForIp && !string.IsNullOrEmpty(ip);
			Trace(string.Format(CultureInfo.InvariantCulture,
				"otherEnabledRowsForIp={0} lastEnabledRemoved={1}", otherEnabledForIp, lastEnabledRemoved));

			if (lastEnabledRemoved)
			{
				// Mark the IP's reconcilable ActiveBlock row(s) Removed in the same transaction.
				List<ActiveBlock> blocks = await db.ActiveBlocks
					.Where(b => b.Ip == ip
						&& (b.Status == ActiveBlockStatus.Active
							|| b.Status == ActiveBlockStatus.Pending
							|| b.Status == ActiveBlockStatus.Failed))
					.ToListAsync(ct).ConfigureAwait(false);
				foreach (ActiveBlock block in blocks)
				{
					block.Status = ActiveBlockStatus.Removed;
					block.LastError = "Removed: last enabled BlockList row for this IP was removed.";
				}

				result.ActiveBlockRemoved = blocks.Count > 0;
				Trace(string.Format(CultureInfo.InvariantCulture,
					"Marked {0} ActiveBlock row(s) Removed for {1}.", blocks.Count, ip));
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
			await tx.CommitAsync(ct).ConfigureAwait(false);
			Trace("DB transaction committed.");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "RemoveBlocklistEntry DB phase failed for Id={Id}", selectedId);
			result.Status = IpcResultStatus.Unavailable;
			result.Error = "Database error while removing the BlockList row; no firewall change was made.";
			result.Message = result.Error;
			Trace("DB phase exception: " + ex.GetType().Name + ": " + ex.Message);
			result.DebugLog = log.ToString();
			return result;
		}

		// Firewall phase: only when the last enabled row for the IP was removed. Runs after the DB state
		// is durably committed so a backend failure cannot leave an enabled row with no rule.
		if (lastEnabledRemoved && !string.IsNullOrEmpty(ip))
		{
			try
			{
				await RemoveLiveFirewallForIpAsync(ip, cfg, result, Trace, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "RemoveBlocklistEntry firewall phase failed for {Ip}", ip);
				result.Status = IpcResultStatus.Unavailable;
				result.Error = "BlockList row removed, but the live firewall rule could not be removed: "
					+ ex.GetType().Name + ".";
				Trace("Firewall phase exception: " + ex.GetType().Name + ": " + ex.Message);
			}
		}

		if (result.Error is null)
		{
			result.Status = IpcResultStatus.Success;
			result.Message = BuildRemovalMessage(result, ip, lastEnabledRemoved);
		}
		else if (string.IsNullOrEmpty(result.Message))
		{
			result.Message = result.Error;
		}

		Trace("Result: " + result.Message);
		result.DebugLog = log.ToString();
		_logger.LogInformation(
			"RemoveBlocklistEntry Id={Id} ip={Ip} rows={Rows} activeBlockRemoved={Abr} firewallRemoved={Fwr} orphans={Orph}",
			selectedId, ip, result.RowsAffected, result.ActiveBlockRemoved, result.FirewallRuleRemoved, result.OrphanRulesRemoved);
		return result;
	}

	private static string BuildRemovalMessage(BlocklistRemovalResultDto r, string ip, bool lastEnabledRemoved)
	{
		if (!lastEnabledRemoved)
		{
			return string.Format(CultureInfo.InvariantCulture,
				"Removed BlockList row Id={0} for {1}; other enabled rows for this IP remain, so enforcement was left in place.",
				r.SelectedId, ip);
		}

		string fw = r.FirewallRuleRemoved
			? "removed the live firewall rule"
			: "no matching live firewall rule was found to remove";
		return string.Format(CultureInfo.InvariantCulture,
			"Removed the last enabled BlockList row Id={0} for {1}; marked the ActiveBlock Removed and {2}{3}.",
			r.SelectedId, ip, fw,
			r.OrphanRulesRemoved > 0
				? string.Format(CultureInfo.InvariantCulture, " ({0} orphan rule(s) cleaned)", r.OrphanRulesRemoved)
				: string.Empty);
	}

	/// <summary>Removes every live RdpAudit firewall rule whose remote IP matches <paramref name="ip"/>
	/// through the owning provider. Only RdpAudit-prefixed rules are scanned, so unrelated admin rules
	/// are never touched. Records each action into the debug trace.</summary>
	private async Task RemoveLiveFirewallForIpAsync(
		string ip, FirewallOptions cfg, BlocklistRemovalResultDto result, Action<string> trace, CancellationToken ct)
	{
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);
		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		if (windows is null)
		{
			trace("Windows firewall provider not registered; skipping live rule removal.");
			return;
		}

		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);
		if (!scan.Scannable)
		{
			trace("Firewall not scannable (" + (scan.Note ?? "no detail") + "); skipping live rule removal.");
			return;
		}

		List<DiscoveredBlockRule> matching = scan.Rules
			.Where(r => r.RemoteIps.Any(x => string.Equals(x, ip, StringComparison.OrdinalIgnoreCase)))
			.ToList();
		trace(string.Format(CultureInfo.InvariantCulture,
			"Scanned firewall ({0}); {1} rule(s) match {2}.", scan.Backend, matching.Count, ip));

		bool first = true;
		foreach (DiscoveredBlockRule rule in matching)
		{
			ct.ThrowIfCancellationRequested();
			FirewallActionResult action = await windows.UnblockAsync(ip, cfg.BlockRuleName, ct).ConfigureAwait(false);
			if (action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound)
			{
				if (first)
				{
					result.FirewallRuleRemoved = true;
					first = false;
				}
				else
				{
					result.OrphanRulesRemoved++;
				}

				trace(string.Format(CultureInfo.InvariantCulture,
					"Removed firewall rule {0} for {1} (status={2}).", rule.RuleName, ip, action.Status));
			}
			else
			{
				trace(string.Format(CultureInfo.InvariantCulture,
					"Provider returned {0} removing rule {1} for {2}.", action.Status, rule.RuleName, ip));
				throw new InvalidOperationException(
					"Provider returned " + action.Status + " removing rule " + rule.RuleName + ".");
			}
		}
	}

	/// <summary>Builds the pure reconciliation report from the supplied DB rows by scanning every
	/// backend that owns at least one row.</summary>
	private async Task<ReconciliationReport> BuildReportAsync(
		List<ActiveBlock> rows,
		FirewallOptions cfg,
		string rulePrefix,
		DateTime nowUtc,
		CancellationToken ct)
	{
		List<DesiredBlock> desired = new(rows.Count);
		HashSet<FirewallProviderKind> providerKinds = new();
		foreach (ActiveBlock row in rows)
		{
			FirewallEnforcementBackend backend = ResolveBackend(cfg, row.Provider);
			desired.Add(new DesiredBlock(
				ActiveBlockId: row.Id,
				Ip: row.Ip,
				Provider: row.Provider,
				Backend: backend,
				RuleHandle: row.RuleHandle,
				CreatedUtc: row.CreatedUtc,
				ExpiresUtc: row.ExpiresUtc,
				Reason: row.Reason,
				RecordedFailed: row.Status == ActiveBlockStatus.Failed));
			providerKinds.Add(row.Provider);
		}

		// Scan the Windows backend once if any desired block (or orphan detection) needs it. Other
		// backends (route / IPsec) are not live-scannable here and are reported as such.
		List<BackendScanResult> scans = new();
		bool needWindows = providerKinds.Count == 0 || providerKinds.Contains(FirewallProviderKind.Windows);
		if (needWindows)
		{
			scans.Add(await ScanWindowsAsync(cfg, rulePrefix, ct).ConfigureAwait(false));
		}

		foreach (FirewallProviderKind kind in providerKinds)
		{
			if (kind == FirewallProviderKind.Windows)
			{
				continue;
			}

			scans.Add(BuildUnscannableScan(kind, cfg));
		}

		return EnforcementReconciler.Reconcile(desired, scans, rulePrefix, nowUtc, NetshCommandBuilder.RdpAuditGroup);
	}

	private async Task<BackendScanResult> ScanWindowsAsync(FirewallOptions cfg, string rulePrefix, CancellationToken ct)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, FirewallProviderKind.Windows);
		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);
		bool thirdPartyMayBypass = await DetectThirdPartyBypassAsync(ct).ConfigureAwait(false);

		string? thirdPartyNote = thirdPartyMayBypass
			? "A third-party provider may control effective enforcement."
			: null;
		string? note = (scan.Note, thirdPartyNote) switch
		{
			(null, null) => null,
			(string s, null) => s,
			(null, string t) => t,
			(string s, string t) => s + " " + t,
		};

		return new BackendScanResult(
			Provider: FirewallProviderKind.Windows,
			Backend: backend,
			ProviderAvailable: scan.Scannable,
			Scannable: scan.Scannable,
			DiscoveredRules: scan.Rules,
			ThirdPartyMayBypass: thirdPartyMayBypass,
			Note: note)
		{
			ScannerBackend = scan.Backend.ToString(),
		};
	}

	private BackendScanResult BuildUnscannableScan(FirewallProviderKind kind, FirewallOptions cfg)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, kind);
		string providerId = FirewallProviderRouting.ResolveProviderId(kind, backend);
		IFirewallProvider? provider = FindProvider(providerId);
		bool available = provider is not null;
		return new BackendScanResult(
			Provider: kind,
			Backend: backend,
			ProviderAvailable: available,
			Scannable: false,
			DiscoveredRules: Array.Empty<DiscoveredBlockRule>(),
			ThirdPartyMayBypass: false,
			Note: kind == FirewallProviderKind.MikroTik
				? "External MikroTik backend is not live-scanned by the local reconciler."
				: "This backend (" + backend + ") cannot be live-scanned for enforcement here.");
	}

	/// <summary>Best-effort detection that a third-party firewall (e.g. Kaspersky) is present and may
	/// control or bypass effective enforcement. Non-Windows hosts always return false.</summary>
	private async Task<bool> DetectThirdPartyBypassAsync(CancellationToken ct)
	{
		if (!OperatingSystem.IsWindows())
		{
			return false;
		}

		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		if (windows is null)
		{
			return false;
		}

		try
		{
			FirewallStatusReport report = await windows.GetStatusAsync(ct).ConfigureAwait(false);
			// A disabled Windows firewall while RdpAudit believes it installed rules strongly implies
			// a third-party stack is managing enforcement; surface the may-bypass caveat.
			return report.Status == FirewallProviderStatus.Disabled;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Third-party bypass detection failed; assuming no third-party interference");
			return false;
		}
	}

	private IFirewallProvider? ResolveProvider(FirewallOptions cfg, FirewallProviderKind kind)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, kind);
		string providerId = FirewallProviderRouting.ResolveProviderId(kind, backend);
		return FindProvider(providerId);
	}

	private IFirewallProvider? FindProvider(string providerId)
	{
		if (string.IsNullOrEmpty(providerId))
		{
			return null;
		}

		foreach (IFirewallProvider provider in _providers)
		{
			if (string.Equals(provider.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
			{
				return provider;
			}
		}

		return null;
	}

	/// <summary>Resolves the enforcement backend for a block: Windows-host blocks honour the
	/// configured local backend; external providers (MikroTik) always use WindowsFirewall as a
	/// neutral placeholder since the local reconciler does not own their objects.</summary>
	private static FirewallEnforcementBackend ResolveBackend(FirewallOptions cfg, FirewallProviderKind kind)
		=> kind == FirewallProviderKind.Windows ? cfg.EnforcementBackend : FirewallEnforcementBackend.WindowsFirewall;

	private static ReconciliationReportDto MapReport(ReconciliationReport report)
	{
		ReconciliationReportDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = report.GeneratedUtc,
			VerifiedCount = report.VerifiedCount,
			UnenforcedCount = report.UnenforcedCount,
			ScannerBackend = report.ScannerBackend,
			ScannerNote = report.ScannerNote,
		};

		foreach (ReconciledBlock b in report.Blocks)
		{
			dto.Blocks.Add(MapBlock(b));
		}

		foreach (ReconciledBlock o in report.Orphans)
		{
			dto.Orphans.Add(MapBlock(o));
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"Reconciled {0} block(s): {1} verified, {2} unenforced, {3} orphan(s).",
			report.Blocks.Count,
			report.VerifiedCount,
			report.UnenforcedCount,
			report.Orphans.Count);
		return dto;
	}

	private static ReconciledBlockDto MapBlock(ReconciledBlock b) => new()
	{
		ActiveBlockId = b.ActiveBlockId,
		Ip = b.Ip,
		Provider = b.Provider,
		Backend = b.Backend,
		Status = b.Status,
		Confidence = b.Confidence,
		EnforcementObjectId = b.EnforcementObjectId,
		ExpiresUtc = b.ExpiresUtc,
		Detail = b.Detail,
		RecommendedAction = b.RecommendedAction,
	};
}
