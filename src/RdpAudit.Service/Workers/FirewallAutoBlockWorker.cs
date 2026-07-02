/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.4.2
// File   : FirewallAutoBlockWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Reads newly raised Alerts and applies the Stage 3 auto-block policy. Fixed: Failed
//          provider results no longer persist ghost ActiveBlock/BlocklistEntry rows that caused the
//          UI to display IPs as blocked even when no firewall rule existed in the OS store.
// Depends: IFirewallProvider, AuditDbContext, AutoBlockPolicy, IOptionsMonitor<RdpAuditOptions>
// Extends: When adding a new block trigger: extend AutoBlockPolicy.Decide; no changes needed here.

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Firewall;

namespace RdpAudit.Service.Workers;

/// <summary>Reads newly raised Alerts and applies the Stage 3 auto-block policy.</summary>
public sealed class FirewallAutoBlockWorker : BackgroundService
{
	private static readonly TimeSpan IdleDelay = TimeSpan.FromSeconds(5);
	private static readonly TimeSpan ErrorDelay = TimeSpan.FromSeconds(10);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly ILogger<FirewallAutoBlockWorker> _logger;

	private readonly ConcurrentDictionary<string, DateTime> _debounceUntilUtc = new(StringComparer.OrdinalIgnoreCase);

	private long _lastProcessedAlertId;

	public FirewallAutoBlockWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IEnumerable<IFirewallProvider> providers,
		ILogger<FirewallAutoBlockWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(providers);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_providers = providers;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(FirewallAutoBlockWorker));

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(stoppingToken).ConfigureAwait(false);
			_lastProcessedAlertId = await db.Alerts.AsNoTracking().MaxAsync(a => (long?)a.Id, stoppingToken).ConfigureAwait(false) ?? 0L;
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
			return;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to resolve initial high-water alert id; starting from 0");
		}

		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					int processed = await ProcessBatchAsync(stoppingToken).ConfigureAwait(false);
					if (processed == 0)
					{
						await Task.Delay(IdleDelay, stoppingToken).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Auto-block iteration failed");
					await Task.Delay(ErrorDelay, stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(FirewallAutoBlockWorker));
		}
	}

	private async Task<int> ProcessBatchAsync(CancellationToken ct)
	{
		RdpAuditOptions opts = _options.CurrentValue;
		FirewallOptions cfg = opts.Firewall;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<Alert> batch = await db.Alerts.AsNoTracking()
			.Where(a => a.Id > _lastProcessedAlertId)
			.OrderBy(a => a.Id)
			.Take(200)
			.ToListAsync(ct).ConfigureAwait(false);

		if (batch.Count == 0)
		{
			return 0;
		}

		HashSet<string> whitelistDb = (await db.WhitelistEntries.AsNoTracking()
			.Select(w => w.Ip)
			.ToListAsync(ct).ConfigureAwait(false))
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.Select(static s => s.Trim())
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		HashSet<string> instantLogins = cfg.InstantBlockLogins
			.Concat(await db.LoginRules.AsNoTracking()
				.Where(r => r.Enabled)
				.Select(r => r.Login)
				.ToListAsync(ct).ConfigureAwait(false))
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.Select(static s => s.Trim())
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		HashSet<string> blacklistLiteral = cfg.Blacklist
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.Select(static s => s.Trim())
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		HashSet<string> whitelistConfig = cfg.Whitelist.Concat(cfg.WhitelistIps)
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.Select(static s => s.Trim())
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		IReadOnlyList<CidrRange> whitelistRanges = AutoBlockPolicy.BuildWhitelistRanges(
			whitelistDb.Concat(whitelistConfig));

		int processed = 0;
		foreach (Alert alert in batch)
		{
			ct.ThrowIfCancellationRequested();
			processed++;

			AutoBlockDecision decision = AutoBlockPolicy.Decide(
				alert,
				cfg,
				whitelistDb,
				whitelistConfig,
				blacklistLiteral,
				instantLogins,
				whitelistRanges);

			if (decision.Action == AutoBlockAction.Skip)
			{
				_logger.LogDebug(
					"Auto-block skipped alert {AlertId} ip={Ip} reason={Reason}",
					alert.Id,
					alert.SourceIp,
					decision.SkipReason);
				continue;
			}

			if (decision.NormalizedIp is null)
			{
				continue;
			}

			if (IsDebounced(decision.NormalizedIp, cfg.AutoBlockDebounceSeconds))
			{
				_logger.LogDebug("Auto-block debounced for {Ip}", decision.NormalizedIp);
				continue;
			}

			// FIX Bug 1: ApplyBlockAsync now returns bool indicating whether a successful block
			// was installed. SaveChangesAsync is still called once per batch (EF tracks all
			// changes), but Failed provider attempts no longer add ActiveBlock or BlocklistEntry
			// rows — those are only added when the provider confirms Success.
			bool applied = await ApplyBlockAsync(db, alert, decision, cfg, ct).ConfigureAwait(false);
			if (applied)
			{
				TouchDebounce(decision.NormalizedIp, cfg.AutoBlockDebounceSeconds);
			}

			if (applied && string.Equals(decision.ReasonTag, "InstantLogin", StringComparison.Ordinal))
			{
				await RecordTripWireFiringAsync(db, alert, decision, ct).ConfigureAwait(false);
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		// Advance the high-water mark regardless of individual block outcomes: alerts are not
		// retried (the alert itself was processed; only the OS firewall call may have failed).
		// The reconciliation worker handles any missing OS rules independently.
		_lastProcessedAlertId = batch[^1].Id;
		return processed;
	}

	// FIX Bug 1: returns true only when at least one provider installed a successful block.
	// Failed provider calls no longer write ghost ActiveBlock/BlocklistEntry rows to the DB.
	private async Task<bool> ApplyBlockAsync(
		AuditDbContext db,
		Alert alert,
		AutoBlockDecision decision,
		FirewallOptions cfg,
		CancellationToken ct)
	{
		string ip = decision.NormalizedIp!;
		FirewallProviderKind providerKind = cfg.Provider;

		_logger.LogDebug(
			"Auto-block applying for {Ip}: action={Action} reasonTag={ReasonTag} alert={AlertId} providerKind={ProviderKind} backend={Backend}",
			ip,
			decision.Action,
			decision.ReasonTag,
			alert.Id,
			providerKind,
			cfg.EnforcementBackend);

		bool alreadyActive = await db.ActiveBlocks
			.AnyAsync(b => b.Ip == ip
				&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending),
				ct).ConfigureAwait(false);

		if (alreadyActive)
		{
			_logger.LogDebug("Auto-block already active for {Ip}; skipping", ip);
			return false;
		}

		int maxActive = Math.Max(1, cfg.MaxActiveBlocks);
		int activeCount = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);
		if (activeCount >= maxActive)
		{
			_logger.LogWarning(
				"Auto-block refused for {Ip}: MaxActiveBlocks reached ({Count}/{Max})",
				ip,
				activeCount,
				maxActive);
			return false;
		}

		DateTime nowUtc = DateTime.UtcNow;
		DateTime expiresUtc = nowUtc.AddMinutes(AutoBlockPolicy.ResolveBlockDurationMinutes(cfg.DefaultBlockDurationMinutes));
		string reason = string.Format(
			CultureInfo.InvariantCulture,
			"{0}: alert {1}",
			decision.ReasonTag,
			alert.RuleId);

		if (providerKind == FirewallProviderKind.None)
		{
			// Audit-only mode: always record regardless of any OS firewall action.
			bool blockedAlready = await db.BlocklistEntries
				.AnyAsync(b => b.Ip == ip && b.IsEnabled, ct).ConfigureAwait(false);
			if (!blockedAlready)
			{
				db.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = ip,
					Login = decision.LoginForJournal,
					Reason = reason,
					AddedUtc = nowUtc,
					ExpiresUtc = expiresUtc,
					Source = BlocklistSource.Auto,
					LinkedAlertId = alert.Id,
					IsEnabled = true,
				});
			}

			ActiveBlock audit = new()
			{
				Ip = ip,
				Provider = FirewallProviderKind.None,
				CreatedUtc = nowUtc,
				ExpiresUtc = expiresUtc,
				Reason = reason,
				Status = ActiveBlockStatus.AuditOnly,
			};
			db.ActiveBlocks.Add(audit);
			_logger.LogInformation(
				"Auto-block recorded (audit-only) for {Ip} via alert {AlertId}",
				ip,
				alert.Id);
			return true;
		}

		string ruleName = string.IsNullOrWhiteSpace(cfg.BlockRuleName) ? "RdpAudit-Block" : cfg.BlockRuleName;
		TimeSpan duration = expiresUtc - nowUtc;
		FirewallBlockRequest request = new(ip, ruleName)
		{
			Duration = duration,
			Reason = reason,
		};

		List<FirewallProviderKind> targets = providerKind == FirewallProviderKind.Both
			? new List<FirewallProviderKind> { FirewallProviderKind.Windows, FirewallProviderKind.MikroTik }
			: new List<FirewallProviderKind> { providerKind };

		bool anySuccess = false;

		foreach (FirewallProviderKind target in targets)
		{
			IFirewallProvider? provider = ResolveProvider(target, cfg.EnforcementBackend);
			if (provider is null)
			{
				_logger.LogWarning(
					"Auto-block failed for {Ip}: no provider for kind {Kind} backend {Backend}",
					ip,
					target,
					cfg.EnforcementBackend);
				continue;
			}

			try
			{
				FirewallActionResult result = await provider.BlockAsync(request, ct).ConfigureAwait(false);
				if (result.Status == FirewallActionStatus.Success)
				{
					// FIX Bug 1: only add ActiveBlock and BlocklistEntry rows when the OS
					// firewall rule was actually installed and verified. Previously these rows
					// were added unconditionally (before calling the provider), so a Failed
					// result left ghost rows that the UI displayed as 'blocked'.
					ActiveBlock active = new()
					{
						Ip = ip,
						Provider = target,
						CreatedUtc = nowUtc,
						ExpiresUtc = expiresUtc,
						Reason = reason,
						Status = ActiveBlockStatus.Active,
						RuleHandle = result.RuleId,
					};
					db.ActiveBlocks.Add(active);

					bool blockedAlready = await db.BlocklistEntries
						.AnyAsync(b => b.Ip == ip && b.IsEnabled, ct).ConfigureAwait(false);
					if (!blockedAlready)
					{
						db.BlocklistEntries.Add(new BlocklistEntry
						{
							Ip = ip,
							Login = decision.LoginForJournal,
							Reason = reason,
							AddedUtc = nowUtc,
							ExpiresUtc = expiresUtc,
							Source = BlocklistSource.Auto,
							LinkedAlertId = alert.Id,
							IsEnabled = true,
						});
					}

					anySuccess = true;
					_logger.LogInformation(
						"Auto-block installed for {Ip} provider={Provider} rule={Rule}",
						ip,
						provider.ProviderId,
						result.RuleId);
				}
				else
				{
					// Do NOT persist any DB row for a failed block — the IP must NOT appear
					// in the blocked list when the OS firewall rule was never installed.
					_logger.LogWarning(
						"Auto-block provider returned {Status} for {Ip}: {Message} (no DB row written)",
						result.Status,
						ip,
						result.Message);
				}
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				// Do NOT persist a ghost row on exception either.
				_logger.LogError(ex, "Auto-block provider threw for {Ip} (no DB row written)", ip);
			}
		}

		return anySuccess;
	}

	/// <summary>Increments per-rule trip-wire telemetry for the enabled <see cref="LoginRule"/> whose
	/// login matched the firing alert. Config-only trip-wires have no DB row and are silently ignored.</summary>
	private async Task RecordTripWireFiringAsync(
		AuditDbContext db,
		Alert alert,
		AutoBlockDecision decision,
		CancellationToken ct)
	{
		string? login = decision.LoginForJournal;
		if (string.IsNullOrWhiteSpace(login))
		{
			return;
		}

		string trimmed = login.Trim();
		LoginRule? rule = await db.LoginRules
			.FirstOrDefaultAsync(r => r.Enabled && r.Login == trimmed, ct).ConfigureAwait(false);

		if (rule is null)
		{
			List<LoginRule> enabled = await db.LoginRules
				.Where(r => r.Enabled).ToListAsync(ct).ConfigureAwait(false);
			rule = enabled.Find(r => string.Equals(r.Login, trimmed, StringComparison.OrdinalIgnoreCase));
		}

		if (rule is null)
		{
			return;
		}

		DateTime nowUtc = DateTime.UtcNow;
		rule.TriggerCount++;
		rule.FirstTriggeredUtc ??= nowUtc;
		rule.LastTriggeredUtc = nowUtc;
		rule.LastSourceIp = decision.NormalizedIp;
	}

	private IFirewallProvider? ResolveProvider(FirewallProviderKind kind, FirewallEnforcementBackend backend)
	{
		string id = FirewallProviderRouting.ResolveProviderId(kind, backend);
		if (id.Length == 0)
		{
			return null;
		}

		foreach (IFirewallProvider p in _providers)
		{
			if (string.Equals(p.ProviderId, id, StringComparison.OrdinalIgnoreCase))
			{
				return p;
			}
		}
		return null;
	}

	private bool IsDebounced(string ip, int debounceSeconds)
	{
		if (debounceSeconds <= 0)
		{
			return false;
		}

		return _debounceUntilUtc.TryGetValue(ip, out DateTime until) && until > DateTime.UtcNow;
	}

	private void TouchDebounce(string ip, int debounceSeconds)
	{
		if (debounceSeconds <= 0)
		{
			return;
		}
		_debounceUntilUtc[ip] = DateTime.UtcNow.AddSeconds(debounceSeconds);
	}
}

/// <summary>What the Stage 3 auto-block policy decided about a single alert.</summary>
internal enum AutoBlockAction
{
	Skip = 0,
	Block = 1,
}

/// <summary>Single decision returned by <see cref="AutoBlockPolicy.Decide"/>.</summary>
internal readonly record struct AutoBlockDecision(
	AutoBlockAction Action,
	string? NormalizedIp,
	string? LoginForJournal,
	string ReasonTag,
	string SkipReason);

/// <summary>Pure decision function consumed by <see cref="FirewallAutoBlockWorker"/>.</summary>
/// <remarks>
/// Exposed as a separate static for testability — kept free of EF Core types so unit tests can
/// drive it without spinning up SQLite.
/// </remarks>
internal static class AutoBlockPolicy
{
	/// <summary>Duration applied to an auto-block when the operator left
	/// <see cref="FirewallOptions.DefaultBlockDurationMinutes"/> at zero / negative.</summary>
	public const int FallbackBlockDurationMinutes = 60;

	/// <summary>Resolves the effective auto-block duration in minutes.</summary>
	public static int ResolveBlockDurationMinutes(int configuredMinutes)
		=> configuredMinutes > 0 ? configuredMinutes : FallbackBlockDurationMinutes;

	public static AutoBlockDecision Decide(
		Alert alert,
		FirewallOptions cfg,
		HashSet<string> whitelistDb,
		HashSet<string> whitelistConfig,
		HashSet<string> blacklistLiteral,
		HashSet<string> instantLogins,
		IReadOnlyList<CidrRange>? whitelistRanges = null)
	{
		ArgumentNullException.ThrowIfNull(alert);
		ArgumentNullException.ThrowIfNull(cfg);
		ArgumentNullException.ThrowIfNull(whitelistDb);
		ArgumentNullException.ThrowIfNull(whitelistConfig);
		ArgumentNullException.ThrowIfNull(blacklistLiteral);
		ArgumentNullException.ThrowIfNull(instantLogins);

		if (string.IsNullOrWhiteSpace(alert.SourceIp))
		{
			return new AutoBlockDecision(AutoBlockAction.Skip, null, alert.UserName, string.Empty, "no-source-ip");
		}

		if (!IPAddress.TryParse(alert.SourceIp.Trim(), out IPAddress? parsed))
		{
			return new AutoBlockDecision(AutoBlockAction.Skip, null, alert.UserName, string.Empty, "invalid-ip");
		}

		string normalizedIp = parsed.ToString();

		if (whitelistDb.Contains(normalizedIp)
			|| whitelistConfig.Contains(normalizedIp)
			|| MatchesWhitelistRange(parsed, whitelistRanges))
		{
			return new AutoBlockDecision(AutoBlockAction.Skip, normalizedIp, alert.UserName, string.Empty, "whitelist");
		}

		if (!string.IsNullOrWhiteSpace(alert.UserName) && instantLogins.Contains(alert.UserName!))
		{
			return new AutoBlockDecision(
				AutoBlockAction.Block,
				normalizedIp,
				alert.UserName,
				"InstantLogin",
				string.Empty);
		}

		if (cfg.BlockOnBlacklistedLogin && !string.IsNullOrWhiteSpace(alert.UserName) && blacklistLiteral.Contains(alert.UserName!))
		{
			return new AutoBlockDecision(
				AutoBlockAction.Block,
				normalizedIp,
				alert.UserName,
				"BlacklistedLogin",
				string.Empty);
		}

		if (cfg.AutoBlockBruteForce && IsBruteForceClass(alert))
		{
			return new AutoBlockDecision(
				AutoBlockAction.Block,
				normalizedIp,
				alert.UserName,
				"BruteForce",
				string.Empty);
		}

		return new AutoBlockDecision(AutoBlockAction.Skip, normalizedIp, alert.UserName, string.Empty, "no-policy-match");
	}

	private static bool IsBruteForceClass(Alert alert)
	{
		if (alert.RuleId.Length == 0)
		{
			return false;
		}

		return alert.RuleId.StartsWith("BRUTE_FORCE", StringComparison.OrdinalIgnoreCase)
			|| alert.RuleId.StartsWith("KERBEROS_SPRAY", StringComparison.OrdinalIgnoreCase)
			|| alert.RuleId.StartsWith("UNKNOWN_IP_SUCCESS", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Parses CIDR-shaped entries from a set of whitelist literals into <see cref="CidrRange"/>
	/// objects, silently dropping malformed entries.</summary>
	public static IReadOnlyList<CidrRange> BuildWhitelistRanges(IEnumerable<string> literals)
	{
		ArgumentNullException.ThrowIfNull(literals);

		List<CidrRange> ranges = new();
		foreach (string literal in literals)
		{
			if (CidrRange.LooksLikeCidr(literal) && CidrRange.TryParse(literal, out CidrRange? range) && range is not null)
			{
				ranges.Add(range);
			}
		}

		return ranges;
	}

	private static bool MatchesWhitelistRange(IPAddress candidate, IReadOnlyList<CidrRange>? ranges)
	{
		if (ranges is null || ranges.Count == 0)
		{
			return false;
		}

		foreach (CidrRange range in ranges)
		{
			if (range.Contains(candidate))
			{
				return true;
			}
		}

		return false;
	}
}
