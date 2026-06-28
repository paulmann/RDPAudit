// File:    src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Reads newly raised Alerts and applies the Stage 3 auto-block policy:
//          1. Skip when source IP is missing / invalid.
//          2. Skip when IP is in WhitelistEntries / Firewall.Whitelist / Firewall.WhitelistIps.
//          3. Block brute-force when FailCount exceeds AutoBlockThreshold and no active block exists.
//          4. Block when login is blacklisted and BlockOnBlacklistedLogin is enabled.
//          5. Block when login matches InstantBlockLogins (case-insensitive trip-wires).
//          Writes ActiveBlocks + BlocklistEntries rows with UTC timestamps, provider, reason,
//          expiration, and linked alert id.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.1

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

		// Resume from the current high-water mark so we do not double-process pre-existing alerts.
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

		// Snapshot whitelist / blacklist / login-rule state once per batch to amortise the cost.
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

		// Parse every CIDR-shaped whitelist entry (DB + config) once per batch so a whole private range
		// (e.g. 10.0.0.0/8, fc00::/7) exempts its members from auto-blocking, not just literal hosts.
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

			await ApplyBlockAsync(db, alert, decision, cfg, ct).ConfigureAwait(false);
			TouchDebounce(decision.NormalizedIp, cfg.AutoBlockDebounceSeconds);

			if (string.Equals(decision.ReasonTag, "InstantLogin", StringComparison.Ordinal))
			{
				await RecordTripWireFiringAsync(db, alert, decision, ct).ConfigureAwait(false);
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		_lastProcessedAlertId = batch[^1].Id;
		return processed;
	}

	private async Task ApplyBlockAsync(
		AuditDbContext db,
		Alert alert,
		AutoBlockDecision decision,
		FirewallOptions cfg,
		CancellationToken ct)
	{
		string ip = decision.NormalizedIp!;
		FirewallProviderKind providerKind = cfg.Provider;

		// v1.4.1: DEBUG trace of the resolved decision so an operator running with LogLevel=Debug can see
		// exactly which rule fired, the resolved action / reason tag, the target provider kind and backend.
		_logger.LogDebug(
			"Auto-block applying for {Ip}: action={Action} reasonTag={ReasonTag} alert={AlertId} providerKind={ProviderKind} backend={Backend}",
			ip,
			decision.Action,
			decision.ReasonTag,
			alert.Id,
			providerKind,
			cfg.EnforcementBackend);

		// Active block guard: if any provider already has an active block we keep it and skip.
		bool alreadyActive = await db.ActiveBlocks
			.AnyAsync(b => b.Ip == ip
				&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending),
				ct).ConfigureAwait(false);

		if (alreadyActive)
		{
			_logger.LogDebug("Auto-block already active for {Ip}; skipping", ip);
			return;
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
			return;
		}

		DateTime nowUtc = DateTime.UtcNow;
		// Auto-blocks ALWAYS expire: a runaway or stale policy must never leave a host permanently
		// firewalled off an IP it can no longer justify. A non-positive configured duration falls back
		// to AutoBlockPolicy.FallbackBlockDurationMinutes rather than producing a permanent block —
		// only manual operator blocks are allowed to be "Never".
		DateTime expiresUtc = nowUtc.AddMinutes(AutoBlockPolicy.ResolveBlockDurationMinutes(cfg.DefaultBlockDurationMinutes));
		string reason = string.Format(
			CultureInfo.InvariantCulture,
			"{0}: alert {1}",
			decision.ReasonTag,
			alert.RuleId);

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

		if (providerKind == FirewallProviderKind.None)
		{
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
			return;
		}

		string ruleName = string.IsNullOrWhiteSpace(cfg.BlockRuleName) ? "RdpAudit-Block" : cfg.BlockRuleName;
		TimeSpan duration = expiresUtc - nowUtc;
		FirewallBlockRequest request = new(ip, ruleName)
		{
			Duration = duration,
			Reason = reason,
		};

		// Fan-out: when configured Both, drive Windows then MikroTik with one ActiveBlock row each so
		// every rule has its own RuleHandle and can be expired by FirewallExpirationWorker on its own.
		List<FirewallProviderKind> targets = providerKind == FirewallProviderKind.Both
			? new List<FirewallProviderKind> { FirewallProviderKind.Windows, FirewallProviderKind.MikroTik }
			: new List<FirewallProviderKind> { providerKind };

		foreach (FirewallProviderKind target in targets)
		{
			ActiveBlock active = new()
			{
				Ip = ip,
				Provider = target,
				CreatedUtc = nowUtc,
				ExpiresUtc = expiresUtc,
				Reason = reason,
				Status = ActiveBlockStatus.Pending,
			};
			db.ActiveBlocks.Add(active);

			IFirewallProvider? provider = ResolveProvider(target, cfg.EnforcementBackend);
			if (provider is null)
			{
				active.Status = ActiveBlockStatus.Failed;
				active.LastError = "No firewall provider registered for the configured provider kind / backend.";
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
					active.Status = ActiveBlockStatus.Active;
					active.RuleHandle = result.RuleId;
					_logger.LogInformation(
						"Auto-block installed for {Ip} provider={Provider} rule={Rule}",
						ip,
						provider.ProviderId,
						result.RuleId);
				}
				else
				{
					active.Status = ActiveBlockStatus.Failed;
					active.LastError = result.Message;
					_logger.LogWarning(
						"Auto-block provider returned {Status} for {Ip}: {Message}",
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
				active.Status = ActiveBlockStatus.Failed;
				active.LastError = ex.Message;
				_logger.LogError(ex, "Auto-block provider threw for {Ip}", ip);
			}
		}
	}

	/// <summary>Increments per-rule trip-wire telemetry (TriggerCount / First / Last / LastSourceIp) for
	/// the enabled <see cref="LoginRule"/> whose login matched the firing alert. Config-only trip-wires
	/// (<see cref="FirewallOptions.InstantBlockLogins"/>) have no DB row and are silently ignored.</summary>
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

		// The policy folds DB logins to their stored (lower-cased) key, so a direct match should hit;
		// fall back to a case-insensitive client-side match for any legacy mixed-case rows.
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
	/// <see cref="FirewallOptions.DefaultBlockDurationMinutes"/> at zero / negative. Auto-blocks must
	/// always expire (see <see cref="ResolveBlockDurationMinutes"/>); only manual blocks may be
	/// permanent, so this guarantees a bounded, self-healing auto-block.</summary>
	public const int FallbackBlockDurationMinutes = 60;

	/// <summary>Resolves the effective auto-block duration in minutes. A positive configured value is
	/// honoured verbatim; zero or negative falls back to <see cref="FallbackBlockDurationMinutes"/> so
	/// an auto-block is never permanent.</summary>
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

		// Whitelist precedence: an exact-literal hit (fast path) OR membership in any whitelisted CIDR
		// range. Range matching is family-aware, so an IPv4 source is tested only against IPv4 networks
		// and an IPv6 source only against IPv6 networks (e.g. fc00::/7, fd00::/8).
		if (whitelistDb.Contains(normalizedIp)
			|| whitelistConfig.Contains(normalizedIp)
			|| MatchesWhitelistRange(parsed, whitelistRanges))
		{
			return new AutoBlockDecision(AutoBlockAction.Skip, normalizedIp, alert.UserName, string.Empty, "whitelist");
		}

		// 5: instant-login trip-wire (highest priority — explicit operator-supplied honeypots).
		if (!string.IsNullOrWhiteSpace(alert.UserName) && instantLogins.Contains(alert.UserName!))
		{
			return new AutoBlockDecision(
				AutoBlockAction.Block,
				normalizedIp,
				alert.UserName,
				"InstantLogin",
				string.Empty);
		}

		// 4: blacklisted login on a configured Blacklist member.
		if (cfg.BlockOnBlacklistedLogin && !string.IsNullOrWhiteSpace(alert.UserName) && blacklistLiteral.Contains(alert.UserName!))
		{
			return new AutoBlockDecision(
				AutoBlockAction.Block,
				normalizedIp,
				alert.UserName,
				"BlacklistedLogin",
				string.Empty);
		}

		// 3: brute-force class alerts. Both severity High AND a known brute-force rule id qualify.
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

	/// <summary>Parses the CIDR-shaped entries (those containing '/') from a set of whitelist literals into
	/// <see cref="CidrRange"/> objects, silently dropping malformed entries. Single-IP literals are left to
	/// the existing exact-match HashSet path and are not returned here.</summary>
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

	/// <summary>Returns true when the candidate address falls inside any whitelisted CIDR network. The
	/// <see cref="CidrRange.Contains(IPAddress?)"/> test is family-aware, so IPv4 and IPv6 never cross-match.</summary>
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
