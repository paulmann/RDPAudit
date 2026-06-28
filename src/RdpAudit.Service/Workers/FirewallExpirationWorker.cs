// File:    src/RdpAudit.Service/Workers/FirewallExpirationWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Sleeps until the earliest ActiveBlocks.ExpiresUtc for a still-active row, then calls
//          the firewall provider to remove the rule and flips the ActiveBlock to Removed.
//          When the table has no due rows it falls back to a bounded delay to keep the worker
//          responsive to config changes without hot-polling SQLite.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.1

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Workers;

/// <summary>Sleeps until the earliest expiring ActiveBlock, then removes it via the firewall provider.</summary>
public sealed class FirewallExpirationWorker : BackgroundService
{
	private static readonly TimeSpan FallbackDelay = TimeSpan.FromMinutes(5);
	private static readonly TimeSpan MinDelay = TimeSpan.FromSeconds(1);
	private static readonly TimeSpan ErrorDelay = TimeSpan.FromSeconds(30);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly ILogger<FirewallExpirationWorker> _logger;

	public FirewallExpirationWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IEnumerable<IFirewallProvider> providers,
		ILogger<FirewallExpirationWorker> logger)
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
		_logger.LogInformation("{Worker} starting", nameof(FirewallExpirationWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					TimeSpan wait = await TickAsync(stoppingToken).ConfigureAwait(false);
					if (wait > TimeSpan.Zero)
					{
						await Task.Delay(wait, stoppingToken).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Expiration iteration failed");
					await Task.Delay(ErrorDelay, stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(FirewallExpirationWorker));
		}
	}

	/// <summary>Performs one tick: removes any expired rows, then returns the wait time until the next due block.</summary>
	internal async Task<TimeSpan> TickAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		DateTime nowUtc = DateTime.UtcNow;
		List<ActiveBlock> due = await db.ActiveBlocks
			.Where(b => (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				&& b.ExpiresUtc != null
				&& b.ExpiresUtc <= nowUtc)
			.OrderBy(b => b.ExpiresUtc)
			.Take(100)
			.ToListAsync(ct).ConfigureAwait(false);

		// v1.4.1: DEBUG trace of the per-tick due set so an operator can see how many blocks the
		// expiration sweep picked up and which IPs are about to be removed when LogLevel=Debug.
		if (_logger.IsEnabled(LogLevel.Debug))
		{
			_logger.LogDebug(
				"Expiration tick at {NowUtc:o}: {DueCount} due block(s) [{Ips}]",
				nowUtc,
				due.Count,
				string.Join(", ", due.Select(b => b.Ip)));
		}

		foreach (ActiveBlock block in due)
		{
			ct.ThrowIfCancellationRequested();
			await ExpireOneAsync(block, ct).ConfigureAwait(false);
		}

		if (due.Count > 0)
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		// Compute next due time.
		DateTime? nextDue = await db.ActiveBlocks.AsNoTracking()
			.Where(b => (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				&& b.ExpiresUtc != null)
			.MinAsync(b => (DateTime?)b.ExpiresUtc, ct).ConfigureAwait(false);

		if (nextDue is null)
		{
			_logger.LogDebug("Expiration sweep idle: no future-dated active blocks; sleeping {Seconds}s", FallbackDelay.TotalSeconds);
			return FallbackDelay;
		}

		TimeSpan delay = nextDue.Value - DateTime.UtcNow;
		if (delay < MinDelay)
		{
			delay = MinDelay;
		}
		if (delay > FallbackDelay)
		{
			delay = FallbackDelay;
		}

		_logger.LogDebug("Next expiration due at {NextDue:o}; sleeping {Seconds:0.###}s", nextDue.Value, delay.TotalSeconds);
		return delay;
	}

	private async Task ExpireOneAsync(ActiveBlock block, CancellationToken ct)
	{
		string ruleName = string.IsNullOrWhiteSpace(_options.CurrentValue.Firewall.BlockRuleName)
			? "RdpAudit-Block"
			: _options.CurrentValue.Firewall.BlockRuleName;

		// v1.4.1: DEBUG trace of the expiry attempt - provider kind, backend, rule name, and
		// expiry timestamp - so a stuck or no-op removal can be diagnosed from the log alone.
		_logger.LogDebug(
			"Expiring block for {Ip}: provider={Provider} backend={Backend} rule={RuleName} expiresUtc={ExpiresUtc:o}",
			block.Ip,
			block.Provider,
			_options.CurrentValue.Firewall.EnforcementBackend,
			ruleName,
			block.ExpiresUtc);

		if (block.Provider == FirewallProviderKind.None || block.Status == ActiveBlockStatus.AuditOnly)
		{
			block.Status = ActiveBlockStatus.Removed;
			_logger.LogInformation("Audit-only block expired for {Ip}", block.Ip);
			return;
		}

		IFirewallProvider? provider = ResolveProvider(block.Provider, _options.CurrentValue.Firewall.EnforcementBackend);
		if (provider is null)
		{
			block.Status = ActiveBlockStatus.Failed;
			block.LastError = "No firewall provider registered for the configured provider kind / backend.";
			_logger.LogWarning(
				"Expiration failed for {Ip}: no provider for kind {Kind}",
				block.Ip,
				block.Provider);
			return;
		}

		try
		{
			FirewallActionResult result = await provider.UnblockAsync(block.Ip, ruleName, ct).ConfigureAwait(false);
			if (result.Status == FirewallActionStatus.Success || result.Status == FirewallActionStatus.NotFound)
			{
				block.Status = ActiveBlockStatus.Removed;
				_logger.LogInformation(
					"Block expired and removed for {Ip} provider={Provider} status={Status}",
					block.Ip,
					provider.ProviderId,
					result.Status);
			}
			else
			{
				block.Status = ActiveBlockStatus.Failed;
				block.LastError = result.Message;
				_logger.LogWarning(
					"Expiration provider returned {Status} for {Ip}: {Message}",
					result.Status,
					block.Ip,
					result.Message);
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			block.Status = ActiveBlockStatus.Failed;
			block.LastError = ex.Message;
			_logger.LogError(ex, "Expiration provider threw for {Ip}", block.Ip);
		}
	}

	private IFirewallProvider? ResolveProvider(FirewallProviderKind kind, FirewallEnforcementBackend backend)
	{
		// Each ActiveBlock row carries exactly one provider kind by Stage 9 — the auto-block worker
		// splits Both into one row per provider so the expiration worker never needs to fan out here.
		// The local Windows kind is dispatched to the configured enforcement backend so the row is
		// unblocked by the same provider that installed it.
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
}
