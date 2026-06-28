// File:    src/RdpAudit.Service/Firewall/MikroTikFirewallProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: IFirewallProvider implementation for MikroTik RouterOS v7. Delegates the actual REST
//          calls to IMikroTikClient and adapts them into the FirewallActionResult shape consumed
//          by the auto-block and expiration workers.
//
//          Guarantees enforced here:
//          • Returns Unavailable / NotConfigured states without ever touching credentials.
//          • Never logs the API password.
//          • Always uses the configured comment prefix so the delete path only removes RdpAudit-
//            owned rules.
//          • Idempotent: AlreadyExists is mapped to FirewallActionStatus.Success with the existing
//            RuleId so the auto-block worker can persist the rule handle either way.
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.MikroTik;

namespace RdpAudit.Service.Firewall;

/// <summary><see cref="IFirewallProvider"/> implementation for MikroTik RouterOS v7.</summary>
public sealed class MikroTikFirewallProvider : IFirewallProvider
{
	private readonly ILogger<MikroTikFirewallProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IMikroTikClient _client;

	public MikroTikFirewallProvider(
		ILogger<MikroTikFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IMikroTikClient client)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(client);
		_logger = logger;
		_options = options;
		_client = client;
	}

	public string ProviderId => "MikroTik";

	public async Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		MikroTikOptions cfg = _options.CurrentValue.MikroTik;

		if (!cfg.Enabled)
		{
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Disabled,
				ProviderId = ProviderId,
				Message = "MikroTik provider is disabled in configuration.",
			};
		}

		if (!HasMinimumConfig(cfg))
		{
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.NotConfigured,
				ProviderId = ProviderId,
				Message = "MikroTik provider is missing endpoint or credentials.",
			};
		}

		MikroTikOperationResult ping = await _client.PingAsync(ct).ConfigureAwait(false);
		return ping.Outcome switch
		{
			MikroTikOutcome.Accepted => new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Available,
				ProviderId = ProviderId,
				Message = "MikroTik REST endpoint reachable.",
			},
			MikroTikOutcome.NotConfigured => new FirewallStatusReport
			{
				Status = FirewallProviderStatus.NotConfigured,
				ProviderId = ProviderId,
				Message = ping.Message,
			},
			_ => new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = ping.Message,
			},
		};
	}

	public async Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();

		MikroTikOptions cfg = _options.CurrentValue.MikroTik;
		if (!cfg.Enabled || !cfg.AddAttackerRules)
		{
			return FirewallActionResult.UnavailableFor(ProviderId,
				cfg.Enabled
					? "MikroTik provider has AddAttackerRules disabled."
					: "MikroTik provider is disabled in configuration.");
		}

		if (!HasMinimumConfig(cfg))
		{
			return FirewallActionResult.UnavailableFor(ProviderId,
				"MikroTik provider is missing endpoint or credentials.");
		}

		string prefix = string.IsNullOrWhiteSpace(cfg.CommentPrefix) ? "RdpAudit" : cfg.CommentPrefix.Trim();
		DateTime nowUtc = DateTime.UtcNow;
		DateTime? expiresUtc = request.Duration.HasValue && request.Duration.Value > TimeSpan.Zero
			? nowUtc + request.Duration.Value
			: null;

		string comment = BuildComment(prefix, request.Reason, nowUtc, expiresUtc, cfg.CommentTemplate);

		MikroTikBlockRequest mtRequest = new()
		{
			Ip = request.Ip,
			Chain = cfg.FilterChain,
			Action = cfg.FilterAction,
			Comment = comment,
			CreatedUtc = nowUtc,
			ExpiresUtc = expiresUtc,
			AddressList = cfg.AddressList,
		};

		MikroTikOperationResult result = await _client.AddBlockAsync(mtRequest, ct).ConfigureAwait(false);
		return MapToFirewallResult(result);
	}

	public async Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		MikroTikOptions cfg = _options.CurrentValue.MikroTik;
		if (!cfg.Enabled)
		{
			return FirewallActionResult.UnavailableFor(ProviderId,
				"MikroTik provider is disabled in configuration.");
		}
		if (!HasMinimumConfig(cfg))
		{
			return FirewallActionResult.UnavailableFor(ProviderId,
				"MikroTik provider is missing endpoint or credentials.");
		}

		MikroTikOperationResult result = await _client.RemoveBlockAsync(null, ip, ct).ConfigureAwait(false);
		return MapToFirewallResult(result);
	}

	public async Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		MikroTikOptions cfg = _options.CurrentValue.MikroTik;
		if (!cfg.Enabled || !HasMinimumConfig(cfg))
		{
			return Array.Empty<FirewallBlockEntry>();
		}

		(MikroTikOperationResult listResult, IReadOnlyList<MikroTikRule> rules) =
			await _client.ListOwnedRulesAsync(ct).ConfigureAwait(false);

		if (listResult.Outcome != MikroTikOutcome.Accepted)
		{
			_logger.LogDebug("MikroTik ListBlocks list call returned {Outcome}", listResult.Outcome);
			return Array.Empty<FirewallBlockEntry>();
		}

		List<FirewallBlockEntry> projected = new(rules.Count);
		foreach (MikroTikRule rule in rules)
		{
			projected.Add(new FirewallBlockEntry
			{
				Ip = rule.Ip,
				RuleId = rule.Id,
				ProviderId = ProviderId,
				Reason = rule.Comment,
			});
		}
		return projected;
	}

	internal static bool HasMinimumConfig(MikroTikOptions cfg)
	{
		ArgumentNullException.ThrowIfNull(cfg);
		string endpoint = cfg.DescribeEndpoint();
		return !string.IsNullOrWhiteSpace(endpoint)
			&& !string.IsNullOrWhiteSpace(cfg.UserName)
			&& !string.IsNullOrWhiteSpace(cfg.Password);
	}

	internal static string BuildComment(string prefix, string? reason, DateTime nowUtc, DateTime? expiresUtc, string? template)
	{
		string head = string.IsNullOrWhiteSpace(prefix) ? "RdpAudit" : prefix.Trim();
		string body = string.IsNullOrWhiteSpace(template) ? "auto-block" : template.Trim();
		string reasonPart = string.IsNullOrWhiteSpace(reason) ? string.Empty : " reason=" + reason!.Trim();
		string expiryPart = expiresUtc.HasValue
			? string.Format(CultureInfo.InvariantCulture, " expires={0:yyyy-MM-ddTHH:mm:ssZ}", expiresUtc.Value)
			: string.Empty;
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0} {1} created={2:yyyy-MM-ddTHH:mm:ssZ}{3}{4}",
			head,
			body,
			nowUtc,
			expiryPart,
			reasonPart);
	}

	internal static FirewallActionResult MapToFirewallResult(MikroTikOperationResult result)
	{
		ArgumentNullException.ThrowIfNull(result);
		return result.Outcome switch
		{
			MikroTikOutcome.Accepted => new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = "MikroTik",
				Message = result.Message,
				RuleId = result.RuleId,
			},
			MikroTikOutcome.AlreadyExists => new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = "MikroTik",
				Message = result.Message,
				RuleId = result.RuleId,
			},
			MikroTikOutcome.NotConfigured => new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = "MikroTik",
				Message = result.Message,
			},
			MikroTikOutcome.NotFound => new FirewallActionResult
			{
				Status = FirewallActionStatus.NotFound,
				ProviderId = "MikroTik",
				Message = result.Message,
			},
			MikroTikOutcome.Rejected => new FirewallActionResult
			{
				Status = FirewallActionStatus.Refused,
				ProviderId = "MikroTik",
				Message = result.Message,
			},
			MikroTikOutcome.RateLimited or MikroTikOutcome.ServerError or MikroTikOutcome.TransportError =>
				new FirewallActionResult
				{
					Status = FirewallActionStatus.Unavailable,
					ProviderId = "MikroTik",
					Message = result.Message,
				},
			_ => new FirewallActionResult
			{
				Status = FirewallActionStatus.NotImplemented,
				ProviderId = "MikroTik",
				Message = result.Message,
			},
		};
	}
}
