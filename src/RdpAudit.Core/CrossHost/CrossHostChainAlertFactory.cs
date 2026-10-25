// File:    src/RdpAudit.Core/CrossHost/CrossHostChainAlertFactory.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Pure factory that projects a persisted cross-host chain (plus its host path) into the
//          CROSS_HOST_CHAIN alert. Kept free of EF Core and logging so AlertWorker, the IPC layer
//          and tests all produce identical alert payloads; the Service owns persistence and
//          the chain -> alert linking (the durable dedup gate).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.CrossHost;

/// <summary>Alert-annex data for a cross-host chain that alert consumers / tests may fabricate.
/// Carries everything <see cref="CrossHostChainAlertFactory"/> needs without coupling it to the
/// entity model.</summary>
public sealed class CrossHostChainAlertContext
{
	/// <summary>Surrogate id of the persisted <see cref="CrossHostChain"/> row.</summary>
	public long ChainId { get; set; }

	/// <summary>Stable chain key computed by the correlation engine.</summary>
	public string ChainKey { get; set; } = string.Empty;

	/// <summary>Rule that produced the chain (e.g. 'RDP_LATERAL_MOVEMENT').</summary>
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Canonical user key the chain pivots on.</summary>
	public string NormalizedUserName { get; set; } = string.Empty;

	/// <summary>UTC time of the first link in the chain.</summary>
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC time of the last link in the chain.</summary>
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Risk score computed by the rule (0..100).</summary>
	public int Score { get; set; }

	/// <summary>Number of failed-login facts that fed the first link.</summary>
	public int FailedAttemptCount { get; set; }

	/// <summary>Ordered host names of the chain path (SRV-A -> SRV-B -> SRV-C).</summary>
	public string HostPath { get; set; } = string.Empty;
}

/// <summary>Builds CROSS_HOST_CHAIN alerts from chain annex data.</summary>
public static class CrossHostChainAlertFactory
{
	/// <summary>Alert rule id used by the CROSS_HOST_CHAIN alert. Kept as a constant so the
	/// AlertWorker phase, the Dispatcher ack path and tests share the exact same value.</summary>
	public const string RuleId = "CROSS_HOST_CHAIN";

	/// <summary>Builds the alert for one newly detected chain. Never null. Severity Critical:
	/// lateral movement across hosts is the highest-value detection in the product. The alert
	/// carries no secret material; SourceIp is left empty because a chain aggregates several
	/// hosts and a single IP would be misleading.</summary>
	public static Alert CreateAlert(CrossHostChainAlertContext ctx)
	{
		ArgumentNullException.ThrowIfNull(ctx);

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"Cross-host attack chain detected: user={0} path={1} rule={2} score={3}",
			string.IsNullOrWhiteSpace(ctx.NormalizedUserName) ? "(unknown)" : ctx.NormalizedUserName,
			string.IsNullOrWhiteSpace(ctx.HostPath) ? "(no host path)" : ctx.HostPath,
			ctx.RuleId,
			ctx.Score);

		var details = new
		{
			chainId = ctx.ChainId,
			chainKey = ctx.ChainKey,
			ruleId = ctx.RuleId,
			hostPath = ctx.HostPath,
			score = ctx.Score,
			failedAttemptCount = ctx.FailedAttemptCount,
			firstSeenUtc = ctx.FirstSeenUtc,
			lastSeenUtc = ctx.LastSeenUtc,
		};

		return new Alert
		{
			RuleId = RuleId,
			Severity = AlertSeverity.Critical,
			TimeUtc = DateTime.UtcNow,
			SourceIp = string.Empty,
			UserName = string.IsNullOrWhiteSpace(ctx.NormalizedUserName) ? null : ctx.NormalizedUserName,
			Message = message,
			Details = System.Text.Json.JsonSerializer.Serialize(details, JsonOptions.Default),
			Acknowledged = false,
			TriggerEventId = ctx.ChainId,
		};
	}
}
