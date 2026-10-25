// File:    src/RdpAudit.Service/Workers/CrossHostChainAlertProcessor.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Cross-host alert phase used by AlertWorker: raises exactly one CROSS_HOST_CHAIN alert
//          per newly detected chain and links the alert id into the chain row. The chain row's
//          AlertId is the durable dedup gate, so repeated passes can never duplicate alerts.
//          Does not call SaveChanges: the caller owns the unit of work.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Workers;

/// <summary>Alert phase for newly detected cross-host chains.</summary>
public static class CrossHostChainAlertProcessor
{
	/// <summary>Maximum unalerted chains processed in one pass; the next pass continues.</summary>
	private const int MaxChainsPerPass = 50;

	/// <summary>Raises one CROSS_HOST_CHAIN alert for every chain whose AlertId is still null and
	/// which is not acknowledged, then links the alert id back into the chain row. Returns the
	/// number of alerts raised. The caller saves the changes.</summary>
	public static async Task<int> ProcessAsync(AuditDbContext db, ILogger logger, CancellationToken ct)
	{
		List<CrossHostChain> chains = await db.CrossHostChains
			.Include(c => c.Links)
			.Where(c => c.AlertId == null && !c.IsAcknowledged)
			.OrderBy(c => c.Id)
			.Take(MaxChainsPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		foreach (CrossHostChain chain in chains)
		{
			ct.ThrowIfCancellationRequested();
			List<CrossHostLink> links = chain.Links.OrderBy(l => l.Ordinal).ToList();
			string hostPath = string.Join(" -> ", links.Select(l => l.HostName.Trim()));

			Alert alert = CrossHostChainAlertFactory.CreateAlert(new CrossHostChainAlertContext
			{
				ChainId = chain.Id,
				ChainKey = chain.ChainKey,
				RuleId = chain.RuleId,
				NormalizedUserName = chain.NormalizedUserName,
				FirstSeenUtc = chain.FirstSeenUtc,
				LastSeenUtc = chain.LastSeenUtc,
				Score = chain.Score,
				FailedAttemptCount = chain.FailedAttemptCount,
				HostPath = hostPath,
			});

			db.Alerts.Add(alert);
			chain.Alert = alert;
			logger.LogWarning(
				"Alert {RuleId} severity={Severity} user={UserName} message={Message}",
				alert.RuleId,
				alert.Severity,
				alert.UserName,
				alert.Message);
		}

		return chains.Count;
	}
}
