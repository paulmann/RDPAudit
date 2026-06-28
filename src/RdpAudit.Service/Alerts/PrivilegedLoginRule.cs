// File:    src/RdpAudit.Service/Alerts/PrivilegedLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4672 — Special privileges (SeDebug / SeTcb) assigned at logon.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4672 — Special privileges assigned at logon.</summary>
public sealed class PrivilegedLoginRule : AlertRuleBase
{
	private static readonly string[] WatchedPrivileges =
	{
		"SeDebugPrivilege",
		"SeTcbPrivilege",
		"SeImpersonatePrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
	};

	public override string RuleId => "PRIVILEGED_LOGIN";

	public override string Name => "Privileged Account Logon";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4672 || string.IsNullOrEmpty(evt.Details))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!string.IsNullOrEmpty(evt.UserName)
			&& ctx.Options.Alerts.WhitelistUsers.Contains(evt.UserName, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		string details = evt.Details;
		bool match = WatchedPrivileges.Any(p => details.Contains(p, StringComparison.Ordinal));
		if (!match)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Privileged logon by {evt.UserName} (sensitive privileges granted)",
			new { Mitre = "T1078" }));
	}
}
