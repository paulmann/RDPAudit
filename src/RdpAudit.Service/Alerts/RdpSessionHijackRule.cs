// File:    src/RdpAudit.Service/Alerts/RdpSessionHijackRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects T1563.002 — RDP session hijack via tscon.exe or mstsc /shadow.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects T1563.002 — RDP session hijack via tscon.exe or mstsc /shadow.</summary>
public sealed class RdpSessionHijackRule : AlertRuleBase
{
	public override string RuleId => "RDP_SESSION_HIJACK";

	public override string Name => "RDP Session Hijack";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4688 || string.IsNullOrEmpty(evt.ProcessName))
		{
			return Task.FromResult<Alert?>(null);
		}

		string proc = ExtractFileName(evt.ProcessName).ToLowerInvariant();
		string cmd = (evt.CommandLine ?? string.Empty).ToLowerInvariant();

		bool tscon = proc == "tscon.exe";
		bool mstscShadow = proc == "mstsc.exe" && cmd.Contains("/shadow", StringComparison.Ordinal);
		if (!tscon && !mstscShadow)
		{
			return Task.FromResult<Alert?>(null);
		}

		string indicator = tscon ? "tscon.exe" : "mstsc /shadow";
		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"RDP session hijack indicator: {indicator} executed by {evt.UserName}",
			new { evt.ProcessName, evt.CommandLine, Mitre = "T1563.002" }));
	}

	private static string ExtractFileName(string path)
	{
		int slash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
		return slash >= 0 ? path[(slash + 1)..] : path;
	}
}
