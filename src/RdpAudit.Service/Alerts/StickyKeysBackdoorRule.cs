// File:    src/RdpAudit.Service/Alerts/StickyKeysBackdoorRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects T1546.008 — accessibility binary IFEO hijack and shell-from-winlogon.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects T1546.008 — Accessibility Feature Backdoor (Sticky Keys / Utilman / etc.).</summary>
public sealed class StickyKeysBackdoorRule : AlertRuleBase
{
	private static readonly string[] WatchedKeys =
	{
		"sethc",
		"utilman",
		"osk.exe",
		"magnify",
		"narrator",
		"displayswitch",
		"atbroker",
	};

	private static readonly string[] ShellProcs =
	{
		"cmd.exe",
		"powershell.exe",
		"wscript.exe",
		"cscript.exe",
		"mshta.exe",
	};

	public override string RuleId => "STICKY_KEYS_BACKDOOR";

	public override string Name => "Accessibility Feature Backdoor (T1546.008)";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId == 4657 && evt.ObjectName is not null)
		{
			string obj = evt.ObjectName.ToLowerInvariant();
			if (obj.Contains("image file execution options", StringComparison.Ordinal)
				&& WatchedKeys.Any(k => obj.Contains(k, StringComparison.Ordinal)))
			{
				return Task.FromResult<Alert?>(CreateAlert(evt,
					$"Accessibility backdoor: IFEO key modified — {evt.ObjectName}",
					new { Path = evt.ObjectName, Actor = evt.UserName, Mitre = "T1546.008" }));
			}
		}

		if (evt.EventId == 4688 && evt.ProcessName is not null)
		{
			string proc = ExtractFileName(evt.ProcessName).ToLowerInvariant();
			string parent = ExtractParent(evt.Details).ToLowerInvariant();
			if (parent.Contains("winlogon", StringComparison.Ordinal)
				&& ShellProcs.Any(s => string.Equals(proc, s, StringComparison.Ordinal)))
			{
				return Task.FromResult<Alert?>(CreateAlert(evt,
					$"Accessibility backdoor: {evt.ProcessName} spawned by winlogon.exe",
					new { evt.ProcessName, Parent = parent, Mitre = "T1546.008" }));
			}
		}

		return Task.FromResult<Alert?>(null);
	}

	private static string ExtractFileName(string path)
	{
		int slash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
		return slash >= 0 ? path[(slash + 1)..] : path;
	}

	private static string ExtractParent(string? json)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty("ParentProcessName", out JsonElement v))
			{
				return v.GetString() ?? string.Empty;
			}
		}
		catch (JsonException)
		{
		}

		return string.Empty;
	}
}
