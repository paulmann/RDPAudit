// File:    src/RdpAudit.Service/Alerts/ProcessAnomalyRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags shells (cmd / PowerShell) spawned from svchost / mstsc / rdpclip / explorer.
//          cmd-from-explorer can be suppressed (interactive use is common) via configuration.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags shells (cmd / PowerShell) spawned from svchost / mstsc / rdpclip / explorer.</summary>
public sealed class ProcessAnomalyRule : AlertRuleBase
{
	private static readonly string[] SuspiciousChildren =
	{
		"cmd.exe",
		"powershell.exe",
		"pwsh.exe",
		"wscript.exe",
		"cscript.exe",
	};

	private static readonly string[] SuspiciousParents =
	{
		"svchost.exe",
		"mstsc.exe",
		"rdpclip.exe",
		"explorer.exe",
	};

	public override string RuleId => "PROCESS_ANOMALY";

	public override string Name => "Anomalous Process Parentage";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4688 || string.IsNullOrEmpty(evt.ProcessName))
		{
			return Task.FromResult<Alert?>(null);
		}

		string child = ExtractFileName(evt.ProcessName).ToLowerInvariant();
		if (!SuspiciousChildren.Contains(child, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		string parent = ExtractParent(evt.Details).ToLowerInvariant();
		if (!SuspiciousParents.Any(p => parent.EndsWith(p, StringComparison.Ordinal)))
		{
			return Task.FromResult<Alert?>(null);
		}

		// Reduce false positives: cmd.exe spawned by explorer.exe is a routine interactive
		// pattern (Win+R, Run dialog, double-click batch). Suppress unless explicitly tracked.
		bool fromExplorer = parent.EndsWith("explorer.exe", StringComparison.Ordinal);
		if (fromExplorer && string.Equals(child, "cmd.exe", StringComparison.OrdinalIgnoreCase)
			&& ctx.Options.Alerts.ProcessAnomalyAllowExplorerCmd)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"{child} spawned by {parent} for {evt.UserName}",
			new { Parent = parent, Child = child, Mitre = "T1059" }));
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
