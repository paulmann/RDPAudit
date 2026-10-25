// File:    src/RdpAudit.Core/Ipc/Contracts/MikroTikSecurityAuditDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Reply payload of GetMikroTikSecurityAudit: the RouterOS security audit rendered for the
//          Configurator. Carries the pasport, the risk index and verdict, per-severity counts, one
//          entry per finding (with evidence, reason, recommendation and ready commands), the menus
//          the device does not have, and the finished Markdown report.
//          Never carries a credential: the audit never reads one, and the SNMP community string and
//          the /system note text are redacted by the evaluator before they reach this DTO.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One finding of the security audit, as the Configurator grid displays it.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class MikroTikSecurityFindingDto
{
	/// <summary>Stable rule id (S-00 … S-35, S-27b).</summary>
	[Key(0)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>critical | high | medium | low | info.</summary>
	[Key(1)]
	public string Severity { get; set; } = string.Empty;

	/// <summary>Concrete finding line (catalogue title plus the offending object).</summary>
	[Key(2)]
	public string Title { get; set; } = string.Empty;

	/// <summary>RouterOS menu in console notation.</summary>
	[Key(3)]
	public string Menu { get; set; } = string.Empty;

	/// <summary>Proof in the form <c>menu :: value</c>. A finding without evidence is a report defect.</summary>
	[Key(4)]
	public string Evidence { get; set; } = string.Empty;

	/// <summary>Why the finding is dangerous.</summary>
	[Key(5)]
	public string Why { get; set; } = string.Empty;

	/// <summary>What to do about it.</summary>
	[Key(6)]
	public string Recommendation { get; set; } = string.Empty;

	/// <summary>auto | risky | manual | none.</summary>
	[Key(7)]
	public string Autofix { get; set; } = string.Empty;

	/// <summary>Copy-paste RouterOS commands for this finding; empty when there is no one-liner.</summary>
	[Key(8)]
	public List<string> Commands { get; set; } = [];
}

/// <summary>Reply payload of <c>GetMikroTikSecurityAudit</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class MikroTikSecurityAuditDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Router identity name, when the device answered.</summary>
	[Key(1)]
	public string DeviceName { get; set; } = string.Empty;

	/// <summary>RouterOS version reported by /system/resource.</summary>
	[Key(2)]
	public string RouterOsVersion { get; set; } = string.Empty;

	/// <summary>Board name reported by /system/resource.</summary>
	[Key(3)]
	public string BoardName { get; set; } = string.Empty;

	/// <summary>Device uptime (context only; changes on every run).</summary>
	[Key(4)]
	public string Uptime { get; set; } = string.Empty;

	/// <summary>UTC of the snapshot this report was evaluated against.</summary>
	[Key(5)]
	public DateTime CapturedUtc { get; set; }

	/// <summary>0..100, worse is higher (critical 40, high 15, medium 5, low 1, info 0, capped at 100).</summary>
	[Key(6)]
	public int RiskIndex { get; set; }

	/// <summary>no findings | low risk | medium risk | high risk | critical risk.</summary>
	[Key(7)]
	public string Verdict { get; set; } = string.Empty;

	[Key(8)]
	public int Total { get; set; }

	[Key(9)]
	public int Critical { get; set; }

	[Key(10)]
	public int High { get; set; }

	[Key(11)]
	public int Medium { get; set; }

	[Key(12)]
	public int Low { get; set; }

	[Key(13)]
	public int Info { get; set; }

	/// <summary>How many findings an automated pass would be allowed to touch.</summary>
	[Key(14)]
	public int AutoFixable { get; set; }

	/// <summary>Human-readable outcome of the read (how many menus were read, how many failed).</summary>
	[Key(15)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Findings in report order (severity first, then rule id).</summary>
	[Key(16)]
	public List<MikroTikSecurityFindingDto> Findings { get; set; } = [];

	/// <summary>Menus the device does not have (package absent) — reported, never treated as compliant.</summary>
	[Key(17)]
	public List<string> UnavailableMenus { get; set; } = [];

	/// <summary>The finished Markdown report, ready to copy or paste into a ticket.</summary>
	[Key(18)]
	public string Markdown { get; set; } = string.Empty;
}
