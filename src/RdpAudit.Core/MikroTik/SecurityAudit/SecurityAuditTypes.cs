// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditTypes.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: Value types of the RouterOS security audit: severity, autofix classification,
//          operator profile, one rule definition, one finding and the finished report.
//          The catalogue itself lives in SecurityAuditCatalog.cs, the checks in
//          SecurityAuditEvaluator.cs, the rendering in SecurityAuditMarkdown.cs.
//          Everything here is plain data: no HTTP, no RouterOS, no clock reads, so the whole
//          audit is testable with xunit against a fabricated snapshot.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>Severity of an audit finding. Numeric order is the report order (worst first).</summary>
public enum SecurityAuditSeverity
{
	Critical = 0,
	High = 1,
	Medium = 2,
	Low = 3,
	Info = 4,
}

/// <summary>
/// How a finding can be fixed. The reference implementation draws this line and the product keeps
/// it: <see cref="Auto"/> is the only class an automated pass may apply, <see cref="Risky"/> may cut
/// the operator's own management channel, <see cref="Manual"/> needs a human decision (rule order,
/// account names, time windows) and <see cref="None"/> cannot be done over the API at all.
/// </summary>
public enum SecurityAuditAutofix
{
	None = 0,
	Manual = 1,
	Risky = 2,
	Auto = 3,
}

/// <summary>What the operator wants this class of device to look like.</summary>
public sealed class SecurityAuditProfile
{
	/// <summary>Management network(s) an administrative account or service may be restricted to.</summary>
	public string ManagementNetworks { get; set; } = "192.168.31.0/24";

	/// <summary>NTP servers proposed by the recommendation text (never applied automatically here).</summary>
	public string NtpServers { get; set; } = "162.159.200.1,216.239.35.0";

	/// <summary>Clock skew (seconds) above which S-27b reports the device clock as drifting.</summary>
	public int ClockToleranceSeconds { get; set; } = 300;

	/// <summary>Emergency full account deliberately left without an address restriction (excluded from S-01).</summary>
	public string BackupUser { get; set; } = string.Empty;
}

/// <summary>One catalogue entry: what is checked, why it matters, what to do, whether it is automatable.</summary>
/// <param name="Id">Stable rule id (S-00 … S-35, plus S-27b). Never reused for a different check.</param>
/// <param name="Severity">Report severity; also drives the risk index weigh-off.</param>
/// <param name="Menu">RouterOS menu the evidence comes from, in console notation (<c>/ip/service</c>).</param>
/// <param name="Title">Generic finding title; a concrete subject is appended by the finding.</param>
/// <param name="Why">Why the finding is dangerous — one sentence an operator can act on.</param>
/// <param name="Recommendation">What to do about it, including the decision that is not ours to make.</param>
/// <param name="Autofix">Autofix classification.</param>
public sealed record SecurityAuditRule(
	string Id,
	SecurityAuditSeverity Severity,
	string Menu,
	string Title,
	string Why,
	string Recommendation,
	SecurityAuditAutofix Autofix);

/// <summary>One concrete finding produced by the evaluator.</summary>
public sealed class SecurityAuditFinding
{
	public required string RuleId { get; init; }

	public required SecurityAuditSeverity Severity { get; init; }

	/// <summary>Concrete title (the catalogue title plus the offending object, if any).</summary>
	public required string Title { get; init; }

	public required string Menu { get; init; }

	/// <summary>Proof in the form <c>menu :: value</c>. A finding without evidence is a report defect.</summary>
	public required string Evidence { get; init; }

	public required string Why { get; init; }

	public required string Recommendation { get; init; }

	public SecurityAuditAutofix Autofix { get; init; }

	/// <summary>Copy-paste RouterOS commands printed for the operator. Empty when there is no one-liner.</summary>
	public IReadOnlyList<string> Commands { get; init; } = [];
}

/// <summary>The finished audit: findings, per-severity counts, risk index and verdict.</summary>
public sealed class SecurityAuditReport
{
	/// <summary>Fixed weights, mirrored from the reference implementation and locked by a test.</summary>
	public static int WeightOf(SecurityAuditSeverity severity) => severity switch
	{
		SecurityAuditSeverity.Critical => 40,
		SecurityAuditSeverity.High => 15,
		SecurityAuditSeverity.Medium => 5,
		SecurityAuditSeverity.Low => 1,
		_ => 0,
	};

	public string DeviceName { get; init; } = string.Empty;

	public string RouterOsVersion { get; init; } = string.Empty;

	public string BoardName { get; init; } = string.Empty;

	public string Uptime { get; init; } = string.Empty;

	public DateTime CapturedUtc { get; init; }

	/// <summary>Findings in report order: severity first, then rule id, then evidence.</summary>
	public IReadOnlyList<SecurityAuditFinding> Findings { get; init; } = [];

	/// <summary>Menus the device simply does not have (package absent). Not findings, and not silence.</summary>
	public IReadOnlyList<string> UnavailableMenus { get; init; } = [];

	/// <summary>0..100, worse is higher. Capped at 100 exactly like the reference.</summary>
	public int RiskIndex => Math.Min(100, Findings.Sum(f => WeightOf(f.Severity)));

	public int CountOf(SecurityAuditSeverity severity) => Findings.Count(f => f.Severity == severity);

	public int Total => Findings.Count;

	/// <summary>Thresholds are part of the contract (0/15/40/70/100), not a presentation choice.</summary>
	public string Verdict => RiskIndex switch
	{
		<= 0 => "no findings",
		<= 15 => "low risk",
		<= 40 => "medium risk",
		<= 70 => "high risk",
		_ => "critical risk",
	};

	/// <summary>How many findings an automated pass would be allowed to touch.</summary>
	public int AutoFixableCount => Findings.Count(f => f.Autofix == SecurityAuditAutofix.Auto);

	public string SeveritySummary() => string.Format(
		CultureInfo.InvariantCulture,
		"critical {0}, high {1}, medium {2}, low {3}, info {4} (total {5})",
		CountOf(SecurityAuditSeverity.Critical),
		CountOf(SecurityAuditSeverity.High),
		CountOf(SecurityAuditSeverity.Medium),
		CountOf(SecurityAuditSeverity.Low),
		CountOf(SecurityAuditSeverity.Info),
		Total);
}
