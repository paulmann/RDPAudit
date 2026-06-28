// File:    src/RdpAudit.Core/Models/ActiveBlock.cs
// Module:  RdpAudit.Core.Models
// Purpose: Currently installed firewall block. One row per (Provider, Ip) pair lets the eventual
//          AutoBlockWorker reconcile DB intent with provider state, retry failed installs, and
//          drive scheduled unblocks at ExpiresUtc.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;

namespace RdpAudit.Core.Models;

/// <summary>Currently installed firewall block.</summary>
/// <remarks>
/// <see cref="Provider"/> reuses <see cref="FirewallProviderKind"/> for ordinal stability. The
/// composite (<see cref="Provider"/>, <see cref="Ip"/>) is unique so reconciliation can rely on
/// idempotent upserts.
/// </remarks>
public sealed class ActiveBlock
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Blocked IP address in IPv4 or IPv6 textual form.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>Firewall provider that owns the rule (None means audit-only, no provider driven).</summary>
	public FirewallProviderKind Provider { get; set; }

	/// <summary>Provider-specific rule identifier (rule name on Windows, list entry id on MikroTik).</summary>
	public string? RuleHandle { get; set; }

	/// <summary>UTC timestamp when the block was first installed.</summary>
	public DateTime CreatedUtc { get; set; }

	/// <summary>UTC timestamp when the block must be removed; null means permanent.</summary>
	public DateTime? ExpiresUtc { get; set; }

	/// <summary>Reason recorded for audit (rule id, manual operator action, etc.).</summary>
	public string Reason { get; set; } = string.Empty;

	/// <summary>Operational status of the block.</summary>
	public ActiveBlockStatus Status { get; set; }

	/// <summary>Last provider error, when <see cref="Status"/> is <see cref="ActiveBlockStatus.Failed"/>.</summary>
	public string? LastError { get; set; }

	/// <summary>UTC timestamp of the most recent block / repair attempt, regardless of outcome.</summary>
	public DateTime? LastAttemptUtc { get; set; }

	/// <summary>Backend command line of the most recent block / verify attempt (e.g. the netsh argument
	/// vector), for operator diagnostics. Never contains secret material.</summary>
	public string? BackendCommand { get; set; }

	/// <summary>Bounded, control-character-flattened stdout preview of the most recent backend attempt.</summary>
	public string? BackendStdoutPreview { get; set; }

	/// <summary>Bounded, control-character-flattened stderr preview of the most recent backend attempt.</summary>
	public string? BackendStderrPreview { get; set; }

	/// <summary>Process exit code of the most recent backend attempt; null when no attempt was captured.</summary>
	public int? ExitCode { get; set; }

	/// <summary>True when the most recent backend attempt hit its hard timeout.</summary>
	public bool? TimedOut { get; set; }

	/// <summary>Wall-clock duration in milliseconds of the most recent backend attempt.</summary>
	public long? DurationMs { get; set; }

	/// <summary>Scanner / runner backend used for the most recent attempt (e.g. NetshText, PowerShellJson).</summary>
	public string? ScannerBackend { get; set; }

	/// <summary>Human-readable reason the post-block verifier reached its verdict on the most recent attempt.</summary>
	public string? VerifierReason { get; set; }
}
