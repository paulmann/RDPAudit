// File:    src/RdpAudit.Core/Ipc/Contracts/ActiveBlockDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for ListActiveBlocksDetailed returning the full ActiveBlock row shape.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for a currently installed firewall block.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ActiveBlockDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	[Key(2)]
	public FirewallProviderKind Provider { get; set; }

	[Key(3)]
	public string? RuleHandle { get; set; }

	[Key(4)]
	public DateTime CreatedUtc { get; set; }

	[Key(5)]
	public DateTime? ExpiresUtc { get; set; }

	[Key(6)]
	public string Reason { get; set; } = string.Empty;

	[Key(7)]
	public ActiveBlockStatus Status { get; set; }

	[Key(8)]
	public string? LastError { get; set; }

	// --- Stage 1.2.4: live enforcement reconciliation fields ---------------------------------
	// Populated when the row is produced from a reconciliation pass (ListActiveBlocksDetailed now
	// reconciles against the live firewall scan). Older clients that ignore these keys still bind.

	/// <summary>Enforcement backend that owns this block (Windows firewall / route / IPsec).</summary>
	[Key(9)]
	public FirewallEnforcementBackend EnforcementBackend { get; set; }

	/// <summary>Concrete backend object id discovered live (firewall rule name / route / policy id).</summary>
	[Key(10)]
	public string? EnforcementObjectId { get; set; }

	/// <summary>Reconciled enforcement status (Active / MissingRule / ParameterMismatch / ...).</summary>
	[Key(11)]
	public EnforcementStatus EnforcementStatus { get; set; }

	/// <summary>Reconciled confidence that traffic is actually blocked.</summary>
	[Key(12)]
	public EnforcementConfidence EnforcementConfidence { get; set; }

	/// <summary>UTC instant of the reconciliation pass that produced this row.</summary>
	[Key(13)]
	public DateTime? LastVerifiedUtc { get; set; }

	/// <summary>Recommended next action for this IP (Repair / Remove enforcement / No action / ...).</summary>
	[Key(14)]
	public string? RecommendedAction { get; set; }

	// --- v1.2.9: persisted per-attempt backend diagnostics -----------------------------------
	// Populated from the ActiveBlock row's last block / repair attempt so per-IP diagnostics never
	// show a bare "Failed / Failed". Older clients that ignore these keys still bind.

	/// <summary>UTC timestamp of the most recent block / repair attempt for this IP.</summary>
	[Key(15)]
	public DateTime? LastAttemptUtc { get; set; }

	/// <summary>Backend command line of the most recent attempt (e.g. the netsh argument vector).</summary>
	[Key(16)]
	public string? BackendCommand { get; set; }

	/// <summary>Bounded stdout preview of the most recent backend attempt.</summary>
	[Key(17)]
	public string? BackendStdoutPreview { get; set; }

	/// <summary>Bounded stderr preview of the most recent backend attempt.</summary>
	[Key(18)]
	public string? BackendStderrPreview { get; set; }

	/// <summary>Process exit code of the most recent backend attempt; null when none captured.</summary>
	[Key(19)]
	public int? ExitCode { get; set; }

	/// <summary>True when the most recent backend attempt hit its hard timeout.</summary>
	[Key(20)]
	public bool? TimedOut { get; set; }

	/// <summary>Wall-clock duration in milliseconds of the most recent backend attempt.</summary>
	[Key(21)]
	public long? DurationMs { get; set; }

	/// <summary>Scanner / runner backend used for the most recent attempt (e.g. NetshText).</summary>
	[Key(22)]
	public string? ScannerBackend { get; set; }

	/// <summary>Human-readable reason the post-block verifier reached its verdict on the most recent attempt.</summary>
	[Key(23)]
	public string? VerifierReason { get; set; }
}
