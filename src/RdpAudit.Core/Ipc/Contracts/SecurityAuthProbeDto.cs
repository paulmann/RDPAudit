// File:    src/RdpAudit.Core/Ipc/Contracts/SecurityAuthProbeDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Outcome envelope returned by the RunSecurityAuthProbe IPC command. Distinguishes the
//          three failure modes operators conflate when the Security channel appears "stuck":
//          access denied (service account lacks the Manage auditing and security log right),
//          query timeout (massive Security log + slow disk), and zero events (audit policy off
//          or no recent auth). The probe is a one-shot 24h ReverseDirection=true read of up to
//          20 Security 4624/4625 events that runs inside the service process so it observes
//          exactly what the long-running collector sees.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome envelope returned by the RunSecurityAuthProbe IPC command.</summary>
public sealed class SecurityAuthProbeDto
{
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Short human-readable status: <c>Ok</c>, <c>NoEvents</c>, <c>AccessDenied</c>,
	/// <c>Timeout</c>, <c>ChannelNotFound</c>, <c>NotWindows</c>, or <c>Error</c>.</summary>
	public string Outcome { get; set; } = string.Empty;

	/// <summary>Free-form message paired with <see cref="Outcome"/>.</summary>
	public string? Message { get; set; }

	public DateTime GeneratedUtc { get; set; }

	/// <summary>Identity (token / SID context) the probe executed under — proves it ran inside
	/// the service process rather than the Configurator's interactive token.</summary>
	public string? Identity { get; set; }

	/// <summary>The XPath the probe issued. Surfaced verbatim so the operator can copy it into
	/// PowerShell <c>Get-WinEvent -FilterXml</c> for cross-checking.</summary>
	public string? Query { get; set; }

	/// <summary>Wall-clock duration of the probe read.</summary>
	public long ElapsedMilliseconds { get; set; }

	/// <summary>Number of EventRecords returned by the probe (capped to MaxEvents).</summary>
	public int Count { get; set; }

	/// <summary>Time window used by the probe (hours of lookback).</summary>
	public int LookbackHours { get; set; }

	/// <summary>The first (most-recent, since ReverseDirection=true) event the probe parsed,
	/// when one was returned. Null on AccessDenied / Timeout / NoEvents.</summary>
	public SecurityAuthProbeEvent? FirstEvent { get; set; }

	/// <summary>Exception type name when the probe failed.</summary>
	public string? ExceptionType { get; set; }

	/// <summary>HResult of the exception when present (NTSTATUS-shaped hex).</summary>
	public string? ExceptionHResult { get; set; }

	/// <summary>Exception message, when the probe failed.</summary>
	public string? ExceptionMessage { get; set; }
}

/// <summary>Parsed fields of the first event returned by the Security auth probe.</summary>
public sealed class SecurityAuthProbeEvent
{
	public int EventId { get; set; }

	public DateTime? TimeUtc { get; set; }

	public string? User { get; set; }

	public string? Domain { get; set; }

	public string? Ip { get; set; }

	public int? LogonType { get; set; }

	public string? Status { get; set; }

	public string? SubStatus { get; set; }

	public string? SubStatusMeaning { get; set; }

	public string? AuthPackage { get; set; }

	public string? WorkstationName { get; set; }
}
