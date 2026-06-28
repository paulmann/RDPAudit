// File:    src/RdpAudit.Core/Ipc/Contracts/MikroTikStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetMikroTikStatus. Reports whether MikroTik integration is configured /
//          enabled, summarises connectivity result of the last probe, and surfaces aggregate
//          MikroTik active-block counters. NEVER contains the API password — only a flag.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetMikroTikStatus</c>. Reports configuration and probe telemetry only.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class MikroTikStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when a host/credentials envelope is configured.</summary>
	[Key(1)]
	public bool Configured { get; set; }

	/// <summary>True when an envelope-protected password is present.</summary>
	[Key(2)]
	public bool CredentialPresent { get; set; }

	/// <summary>True when Enabled is set in configuration.</summary>
	[Key(3)]
	public bool Enabled { get; set; }

	/// <summary>True when AddAttackerRules is set.</summary>
	[Key(4)]
	public bool AddAttackerRules { get; set; }

	/// <summary>Sanitised endpoint description (scheme://host[:port]) — never carries credentials.</summary>
	[Key(5)]
	public string Endpoint { get; set; } = string.Empty;

	/// <summary>Resolved scheme used by the URL builder ("http", "https", or empty when unconfigured).</summary>
	[Key(6)]
	public string Scheme { get; set; } = string.Empty;

	/// <summary>Configured host literal.</summary>
	[Key(7)]
	public string Host { get; set; } = string.Empty;

	/// <summary>Configured port. 0 means "scheme default".</summary>
	[Key(8)]
	public int Port { get; set; }

	/// <summary>Provider operational state (Available / Unreachable / Disabled / NotConfigured / NotImplemented).</summary>
	[Key(9)]
	public string ProviderStatus { get; set; } = string.Empty;

	/// <summary>Count of currently-active MikroTik rows in the ActiveBlocks table.</summary>
	[Key(10)]
	public long ActiveBlockCount { get; set; }

	/// <summary>Configured firewall filter chain.</summary>
	[Key(11)]
	public string FilterChain { get; set; } = string.Empty;

	/// <summary>Configured firewall filter action.</summary>
	[Key(12)]
	public string FilterAction { get; set; } = string.Empty;

	/// <summary>Configured comment prefix used to identify RdpAudit-owned rules.</summary>
	[Key(13)]
	public string CommentPrefix { get; set; } = string.Empty;

	/// <summary>Configured block-duration TimeSpan in seconds (composed from days/hours/minutes).</summary>
	[Key(14)]
	public long BlockDurationSeconds { get; set; }

	/// <summary>TLS certificate validation flag.</summary>
	[Key(15)]
	public bool ValidateServerCertificate { get; set; }

	/// <summary>Sanitised last-error string; null when the last probe succeeded.</summary>
	[Key(16)]
	public string? LastError { get; set; }

	/// <summary>Optional human-readable message describing the current MikroTik state.</summary>
	[Key(17)]
	public string? Message { get; set; }
}
