// File:    src/RdpAudit.Core/Config/SessionControlOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for RDP session control actions (disconnect, log off, shadow).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for RDP session control actions (disconnect, log off, shadow).</summary>
/// <remarks>
/// All session-control actions are auditable, reversible (where applicable), and rate-limited.
/// Shadow policy operations modify Group Policy on the host; backups are required by default.
/// </remarks>
public sealed class SessionControlOptions
{
	/// <summary>Enables UI / IPC session-control surfaces. When false related IPC commands return Unavailable.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>Allows operators to disconnect (but not log off) RDP sessions through the Configurator.</summary>
	public bool AllowDisconnect { get; set; } = true;

	/// <summary>Allows operators to log off RDP sessions through the Configurator.</summary>
	public bool AllowLogoff { get; set; } = true;

	/// <summary>Allows operators to initiate session shadowing through the Configurator.
	/// Defaults to true — the actual gate is the Microsoft Terminal Services Shadow
	/// registry policy, which is consulted before the launch; an additional service-side
	/// hard-deny defeated the operator's intent when the OS policy already permitted the
	/// action (e.g. when <c>mstsc /shadow:N /control /noConsentPrompt /admin</c> works
	/// manually).</summary>
	public bool AllowShadow { get; set; } = true;

	/// <summary>Requires the configured shadow policy to be present before shadowing is permitted.</summary>
	public bool RequireShadowPolicy { get; set; } = true;

	/// <summary>Always backs up the existing shadow policy before applying or restoring changes.</summary>
	public bool BackupShadowPolicyOnApply { get; set; } = true;

	/// <summary>Forced default for the Terminal Services shadow policy when applied.</summary>
	/// <remarks>
	/// Allowed values map to Microsoft's <c>Shadow</c> registry value:
	/// 0 = no shadow, 1 = full control with user permission, 2 = full control without user permission,
	/// 3 = view session with user permission, 4 = view session without user permission.
	/// Default 1 is the only setting that prompts the user — the safest default.
	/// </remarks>
	public int ShadowPolicyMode { get; set; } = 1;

	/// <summary>Maximum session-control operations a single operator may issue per minute.</summary>
	public int MaxOperationsPerMinute { get; set; } = 30;

	/// <summary>When true, every disconnect / logoff / shadow request is mirrored to the alert audit log.</summary>
	public bool AuditAllOperations { get; set; } = true;
}
