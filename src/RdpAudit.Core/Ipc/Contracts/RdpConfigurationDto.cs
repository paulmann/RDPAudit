// File:    src/RdpAudit.Core/Ipc/Contracts/RdpConfigurationDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO describing the current RDP listener configuration that the new RDP Configuration
//          tab renders — port, enabled flag, NLA / SecurityLayer, single-session, hide-users
//          policy values, session shadowing mode, plus service / version context. Read-only;
//          mutation flows through existing elevated registry helpers in a later milestone.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO describing the current RDP listener configuration snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RdpConfigurationDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Optional human-readable status / error message; null on Success unless extra detail
	/// is helpful (e.g. "TermService not installed").</summary>
	[Key(1)]
	public string? Message { get; set; }

	/// <summary>Configured TCP port read from RDP-Tcp\PortNumber. null when the value is missing
	/// or out of range; the UI should show the default 3389 alongside a "not configured" hint.</summary>
	[Key(2)]
	public int? ConfiguredPort { get; set; }

	/// <summary>True when fDenyTSConnections=0; false when 1; null when the value is missing.</summary>
	[Key(3)]
	public bool? RdpEnabled { get; set; }

	/// <summary>Raw <c>UserAuthentication</c> registry DWORD; -1 = missing / unknown.</summary>
	[Key(4)]
	public int UserAuthenticationRaw { get; set; } = -1;

	/// <summary>Raw <c>SecurityLayer</c> registry DWORD; -1 = missing / unknown.</summary>
	[Key(5)]
	public int SecurityLayerRaw { get; set; } = -1;

	/// <summary>Raw <c>fSingleSessionPerUser</c> DWORD; null = missing.</summary>
	[Key(6)]
	public int? SingleSessionPerUserRaw { get; set; }

	/// <summary>Raw <c>dontdisplaylastusername</c> DWORD under Policies\System; null = missing.</summary>
	[Key(7)]
	public int? DontDisplayLastUserNameRaw { get; set; }

	/// <summary>Raw <c>DontEnumerateConnectedUsers</c> DWORD under Policies\System; null = missing.</summary>
	[Key(8)]
	public int? DontEnumerateConnectedUsersRaw { get; set; }

	/// <summary>Effective Shadow policy value (0..4) — copied from <see cref="ShadowPolicyStatusDto"/>
	/// so the tab can render without making a second IPC round-trip; -1 when not configured.</summary>
	[Key(9)]
	public int ShadowModeRaw { get; set; } = -1;

	/// <summary>True when the TermService Windows service is installed.</summary>
	[Key(10)]
	public bool TermServiceInstalled { get; set; }

	/// <summary>True when the TermService Windows service is currently running.</summary>
	[Key(11)]
	public bool TermServiceRunning { get; set; }

	/// <summary>OS description (Environment.OSVersion-derived) — best-effort, never throws.</summary>
	[Key(12)]
	public string? OsVersion { get; set; }

	/// <summary>Product version of termsrv.dll when readable; null when unavailable.</summary>
	[Key(13)]
	public string? TermServiceVersion { get; set; }

	/// <summary>Captured UTC timestamp of the snapshot.</summary>
	[Key(14)]
	public DateTime CapturedUtc { get; set; } = DateTime.UtcNow;

	/// <summary>Raw <c>fPromptForPassword</c> DWORD read from the Terminal Services policy key
	/// (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services). null when the value is
	/// absent or unreadable. Policy value is authoritative when present.</summary>
	[Key(15)]
	public int? PromptForPasswordPolicyRaw { get; set; }

	/// <summary>Raw <c>fPromptForPassword</c> DWORD read from the per-listener RDP-Tcp key
	/// (HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp). null when
	/// absent. Used as a fallback only when <see cref="PromptForPasswordPolicyRaw"/> is null.</summary>
	[Key(16)]
	public int? PromptForPasswordListenerRaw { get; set; }
}
