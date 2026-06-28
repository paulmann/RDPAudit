// File:    src/RdpAudit.Core/Ipc/Contracts/ShadowPolicyApplyRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload for the ApplyShadowPolicy IPC command. Captures the desired
//          Microsoft Shadow value (0..4) and optional "enable all permissions" preset
//          flag. Append-only — never reuse or reorder keys.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>ApplyShadowPolicy</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShadowPolicyApplyRequest
{
	/// <summary>Desired Microsoft "Shadow" value (0..4). When <see cref="EnableAllPermissions"/>
	/// is true this field is ignored and the canonical "enable all permissions" preset is applied.</summary>
	[Key(0)]
	public int ShadowMode { get; set; } = 1;

	/// <summary>When true, applies the canonical "enable all permissions" preset
	/// (full control with no consent prompt) under the group-policy key.</summary>
	[Key(1)]
	public bool EnableAllPermissions { get; set; }

	/// <summary>When true, a backup snapshot is taken before changes are applied so the operator
	/// can revert via <c>RestoreShadowPolicy</c>. Defaults to true server-side.</summary>
	[Key(2)]
	public bool TakeBackupFirst { get; set; } = true;

	/// <summary>Optional operator-provided reason recorded in the service audit log.</summary>
	[Key(3)]
	public string? Reason { get; set; }
}
