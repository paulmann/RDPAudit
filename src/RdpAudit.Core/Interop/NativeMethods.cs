// File:    src/RdpAudit.Core/Interop/NativeMethods.cs
// Module:  RdpAudit.Core.Interop
// Purpose: Source-generated P/Invoke declarations only — no logic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RdpAudit.Core.Interop;

/// <summary>Source-generated P/Invoke declarations only — no logic.</summary>
internal static partial class NativeMethods
{
	internal const uint TOKEN_QUERY = 0x0008;

	// Audit policy inclusion flags returned by AuditQuerySystemPolicy.AuditingInformation.
	internal const uint POLICY_AUDIT_EVENT_UNCHANGED = 0x0;
	internal const uint POLICY_AUDIT_EVENT_SUCCESS = 0x1;
	internal const uint POLICY_AUDIT_EVENT_FAILURE = 0x2;
	internal const uint POLICY_AUDIT_EVENT_NONE = 0x4;

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool OpenProcessToken(
		SafeProcessHandle processHandle,
		uint desiredAccess,
		out SafeAccessTokenHandle tokenHandle);

	/// <summary>AUDIT_POLICY_INFORMATION as defined in ntsecapi.h.
	/// Locale-stable bitfield representation of an audit subcategory state.</summary>
	[StructLayout(LayoutKind.Sequential)]
	internal struct AUDIT_POLICY_INFORMATION
	{
		internal Guid AuditSubCategoryGuid;
		internal uint AuditingInformation;
		internal Guid AuditCategoryGuid;
	}

	[LibraryImport("advapi32.dll", EntryPoint = "AuditQuerySystemPolicy", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditQuerySystemPolicy(
		[In] Guid[] pSubCategoryGuids,
		uint policyCount,
		out IntPtr ppAuditPolicy);

	[LibraryImport("advapi32.dll", EntryPoint = "AuditFree")]
	internal static partial void AuditFree(IntPtr buffer);
}
