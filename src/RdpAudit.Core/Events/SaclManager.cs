// File:    src/RdpAudit.Core/Events/SaclManager.cs
// Module:  RdpAudit.Core.Events
// Purpose: Configures registry SACLs for IFEO, Terminal Server RDP-Tcp, and Lsa keys so that
//          object-access audit events fire for the rules STICKY_KEYS_BACKDOOR, RDP_PORT_CHANGED,
//          LSASS_PPL_TAMPER. Uses Microsoft.Win32.RegistryKey.GetAccessControl APIs and
//          SeSecurityPrivilege via the running elevated process.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace RdpAudit.Core.Events;

/// <summary>Result of configuring a single SACL target.</summary>
public sealed record SaclApplyResult(string Path, bool Success, string? Error);

/// <summary>Configures registry SACLs for the keys our object-access alert rules depend on.</summary>
[SupportedOSPlatform("windows")]
public sealed class SaclManager
{
	private static readonly IReadOnlyList<string> IfeoBinaries =
	[
		"sethc.exe",
		"utilman.exe",
		"osk.exe",
		"magnify.exe",
		"narrator.exe",
		"displayswitch.exe",
		"atbroker.exe",
	];

	private const string IfeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
	private const string RdpTcp = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
	private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";

	/// <summary>Applies SACLs to all keys required by RdpAudit alert rules.</summary>
	public IReadOnlyList<SaclApplyResult> ApplyAll()
	{
		List<SaclApplyResult> results = new();
		SecurityIdentifier everyone = new(WellKnownSidType.WorldSid, null);

		// IFEO keys for accessibility binaries — create if missing so handle requests are auditable.
		foreach (string binary in IfeoBinaries)
		{
			string subkey = string.Format(CultureInfo.InvariantCulture, @"{0}\{1}", IfeoBase, binary);
			results.Add(ApplyKey(RegistryHive.LocalMachine, subkey, everyone, createIfMissing: true));
		}

		// RDP listener and Lsa keys must already exist.
		results.Add(ApplyKey(RegistryHive.LocalMachine, RdpTcp, everyone, createIfMissing: false));
		results.Add(ApplyKey(RegistryHive.LocalMachine, LsaPath, everyone, createIfMissing: false));

		return results;
	}

	private static SaclApplyResult ApplyKey(RegistryHive hive, string subkey, SecurityIdentifier auditedSid, bool createIfMissing)
	{
		string display = string.Format(CultureInfo.InvariantCulture, "HKLM\\{0}", subkey);
		try
		{
			using RegistryKey root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
			using RegistryKey? key = root.OpenSubKey(
				subkey,
				RegistryKeyPermissionCheck.ReadWriteSubTree,
				RegistryRights.ChangePermissions | RegistryRights.ReadPermissions | RegistryRights.SetValue);

			using RegistryKey? target = key
				?? (createIfMissing
					? root.CreateSubKey(subkey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.None)
					: null);

			if (target is null)
			{
				return new SaclApplyResult(display, false, "Key not found and createIfMissing=false");
			}

			RegistrySecurity security = target.GetAccessControl(AccessControlSections.Audit);

			RegistryAuditRule rule = new(
				auditedSid,
				RegistryRights.SetValue
					| RegistryRights.CreateSubKey
					| RegistryRights.Delete
					| RegistryRights.WriteKey
					| RegistryRights.ChangePermissions
					| RegistryRights.TakeOwnership,
				InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
				PropagationFlags.None,
				AuditFlags.Success | AuditFlags.Failure);

			security.AddAuditRule(rule);
			target.SetAccessControl(security);
			return new SaclApplyResult(display, true, null);
		}
		catch (UnauthorizedAccessException ex)
		{
			return new SaclApplyResult(display, false, "Access denied (run elevated): " + ex.Message);
		}
		catch (System.Security.SecurityException ex)
		{
			return new SaclApplyResult(display, false, "SeSecurityPrivilege required: " + ex.Message);
		}
		catch (Exception ex)
		{
			return new SaclApplyResult(display, false, ex.Message);
		}
	}
}
