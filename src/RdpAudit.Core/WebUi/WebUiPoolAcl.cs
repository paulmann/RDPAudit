// File:    src/RdpAudit.Core/WebUi/WebUiPoolAcl.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Single implementation of the IIS application-pool read grant shared by the WebUI
//          publisher (wwwroot static content) and the WebUI app stager (full in-process app
//          root). Both paths must let the dedicated pool identity read the deployed folder;
//          keeping the grant+verify logic in one place guarantees the two staging paths cannot
//          drift apart in their security behavior. The grant is container+object inherited, so
//          every file landing afterwards picks it up. A blank identity (or a non-Windows host)
//          is a no-op success - the caller decides whether a pool grant is required at all.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RdpAudit.Core.WebUi;

/// <summary>Applies and verifies the application-pool ReadAndExecute grant on a web-UI folder.</summary>
internal static class WebUiPoolAcl
{
	/// <summary>Grants (on Windows) ReadAndExecute to the configured pool identity on
	/// <paramref name="directory"/> and verifies the grant by reading the folder DACL back after
	/// applying it. Returns true for a blank identity or a non-Windows host (no grant needed);
	/// returns false with a curated failure line when the identity cannot be resolved or the
	/// grant cannot be applied or verified.</summary>
	public static bool TryGrantReadAndExecute(string directory, string? webPoolIdentity, out string failure)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(directory);
		failure = string.Empty;

		if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(webPoolIdentity))
		{
			return true;
		}

		SecurityIdentifier poolSid;
		try
		{
			poolSid = (SecurityIdentifier)new NTAccount(webPoolIdentity.Trim())
				.Translate(typeof(SecurityIdentifier));
		}
		catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
		{
			failure = "The configured web pool identity could not be resolved to a security identifier: "
				+ webPoolIdentity.Trim();
			return false;
		}

		try
		{
			DirectoryInfo info = new(directory);
			DirectorySecurity security = info.GetAccessControl();

			bool alreadyGranted = security
				.GetAccessRules(
					includeExplicit: true,
					includeInherited: true,
					targetType: typeof(SecurityIdentifier))
				.Cast<FileSystemAccessRule>()
				.Any(rule => rule.AccessControlType == AccessControlType.Allow
					&& rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute)
					&& rule.IdentityReference == poolSid);

			if (!alreadyGranted)
			{
				security.AddAccessRule(new FileSystemAccessRule(
					poolSid,
					FileSystemRights.ReadAndExecute,
					InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
					PropagationFlags.None,
					AccessControlType.Allow));
				info.SetAccessControl(security);
			}

			DirectorySecurity after = new DirectoryInfo(directory)
				.GetAccessControl(AccessControlSections.Access);
			bool present = after
				.GetAccessRules(
					includeExplicit: true,
					includeInherited: true,
					targetType: typeof(SecurityIdentifier))
				.Cast<FileSystemAccessRule>()
				.Any(rule => rule.AccessControlType == AccessControlType.Allow
					&& rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute)
					&& rule.IdentityReference == poolSid);
			if (!present)
			{
				failure = "The web pool identity was not granted ReadAndExecute on the web-UI folder; publishing was stopped.";
				return false;
			}

			return true;
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException
			or IOException or InvalidOperationException or PlatformNotSupportedException)
		{
			failure = "The web pool identity access could not be applied to the web-UI folder: " + ex.Message;
			return false;
		}
	}
}
