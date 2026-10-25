// File:    src/RdpAudit.Notifier/Notifications/ToastAppRegistration.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: AUMID registration for unpackaged WinRT toasts; idempotent, current-user only.

using Microsoft.Win32;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Ensures the AppUserModelId registry registration for WinRT toasts.</summary>
public static class ToastAppRegistration
{
	/// <summary>The AUMID this notifier publishes toasts under.</summary>
	public const string AppUserModelId = "RdpAudit.Notifier";

	public const string ShellAppIdKeyPath = @"Software\Classes\AppUserModelId\RdpAudit.Notifier";

	/// <summary>True when the AUMID key already exists.</summary>
	public static bool IsRegistered()
	{
		using RegistryKey? key = Registry.CurrentUser.OpenSubKey(ShellAppIdKeyPath);
		return key is not null;
	}

	/// <summary>Writes the AUMID key with a display name when missing.</summary>
	public static void EnsureRegistered()
	{
		if (IsRegistered())
		{
			return;
		}

		using RegistryKey key = Registry.CurrentUser.CreateSubKey(ShellAppIdKeyPath);
		key.SetValue("DisplayName", "RdpAudit Notifier", RegistryValueKind.String);
	}
}
