// File:    src/RdpAudit.Configurator/Services/RegistryWebAccessPreferenceStore.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: HKCU-backed preference store for the Configurator "Web Access" tab. Both flags
//          default to false (privacy-first); the management flag is additionally phase-gated
//          by the UI before anything is persisted. Registry access is best-effort on every
//          call: on failure the store answers false and the last write attempt is reported as
//          unsuccessful, so the tab degrades to a safe locked state instead of throwing.
//          Never stores secrets - only the two booleans.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Services;

/// <summary>Registry-backed <see cref="IWebAccessPreferenceStore"/> scoped to the current user.</summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryWebAccessPreferenceStore : IWebAccessPreferenceStore
{
	/// <summary>Single registry key under HKCU\Software holding both flags.</summary>
	public const string RegistryKeyPath = @"Software\RdpAudit\Configurator";

	/// <summary>Value name for the show-tab flag.</summary>
	public const string ShowTabValueName = "WebAccessShowTab";

	/// <summary>Value name for the allow-management flag.</summary>
	public const string AllowManagementValueName = "WebAccessAllowManagement";

	/// <inheritdoc/>
	public bool IsTabEnabled => ReadBool(ShowTabValueName);

	/// <inheritdoc/>
	public bool IsManagementEnabled => ReadBool(AllowManagementValueName);

	/// <inheritdoc/>
	public Task<bool> SetTabEnabledAsync(bool enabled, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return Task.FromResult(WriteBool(ShowTabValueName, enabled));
	}

	/// <inheritdoc/>
	public Task<bool> SetManagementEnabledAsync(bool enabled, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return Task.FromResult(WriteBool(AllowManagementValueName, enabled));
	}

	private static bool ReadBool(string valueName)
	{
		try
		{
			using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegistryKeyPath);
			return key?.GetValue(valueName) is int raw && raw != 0;
		}
		catch (Exception ex) when (ex is System.Security.SecurityException
			or UnauthorizedAccessException or System.IO.IOException)
		{
			return false;
		}
	}

	private static bool WriteBool(string valueName, bool value)
	{
		try
		{
			using RegistryKey key = Registry.CurrentUser.CreateSubKey(RegistryKeyPath);
			key.SetValue(valueName, value ? 1 : 0, RegistryValueKind.DWord);
			return true;
		}
		catch (Exception ex) when (ex is System.Security.SecurityException
			or UnauthorizedAccessException or System.IO.IOException)
		{
			return false;
		}
	}
}
