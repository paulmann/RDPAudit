// File:    src/RdpAudit.Configurator/Services/LocalShadowPolicyReader.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side, read-only reader for the Microsoft Terminal Services
//          Shadow registry policy. Used when the RdpAudit service IPC is unreachable
//          so the gating logic still has a fresh policy snapshot to consult before
//          spawning mstsc. Mirrors the service-side ShadowPolicyManager registry-read
//          path (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow,
//          with HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Shadow as the
//          legacy fallback). Read-only: no <see cref="Microsoft.Win32.Registry"/>
//          write APIs are referenced.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Configurator-side, read-only Shadow policy reader.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalShadowPolicyReader
{
	/// <summary>Read the current Shadow policy mode from HKLM. Returns
	/// <see cref="ShadowPolicyMode.NotConfigured"/> when neither the group-policy nor the
	/// per-machine value is present (or any read throws).</summary>
	public ShadowPolicyMode Read()
	{
		int? primary = TryReadValue(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.ShadowValueName)
			?? TryReadValue(ShadowPolicyModel.TerminalServicesMachineKey, ShadowPolicyModel.ShadowValueName);
		return ShadowPolicyModel.FromRawValue(primary);
	}

	private static int? TryReadValue(string hklmKeyPath, string valueName)
	{
		string? subKey = StripHklm(hklmKeyPath);
		if (subKey is null)
		{
			return null;
		}

		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKey, writable: false);
			if (key is null)
			{
				return null;
			}

			object? raw = key.GetValue(valueName);
			if (raw is null)
			{
				return null;
			}

			if (raw is int i)
			{
				return i;
			}

			return int.TryParse(raw.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
				? parsed
				: null;
		}
		catch
		{
			return null;
		}
	}

	private static string? StripHklm(string path)
	{
		const string prefix = @"HKLM\";
		return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
			? path[prefix.Length..]
			: null;
	}
}
