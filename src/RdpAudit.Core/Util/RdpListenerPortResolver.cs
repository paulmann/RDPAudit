// File:    src/RdpAudit.Core/Util/RdpListenerPortResolver.cs
// Module:  RdpAudit.Core.Util
// Purpose: Resolves the TCP port number on which the local RDP listener is configured. The
//          authoritative source is the DWORD value
//          HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber.
//          When that value is missing or out of range the fallback is the Microsoft default 3389.
//          Production code MUST go through this resolver rather than hardcoding 3389 or any
//          other port; the user diagnostic value 55554 is exclusively a documented example and
//          must not appear as a constant in product code. The resolver exposes two layers:
//            * a pure validator (testable cross-platform) that classifies a raw integer;
//            * a Windows-only Resolve() that reads the registry through Microsoft.Win32.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace RdpAudit.Core.Util;

/// <summary>Outcome of a port-resolution attempt. <see cref="Source"/> identifies whether the
/// port came from the registry or from the documented Microsoft default. Operators see this in
/// diagnostic / status text so it is clear which branch served the live port.</summary>
public sealed record RdpListenerPortResolution(int Port, RdpListenerPortSource Source, string? Detail)
{
	/// <summary>True when the port came from a registry value that parsed inside the valid range.</summary>
	public bool IsFromRegistry => Source == RdpListenerPortSource.Registry;
}

/// <summary>Where the port number came from.</summary>
public enum RdpListenerPortSource
{
	/// <summary>Registry value missing or invalid; <see cref="RdpConfigurationModel.DefaultRdpPort"/> used.</summary>
	Default = 0,

	/// <summary>Registry value present and inside the valid range.</summary>
	Registry = 1,
}

/// <summary>Pure + Windows-only helpers that resolve the configured RDP listener TCP port.</summary>
public static class RdpListenerPortResolver
{
	/// <summary>Minimum valid TCP port (Windows accepts 1..65535; 0 is reserved).</summary>
	public const int MinPort = 1;

	/// <summary>Maximum valid TCP port.</summary>
	public const int MaxPort = 65535;

	/// <summary>Pure helper: returns the resolved port given the raw value read from the
	/// registry. Accepts <c>null</c> (value not present) and integers outside the valid range.
	/// The fallback is always <see cref="RdpConfigurationModel.DefaultRdpPort"/>.</summary>
	public static RdpListenerPortResolution ClassifyRaw(int? raw)
	{
		if (raw is int p && p >= MinPort && p <= MaxPort)
		{
			return new RdpListenerPortResolution(
				p,
				RdpListenerPortSource.Registry,
				"PortNumber=" + p.ToString(CultureInfo.InvariantCulture));
		}

		string detail = raw is null
			? "PortNumber missing — using default " + RdpConfigurationModel.DefaultRdpPort.ToString(CultureInfo.InvariantCulture)
			: "PortNumber=" + raw.Value.ToString(CultureInfo.InvariantCulture)
				+ " out of range — using default "
				+ RdpConfigurationModel.DefaultRdpPort.ToString(CultureInfo.InvariantCulture);

		return new RdpListenerPortResolution(RdpConfigurationModel.DefaultRdpPort, RdpListenerPortSource.Default, detail);
	}

	/// <summary>Windows-only: reads PortNumber from
	/// <c>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp</c> and
	/// classifies the raw value. Never throws — registry failures resolve to the default.</summary>
	[SupportedOSPlatform("windows")]
	public static RdpListenerPortResolution Resolve()
	{
		int? raw = TryReadPortNumber();
		return ClassifyRaw(raw);
	}

	[SupportedOSPlatform("windows")]
	private static int? TryReadPortNumber()
	{
		const string SubKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SubKey, writable: false);
			if (key is null)
			{
				return null;
			}

			object? raw = key.GetValue("PortNumber");
			if (raw is null)
			{
				return null;
			}

			if (raw is int i)
			{
				return i;
			}

			if (int.TryParse(raw.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
			{
				return parsed;
			}

			return null;
		}
		catch (System.Security.SecurityException)
		{
			return null;
		}
		catch (System.IO.IOException)
		{
			return null;
		}
		catch (System.UnauthorizedAccessException)
		{
			return null;
		}
	}
}
