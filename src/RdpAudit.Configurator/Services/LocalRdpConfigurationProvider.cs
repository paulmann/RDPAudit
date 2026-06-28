// File:    src/RdpAudit.Configurator/Services/LocalRdpConfigurationProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side direct reader for the live Windows Terminal Services configuration.
//          Mirrors RdpAudit.Service.Services.RdpConfigurationReader but uses only managed APIs
//          (Microsoft.Win32.Registry, ServiceController, FileVersionInfo, Environment) so the
//          "RDP Configuration" tab can populate even when the RdpAudit monitoring service is not
//          installed / not running / unreachable over the named-pipe IPC. Behavioral parity with
//          stascorp/rdpwrap's RDPConf.exe: registry-driven listener inspection plus termsrv.dll
//          version probing. Read-only — no registry mutation here.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Local, in-process source of <see cref="RdpConfigurationDto"/> snapshots. Used by the
/// Configurator UI as a fallback when the RdpAudit service IPC pipe is unreachable.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalRdpConfigurationProvider
{
	private const string TermServiceName = "TermService";

	/// <summary>Build a fresh snapshot directly from the registry and service surface.
	/// Never throws; absent / unreadable values surface as null or sentinel -1 so the UI can
	/// render a deterministic "not configured" / "unknown" hint.</summary>
	public RdpConfigurationDto Read()
	{
		RdpConfigurationDto dto = new()
		{
			Status = IpcResultStatus.Success,
			CapturedUtc = DateTime.UtcNow,
		};

		int? port = ReadHklmInt(
			RdpConfigurationModel.RdpTcpListenerKey,
			RdpConfigurationModel.PortNumberValueName);
		dto.ConfiguredPort = port is int p && RdpConfigurationModel.IsValidPort(p) ? p : null;

		int? deny = ReadHklmInt(
			RdpConfigurationModel.TerminalServerKey,
			RdpConfigurationModel.DenyTsConnectionsValueName);
		dto.RdpEnabled = RdpConfigurationModel.RdpEnabledFromRaw(deny);

		dto.UserAuthenticationRaw = ReadHklmInt(
			RdpConfigurationModel.RdpTcpListenerKey,
			RdpConfigurationModel.UserAuthenticationValueName) ?? -1;

		dto.SecurityLayerRaw = ReadHklmInt(
			RdpConfigurationModel.RdpTcpListenerKey,
			RdpConfigurationModel.SecurityLayerValueName) ?? -1;

		dto.SingleSessionPerUserRaw = ReadHklmInt(
			RdpConfigurationModel.TerminalServerKey,
			RdpConfigurationModel.SingleSessionPerUserValueName);

		dto.DontDisplayLastUserNameRaw = ReadHklmInt(
			RdpConfigurationModel.SystemPolicyKey,
			RdpConfigurationModel.DontDisplayLastUserNameValueName);

		dto.DontEnumerateConnectedUsersRaw = ReadHklmInt(
			RdpConfigurationModel.SystemPolicyKey,
			RdpConfigurationModel.DontEnumerateConnectedUsersValueName);

		int? shadowPolicy = ReadHklmInt(
			ShadowPolicyModel.TerminalServicesPolicyKey,
			ShadowPolicyModel.ShadowValueName)
			?? ReadHklmInt(
				ShadowPolicyModel.TerminalServicesMachineKey,
				ShadowPolicyModel.ShadowValueName);
		dto.ShadowModeRaw = shadowPolicy ?? -1;

		dto.PromptForPasswordPolicyRaw = ReadHklmInt(
			RdpConfigurationModel.TerminalServicesPolicyKey,
			RdpConfigurationModel.PromptForPasswordValueName);
		dto.PromptForPasswordListenerRaw = ReadHklmInt(
			RdpConfigurationModel.RdpTcpListenerKey,
			RdpConfigurationModel.PromptForPasswordValueName);

		(bool installed, bool running) = QueryTermService();
		dto.TermServiceInstalled = installed;
		dto.TermServiceRunning = running;

		dto.OsVersion = SafeOsVersion();
		dto.TermServiceVersion = SafeTermSrvVersion();

		return dto;
	}

	private static (bool Installed, bool Running) QueryTermService()
	{
		try
		{
			using ServiceController controller = new(TermServiceName);
			ServiceControllerStatus status = controller.Status; // throws when not installed
			return (true, status == ServiceControllerStatus.Running);
		}
		catch (InvalidOperationException)
		{
			return (false, false);
		}
		catch (System.ComponentModel.Win32Exception)
		{
			return (false, false);
		}
	}

	private static string? SafeOsVersion()
	{
		try
		{
			return Environment.OSVersion.VersionString;
		}
		catch (InvalidOperationException)
		{
			return null;
		}
	}

	private static string? SafeTermSrvVersion()
	{
		string? root = Environment.GetEnvironmentVariable("SystemRoot");
		if (string.IsNullOrEmpty(root))
		{
			return null;
		}

		string candidate = Path.Combine(root, "System32", "termsrv.dll");
		if (!File.Exists(candidate))
		{
			return null;
		}

		try
		{
			FileVersionInfo info = FileVersionInfo.GetVersionInfo(candidate);
			string? productVersion = info.ProductVersion;
			if (!string.IsNullOrWhiteSpace(productVersion))
			{
				return productVersion.Trim();
			}

			return info.FileVersion?.Trim();
		}
		catch (IOException)
		{
			return null;
		}
		catch (UnauthorizedAccessException)
		{
			return null;
		}
	}

	private static int? ReadHklmInt(string hklmKeyPath, string valueName)
	{
		string subKey = StripHklm(hklmKeyPath);
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
		catch (UnauthorizedAccessException)
		{
			return null;
		}
		catch (IOException)
		{
			return null;
		}
	}

	private static string StripHklm(string path)
	{
		const string Prefix = @"HKLM\";
		if (path.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
		{
			return path[Prefix.Length..];
		}

		return path;
	}
}
