// File:    src/RdpAudit.Service/Services/RdpConfigurationReader.cs
// Module:  RdpAudit.Service.Services
// Purpose: Service-side reader that builds an <see cref="RdpConfigurationDto"/> snapshot from the
//          Windows registry, the TermService Windows service, and termsrv.dll product version when
//          readable. The reader never throws on missing keys; absent values surface as null /
//          sentinel -1 so the Configurator UI can render a deterministic "not configured" hint
//          instead of crashing on an IPC fault.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Reads the current RDP listener configuration from the registry and service surface.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpConfigurationReader
{
	internal const string TermServiceName = "TermService";

	private readonly ILogger<RdpConfigurationReader> _logger;
	private readonly ShadowPolicyManager? _shadow;

	public RdpConfigurationReader(ILogger<RdpConfigurationReader> logger, ShadowPolicyManager? shadow = null)
	{
		_logger = logger;
		_shadow = shadow;
	}

	/// <summary>Build a fresh snapshot. Never throws on missing values; logs at Debug for visibility.</summary>
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

		_ = _shadow; // reserved for future integration; reads do not require ShadowPolicyManager today.
		return dto;
	}

	private (bool Installed, bool Running) QueryTermService()
	{
		try
		{
			using ServiceController controller = new(TermServiceName);
			ServiceControllerStatus status = controller.Status; // throws when not installed
			return (true, status == ServiceControllerStatus.Running);
		}
		catch (InvalidOperationException ex)
		{
			_logger.LogDebug(ex, "TermService query failed");
			return (false, false);
		}
		catch (System.ComponentModel.Win32Exception ex)
		{
			_logger.LogDebug(ex, "TermService query failed (Win32)");
			return (false, false);
		}
	}

	private string? SafeOsVersion()
	{
		try
		{
			return Environment.OSVersion.VersionString;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "OSVersion read failed");
			return null;
		}
	}

	private string? SafeTermSrvVersion()
	{
		string? root = Environment.GetEnvironmentVariable("SystemRoot");
		if (string.IsNullOrEmpty(root))
		{
			return null;
		}

		string candidate = System.IO.Path.Combine(root, "System32", "termsrv.dll");
		if (!System.IO.File.Exists(candidate))
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
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "termsrv.dll version read failed");
			return null;
		}
	}

	private int? ReadHklmInt(string hklmKeyPath, string valueName)
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
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Failed to read {Key}\\{Value}", hklmKeyPath, valueName);
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
