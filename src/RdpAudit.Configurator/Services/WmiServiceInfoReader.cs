// File:    src/RdpAudit.Configurator/Services/WmiServiceInfoReader.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Authoritative SCM lookup for the RdpAudit service. Reads Win32_Service via
//          System.Management to retrieve Name, DisplayName, State, ProcessId, StartMode,
//          PathName (ImagePath), Status, ExitCode, and ServiceSpecificExitCode. Surfaces a
//          ServiceInstallationInfo value object suitable for the Service tab state model.
//          Locale-stable: state codes (1..7) are read directly from the State enum rather
//          than from sc.exe textual output, so non-English Windows installs do not break
//          the run-state detection.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Authoritative Win32_Service reader used by the Service tab. All calls execute
/// synchronously on the thread pool via <see cref="ReadAsync"/>; the caller is expected to
/// await the returned task on a non-UI thread.</summary>
[SupportedOSPlatform("windows")]
public sealed class WmiServiceInfoReader
{
	private readonly string _serviceName;

	public WmiServiceInfoReader(string serviceName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		_serviceName = serviceName;
	}

	/// <summary>Reads the SCM snapshot for the configured service name. Never throws -
	/// any error is captured in <see cref="ServiceInstallationInfo.Diagnostic"/>.</summary>
	public async Task<ServiceInstallationInfo> ReadAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => ReadCore(), ct).ConfigureAwait(false);
	}

	private ServiceInstallationInfo ReadCore()
	{
		string escaped = _serviceName.Replace("\\", "\\\\", StringComparison.Ordinal)
			.Replace("'", "\\'", StringComparison.Ordinal);
		string query = $"SELECT Name, DisplayName, State, ProcessId, StartMode, PathName, Status, ExitCode, ServiceSpecificExitCode FROM Win32_Service WHERE Name='{escaped}'";

		try
		{
			using ManagementObjectSearcher searcher = new(new ObjectQuery(query));
			using ManagementObjectCollection results = searcher.Get();
			foreach (ManagementBaseObject row in results)
			{
				using (row)
				{
					return Project(row);
				}
			}

			return NotInstalled(diagnostic: null);
		}
		catch (ManagementException ex)
		{
			return NotInstalled($"WMI query failed: {ex.Message}");
		}
		catch (System.Runtime.InteropServices.COMException ex)
		{
			return NotInstalled($"WMI COM failure: {ex.Message}");
		}
		catch (UnauthorizedAccessException ex)
		{
			return NotInstalled($"WMI access denied: {ex.Message}");
		}
	}

	private ServiceInstallationInfo Project(ManagementBaseObject row)
	{
		string? stateName = ReadString(row, "State");
		int? stateCode = MapStateCode(stateName);
		uint? processIdRaw = ReadUInt32(row, "ProcessId");
		int? processId = processIdRaw is uint p && p != 0 ? (int)p : null;
		uint? exitCodeRaw = ReadUInt32(row, "ExitCode");
		int? exitCode = exitCodeRaw is uint e ? (int)e : null;
		uint? serviceSpecificRaw = ReadUInt32(row, "ServiceSpecificExitCode");
		int? serviceSpecific = serviceSpecificRaw is uint s ? (int)s : null;

		return new ServiceInstallationInfo(
			ServiceName: _serviceName,
			Installed: true,
			DisplayName: ReadString(row, "DisplayName"),
			StateCode: stateCode,
			StateName: stateName,
			ProcessId: processId,
			ImagePath: ReadString(row, "PathName"),
			StartMode: ReadString(row, "StartMode"),
			Status: ReadString(row, "Status"),
			Win32ExitCode: exitCode,
			ServiceSpecificExitCode: serviceSpecific,
			Diagnostic: null);
	}

	private static int? MapStateCode(string? stateName) => stateName switch
	{
		null => null,
		"Stopped" => 1,
		"Start Pending" => 2,
		"Stop Pending" => 3,
		"Running" => 4,
		"Continue Pending" => 5,
		"Pause Pending" => 6,
		"Paused" => 7,
		_ => null,
	};

	private static string? ReadString(ManagementBaseObject row, string property)
	{
		try
		{
			object? value = row[property];
			if (value is null)
			{
				return null;
			}

			string text = value.ToString() ?? string.Empty;
			return text.Length == 0 ? null : text;
		}
		catch (ManagementException)
		{
			return null;
		}
	}

	private static uint? ReadUInt32(ManagementBaseObject row, string property)
	{
		try
		{
			object? value = row[property];
			if (value is null)
			{
				return null;
			}

			return value switch
			{
				uint u => u,
				int i => i >= 0 ? (uint?)i : null,
				long l => l >= 0 ? (uint?)l : null,
				string s when uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint p) => p,
				_ => null,
			};
		}
		catch (ManagementException)
		{
			return null;
		}
	}

	private ServiceInstallationInfo NotInstalled(string? diagnostic) =>
		new(
			ServiceName: _serviceName,
			Installed: false,
			DisplayName: null,
			StateCode: null,
			StateName: null,
			ProcessId: null,
			ImagePath: null,
			StartMode: null,
			Status: null,
			Win32ExitCode: null,
			ServiceSpecificExitCode: null,
			Diagnostic: diagnostic);
}
