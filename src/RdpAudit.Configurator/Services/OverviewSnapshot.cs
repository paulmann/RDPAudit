// File:    src/RdpAudit.Configurator/Services/OverviewSnapshot.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Aggregates first-run / health information shown on the Overview tab:
//          ProgramData state, DB readiness, service distribution presence, Windows
//          service status, and the list of errors/warnings detected during probing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.ServiceProcess;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Aggregated first-run / health snapshot for the Overview tab.</summary>
public sealed record OverviewSnapshot(
	ServiceLayoutInfo Layout,
	bool ProgramDataExists,
	bool ProgramDataWritable,
	bool AppSettingsExists,
	bool DatabaseExists,
	string DatabasePath,
	bool ServiceInstalled,
	string ServiceStatus,
	bool IsFirstRun,
	IReadOnlyList<string> Errors,
	IReadOnlyList<string> Warnings);

/// <summary>Probes the local machine for first-run / health state shown on the Overview tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class OverviewProbe
{
	public OverviewSnapshot Capture()
	{
		ServiceLayoutInfo layout = ServiceLayout.Discover(AppContext.BaseDirectory);
		List<string> errors = new();
		List<string> warnings = new();

		bool programDataExists = Directory.Exists(layout.ProgramDataDirectory);
		bool programDataWritable = false;
		if (programDataExists)
		{
			try
			{
				string probe = Path.Combine(layout.ProgramDataDirectory, ".rdpaudit-write-probe");
				File.WriteAllText(probe, "ok");
				File.Delete(probe);
				programDataWritable = true;
			}
			catch (Exception ex)
			{
				errors.Add($"ProgramData not writable: {ex.Message}");
			}
		}
		else
		{
			warnings.Add($"ProgramData directory missing: {layout.ProgramDataDirectory}");
		}

		bool appSettingsExists = File.Exists(layout.AppSettingsPath);
		if (!appSettingsExists)
		{
			warnings.Add($"appsettings.json missing at {layout.AppSettingsPath}");
		}

		string databasePath = ReadOnlyDb.DatabasePath;
		bool databaseExists = File.Exists(databasePath);
		if (!databaseExists)
		{
			warnings.Add($"Audit database missing at {databasePath}");
		}

		(bool installed, string status) = ProbeService();
		if (!installed)
		{
			warnings.Add("RdpAuditService is not registered.");
		}
		else if (!string.Equals(status, "Running", StringComparison.OrdinalIgnoreCase))
		{
			warnings.Add($"RdpAuditService is not running (status: {status}).");
		}

		if (!layout.DistributionExists)
		{
			warnings.Add($"Service distribution folder not found near Configurator (expected {ServiceLayout.ResolveSiblingDistribution(layout.ConfiguratorDirectory)}).");
		}
		else if (!layout.ServiceExecutableExists)
		{
			errors.Add($"Service executable missing inside distribution: {layout.ExpectedServiceExecutable}");
		}

		bool isFirstRun = !programDataExists || !appSettingsExists || !databaseExists || !installed;

		return new OverviewSnapshot(
			layout,
			programDataExists,
			programDataWritable,
			appSettingsExists,
			databaseExists,
			databasePath,
			installed,
			status,
			isFirstRun,
			errors,
			warnings);
	}

	private static (bool Installed, string Status) ProbeService()
	{
		try
		{
			using ServiceController controller = new(InstallationService.ServiceName);
			return (true, controller.Status.ToString());
		}
		catch (InvalidOperationException)
		{
			return (false, "NotInstalled");
		}
		catch (Exception ex)
		{
			return (false, ex.GetType().Name);
		}
	}
}
