// File:    src/RdpAudit.Core/Util/ServiceLayout.cs
// Module:  RdpAudit.Core.Util
// Purpose: Locates the published Service distribution folder relative to the running
//          Configurator and resolves runtime paths (DB, appsettings, install destination)
//          on any machine — no hard-coded "C:\1st_RdpMON" assumptions.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;

namespace RdpAudit.Core.Util;

/// <summary>Snapshot of the service distribution layout discovered relative to the running Configurator.</summary>
public sealed record ServiceLayoutInfo(
	string ConfiguratorDirectory,
	string? DistributionDirectory,
	bool DistributionExists,
	string ExpectedServiceExecutable,
	bool ServiceExecutableExists,
	string InstallDirectory,
	string ProgramDataDirectory,
	string AppSettingsPath,
	string DefaultDatabasePath);

/// <summary>Locates published service files relative to the Configurator and resolves install/runtime paths.</summary>
public static class ServiceLayout
{
	/// <summary>The expected file name of the service executable.</summary>
	public const string ServiceExeName = "RdpAudit.Service.exe";

	/// <summary>Discovers the on-disk layout for the running Configurator.</summary>
	/// <param name="configuratorDir">Base directory of the running Configurator. Pass
	/// <c>AppContext.BaseDirectory</c> in production, override in tests.</param>
	[SupportedOSPlatform("windows")]
	public static ServiceLayoutInfo Discover(string configuratorDir)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(configuratorDir);
		string distribution = ResolveSiblingDistribution(configuratorDir);
		string expectedExe = Path.Combine(distribution, ServiceExeName);
		bool distExists = Directory.Exists(distribution);
		bool exeExists = File.Exists(expectedExe);

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string programDataRdp = Path.Combine(programData, "RdpAudit");
		string installDir = ResolveInstallDirectory();

		return new ServiceLayoutInfo(
			ConfiguratorDirectory: configuratorDir,
			DistributionDirectory: distExists ? distribution : null,
			DistributionExists: distExists,
			ExpectedServiceExecutable: expectedExe,
			ServiceExecutableExists: exeExists,
			InstallDirectory: installDir,
			ProgramDataDirectory: programDataRdp,
			AppSettingsPath: Path.Combine(programDataRdp, "appsettings.json"),
			DefaultDatabasePath: Path.Combine(programDataRdp, "rdpaudit.db"));
	}

	/// <summary>Resolves the sibling 'Service' distribution folder for the Configurator.
	/// Heuristic: <c>publish/Configurator</c> sibling is <c>publish/Service</c>; if the
	/// Configurator runs from a non-publish location we fall back to a sibling 'Service'
	/// folder under the same parent.</summary>
	public static string ResolveSiblingDistribution(string configuratorDir)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(configuratorDir);
		string trimmed = configuratorDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		DirectoryInfo? parent = Directory.GetParent(trimmed);
		if (parent is null)
		{
			return Path.Combine(trimmed, "Service");
		}

		return Path.Combine(parent.FullName, "Service");
	}

	/// <summary>Resolves the runtime install directory — honours an environment override and
	/// otherwise targets <c>%ProgramFiles%\RdpAudit\Service</c>.</summary>
	[SupportedOSPlatform("windows")]
	public static string ResolveInstallDirectory()
	{
		string? envOverride = Environment.GetEnvironmentVariable("RDPAUDIT_INSTALL_DIR");
		if (!string.IsNullOrWhiteSpace(envOverride))
		{
			return envOverride;
		}

		string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
		return Path.Combine(programFiles, "RdpAudit", "Service");
	}
}
