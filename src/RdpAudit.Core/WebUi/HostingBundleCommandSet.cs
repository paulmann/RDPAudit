// File:    src/RdpAudit.Core/WebUi/HostingBundleCommandSet.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Command shapes and read-only detection for the IIS-side prerequisite the web UI cannot
//          run without: the ASP.NET Core Module v2 (ANCM). The module is a native IIS component
//          that ships ONLY inside the ASP.NET Core Hosting Bundle - no DISM feature provides it -
//          and the published application is hosted in-process
//          (publish/Web/web.config: hostingModel="inprocess", modules="AspNetCoreModuleV2"), so
//          without it Configure IIS refuses to proceed and the Dashboard can never come up.
//
//          The installer is driven through winget, the same channel install.ps1 already uses for
//          its prerequisites (install.ps1:1141-1156), so no new download or trust surface is
//          introduced. Detection is deliberately file-system based and read-only: it needs no
//          elevation, and it is an INDICATION only - the authoritative check stays the appcmd
//          module listing performed by the Configure IIS workflow. Nothing in this file executes a
//          command or changes system state.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.IO;

namespace RdpAudit.Core.WebUi;

/// <summary>Well-known identifiers of the ASP.NET Core Hosting Bundle and the native module it
/// installs. Verified against the machine's own winget source: the package id resolves
/// (<c>winget show --id Microsoft.DotNet.HostingBundle.8 --exact</c>) and the module file names
/// match what the bundle drops into the IIS directory.</summary>
public static class HostingBundlePackage
{
	/// <summary>winget package identifier of the .NET 8 ASP.NET Core Hosting Bundle.</summary>
	public const string WingetPackageId = "Microsoft.DotNet.HostingBundle.8";

	/// <summary>Native module name IIS records in its globalModules list; this is the token the
	/// Configure IIS workflow looks for (see <c>IisConfigureCommandSet.ContainsAspNetCoreModuleV2</c>).</summary>
	public const string ModuleName = "AspNetCoreModuleV2";

	/// <summary>Out-of-process native module binary installed by the bundle.</summary>
	public const string ModuleFileName = "aspnetcorev2.dll";

	/// <summary>In-process native module binary installed by the bundle. In-process hosting - the
	/// hosting model this product publishes with - is served by this one.</summary>
	public const string InProcessModuleFileName = "aspnetcorev2_inprocess.dll";
}

/// <summary>Deterministic command shapes for installing and locating the Hosting Bundle. The
/// builder never runs anything; the workflow executes the returned vector through
/// <see cref="RdpAudit.Core.Util.IExternalCommandRunner"/> after operator consent.</summary>
public static class HostingBundleCommandSet
{
	/// <summary>winget executable, resolved from PATH the same way install.ps1 resolves it.</summary>
	public const string WingetExecutable = "winget.exe";

	/// <summary>Command label used in logs and UI diagnostics.</summary>
	public const string InstallCommandLabel = "winget ASP.NET Core Hosting Bundle install";

	/// <summary>Hard timeout for the winget install. A Hosting Bundle install downloads the package
	/// and runs a Microsoft installer, so the cap is deliberately generous - same reasoning as the
	/// DISM timeout in the install workflow.</summary>
	public static readonly TimeSpan DefaultInstallTimeout = TimeSpan.FromMinutes(15);

	/// <summary>Argument vector that installs the Hosting Bundle unattended. Mirrors the flags
	/// install.ps1 already uses (<c>--exact --silent --accept-source-agreements
	/// --accept-package-agreements</c>) so the operator never sees an interactive prompt from a
	/// service-adjacent workflow.</summary>
	public static IReadOnlyList<string> BuildInstallArguments()
	{
		return new[]
		{
			"install",
			"--id",
			HostingBundlePackage.WingetPackageId,
			"--exact",
			"--silent",
			"--accept-source-agreements",
			"--accept-package-agreements",
		};
	}
}

/// <summary>
/// Read-only detection of the ASP.NET Core Module v2 on the IIS side. Reports the module as present
/// only when BOTH native binaries the bundle installs are on disk; anything else is reported as not
/// present together with the missing file names, so the operator sees what is actually wrong instead
/// of a bare "failed". This is an indication, not an authority: only IIS itself can confirm that the
/// module is registered - that check belongs to the Configure IIS workflow.
/// </summary>
public sealed class AspNetCoreModuleProbe
{
	private readonly Func<string, bool> _fileExists;

	/// <summary>Creates the probe for the given IIS directory (null = the machine's own
	/// <c>%windir%\System32\inetsrv</c>) with an injectable file-existence check so the contract is
	/// unit-testable without a Windows host.</summary>
	/// <param name="inetsrvDirectory">IIS binary directory; null resolves the machine default.</param>
	/// <param name="fileExists">File-existence probe; null uses <see cref="File.Exists(string)"/>.</param>
	public AspNetCoreModuleProbe(string? inetsrvDirectory = null, Func<string, bool>? fileExists = null)
	{
		InetsrvDirectory = inetsrvDirectory ?? ResolveDefaultInetsrvDirectory();
		_fileExists = fileExists ?? File.Exists;
	}

	/// <summary>The IIS binary directory this probe inspects.</summary>
	public string InetsrvDirectory { get; }

	/// <summary>True only when every native module binary the Hosting Bundle installs is present.</summary>
	public bool IsModuleInstalled() => MissingFileNames().Count == 0;

	/// <summary>Names of the expected module binaries that are absent; empty when the module is
	/// fully present. Never throws - an unreadable location reports "missing", never "installed".</summary>
	public IReadOnlyList<string> MissingFileNames()
	{
		List<string> missing = new(2);
		foreach (string fileName in new[]
			{
				HostingBundlePackage.ModuleFileName,
				HostingBundlePackage.InProcessModuleFileName,
			})
		{
			if (!Exists(Path.Combine(InetsrvDirectory, fileName)))
			{
				missing.Add(fileName);
			}
		}

		return missing;
	}

	private bool Exists(string path)
	{
		try
		{
			return _fileExists(path);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
			or ArgumentException or NotSupportedException)
		{
			// An unreadable location must never be reported as "the module is installed".
			return false;
		}
	}

	private static string ResolveDefaultInetsrvDirectory() => Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.System),
		"inetsrv");
}
