// File:    src/RdpAudit.Configurator/Services/InstallationService.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: First-run installer used by the Overview and Service tabs. Creates the
//          ProgramData layout with administrator/SYSTEM-friendly ACLs, copies the
//          sibling Service distribution into Program Files, and registers the
//          Windows service via sc.exe. Surfaces errors without swallowing them.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Summary of the work performed by <see cref="InstallationService"/>.</summary>
public sealed record InstallationOutcome(
	bool Success,
	IReadOnlyList<string> Steps,
	IReadOnlyList<string> Warnings,
	IReadOnlyList<string> Errors,
	string? LogFilePath = null);

/// <summary>Single step result for first-run install logging.</summary>
internal sealed record InstallStep(string Description, bool Ok, string? Detail = null);

/// <summary>Result of one sc.exe invocation, with combined stdout/stderr for diagnostics.</summary>
internal sealed record ScResult(int ExitCode, string StdOut, string StdErr)
{
	public string CombinedOutput
	{
		get
		{
			if (StdOut.Length == 0)
			{
				return StdErr;
			}

			if (StdErr.Length == 0)
			{
				return StdOut;
			}

			return StdOut + Environment.NewLine + StdErr;
		}
	}
}

/// <summary>Idempotent installer that prepares ProgramData, copies the published Service
/// distribution into Program Files, and registers the Windows service.</summary>
[SupportedOSPlatform("windows")]
public sealed class InstallationService
{
	internal const string ServiceName = "RdpAuditService";
	internal const string ServiceDisplayName = "RDP Monitor";

	private readonly ServiceLayoutInfo _layout;

	public InstallationService(ServiceLayoutInfo layout)
	{
		_layout = layout ?? throw new ArgumentNullException(nameof(layout));
	}

	/// <summary>Runs the full first-run install. Each step is independent and individual
	/// failures are surfaced via the returned outcome rather than thrown.</summary>
	public async Task<InstallationOutcome> RunAsync(CancellationToken ct = default)
	{
		List<string> steps = new();
		List<string> warnings = new();
		List<string> errors = new();

		InstallUpdateLogger logger = new(_layout, "install");
		logger.Info($"Install started — install directory: {_layout.InstallDirectory}");
		logger.Info($"Distribution directory: {_layout.DistributionDirectory ?? "(missing)"}");

		ElevationStatus elevation = ElevationGuard.Check();
		logger.Info("Elevation check: " + elevation.Message);
		if (!elevation.IsElevated)
		{
			errors.Add(elevation.Message);
			logger.Fail(elevation.Message);
			return new InstallationOutcome(false, steps, warnings, errors, logger.LogFilePath);
		}

		DirectoryEnsureResult installDirCheck = InstallDirectoryGuard.EnsureWritable(_layout.InstallDirectory);
		logger.Info("Install directory check: " + installDirCheck.Message);
		if (!installDirCheck.Success)
		{
			string compose = installDirCheck.Detail is null
				? installDirCheck.Message
				: $"{installDirCheck.Message} — {installDirCheck.Detail}";
			errors.Add(compose);
			logger.Fail(compose);
			return new InstallationOutcome(false, steps, warnings, errors, logger.LogFilePath);
		}

		steps.Add(installDirCheck.Message);

		// Snapshot before any audit policy / SACL / service / appsettings change is made,
		// so a misbehaving repair can be undone via the Restore button.
		await TakePreInstallBackupAsync(steps, warnings, ct).ConfigureAwait(false);

		Record(EnsureProgramDataLayout, steps, errors, logger);
		Record(EnsureAppSettings, steps, errors, logger);
		VerifySqliteSupportBundle(steps, warnings, logger);

		if (_layout.DistributionExists && _layout.ServiceExecutableExists)
		{
			Record(() => CopyDistribution(_layout.DistributionDirectory!, _layout.InstallDirectory),
				steps, errors, logger);
			await Record(InstallOrUpdateServiceAsync, steps, errors, logger, ct).ConfigureAwait(false);
			await Record(StartServiceAsync, steps, errors, logger, ct).ConfigureAwait(false);
		}
		else
		{
			string detail = string.Format(CultureInfo.InvariantCulture,
				"Service distribution not found at '{0}'. Run publish.ps1 so the Configurator can copy '{1}' to '{2}'.",
				_layout.DistributionDirectory ?? ServiceLayout.ResolveSiblingDistribution(_layout.ConfiguratorDirectory),
				ServiceLayout.ServiceExeName, _layout.InstallDirectory);
			warnings.Add(detail);
			logger.Warn(detail);
		}

		bool success = errors.Count == 0;
		logger.Info(success
			? "Install finished — verdict: OK"
			: "Install finished with errors — verdict: see error list");
		return new InstallationOutcome(success, steps, warnings, errors, logger.LogFilePath);
	}

	internal async Task TakePreInstallBackupAsync(List<string> steps, List<string> warnings, CancellationToken ct)
	{
		try
		{
			// Backup runner needs the ProgramData folder; create it without ACLs first so the
			// snapshot directory can be written. Full ACL hardening still runs as a regular install step.
			Directory.CreateDirectory(_layout.ProgramDataDirectory);
			BackupRunner runner = new(_layout);
			BackupOutcome outcome = await runner.RunAsync(BackupReason.FirstRunInstall, ct).ConfigureAwait(false);
			steps.Add($"Pre-install backup snapshot: {outcome.Snapshot.SnapshotDirectory}");
			foreach (BackupStep step in outcome.Steps)
			{
				if (!step.Ok)
				{
					warnings.Add($"Backup step '{step.Description}' did not complete: {step.Detail ?? "(no detail)"}");
				}
			}
		}
		catch (Exception ex)
		{
			warnings.Add($"Pre-install backup could not run: {ex.Message}");
		}
	}

	internal InstallStep EnsureProgramDataLayout()
	{
		try
		{
			Directory.CreateDirectory(_layout.ProgramDataDirectory);
			ApplyProgramDataAcl(_layout.ProgramDataDirectory);
			return new InstallStep($"ProgramData layout: {_layout.ProgramDataDirectory}", true);
		}
		catch (Exception ex)
		{
			return new InstallStep("ProgramData layout", false, ex.Message);
		}
	}

	internal InstallStep EnsureAppSettings()
	{
		try
		{
			if (File.Exists(_layout.AppSettingsPath))
			{
				return new InstallStep($"appsettings.json present at {_layout.AppSettingsPath}", true);
			}

			string template = DefaultAppSettings.Render(_layout.DefaultDatabasePath);
			File.WriteAllText(_layout.AppSettingsPath, template);
			return new InstallStep($"Wrote default appsettings.json to {_layout.AppSettingsPath}", true);
		}
		catch (Exception ex)
		{
			return new InstallStep("Write appsettings.json", false, ex.Message);
		}
	}

	/// <summary>Verifies that the SQLite diagnostic support bundle (Microsoft.Data.Sqlite +
	/// SQLitePCLRaw.* + native e_sqlite3.dll) is physically present next to the running Configurator.
	/// The single-file Configurator embeds these for its own use, but external PowerShell diagnostics
	/// need them as loose files; publish.ps1 (Ensure-SqliteSupportBundle) lays them down. A complete
	/// bundle is recorded as a successful step; an incomplete one is surfaced as a warning that names
	/// every missing file by exact path so the operator can re-run publish.ps1 — it does not block the
	/// service install, which does not itself depend on the loose bundle.</summary>
	internal void VerifySqliteSupportBundle(List<string> steps, List<string> warnings, InstallUpdateLogger? logger = null)
	{
		string configuratorDir = _layout.ConfiguratorDirectory;
		SqliteSupportBundleStatus status = SqliteSupportBundle.Verify(configuratorDir);
		if (status.Complete)
		{
			string ok = string.Format(CultureInfo.InvariantCulture,
				"SQLite diagnostic support bundle verified ({0}/{0} files) in {1}",
				SqliteSupportBundle.RequiredFiles.Count, configuratorDir);
			steps.Add(ok);
			logger?.Info(ok);
			return;
		}

		StringBuilder sb = new();
		sb.Append(SqliteSupportBundle.DescribeMissing(status));
		foreach (string missing in status.MissingFiles)
		{
			sb.AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "  - missing: {0}",
				Path.Combine(configuratorDir, missing));
		}

		string warning = sb.ToString();
		warnings.Add(warning);
		logger?.Warn(warning);
	}

	internal static InstallStep CopyDistribution(string source, string destination)
	{
		DirectoryEnsureResult ensure = InstallDirectoryGuard.EnsureWritable(destination);
		if (!ensure.Success)
		{
			string detail = ensure.Detail is null ? ensure.Message : $"{ensure.Message} — {ensure.Detail}";
			return new InstallStep($"Copy distribution to {destination}", false, detail);
		}

		InstallTransferResult result = InstallTransfer.Copy(source, destination);
		if (result.Success)
		{
			return new InstallStep(
				$"Copied {result.FilesCopied}/{result.FilesConsidered} files to {destination} (SHA-256 verified)",
				true);
		}

		System.Text.StringBuilder sb = new();
		if (result.Mismatches.Count > 0)
		{
			sb.AppendLine("Hash mismatches after copy:");
			foreach (string m in result.Mismatches)
			{
				sb.AppendLine("  " + m);
			}
		}

		if (result.Failures.Count > 0)
		{
			sb.AppendLine("Failures:");
			foreach (string f in result.Failures)
			{
				sb.AppendLine("  " + f);
			}
		}

		return new InstallStep($"Copy distribution to {destination}", false, sb.ToString().Trim());
	}

	internal async Task<InstallStep> InstallOrUpdateServiceAsync(CancellationToken ct)
	{
		string targetExe = Path.Combine(_layout.InstallDirectory, ServiceLayout.ServiceExeName);
		if (!File.Exists(targetExe))
		{
			return new InstallStep("Register Windows service", false, $"Missing target {targetExe}");
		}

		bool exists = ServiceExists(ServiceName);

		// Use the *Quoted variants so the registry ImagePath token is wrapped in literal double
		// quotes. Without quoting, tools that read Win32_Service.PathName verbatim (the Service
		// tab's old ResolveExecutablePath, third-party SCM inspectors) split the path at the
		// first space and report the binary as C:\Program when the install root is C:\Program
		// Files. The quoting is independent of the new extension-aware path resolver — both fixes
		// are required because not every consumer of ImagePath is under our control.
		IReadOnlyList<string> args = exists
			? ScCommandBuilder.BuildConfigQuoted(ServiceName, targetExe)
			: ScCommandBuilder.BuildCreateQuoted(ServiceName, targetExe, ServiceDisplayName);

		ScResult result = await RunScAsync(args, ct).ConfigureAwait(false);
		if (result.ExitCode != 0)
		{
			string verb = exists ? "Update Windows service config" : "Register Windows service";
			return new InstallStep(verb, false, FormatScError(result, args));
		}

		ScResult failure = await RunScAsync(
			ScCommandBuilder.BuildFailure(ServiceName, 86400, "restart/60000/restart/60000/restart/60000"),
			ct).ConfigureAwait(false);
		if (failure.ExitCode != 0)
		{
			return new InstallStep("Configure restart policy", false, FormatScError(failure, args));
		}

		return new InstallStep(exists ? "Updated existing Windows service" : "Registered new Windows service", true);
	}

	internal async Task<InstallStep> StartServiceAsync(CancellationToken ct)
	{
		try
		{
			using ServiceController controller = new(ServiceName);
			if (controller.Status == ServiceControllerStatus.Running)
			{
				return new InstallStep("Service already running", true);
			}

			await Task.Run(() =>
			{
				controller.Start();
				controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
			}, ct).ConfigureAwait(false);
			return new InstallStep("Started RdpAuditService", true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			return new InstallStep("Start service", false, "UAC was cancelled");
		}
		catch (Exception ex)
		{
			return new InstallStep("Start service", false, ex.Message);
		}
	}

	/// <summary>Grants Administrators and LocalSystem full control over the ProgramData
	/// folder so the elevated service and Configurator can both manage the DB.</summary>
	internal static void ApplyProgramDataAcl(string directory)
	{
		DirectoryInfo info = new(directory);
		DirectorySecurity security = info.GetAccessControl();

		SecurityIdentifier admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
		SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);

		security.AddAccessRule(new FileSystemAccessRule(
			admins,
			FileSystemRights.FullControl,
			InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
			PropagationFlags.None,
			AccessControlType.Allow));
		security.AddAccessRule(new FileSystemAccessRule(
			system,
			FileSystemRights.FullControl,
			InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
			PropagationFlags.None,
			AccessControlType.Allow));

		info.SetAccessControl(security);
	}

	private static bool ServiceExists(string serviceName)
	{
		try
		{
			using ServiceController existing = new(serviceName);
			_ = existing.Status;
			return true;
		}
		catch (InvalidOperationException)
		{
			return false;
		}
	}

	private static async Task<ScResult> RunScAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		ProcessStartInfo psi = new("sc.exe")
		{
			UseShellExecute = false,
			RedirectStandardError = true,
			RedirectStandardOutput = true,
			CreateNoWindow = true,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		try
		{
			using Process? p = Process.Start(psi);
			if (p is null)
			{
				return new ScResult(-1, string.Empty, "sc.exe failed to start");
			}

			Task<string> outTask = p.StandardOutput.ReadToEndAsync(ct);
			Task<string> errTask = p.StandardError.ReadToEndAsync(ct);
			await Task.WhenAll(outTask, errTask).ConfigureAwait(false);
			await p.WaitForExitAsync(ct).ConfigureAwait(false);
			string outText = await outTask.ConfigureAwait(false);
			string errText = await errTask.ConfigureAwait(false);
			return new ScResult(p.ExitCode, outText.Trim(), errText.Trim());
		}
		catch (Exception ex)
		{
			return new ScResult(-1, string.Empty, ex.Message);
		}
	}

	private static string FormatScError(ScResult result, IReadOnlyList<string> args)
	{
		StringBuilder sb = new();
		sb.Append("sc.exe exit ");
		sb.Append(result.ExitCode.ToString(CultureInfo.InvariantCulture));
		string combined = result.CombinedOutput;
		if (combined.Length > 0)
		{
			sb.Append(": ");
			sb.Append(combined);
		}

		sb.Append(" [args: sc ");
		for (int i = 0; i < args.Count; i++)
		{
			if (i > 0)
			{
				sb.Append(' ');
			}

			string a = args[i];
			if (a.Length == 0 || a.Contains(' ', StringComparison.Ordinal))
			{
				sb.Append('"').Append(a).Append('"');
			}
			else
			{
				sb.Append(a);
			}
		}

		sb.Append(']');
		return sb.ToString();
	}

	private static void Record(Func<InstallStep> action, List<string> steps, List<string> errors,
		InstallUpdateLogger? logger = null)
	{
		InstallStep step = action();
		string composed = step.Detail is null ? step.Description : $"{step.Description} — {step.Detail}";
		(step.Ok ? steps : errors).Add(composed);
		if (step.Ok)
		{
			logger?.Info(composed);
		}
		else
		{
			logger?.Fail(composed);
		}
	}

	private static async Task Record(Func<CancellationToken, Task<InstallStep>> action,
		List<string> steps, List<string> errors, InstallUpdateLogger? logger, CancellationToken ct)
	{
		InstallStep step = await action(ct).ConfigureAwait(false);
		string composed = step.Detail is null ? step.Description : $"{step.Description} — {step.Detail}";
		(step.Ok ? steps : errors).Add(composed);
		if (step.Ok)
		{
			logger?.Info(composed);
		}
		else
		{
			logger?.Fail(composed);
		}
	}
}
