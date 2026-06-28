// File:    src/RdpAudit.Configurator/Services/BackupRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Windows-side orchestration for the backup feature. Captures audit
//          policy, the RdpAudit registry/SACL state, the sc.exe service
//          configuration and the current appsettings.json into a timestamped
//          snapshot under %ProgramData%\RdpAudit\Backups. Idempotent and
//          tolerant of partial failures — every step is recorded and surfaced
//          back to the UI rather than thrown.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Identifies why a snapshot is being created. Surfaces through metadata for auditing.</summary>
public enum BackupReason
{
	/// <summary>Triggered automatically before first-run install changes audit policy.</summary>
	FirstRunInstall,

	/// <summary>User clicked the Backup button in the Configurator.</summary>
	Manual,

	/// <summary>Captured immediately before a restore so the prior state can itself be rolled back.</summary>
	PreRestore,
}

/// <summary>Outcome of a single backup step. Stable shape so the UI can colour-code rows.</summary>
public sealed record BackupStep(string Description, bool Ok, string? Detail = null);

/// <summary>Aggregate outcome returned by <see cref="BackupRunner.RunAsync"/>.</summary>
public sealed record BackupOutcome(
	bool Success,
	BackupSnapshotPaths Snapshot,
	IReadOnlyList<BackupStep> Steps);

/// <summary>Captures audit policy, registry, service configuration and appsettings into a timestamped
/// snapshot under <c>%ProgramData%\RdpAudit\Backups</c>. All work is best-effort: an unavailable
/// component (e.g. service not yet installed) produces a recorded warning rather than an exception.</summary>
[SupportedOSPlatform("windows")]
public sealed class BackupRunner
{
	private readonly ServiceLayoutInfo _layout;
	private readonly string _serviceName;

	public BackupRunner(ServiceLayoutInfo layout, string serviceName = InstallationService.ServiceName)
	{
		_layout = layout ?? throw new ArgumentNullException(nameof(layout));
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		_serviceName = serviceName;
	}

	/// <summary>Runs the backup workflow. The returned <see cref="BackupOutcome"/> always carries the
	/// snapshot path layout — even if some individual steps failed — so callers can show the user
	/// what was written.</summary>
	public async Task<BackupOutcome> RunAsync(BackupReason reason, CancellationToken ct = default)
	{
		BackupSnapshotPaths snapshot = BackupLayout.Create(_layout.ProgramDataDirectory, DateTime.UtcNow);
		List<BackupStep> steps = new();

		try
		{
			Directory.CreateDirectory(snapshot.SnapshotDirectory);
			steps.Add(new BackupStep($"Created snapshot directory {snapshot.SnapshotDirectory}", true));
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Create snapshot directory", false, ex.Message));
			return new BackupOutcome(false, snapshot, steps);
		}

		bool includesAppSettings = CaptureAppSettings(snapshot, steps);
		bool includesAuditPolicy = await CaptureAuditPolicyAsync(snapshot, steps, ct).ConfigureAwait(false);
		bool includesRegistry = await CaptureRegistryAsync(snapshot, steps, ct).ConfigureAwait(false);
		bool includesService = await CaptureServiceConfigAsync(snapshot, steps, ct).ConfigureAwait(false);

		WriteMetadata(snapshot, reason, includesAppSettings, includesAuditPolicy, includesRegistry, includesService, steps);

		bool overall = steps.All(s => s.Ok || s.Description.StartsWith("Capture ", StringComparison.Ordinal));
		bool anyHardFailure = steps.Any(s => !s.Ok && s.Description.StartsWith("Create ", StringComparison.Ordinal));
		return new BackupOutcome(!anyHardFailure && overall, snapshot, steps);
	}

	internal bool CaptureAppSettings(BackupSnapshotPaths snapshot, List<BackupStep> steps)
	{
		try
		{
			if (!File.Exists(_layout.AppSettingsPath))
			{
				steps.Add(new BackupStep("Capture appsettings.json", true, "Source file does not exist yet — skipped."));
				return false;
			}

			File.Copy(_layout.AppSettingsPath, snapshot.AppSettingsPath, overwrite: true);
			steps.Add(new BackupStep($"Copied appsettings.json -> {snapshot.AppSettingsPath}", true));
			return true;
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Capture appsettings.json", false, ex.Message));
			return false;
		}
	}

	internal async Task<bool> CaptureAuditPolicyAsync(BackupSnapshotPaths snapshot, List<BackupStep> steps, CancellationToken ct)
	{
		try
		{
			IReadOnlyList<string> args = BackupCommandBuilder.BuildAuditPolicyBackup(snapshot.AuditPolicyCsvPath);
			int exit = await RunToolAsync("auditpol.exe", args, captureStdout: false, redirectStdoutToFile: null, ct).ConfigureAwait(false);
			if (exit == 0 && File.Exists(snapshot.AuditPolicyCsvPath))
			{
				steps.Add(new BackupStep($"Exported audit policy -> {snapshot.AuditPolicyCsvPath}", true));
				return true;
			}

			steps.Add(new BackupStep("Capture audit policy", false, $"auditpol exit {exit}"));
			return false;
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Capture audit policy", false, ex.Message));
			return false;
		}
	}

	internal async Task<bool> CaptureRegistryAsync(BackupSnapshotPaths snapshot, List<BackupStep> steps, CancellationToken ct)
	{
		try
		{
			Directory.CreateDirectory(snapshot.RegistryDirectory);
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Create registry export directory", false, ex.Message));
			return false;
		}

		bool any = false;
		foreach (string key in BackupCommandBuilder.RegistryKeys)
		{
			string fileName = BackupCommandBuilder.GetRegistryExportFileName(key);
			string target = PathSafety.SafeChildPath(snapshot.RegistryDirectory, fileName);
			try
			{
				IReadOnlyList<string> args = BackupCommandBuilder.BuildRegExport(key, target);
				int exit = await RunToolAsync("reg.exe", args, captureStdout: false, redirectStdoutToFile: null, ct).ConfigureAwait(false);
				if (exit == 0 && File.Exists(target))
				{
					steps.Add(new BackupStep($"Exported {key} -> {target}", true));
					any = true;
				}
				else
				{
					steps.Add(new BackupStep($"Export {key}", false, $"reg.exe exit {exit}"));
				}
			}
			catch (Exception ex)
			{
				steps.Add(new BackupStep($"Export {key}", false, ex.Message));
			}
		}

		return any;
	}

	internal async Task<bool> CaptureServiceConfigAsync(BackupSnapshotPaths snapshot, List<BackupStep> steps, CancellationToken ct)
	{
		try
		{
			IReadOnlyList<string> args = BackupCommandBuilder.BuildScQueryConfig(_serviceName);
			int exit = await RunToolAsync("sc.exe", args, captureStdout: true, redirectStdoutToFile: snapshot.ServiceConfigPath, ct).ConfigureAwait(false);
			if (exit == 0 && File.Exists(snapshot.ServiceConfigPath))
			{
				steps.Add(new BackupStep($"Captured service configuration -> {snapshot.ServiceConfigPath}", true));
				return true;
			}

			steps.Add(new BackupStep("Capture service configuration", true,
				$"sc.exe qc exit {exit} (service may not be installed yet) — skipped."));
			return false;
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Capture service configuration", false, ex.Message));
			return false;
		}
	}

	internal void WriteMetadata(
		BackupSnapshotPaths snapshot,
		BackupReason reason,
		bool includesAppSettings,
		bool includesAuditPolicy,
		bool includesRegistry,
		bool includesService,
		List<BackupStep> steps)
	{
		try
		{
			BackupMetadata metadata = new()
			{
				SchemaVersion = 1,
				CreatedUtc = DateTime.UtcNow,
				SnapshotId = snapshot.Timestamp,
				MachineName = Environment.MachineName,
				UserName = TryGetCurrentUserName(),
				OsDescription = RuntimeInformation.OSDescription,
				ProductVersion = ResolveProductVersion(),
				Reason = ReasonToString(reason),
				IncludesAppSettings = includesAppSettings,
				IncludesAuditPolicy = includesAuditPolicy,
				IncludesRegistry = includesRegistry,
				IncludesServiceConfig = includesService,
				Redactions = new[]
				{
					"appsettings.json is copied byte-for-byte; the schema currently stores no secret credentials, "
						+ "but if future schemas add secret fields they must be redacted here before serialization.",
				},
				AuditPolicyGuids = Array.Empty<string>(),
				RegistryKeys = BackupCommandBuilder.RegistryKeys,
			};

			File.WriteAllText(snapshot.MetadataPath, metadata.ToJson());
			steps.Add(new BackupStep($"Wrote metadata.json -> {snapshot.MetadataPath}", true));
		}
		catch (Exception ex)
		{
			steps.Add(new BackupStep("Write metadata.json", false, ex.Message));
		}
	}

	private static string ReasonToString(BackupReason reason) => reason switch
	{
		BackupReason.FirstRunInstall => "first-run-install",
		BackupReason.Manual => "manual",
		BackupReason.PreRestore => "pre-restore",
		_ => "unknown",
	};

	private static string TryGetCurrentUserName()
	{
		try
		{
			return WindowsIdentity.GetCurrent().Name;
		}
		catch (Exception)
		{
			return Environment.UserName;
		}
	}

	private static string ResolveProductVersion()
	{
		try
		{
			Assembly asm = Assembly.GetExecutingAssembly();
			string? info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
			if (!string.IsNullOrWhiteSpace(info))
			{
				int plus = info.IndexOf('+', StringComparison.Ordinal);
				return plus < 0 ? info : info[..plus];
			}

			return asm.GetName().Version?.ToString() ?? "0.0.0";
		}
		catch (Exception)
		{
			return "0.0.0";
		}
	}

	private static async Task<int> RunToolAsync(
		string tool,
		IReadOnlyList<string> args,
		bool captureStdout,
		string? redirectStdoutToFile,
		CancellationToken ct)
	{
		ProcessStartInfo psi = new(tool)
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = captureStdout || redirectStdoutToFile is not null,
			RedirectStandardError = true,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		using Process? proc = Process.Start(psi);
		if (proc is null)
		{
			throw new Win32Exception($"{tool} failed to start.");
		}

		Task<string>? stdoutTask = psi.RedirectStandardOutput ? proc.StandardOutput.ReadToEndAsync(ct) : null;
		Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);

		await proc.WaitForExitAsync(ct).ConfigureAwait(false);

		if (stdoutTask is not null)
		{
			string stdout = await stdoutTask.ConfigureAwait(false);
			if (redirectStdoutToFile is not null && stdout.Length > 0)
			{
				await File.WriteAllTextAsync(redirectStdoutToFile, stdout, ct).ConfigureAwait(false);
			}
		}

		_ = await stderrTask.ConfigureAwait(false);
		return proc.ExitCode;
	}

	/// <summary>Lists existing backup snapshot directory names under the configured ProgramData root,
	/// newest first. Returns an empty list when the backup root does not yet exist.</summary>
	public IReadOnlyList<string> ListSnapshots()
	{
		string root = Path.Combine(_layout.ProgramDataDirectory, BackupLayout.BackupsFolderName);
		if (!Directory.Exists(root))
		{
			return Array.Empty<string>();
		}

		IEnumerable<string> names = Directory.EnumerateDirectories(root)
			.Select(p => new DirectoryInfo(p).Name);
		return BackupLayout.SortNewestFirst(names);
	}

	/// <summary>Resolves the absolute snapshot path layout for an existing snapshot name (yyyyMMdd-HHmmss).</summary>
	public BackupSnapshotPaths ResolveSnapshot(string snapshotName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(snapshotName);
		if (!DateTime.TryParseExact(
			snapshotName,
			BackupLayout.TimestampFormat,
			CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
			out _))
		{
			throw new ArgumentException($"Snapshot name '{snapshotName}' is not a valid yyyyMMdd-HHmmss timestamp.", nameof(snapshotName));
		}

		string root = Path.Combine(_layout.ProgramDataDirectory, BackupLayout.BackupsFolderName);
		string snapshot = PathSafety.SafeChildPath(root, snapshotName);
		return new BackupSnapshotPaths(
			RootDirectory: root,
			Timestamp: snapshotName,
			SnapshotDirectory: snapshot,
			AppSettingsPath: Path.Combine(snapshot, BackupLayout.AppSettingsFileName),
			AuditPolicyCsvPath: Path.Combine(snapshot, BackupLayout.AuditPolicyFileName),
			RegistryDirectory: Path.Combine(snapshot, BackupLayout.RegistryFolderName),
			ServiceConfigPath: Path.Combine(snapshot, BackupLayout.ServiceConfigFileName),
			MetadataPath: Path.Combine(snapshot, BackupLayout.MetadataFileName));
	}
}
