// File:    src/RdpAudit.Configurator/Services/RestoreRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Restores audit policy + registry/SACL state captured by BackupRunner.
//          Always takes a pre-restore safety snapshot first so the user can roll
//          forward if the restore turns out to be wrong. Never touches the audit
//          database — event history is preserved by design. The Configurator
//          manifest already requires administrator elevation, which auditpol
//          /restore and reg import both need.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Identifies which parts of a snapshot should be restored.</summary>
[Flags]
public enum RestoreScope
{
	/// <summary>Nothing — placeholder; <see cref="RestoreRunner"/> rejects calls with this scope.</summary>
	None = 0,

	/// <summary>Apply <c>auditpol /restore</c> from the snapshot CSV.</summary>
	AuditPolicy = 1 << 0,

	/// <summary>Apply <c>reg import</c> for every .reg file in the snapshot registry folder.</summary>
	Registry = 1 << 1,

	/// <summary>Overwrite <c>appsettings.json</c> from the snapshot copy.</summary>
	AppSettings = 1 << 2,

	/// <summary>Audit policy + registry; the default safe option requested by the spec.</summary>
	PoliciesAndRegistry = AuditPolicy | Registry,
}

/// <summary>Outcome of one restore step.</summary>
public sealed record RestoreStep(string Description, bool Ok, string? Detail = null);

/// <summary>Aggregate restore outcome surfaced to the UI.</summary>
public sealed record RestoreOutcome(
	bool Success,
	BackupSnapshotPaths SafetySnapshot,
	IReadOnlyList<RestoreStep> Steps);

/// <summary>Restores audit policy + registry/SACL settings from a previously captured snapshot.
/// The audit database is intentionally untouched.</summary>
[SupportedOSPlatform("windows")]
public sealed class RestoreRunner
{
	private readonly ServiceLayoutInfo _layout;
	private readonly BackupRunner _backupRunner;

	public RestoreRunner(ServiceLayoutInfo layout, BackupRunner backupRunner)
	{
		_layout = layout ?? throw new ArgumentNullException(nameof(layout));
		_backupRunner = backupRunner ?? throw new ArgumentNullException(nameof(backupRunner));
	}

	/// <summary>Restores the requested scope from the named snapshot. Always captures a
	/// pre-restore safety snapshot first so the prior state can itself be rolled back.</summary>
	public async Task<RestoreOutcome> RunAsync(string snapshotName, RestoreScope scope, CancellationToken ct = default)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(snapshotName);
		if (scope == RestoreScope.None)
		{
			throw new ArgumentException("Restore scope cannot be RestoreScope.None.", nameof(scope));
		}

		BackupOutcome safety = await _backupRunner.RunAsync(BackupReason.PreRestore, ct).ConfigureAwait(false);
		List<RestoreStep> steps = new()
		{
			new RestoreStep(
				$"Captured pre-restore safety snapshot at {safety.Snapshot.SnapshotDirectory}",
				safety.Success,
				safety.Success ? null : "Pre-restore safety capture reported errors — review the snapshot folder."),
		};

		BackupSnapshotPaths snapshot = _backupRunner.ResolveSnapshot(snapshotName);
		if (!Directory.Exists(snapshot.SnapshotDirectory))
		{
			steps.Add(new RestoreStep($"Locate snapshot {snapshotName}", false, $"Snapshot directory not found: {snapshot.SnapshotDirectory}"));
			return new RestoreOutcome(false, safety.Snapshot, steps);
		}

		bool anyFailure = false;

		if ((scope & RestoreScope.AuditPolicy) != 0)
		{
			bool ok = await RestoreAuditPolicyAsync(snapshot, steps, ct).ConfigureAwait(false);
			anyFailure |= !ok;
		}

		if ((scope & RestoreScope.Registry) != 0)
		{
			bool ok = await RestoreRegistryAsync(snapshot, steps, ct).ConfigureAwait(false);
			anyFailure |= !ok;
		}

		if ((scope & RestoreScope.AppSettings) != 0)
		{
			bool ok = RestoreAppSettings(snapshot, steps);
			anyFailure |= !ok;
		}

		return new RestoreOutcome(!anyFailure, safety.Snapshot, steps);
	}

	internal async Task<bool> RestoreAuditPolicyAsync(BackupSnapshotPaths snapshot, List<RestoreStep> steps, CancellationToken ct)
	{
		if (!File.Exists(snapshot.AuditPolicyCsvPath))
		{
			steps.Add(new RestoreStep("Restore audit policy", false, $"Snapshot does not contain {snapshot.AuditPolicyCsvPath}"));
			return false;
		}

		try
		{
			IReadOnlyList<string> args = BackupCommandBuilder.BuildAuditPolicyRestore(snapshot.AuditPolicyCsvPath);
			int exit = await RunToolAsync("auditpol.exe", args, ct).ConfigureAwait(false);
			if (exit == 0)
			{
				steps.Add(new RestoreStep($"Restored audit policy from {snapshot.AuditPolicyCsvPath}", true));
				return true;
			}

			steps.Add(new RestoreStep("Restore audit policy", false, $"auditpol exit {exit}"));
			return false;
		}
		catch (Exception ex)
		{
			steps.Add(new RestoreStep("Restore audit policy", false, ex.Message));
			return false;
		}
	}

	internal async Task<bool> RestoreRegistryAsync(BackupSnapshotPaths snapshot, List<RestoreStep> steps, CancellationToken ct)
	{
		if (!Directory.Exists(snapshot.RegistryDirectory))
		{
			steps.Add(new RestoreStep("Restore registry", false, $"Snapshot does not contain {snapshot.RegistryDirectory}"));
			return false;
		}

		string[] files = Directory.GetFiles(snapshot.RegistryDirectory, "*.reg", SearchOption.TopDirectoryOnly);
		if (files.Length == 0)
		{
			steps.Add(new RestoreStep("Restore registry", false, "No .reg files found in snapshot registry folder."));
			return false;
		}

		bool anyFailure = false;
		foreach (string file in files.OrderBy(p => p, StringComparer.Ordinal))
		{
			try
			{
				IReadOnlyList<string> args = BackupCommandBuilder.BuildRegImport(file);
				int exit = await RunToolAsync("reg.exe", args, ct).ConfigureAwait(false);
				if (exit == 0)
				{
					steps.Add(new RestoreStep($"Imported {Path.GetFileName(file)}", true));
				}
				else
				{
					steps.Add(new RestoreStep($"Import {Path.GetFileName(file)}", false, $"reg.exe exit {exit}"));
					anyFailure = true;
				}
			}
			catch (Exception ex)
			{
				steps.Add(new RestoreStep($"Import {Path.GetFileName(file)}", false, ex.Message));
				anyFailure = true;
			}
		}

		return !anyFailure;
	}

	internal bool RestoreAppSettings(BackupSnapshotPaths snapshot, List<RestoreStep> steps)
	{
		if (!File.Exists(snapshot.AppSettingsPath))
		{
			steps.Add(new RestoreStep("Restore appsettings.json", false, $"Snapshot does not contain {snapshot.AppSettingsPath}"));
			return false;
		}

		try
		{
			string? targetDir = Path.GetDirectoryName(_layout.AppSettingsPath);
			if (!string.IsNullOrEmpty(targetDir))
			{
				Directory.CreateDirectory(targetDir);
			}

			File.Copy(snapshot.AppSettingsPath, _layout.AppSettingsPath, overwrite: true);
			steps.Add(new RestoreStep($"Copied {snapshot.AppSettingsPath} -> {_layout.AppSettingsPath}", true));
			return true;
		}
		catch (Exception ex)
		{
			steps.Add(new RestoreStep("Restore appsettings.json", false, ex.Message));
			return false;
		}
	}

	private static async Task<int> RunToolAsync(string tool, IReadOnlyList<string> args, CancellationToken ct)
	{
		ProcessStartInfo psi = new(tool)
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardError = true,
			RedirectStandardOutput = true,
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

		Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
		Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);
		await proc.WaitForExitAsync(ct).ConfigureAwait(false);
		_ = await stdoutTask.ConfigureAwait(false);
		_ = await stderrTask.ConfigureAwait(false);
		return proc.ExitCode;
	}
}
