// File:    src/RdpAudit.Service/Services/ShadowPolicyManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Service-side Terminal Services shadow policy management. Reads / writes the
//          group-policy and machine-policy Shadow registry values, captures backups so
//          changes are reversible, and restores from the most recent backup. Backups are
//          stored under %ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\shadow-policy.json
//          to integrate naturally with the existing snapshot layout.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Serialized snapshot of every tracked shadow-policy value. Stored alongside
/// the standard registry .reg backups so a restore can recover the prior state even
/// when the .reg files have been hand-edited or pruned.</summary>
public sealed class ShadowPolicyBackup
{
	public int SchemaVersion { get; set; } = 1;

	public DateTime CapturedUtc { get; set; }

	public List<ShadowPolicyBackupEntry> Entries { get; set; } = new();
}

/// <summary>One captured registry value inside <see cref="ShadowPolicyBackup"/>.</summary>
public sealed class ShadowPolicyBackupEntry
{
	public string KeyPath { get; set; } = string.Empty;

	public string ValueName { get; set; } = string.Empty;

	/// <summary>Captured value, or null if the value was missing at capture time.</summary>
	public int? Value { get; set; }
}

/// <summary>Service-side shadow policy manager — reads, writes, backs up and restores
/// the Microsoft Terminal Services Shadow policy values.</summary>
[SupportedOSPlatform("windows")]
public sealed class ShadowPolicyManager
{
	internal const string BackupFileName = "shadow-policy.json";

	private static readonly IReadOnlyList<(string Key, string ValueName, string Description)> TrackedValues = new[]
	{
		(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.ShadowValueName,
			"Group-policy Shadow value — 0..4 per Microsoft docs."),
		(ShadowPolicyModel.TerminalServicesMachineKey, ShadowPolicyModel.ShadowValueName,
			"Per-machine Shadow value — fallback when group policy is absent."),
		(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.AllowToGetHelpValueName,
			"Legacy 'fAllowToGetHelp' flag — informational."),
	};

	private readonly ILogger<ShadowPolicyManager> _logger;
	private readonly string _backupRoot;

	public ShadowPolicyManager(ILogger<ShadowPolicyManager> logger)
		: this(logger, Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
			"RdpAudit"))
	{
	}

	internal ShadowPolicyManager(ILogger<ShadowPolicyManager> logger, string programDataRdpAudit)
	{
		_logger = logger;
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		_backupRoot = Path.Combine(programDataRdpAudit, BackupLayout.BackupsFolderName);
	}

	/// <summary>Reads the current shadow policy from the registry and returns a DTO snapshot.</summary>
	public ShadowPolicyStatusDto GetStatus()
	{
		ShadowPolicyStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
		};

		foreach ((string keyPath, string valueName, string description) in TrackedValues)
		{
			int? current = TryReadValue(keyPath, valueName);
			int recommended = GetRecommendedValue(keyPath, valueName);
			dto.Values.Add(new ShadowPolicyValueDto
			{
				KeyPath = keyPath,
				ValueName = valueName,
				CurrentValue = current ?? -1,
				RecommendedValue = recommended,
				Description = description,
			});
		}

		int? primary = TryReadValue(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.ShadowValueName)
			?? TryReadValue(ShadowPolicyModel.TerminalServicesMachineKey, ShadowPolicyModel.ShadowValueName);
		dto.ShadowMode = primary ?? -1;

		dto.AllPermissionsEnabled = primary.HasValue && primary.Value == ShadowPolicyModel.EnableAllPermissionsValue;

		(bool found, string? snapshotId, DateTime? capturedUtc) = FindLatestBackup();
		dto.HasBackup = found;
		dto.LatestSnapshotId = snapshotId;
		dto.BackupCreatedUtc = capturedUtc;

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"Shadow={0}, AllPermissions={1}, HasBackup={2}.",
			dto.ShadowMode, dto.AllPermissionsEnabled, dto.HasBackup);
		return dto;
	}

	/// <summary>Writes the requested shadow policy values, taking a backup first when requested.</summary>
	public ShadowPolicyStatusDto Apply(ShadowPolicyApplyRequest request)
	{
		ArgumentNullException.ThrowIfNull(request);

		int desired = request.EnableAllPermissions
			? ShadowPolicyModel.EnableAllPermissionsValue
			: request.ShadowMode;

		if (!ShadowPolicyModel.IsValidShadowValue(desired))
		{
			ShadowPolicyStatusDto err = GetStatus();
			err.Status = IpcResultStatus.InvalidRequest;
			err.Message = string.Format(CultureInfo.InvariantCulture,
				"ShadowMode {0} is out of range (0..4).", desired);
			return err;
		}

		string? backupId = null;
		if (request.TakeBackupFirst)
		{
			backupId = Backup().LatestSnapshotId;
		}

		try
		{
			SetValue(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.ShadowValueName, desired);
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Failed to write shadow policy value (desired={Desired})", desired);
			ShadowPolicyStatusDto fail = GetStatus();
			fail.Status = IpcResultStatus.Unavailable;
			fail.Message = "Failed to write shadow policy: " + ex.GetType().Name;
			return fail;
		}

		_logger.LogInformation("Applied shadow policy desired={Desired} backup={Backup} reason={Reason}",
			desired, backupId ?? "(none)", request.Reason ?? "(none)");

		ShadowPolicyStatusDto status = GetStatus();
		status.Message = string.Format(CultureInfo.InvariantCulture,
			"Shadow policy set to {0}{1}.", desired,
			backupId is null ? string.Empty : " (backup " + backupId + ")");
		return status;
	}

	/// <summary>Captures the current state to a new snapshot directory under ProgramData\RdpAudit\Backups.</summary>
	public ShadowPolicyStatusDto Backup()
	{
		ShadowPolicyBackup backup = new()
		{
			CapturedUtc = DateTime.UtcNow,
			Entries = new List<ShadowPolicyBackupEntry>(),
		};

		foreach ((string keyPath, string valueName, _) in TrackedValues)
		{
			int? current = TryReadValue(keyPath, valueName);
			backup.Entries.Add(new ShadowPolicyBackupEntry
			{
				KeyPath = keyPath,
				ValueName = valueName,
				Value = current,
			});
		}

		BackupSnapshotPaths snapshot = BackupLayout.Create(
			Path.GetDirectoryName(_backupRoot) ?? _backupRoot,
			DateTime.UtcNow);

		try
		{
			Directory.CreateDirectory(snapshot.SnapshotDirectory);
			string target = Path.Combine(snapshot.SnapshotDirectory, BackupFileName);
			string json = JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true });
			File.WriteAllText(target, json);
			_logger.LogInformation("Captured shadow-policy backup to {Path}", target);
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Failed to write shadow-policy backup");
			ShadowPolicyStatusDto fail = GetStatus();
			fail.Status = IpcResultStatus.Unavailable;
			fail.Message = "Failed to write shadow-policy backup: " + ex.GetType().Name;
			return fail;
		}

		ShadowPolicyStatusDto status = GetStatus();
		status.LatestSnapshotId = snapshot.Timestamp;
		status.BackupCreatedUtc = backup.CapturedUtc;
		status.HasBackup = true;
		status.Message = "Shadow policy backup captured at " + snapshot.Timestamp + ".";
		return status;
	}

	/// <summary>Restores the most recent backup snapshot — or the snapshot whose id is supplied
	/// in <paramref name="snapshotId"/> when non-empty.</summary>
	public ShadowPolicyStatusDto Restore(string? snapshotId)
	{
		string? resolved = string.IsNullOrWhiteSpace(snapshotId)
			? FindLatestBackup().SnapshotId
			: snapshotId.Trim();

		if (string.IsNullOrEmpty(resolved))
		{
			ShadowPolicyStatusDto miss = GetStatus();
			miss.Status = IpcResultStatus.Unavailable;
			miss.Message = "No shadow-policy backup available to restore.";
			return miss;
		}

		string source = Path.Combine(_backupRoot, resolved, BackupFileName);
		if (!File.Exists(source))
		{
			ShadowPolicyStatusDto miss = GetStatus();
			miss.Status = IpcResultStatus.Unavailable;
			miss.Message = string.Format(CultureInfo.InvariantCulture,
				"Snapshot '{0}' does not contain a shadow-policy backup.", resolved);
			return miss;
		}

		ShadowPolicyBackup? parsed;
		try
		{
			string json = File.ReadAllText(source);
			parsed = JsonSerializer.Deserialize<ShadowPolicyBackup>(json);
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Failed to parse shadow-policy backup {Path}", source);
			ShadowPolicyStatusDto fail = GetStatus();
			fail.Status = IpcResultStatus.Unavailable;
			fail.Message = "Failed to parse shadow-policy backup: " + ex.GetType().Name;
			return fail;
		}

		if (parsed is null)
		{
			ShadowPolicyStatusDto fail = GetStatus();
			fail.Status = IpcResultStatus.Unavailable;
			fail.Message = "Shadow-policy backup was empty.";
			return fail;
		}

		foreach (ShadowPolicyBackupEntry entry in parsed.Entries)
		{
			if (entry.Value is null)
			{
				TryDeleteValue(entry.KeyPath, entry.ValueName);
			}
			else
			{
				try
				{
					SetValue(entry.KeyPath, entry.ValueName, entry.Value.Value);
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "Restore failed for {Key}\\{Value}", entry.KeyPath, entry.ValueName);
				}
			}
		}

		ShadowPolicyStatusDto status = GetStatus();
		status.Message = "Shadow policy restored from snapshot " + resolved + ".";
		status.LatestSnapshotId = resolved;
		return status;
	}

	/// <summary>Lists snapshot ids that contain a shadow-policy backup, newest first.</summary>
	internal IReadOnlyList<string> ListBackupSnapshotIds()
	{
		if (!Directory.Exists(_backupRoot))
		{
			return Array.Empty<string>();
		}

		List<string> snapshotIds = new();
		foreach (string dir in Directory.EnumerateDirectories(_backupRoot))
		{
			string name = new DirectoryInfo(dir).Name;
			if (!DateTime.TryParseExact(
				name,
				BackupLayout.TimestampFormat,
				CultureInfo.InvariantCulture,
				System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
				out _))
			{
				continue;
			}

			if (File.Exists(Path.Combine(dir, BackupFileName)))
			{
				snapshotIds.Add(name);
			}
		}

		snapshotIds.Sort(StringComparer.Ordinal);
		snapshotIds.Reverse();
		return snapshotIds;
	}

	private (bool Found, string? SnapshotId, DateTime? CapturedUtc) FindLatestBackup()
	{
		IReadOnlyList<string> snapshots = ListBackupSnapshotIds();
		if (snapshots.Count == 0)
		{
			return (false, null, null);
		}

		string latest = snapshots[0];
		DateTime? capturedUtc = null;
		try
		{
			string path = Path.Combine(_backupRoot, latest, BackupFileName);
			if (File.Exists(path))
			{
				ShadowPolicyBackup? snapshot = JsonSerializer.Deserialize<ShadowPolicyBackup>(File.ReadAllText(path));
				capturedUtc = snapshot?.CapturedUtc;
			}
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Failed to parse latest backup for capture time");
		}

		return (true, latest, capturedUtc);
	}

	private static int GetRecommendedValue(string keyPath, string valueName)
	{
		if (string.Equals(keyPath, ShadowPolicyModel.TerminalServicesPolicyKey, StringComparison.OrdinalIgnoreCase)
			&& string.Equals(valueName, ShadowPolicyModel.ShadowValueName, StringComparison.OrdinalIgnoreCase))
		{
			return (int)ShadowPolicyMode.FullControlWithConsent;
		}

		return -1;
	}

	private static int? TryReadValue(string hkmlKeyPath, string valueName)
	{
		string subKey = StripHklm(hkmlKeyPath);
		if (subKey is null)
		{
			return null;
		}

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
		catch
		{
			return null;
		}
	}

	private static void SetValue(string hklmKeyPath, string valueName, int value)
	{
		string subKey = StripHklm(hklmKeyPath)
			?? throw new InvalidOperationException("Key path is not under HKLM: " + hklmKeyPath);
		using RegistryKey key = Registry.LocalMachine.CreateSubKey(subKey, writable: true);
		key.SetValue(valueName, value, RegistryValueKind.DWord);
	}

	private static void TryDeleteValue(string hklmKeyPath, string valueName)
	{
		string? subKey = StripHklm(hklmKeyPath);
		if (subKey is null)
		{
			return;
		}

		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKey, writable: true);
			key?.DeleteValue(valueName, throwOnMissingValue: false);
		}
		catch
		{
			// best effort — restore moves on to the next entry.
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
