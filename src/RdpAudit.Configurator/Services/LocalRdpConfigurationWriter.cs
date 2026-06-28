// File:    src/RdpAudit.Configurator/Services/LocalRdpConfigurationWriter.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Backup-guarded writer for the editable RDP Configuration tab. Captures a JSON
//          snapshot of every tracked Terminal Services value before any mutation lands so
//          the change is reversible from disk (the Configurator backup runner also exports
//          the parent registry keys via reg.exe). The writer never executes a partial change
//          set: if the backup step fails the apply step is skipped, and the operator is told
//          which step failed. Uses only managed Microsoft.Win32.Registry — no DllImport, no
//          shell invocation, no string concatenation with operator input.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of a single <see cref="LocalRdpConfigurationWriter.Apply"/> call. Captures
/// the path of the JSON backup so the operator can refer to it from the UI status line.</summary>
public sealed record LocalRdpConfigurationApplyResult(
	bool Success,
	string? BackupFilePath,
	IReadOnlyList<string> WrittenValueLabels,
	string? Error)
{
	/// <summary>Convenience factory for a successful apply.</summary>
	public static LocalRdpConfigurationApplyResult Ok(string backupPath, IReadOnlyList<string> labels) =>
		new(true, backupPath, labels, null);

	/// <summary>Convenience factory for a failed apply that did not mutate the registry.</summary>
	public static LocalRdpConfigurationApplyResult Failed(string error, string? backupPath = null) =>
		new(false, backupPath, Array.Empty<string>(), error);
}

/// <summary>JSON document persisted alongside each apply so the change is recoverable from
/// disk even if the standard registry .reg exports have not been captured.</summary>
public sealed class LocalRdpConfigurationBackup
{
	public int SchemaVersion { get; set; } = 1;

	public DateTime CapturedUtc { get; set; } = DateTime.UtcNow;

	public List<LocalRdpConfigurationBackupEntry> Entries { get; set; } = new();
}

/// <summary>One captured registry value inside a <see cref="LocalRdpConfigurationBackup"/>.</summary>
public sealed class LocalRdpConfigurationBackupEntry
{
	public string KeyPath { get; set; } = string.Empty;

	public string ValueName { get; set; } = string.Empty;

	/// <summary>Captured DWORD value, or null when the value was missing at capture time.</summary>
	public int? Value { get; set; }
}

/// <summary>Configurator-side backup-guarded writer for the editable RDP Configuration tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalRdpConfigurationWriter
{
	internal const string BackupFileName = "rdp-configuration.json";

	private readonly string _backupRoot;

	/// <summary>Construct using the default ProgramData layout
	/// (<c>%ProgramData%\RdpAudit\Backups</c>), matching <see cref="BackupLayout"/>.</summary>
	public LocalRdpConfigurationWriter()
		: this(Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
			"RdpAudit"))
	{
	}

	/// <summary>Construct with an explicit ProgramData root. Exposed for tests.</summary>
	internal LocalRdpConfigurationWriter(string programDataRdpAudit)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		_backupRoot = Path.Combine(programDataRdpAudit, BackupLayout.BackupsFolderName);
	}

	/// <summary>Captures a backup of every value the change set will touch and then applies
	/// the writes one at a time. The method returns a structured result rather than throwing
	/// so the UI can render a precise status line. Mutations are skipped entirely when the
	/// backup step fails.</summary>
	public LocalRdpConfigurationApplyResult Apply(RdpConfigurationChangeSet changeSet)
	{
		ArgumentNullException.ThrowIfNull(changeSet);

		if (!changeSet.HasChanges)
		{
			return LocalRdpConfigurationApplyResult.Failed("Change set contains no pending writes.");
		}

		string? backupPath;
		try
		{
			backupPath = WriteBackup(changeSet);
		}
		catch (Exception ex)
		{
			return LocalRdpConfigurationApplyResult.Failed(
				"Backup failed before any write: " + ex.GetType().Name + " — " + ex.Message);
		}

		List<string> labels = new();
		foreach (RdpRegistryWrite write in changeSet.Writes)
		{
			try
			{
				if (write.Value is int dword)
				{
					SetDword(write.KeyPath, write.ValueName, dword);
					labels.Add(string.Format(CultureInfo.InvariantCulture,
						"{0}\\{1} = {2}", write.KeyPath, write.ValueName, dword));
				}
				else
				{
					DeleteValue(write.KeyPath, write.ValueName);
					labels.Add(string.Format(CultureInfo.InvariantCulture,
						"{0}\\{1} = (removed)", write.KeyPath, write.ValueName));
				}
			}
			catch (Exception ex)
			{
				return LocalRdpConfigurationApplyResult.Failed(
					string.Format(CultureInfo.InvariantCulture,
						"Write failed for {0}\\{1}: {2} — {3}. Backup retained at {4}.",
						write.KeyPath, write.ValueName, ex.GetType().Name, ex.Message,
						backupPath ?? "(unknown)"),
					backupPath);
			}
		}

		return LocalRdpConfigurationApplyResult.Ok(backupPath ?? string.Empty, labels);
	}

	private string WriteBackup(RdpConfigurationChangeSet changeSet)
	{
		LocalRdpConfigurationBackup backup = new()
		{
			CapturedUtc = DateTime.UtcNow,
			Entries = new List<LocalRdpConfigurationBackupEntry>(),
		};

		foreach (RdpRegistryWrite write in changeSet.Writes)
		{
			int? before = ReadDword(write.KeyPath, write.ValueName);
			backup.Entries.Add(new LocalRdpConfigurationBackupEntry
			{
				KeyPath = write.KeyPath,
				ValueName = write.ValueName,
				Value = before,
			});
		}

		BackupSnapshotPaths snapshot = BackupLayout.Create(
			Path.GetDirectoryName(_backupRoot) ?? _backupRoot,
			DateTime.UtcNow);
		Directory.CreateDirectory(snapshot.SnapshotDirectory);
		string target = Path.Combine(snapshot.SnapshotDirectory, BackupFileName);
		string json = JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true });
		File.WriteAllText(target, json);
		return target;
	}

	private static int? ReadDword(string hklmKeyPath, string valueName)
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

	private static void SetDword(string hklmKeyPath, string valueName, int value)
	{
		string subKey = StripHklm(hklmKeyPath);
		using RegistryKey key = Registry.LocalMachine.CreateSubKey(subKey, writable: true);
		key.SetValue(valueName, value, RegistryValueKind.DWord);
	}

	private static void DeleteValue(string hklmKeyPath, string valueName)
	{
		string subKey = StripHklm(hklmKeyPath);
		using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKey, writable: true);
		key?.DeleteValue(valueName, throwOnMissingValue: false);
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
