// File:    src/RdpAudit.Core/Backup/BackupCommandBuilder.cs
// Module:  RdpAudit.Core.Backup
// Purpose: Composes argument lists for the external command-line tools used by the
//          Configurator backup/restore feature (auditpol.exe, reg.exe, sc.exe).
//          Pure list builders — they never spawn processes themselves, never
//          concatenate user input into a single shell string, and are exercised
//          by Core unit tests so syntax bugs are caught off-Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Backup;

/// <summary>Argument-list builders for the external tools used by backup/restore.</summary>
public static class BackupCommandBuilder
{
	/// <summary>Registry keys captured / restored by the registry backup. Mirrors the
	/// keys SaclManager configures so a restore covers SACLs, RDP listener config and
	/// LSA hardening flags. Keys are HKLM-rooted strings (no leading hive prefix is
	/// duplicated when reg.exe receives them — see <see cref="BuildRegExport"/>).</summary>
	public static IReadOnlyList<string> RegistryKeys { get; } = new[]
	{
		@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
		@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
		@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
		@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
		@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
		@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
		@"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
	};

	/// <summary>Builds <c>auditpol /backup /file:&lt;path&gt;</c> arguments.</summary>
	public static IReadOnlyList<string> BuildAuditPolicyBackup(string csvPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(csvPath);
		return new[] { "/backup", "/file:" + csvPath };
	}

	/// <summary>Builds <c>auditpol /restore /file:&lt;path&gt;</c> arguments.</summary>
	public static IReadOnlyList<string> BuildAuditPolicyRestore(string csvPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(csvPath);
		return new[] { "/restore", "/file:" + csvPath };
	}

	/// <summary>Builds <c>reg export &lt;key&gt; &lt;file&gt; /y</c> arguments.
	/// The /y switch overwrites without prompting; the export captures one key per file
	/// so a partial failure does not corrupt the entire backup.</summary>
	public static IReadOnlyList<string> BuildRegExport(string registryKey, string exportFile)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(registryKey);
		ArgumentException.ThrowIfNullOrWhiteSpace(exportFile);
		return new[] { "export", registryKey, exportFile, "/y" };
	}

	/// <summary>Builds <c>reg import &lt;file&gt;</c> arguments.</summary>
	public static IReadOnlyList<string> BuildRegImport(string importFile)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(importFile);
		return new[] { "import", importFile };
	}

	/// <summary>Builds the sc.exe arguments used to capture service configuration to a text file.
	/// The caller is expected to redirect stdout into the snapshot file — the argument list
	/// itself never embeds the destination path because <c>sc qc</c> writes to stdout.</summary>
	public static IReadOnlyList<string> BuildScQueryConfig(string serviceName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		return new[] { "qc", serviceName };
	}

	/// <summary>Produces the sanitized per-key export filename for a given HKLM key path.
	/// The returned name only contains characters safe for NTFS and is fully deterministic
	/// so tests can verify the mapping.</summary>
	public static string GetRegistryExportFileName(string registryKey)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(registryKey);
		// reg.exe writes one file per key; we sanitize the key into a safe filename
		// so collisions across keys are impossible.
		string trimmed = registryKey.Trim();
		char[] invalid = Path.GetInvalidFileNameChars();
		System.Text.StringBuilder sb = new(trimmed.Length);
		foreach (char c in trimmed)
		{
			if (c == '\\' || c == '/' || c == ':' || Array.IndexOf(invalid, c) >= 0)
			{
				sb.Append('_');
			}
			else
			{
				sb.Append(c);
			}
		}

		return sb.ToString() + ".reg";
	}
}
