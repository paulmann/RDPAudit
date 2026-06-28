// File:    tests/RdpAudit.Core.Tests/BackupCommandBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the argument-list shapes produced by BackupCommandBuilder for
//          auditpol.exe, reg.exe and sc.exe so backup/restore wiring can be caught
//          off-Windows where the actual binaries are unavailable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Argument-list tests for the backup/restore command builders.</summary>
public class BackupCommandBuilderTests
{
	[Fact]
	public void RegistryKeys_CoverIfeoRdpAndLsa()
	{
		Assert.Contains(BackupCommandBuilder.RegistryKeys, k => k.Contains("Image File Execution Options", StringComparison.OrdinalIgnoreCase));
		Assert.Contains(BackupCommandBuilder.RegistryKeys, k => k.Contains("RDP-Tcp", StringComparison.OrdinalIgnoreCase));
		Assert.Contains(BackupCommandBuilder.RegistryKeys, k => k.Contains(@"Control\Lsa", StringComparison.OrdinalIgnoreCase));
		Assert.All(BackupCommandBuilder.RegistryKeys, k => Assert.StartsWith(@"HKLM\", k, StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public void RegistryKeys_CoverBothFPromptForPasswordHostKeys()
	{
		// The "Always prompt for password" policy lives under the Terminal Services policy key;
		// the per-listener fallback lives under the RDP-Tcp WinStation. Both must be backed up so
		// LocalRdpConfigurationWriter's policy-key mutation is recoverable from disk.
		Assert.Contains(BackupCommandBuilder.RegistryKeys, k => string.Equals(
			k, @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", StringComparison.OrdinalIgnoreCase));
		Assert.Contains(BackupCommandBuilder.RegistryKeys, k => string.Equals(
			k, @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public void BuildAuditPolicyBackup_UsesGlueedFileSwitch()
	{
		IReadOnlyList<string> args = BackupCommandBuilder.BuildAuditPolicyBackup("C:/snap/audit.csv");
		Assert.Equal(new[] { "/backup", "/file:C:/snap/audit.csv" }, args);
	}

	[Fact]
	public void BuildAuditPolicyRestore_UsesGlueedFileSwitch()
	{
		IReadOnlyList<string> args = BackupCommandBuilder.BuildAuditPolicyRestore("C:/snap/audit.csv");
		Assert.Equal(new[] { "/restore", "/file:C:/snap/audit.csv" }, args);
	}

	[Fact]
	public void BuildRegExport_EmitsExportVerbAndOverwriteSwitch()
	{
		IReadOnlyList<string> args = BackupCommandBuilder.BuildRegExport(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "C:/snap/lsa.reg");
		Assert.Equal(new[] { "export", @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "C:/snap/lsa.reg", "/y" }, args);
	}

	[Fact]
	public void BuildRegImport_EmitsImportVerb()
	{
		IReadOnlyList<string> args = BackupCommandBuilder.BuildRegImport("C:/snap/lsa.reg");
		Assert.Equal(new[] { "import", "C:/snap/lsa.reg" }, args);
	}

	[Fact]
	public void BuildScQueryConfig_RequiresServiceName()
	{
		Assert.Throws<ArgumentException>(() => BackupCommandBuilder.BuildScQueryConfig(""));
		IReadOnlyList<string> args = BackupCommandBuilder.BuildScQueryConfig("RdpAuditService");
		Assert.Equal(new[] { "qc", "RdpAuditService" }, args);
	}

	[Fact]
	public void GetRegistryExportFileName_SanitisesInvalidCharacters()
	{
		string name = BackupCommandBuilder.GetRegistryExportFileName(@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
		Assert.EndsWith(".reg", name, StringComparison.Ordinal);
		Assert.DoesNotContain('\\', name);
		Assert.DoesNotContain('/', name);
		Assert.DoesNotContain(':', name);
	}

	[Fact]
	public void GetRegistryExportFileName_IsDeterministicForSameKey()
	{
		string a = BackupCommandBuilder.GetRegistryExportFileName(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
		string b = BackupCommandBuilder.GetRegistryExportFileName(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
		Assert.Equal(a, b);
	}

	[Fact]
	public void GetRegistryExportFileName_DiffersBetweenKeys()
	{
		string a = BackupCommandBuilder.GetRegistryExportFileName(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa");
		string b = BackupCommandBuilder.GetRegistryExportFileName(@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
		Assert.NotEqual(a, b);
	}
}
