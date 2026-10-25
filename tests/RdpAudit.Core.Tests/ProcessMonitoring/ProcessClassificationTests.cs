// File:    tests/RdpAudit.Core.Tests/ProcessMonitoring/ProcessClassificationTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit coverage for KnownProcessKey - the pure baseline normalisation of process
//          identities (name sanitisation, system-vs-interactive classification, Domain\User
//          identity). Locks the adversarial guarantees: path segments discarded, control
//          characters stripped, length caps enforced, service/machine accounts classified as
//          System, and empty/blank input yields an unusable (empty) key.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.ProcessMonitoring;
using Xunit;

namespace RdpAudit.Core.Tests.ProcessMonitoring;

/// <summary>Unit coverage for <see cref="KnownProcessKey"/>.</summary>
public class ProcessClassificationTests
{
	// ── Normal ────────────────────────────────────────────────────────────────

	[Fact]
	public void SanitizeProcessName_FullPath_ReturnsExactFileNameLowered()
	{
		Assert.Equal("evil.exe", KnownProcessKey.SanitizeProcessName(@"C:\Windows\Temp\Evil.EXE"));
	}

	[Fact]
	public void SanitizeProcessName_ForwardSlashPath_ReturnsFileName()
	{
		Assert.Equal("evil.exe", KnownProcessKey.SanitizeProcessName("/tmp/evil.exe"));
	}

	[Fact]
	public void SanitizeProcessName_BareName_IsLoweredAndTrimmed()
	{
		Assert.Equal("powershell.exe", KnownProcessKey.SanitizeProcessName("  PowerShell.EXE  "));
	}

	[Fact]
	public void ClassifyUserName_InteractiveUser_IsInteractive()
	{
		Assert.Equal(ProcessUserCategory.Interactive, KnownProcessKey.ClassifyUserName("alice"));
		Assert.Equal(ProcessUserCategory.Interactive, KnownProcessKey.ClassifyUserName(@"CORP\alice"));
	}

	[Theory]
	[InlineData("SYSTEM")]
	[InlineData("system")]
	[InlineData("LOCAL SERVICE")]
	[InlineData("NETWORK SERVICE")]
	[InlineData("ANONYMOUS LOGON")]
	[InlineData("DWM-1")]
	[InlineData("UMFD-2")]
	[InlineData("WIN-SRV01$")]
	public void ClassifyUserName_ServiceAccount_IsSystem(string userName)
	{
		Assert.Equal(ProcessUserCategory.System, KnownProcessKey.ClassifyUserName(userName));
	}

	[Fact]
	public void NormalizeIdentity_DomainAndUser_IsLoweredDomainBackslashUser()
	{
		Assert.Equal(@"corp\alice", KnownProcessKey.NormalizeIdentity("Alice", "CORP"));
	}

	[Fact]
	public void NormalizeIdentity_NoDomain_ReturnsBareUser()
	{
		Assert.Equal("alice", KnownProcessKey.NormalizeIdentity("alice", null));
	}

	[Fact]
	public void Build_InteractiveProcess_ProducesFullKey()
	{
		KnownProcessKey key = KnownProcessKey.Build(@"C:\Temp\Run.exe", "Alice", "CORP");

		Assert.Equal("run.exe", key.ProcessName);
		Assert.Equal(ProcessUserCategory.Interactive, key.UserCategory);
		Assert.Equal(@"corp\alice", key.UserName);
		Assert.False(key.IsEmpty);
	}

	[Fact]
	public void Build_SystemProcess_HasEmptyIdentity()
	{
		KnownProcessKey key = KnownProcessKey.Build("svchost.exe", "SYSTEM", "NT AUTHORITY");

		Assert.Equal("svchost.exe", key.ProcessName);
		Assert.Equal(ProcessUserCategory.System, key.UserCategory);
		Assert.Equal(string.Empty, key.UserName);
		Assert.False(key.IsEmpty);
	}

	[Theory]
	[InlineData("cmd.exe", "cmd.exe")]
	[InlineData("CMD.EXE", "cmd.exe")]
	[InlineData(@"C:\Windows\System32\cmd.exe", "cmd.exe")]
	public void SanitizeProcessName_EquivalentSpellings_ProduceOneKey(string raw, string expected)
	{
		Assert.Equal(expected, KnownProcessKey.SanitizeProcessName(raw));
	}

	// ── Failure / edge ────────────────────────────────────────────────────────

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	public void Build_BlankProcessName_ReturnsEmptyKey(string? raw)
	{
		KnownProcessKey key = KnownProcessKey.Build(raw, "alice", "corp");

		Assert.True(key.IsEmpty);
		Assert.Equal(string.Empty, key.ProcessName);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	public void ClassifyUserName_BlankUser_IsSystem(string? userName)
	{
		Assert.Equal(ProcessUserCategory.System, KnownProcessKey.ClassifyUserName(userName));
	}

	[Fact]
	public void SanitizeProcessName_Null_ReturnsEmpty()
	{
		Assert.Equal(string.Empty, KnownProcessKey.SanitizeProcessName(null));
	}

	// ── Adversarial ───────────────────────────────────────────────────────────

	[Fact]
	public void SanitizeProcessName_TraversalPath_KeepsOnlyFileName()
	{
		Assert.Equal("evil.exe", KnownProcessKey.SanitizeProcessName(@"..\..\..\evil.exe"));
	}

	[Fact]
	public void SanitizeProcessName_ControlCharacters_AreStripped()
	{
		string raw = "evil\u0001.exe\u001f\n";

		Assert.Equal("evil.exe", KnownProcessKey.SanitizeProcessName(raw));
	}

	[Fact]
	public void SanitizeProcessName_OverlongName_IsCapped()
	{
		string raw = new string('a', KnownProcessKey.MaxProcessNameLength + 500);

		string sanitized = KnownProcessKey.SanitizeProcessName(raw);

		Assert.Equal(KnownProcessKey.MaxProcessNameLength, sanitized.Length);
	}

	[Fact]
	public void NormalizeIdentity_OverlongIdentity_IsCapped()
	{
		string longDomain = new string('d', 200);
		string longUser = new string('u', 200);

		string identity = KnownProcessKey.NormalizeIdentity(longUser, longDomain);

		Assert.Equal(KnownProcessKey.MaxUserNameLength, identity.Length);
	}

	[Fact]
	public void NormalizeIdentity_ControlCharactersInDomain_AreStripped()
	{
		string identity = KnownProcessKey.NormalizeIdentity("alice", "COR\u0007P");

		Assert.Equal(@"corp\alice", identity);
	}
}
