// File:    tests/RdpAudit.Core.Tests/EnglishConsoleCommandFactoryTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage-3 generalized parse-stable English console factory. Verifies
//          the exact cmd.exe argument shape emitted for every whitelisted tool, the GUID
//          validation guard on auditpol, and the shell-injection safety of the fixed-string
//          composition. The legacy SessionConsoleCommandFactoryTests stay untouched — this
//          suite is additive.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class EnglishConsoleCommandFactoryTests
{
	[Fact]
	public void Build_Qwinsta_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.Qwinsta);

		Assert.Equal(437, spawn.CodePage);
		Assert.Contains("cmd.exe", spawn.Executable, StringComparison.OrdinalIgnoreCase);
		Assert.Equal("/d /c \"chcp 437 >nul & qwinsta.exe\"", spawn.Arguments);
		Assert.Equal("qwinsta", spawn.CommandLabel);
	}

	[Fact]
	public void Build_Quser_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.Quser);

		Assert.Equal("/d /c \"chcp 437 >nul & quser.exe\"", spawn.Arguments);
		Assert.Equal("quser", spawn.CommandLabel);
	}

	[Fact]
	public void Build_NetshShowAllRulesVerbose_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.NetshShowAllRulesVerbose);

		Assert.Equal(
			"/d /c \"chcp 437 >nul & netsh.exe advfirewall firewall show rule name=all verbose\"",
			spawn.Arguments);
		Assert.Equal("netsh advfirewall firewall show rule name=all verbose", spawn.CommandLabel);
	}

	[Fact]
	public void Build_NetshShowAllProfilesState_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.NetshShowAllProfilesState);

		Assert.Equal(
			"/d /c \"chcp 437 >nul & netsh.exe advfirewall show allprofiles state\"",
			spawn.Arguments);
		Assert.Equal("netsh advfirewall show allprofiles state", spawn.CommandLabel);
	}

	[Fact]
	public void Build_AuditpolGetSubcategory_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv,
			new EnglishConsoleArgs { SubcategoryGuid = "{0CCE9215-69AE-11D9-BED3-505054503030}" });

		Assert.Equal(
			"/d /c \"chcp 437 >nul & auditpol.exe /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /r\"",
			spawn.Arguments);
		Assert.Equal(
			"auditpol /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /r",
			spawn.CommandLabel);
	}

	[Theory]
	[InlineData("0cce9215-69ae-11d9-bed3-505054503030")]
	[InlineData("(0CCE9215-69AE-11D9-BED3-505054503030)")]
	[InlineData("0CCE9215-69AE-11D9-BED3-505054503030")]
	public void Build_AuditpolGetSubcategory_NormalizesGuidToBraceForm(string raw)
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv,
			new EnglishConsoleArgs { SubcategoryGuid = raw });

		Assert.Contains("{0CCE9215-69AE-11D9-BED3-505054503030}", spawn.Arguments, StringComparison.Ordinal);
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("not-a-guid")]
	[InlineData("0CCE9215-69AE-11D9-BED3-505054503030; rd /s /q C:\\")] // command-injection probe
	[InlineData("\" & calc.exe & \"")]
	public void Build_AuditpolGetSubcategory_RejectsNonGuid(string injection)
	{
		Assert.Throws<ArgumentException>(() => EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv,
			new EnglishConsoleArgs { SubcategoryGuid = injection }));
	}

	[Fact]
	public void Build_AuditpolGetSubcategory_RequiresArgs()
	{
		Assert.Throws<ArgumentException>(() => EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv));
	}

	[Fact]
	public void Build_GpresultScopeComputer_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.GpresultScopeComputer);

		Assert.Equal(
			"/d /c \"chcp 437 >nul & gpresult.exe /scope computer /r\"",
			spawn.Arguments);
		Assert.Equal("gpresult /scope computer /r", spawn.CommandLabel);
	}

	[Fact]
	public void Build_NetshShowNamedRuleVerbose_EmitsExpectedShape()
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose,
			new EnglishConsoleArgs { RuleName = "RdpAudit-Block-203.0.113.10" });

		Assert.Equal(
			"/d /c \"chcp 437 >nul & netsh.exe advfirewall firewall show rule name=\"RdpAudit-Block-203.0.113.10\" verbose\"",
			spawn.Arguments);
		Assert.Equal(
			"netsh advfirewall firewall show rule name=RdpAudit-Block-203.0.113.10 verbose",
			spawn.CommandLabel);
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("Rule;Name")]
	[InlineData("\" & calc.exe & \"")]
	[InlineData("name & del")]
	public void Build_NetshShowNamedRuleVerbose_RejectsUnsafeRuleName(string injection)
	{
		Assert.Throws<ArgumentException>(() => EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose,
			new EnglishConsoleArgs { RuleName = injection }));
	}

	[Fact]
	public void Build_NetshShowNamedRuleVerbose_RequiresRuleName()
	{
		Assert.Throws<ArgumentException>(() => EnglishConsoleCommandFactory.Build(
			TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose));
	}

	[Fact]
	public void Build_UnknownTool_Throws()
	{
		Assert.Throws<ArgumentOutOfRangeException>(
			() => EnglishConsoleCommandFactory.Build((TrustedEnglishConsoleTool)999));
	}

	[Fact]
	public void Arguments_AlwaysWrapInChcp437_AndCloseQuote()
	{
		foreach (TrustedEnglishConsoleTool tool in Enum.GetValues<TrustedEnglishConsoleTool>())
		{
			if (tool == TrustedEnglishConsoleTool.None)
			{
				continue;
			}

			EnglishConsoleArgs? args = tool switch
			{
				TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv =>
					new EnglishConsoleArgs { SubcategoryGuid = "{00000000-0000-0000-0000-000000000000}" },
				TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose =>
					new EnglishConsoleArgs { RuleName = "RdpAudit-Block-203.0.113.10" },
				_ => null,
			};

			EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(tool, args);

			Assert.StartsWith("/d /c \"chcp 437 >nul & ", spawn.Arguments, StringComparison.Ordinal);
			Assert.EndsWith("\"", spawn.Arguments, StringComparison.Ordinal);
		}
	}
}
