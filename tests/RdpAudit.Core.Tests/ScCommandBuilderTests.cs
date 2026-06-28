// File:    tests/RdpAudit.Core.Tests/ScCommandBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the sc.exe argument shape returned by ScCommandBuilder. sc.exe
//          exit 1639 (ERROR_INVALID_COMMAND_LINE) reproduces when the option name
//          and its value are passed as a single argv token (e.g. "binPath= C:\Path").
//          These tests pin the contract that the builder emits the option name
//          (ending with '=') and its value as separate argv elements, which is the
//          only shape sc.exe parses reliably under ProcessStartInfo.ArgumentList.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="ScCommandBuilder"/>.</summary>
public class ScCommandBuilderTests
{
	[Fact]
	public void BuildCreate_EmitsBinPathAndValueAsSeparateTokens()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildCreate(
			"RdpAuditService",
			@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
			"RDP Monitor");

		Assert.Equal("create", args[0]);
		Assert.Equal("RdpAuditService", args[1]);
		Assert.Equal("binPath=", args[2]);
		Assert.Equal(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe", args[3]);
		Assert.Equal("start=", args[4]);
		Assert.Equal("auto", args[5]);
		Assert.Equal("obj=", args[6]);
		Assert.Equal("LocalSystem", args[7]);
		Assert.Equal("DisplayName=", args[8]);
		Assert.Equal("RDP Monitor", args[9]);
	}

	[Fact]
	public void BuildCreate_NoTokenContainsGluedKeyValuePair()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildCreate(
			"RdpAuditService",
			@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
			"RDP Monitor");

		foreach (string token in args)
		{
			// "binPath= C:\..." inside a single argv element is what triggers exit 1639.
			Assert.False(token.Contains("= ", StringComparison.Ordinal),
				$"argv token '{token}' glues '= ' which causes sc.exe ERROR_INVALID_COMMAND_LINE (1639).");
		}
	}

	[Fact]
	public void BuildCreate_AllowsCustomStartAndAccount()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildCreate(
			"Svc", @"C:\svc.exe", "Display", startType: "demand", objAccount: "NT AUTHORITY\\NetworkService");

		Assert.Contains("demand", args);
		Assert.Contains("NT AUTHORITY\\NetworkService", args);
	}

	[Fact]
	public void BuildConfig_EmitsExpectedTokens()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildConfig(
			"RdpAuditService", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe");

		Assert.Equal(new[]
		{
			"config",
			"RdpAuditService",
			"binPath=", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
			"start=", "auto",
		}, args);
	}

	[Fact]
	public void BuildFailure_EmitsExpectedTokens()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildFailure(
			"RdpAuditService", 86400, "restart/60000/restart/60000/restart/60000");

		Assert.Equal(new[]
		{
			"failure",
			"RdpAuditService",
			"reset=", "86400",
			"actions=", "restart/60000/restart/60000/restart/60000",
		}, args);
	}

	[Fact]
	public void BuildDelete_EmitsExpectedTokens()
	{
		Assert.Equal(new[] { "delete", "RdpAuditService" },
			ScCommandBuilder.BuildDelete("RdpAuditService"));
	}

	[Fact]
	public void BuildQuery_EmitsExpectedTokens()
	{
		Assert.Equal(new[] { "query", "RdpAuditService" },
			ScCommandBuilder.BuildQuery("RdpAuditService"));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	public void BuildCreate_RejectsMissingServiceName(string? name)
	{
		Assert.ThrowsAny<ArgumentException>(() => ScCommandBuilder.BuildCreate(name!, @"C:\svc.exe", "Display"));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	public void BuildCreate_RejectsMissingBinaryPath(string? path)
	{
		Assert.ThrowsAny<ArgumentException>(() => ScCommandBuilder.BuildCreate("Svc", path!, "Display"));
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	public void BuildCreate_RejectsMissingDisplayName(string? display)
	{
		Assert.ThrowsAny<ArgumentException>(() => ScCommandBuilder.BuildCreate("Svc", @"C:\svc.exe", display!));
	}

	[Fact]
	public void BuildFailure_RejectsNegativeReset()
	{
		Assert.Throws<ArgumentOutOfRangeException>(() => ScCommandBuilder.BuildFailure("Svc", -1, "restart/1000"));
	}

	[Fact]
	public void BuildCreateQuoted_WrapsBinaryPathInLiteralQuotes()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildCreateQuoted(
			"RdpAuditService",
			@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
			"RDP Monitor");

		Assert.Equal("create", args[0]);
		Assert.Equal("RdpAuditService", args[1]);
		Assert.Equal("binPath=", args[2]);
		Assert.Equal("\"C:\\Program Files\\RdpAudit\\Service\\RdpAudit.Service.exe\"", args[3]);
		Assert.Equal("start=", args[4]);
		Assert.Equal("auto", args[5]);
		Assert.Equal("obj=", args[6]);
		Assert.Equal("LocalSystem", args[7]);
		Assert.Equal("DisplayName=", args[8]);
		Assert.Equal("RDP Monitor", args[9]);
	}

	[Fact]
	public void BuildConfigQuoted_WrapsBinaryPathInLiteralQuotes()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildConfigQuoted(
			"RdpAuditService", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe");

		Assert.Contains("\"C:\\Program Files\\RdpAudit\\Service\\RdpAudit.Service.exe\"", args);
	}

	[Fact]
	public void BuildCreateQuoted_DoesNotDoubleQuoteAlreadyQuotedPath()
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildCreateQuoted(
			"Svc", "\"C:\\already.exe\"", "Display");

		Assert.Contains("\"C:\\already.exe\"", args);
		Assert.DoesNotContain("\"\"C:\\already.exe\"\"", args);
	}
}
