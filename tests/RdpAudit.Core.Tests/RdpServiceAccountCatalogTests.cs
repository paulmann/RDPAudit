// File:    tests/RdpAudit.Core.Tests/RdpServiceAccountCatalogTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the RdpServiceAccountCatalog contract: well-known built-in principals and the
//          per-session DWM-/UMFD- families and machine ($) accounts are recognised and described,
//          ordinary human usernames return null, the legend covers the documented accounts, and
//          the inline annotator round-trips ordinary names unchanged.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Coverage for the RDP service / built-in account decoding catalog.</summary>
public class RdpServiceAccountCatalogTests
{
	[Theory]
	[InlineData("SYSTEM")]
	[InlineData("system")]
	[InlineData("LOCAL SERVICE")]
	[InlineData("NETWORK SERVICE")]
	[InlineData("ANONYMOUS LOGON")]
	[InlineData("LOCAL")]
	[InlineData("DWM")]
	[InlineData("UMFD")]
	public void Describe_ExactBuiltIn_ReturnsDescription(string login)
	{
		string? description = RdpServiceAccountCatalog.Describe(login);

		Assert.NotNull(description);
		Assert.False(string.IsNullOrWhiteSpace(description));
	}

	[Theory]
	[InlineData("DWM-2")]
	[InlineData("dwm-15")]
	[InlineData("UMFD-0")]
	[InlineData("umfd-3")]
	public void Describe_PerSessionFamily_ReturnsDescription(string login)
	{
		string? description = RdpServiceAccountCatalog.Describe(login);

		Assert.NotNull(description);
	}

	[Theory]
	[InlineData("WIN-SRV01$")]
	[InlineData("DC1$")]
	public void Describe_MachineAccount_ReturnsComputerDescription(string login)
	{
		string? description = RdpServiceAccountCatalog.Describe(login);

		Assert.NotNull(description);
		Assert.Contains("machine", description!, System.StringComparison.OrdinalIgnoreCase);
	}

	[Theory]
	[InlineData("administrator")]
	[InlineData("maria")]
	[InlineData("god_user")]
	[InlineData("sales_3")]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData(null)]
	public void Describe_OrdinaryOrEmpty_ReturnsNull(string? login)
	{
		Assert.Null(RdpServiceAccountCatalog.Describe(login));
	}

	[Theory]
	[InlineData("SYSTEM", true)]
	[InlineData("DWM-2", true)]
	[InlineData("SRV$", true)]
	[InlineData("administrator", false)]
	[InlineData(null, false)]
	public void IsServiceAccount_MatchesDescribe(string? login, bool expected)
	{
		Assert.Equal(expected, RdpServiceAccountCatalog.IsServiceAccount(login));
	}

	[Fact]
	public void BuildLegend_CoversDocumentedAccounts()
	{
		string legend = RdpServiceAccountCatalog.BuildLegend();

		Assert.Contains("DWM", legend, System.StringComparison.Ordinal);
		Assert.Contains("UMFD", legend, System.StringComparison.Ordinal);
		Assert.Contains("SYSTEM", legend, System.StringComparison.Ordinal);
		Assert.Contains("ANONYMOUS LOGON", legend, System.StringComparison.Ordinal);
		Assert.Contains("NAME$", legend, System.StringComparison.Ordinal);
	}

	[Fact]
	public void AnnotateInline_ServiceAccount_AppendsDescription()
	{
		string annotated = RdpServiceAccountCatalog.AnnotateInline("DWM-2");

		Assert.StartsWith("DWM-2", annotated, System.StringComparison.Ordinal);
		Assert.NotEqual("DWM-2", annotated);
	}

	[Fact]
	public void AnnotateInline_OrdinaryUser_ReturnsUnchanged()
	{
		Assert.Equal("maria", RdpServiceAccountCatalog.AnnotateInline("maria"));
	}
}
