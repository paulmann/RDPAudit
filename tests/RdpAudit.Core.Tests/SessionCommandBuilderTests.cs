// File:    tests/RdpAudit.Core.Tests/SessionCommandBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the SessionCommandBuilder: session-id range checks, disconnect
//          and logoff argument shapes, and the three mstsc /shadow variants.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class SessionCommandBuilderTests
{
	[Theory]
	[InlineData(0, true)]
	[InlineData(1, true)]
	[InlineData(42, true)]
	[InlineData(65535, true)]
	[InlineData(-1, false)]
	[InlineData(65536, false)]
	[InlineData(int.MaxValue, false)]
	public void ValidateSessionId_ChecksRange(int id, bool ok)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(id);
		Assert.Equal(ok, v.Ok);
		Assert.Equal(ok, v.Error is null);
	}

	[Fact]
	public void BuildDisconnect_ProducesSingleNumericArg()
	{
		IReadOnlyList<string> args = SessionCommandBuilder.BuildDisconnect(7);
		Assert.Single(args);
		Assert.Equal("7", args[0]);
	}

	[Fact]
	public void BuildLogoff_ProducesSingleNumericArg()
	{
		IReadOnlyList<string> args = SessionCommandBuilder.BuildLogoff(42);
		Assert.Single(args);
		Assert.Equal("42", args[0]);
	}

	[Fact]
	public void BuildDisconnect_RejectsInvalidId()
	{
		Assert.Throws<ArgumentOutOfRangeException>(() => SessionCommandBuilder.BuildDisconnect(-1));
		Assert.Throws<ArgumentOutOfRangeException>(() => SessionCommandBuilder.BuildLogoff(70000));
	}

	[Fact]
	public void BuildShadow_ViewOnly_OmitsControlAndConsent()
	{
		IReadOnlyList<string> args = SessionCommandBuilder.BuildShadow(3, SessionCommandBuilder.ShadowMode.ViewOnly);
		Assert.Single(args);
		Assert.Equal("/shadow:3", args[0]);
	}

	[Fact]
	public void BuildShadow_Control_AddsControlAndAdmin()
	{
		IReadOnlyList<string> args = SessionCommandBuilder.BuildShadow(4, SessionCommandBuilder.ShadowMode.Control);
		Assert.Equal(3, args.Count);
		Assert.Equal("/shadow:4", args[0]);
		Assert.Equal("/control", args[1]);
		Assert.Equal("/admin", args[2]);
		Assert.DoesNotContain("/noConsentPrompt", args);
	}

	[Fact]
	public void BuildShadow_ControlNoConsent_MatchesOperatorManualCommandLine()
	{
		IReadOnlyList<string> args = SessionCommandBuilder.BuildShadow(2, SessionCommandBuilder.ShadowMode.ControlNoConsent);
		Assert.Equal(4, args.Count);
		Assert.Equal("/shadow:2", args[0]);
		Assert.Equal("/control", args[1]);
		Assert.Equal("/noConsentPrompt", args[2]);
		Assert.Equal("/admin", args[3]);
	}

	[Fact]
	public void BuildShadow_InvalidId_Throws()
	{
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			SessionCommandBuilder.BuildShadow(-2, SessionCommandBuilder.ShadowMode.ViewOnly));
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			SessionCommandBuilder.BuildShadow(99999, SessionCommandBuilder.ShadowMode.Control));
	}
}
