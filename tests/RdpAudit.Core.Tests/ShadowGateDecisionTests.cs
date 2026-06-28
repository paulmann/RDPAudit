// File:    tests/RdpAudit.Core.Tests/ShadowGateDecisionTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Exercises the pure ShadowGate evaluator — covers the regression where the
//          Configurator refused mstsc /shadow even though the operator's manual
//          `mstsc /noConsentPrompt /control /admin /shadow:N` command works because the
//          OS Shadow policy in fact permits it. Verifies that local registry policy is
//          honoured when the service is unreachable or returns a stale refusal, and that
//          genuine denials still fall through.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ShadowGateDecisionTests
{
	[Fact]
	public void Evaluate_ServiceApproves_AllowsImmediately()
	{
		ShadowGateDecision decision = ShadowGate.Evaluate(
			ShadowServiceDecision.FromApproval("ok"),
			ShadowPolicyMode.NotConfigured,
			SessionCommandBuilder.ShadowMode.ControlNoConsent);

		Assert.True(decision.ShouldLaunch);
		Assert.Equal(ShadowGateOutcome.AllowByService, decision.Outcome);
	}

	[Fact]
	public void Evaluate_ServiceUnreachable_AndLocalPolicyAllows_AllowsByLocal()
	{
		ShadowGateDecision decision = ShadowGate.Evaluate(
			ShadowServiceDecision.FromUnreachable("pipe closed"),
			ShadowPolicyMode.FullControlNoConsent,
			SessionCommandBuilder.ShadowMode.ControlNoConsent);

		Assert.True(decision.ShouldLaunch);
		Assert.Equal(ShadowGateOutcome.AllowByLocalPolicy, decision.Outcome);
		Assert.Contains("service unreachable", decision.Reason);
	}

	[Fact]
	public void Evaluate_ServiceUnreachable_AndLocalPolicyForbids_Denies()
	{
		ShadowGateDecision decision = ShadowGate.Evaluate(
			ShadowServiceDecision.FromUnreachable(),
			ShadowPolicyMode.NoShadow,
			SessionCommandBuilder.ShadowMode.Control);

		Assert.False(decision.ShouldLaunch);
		Assert.Equal(ShadowGateOutcome.Deny, decision.Outcome);
	}

	[Fact]
	public void Evaluate_ServiceRefuses_ButLocalPolicyAllows_OverridesStaleService()
	{
		// This is the user's reported regression: the service hard-refuses with
		// "Shadow is disabled by SessionControl policy" while the OS Shadow registry
		// in fact permits full control without consent (value 2).
		ShadowGateDecision decision = ShadowGate.Evaluate(
			ShadowServiceDecision.FromRefusal("Shadow is disabled by SessionControl policy."),
			ShadowPolicyMode.FullControlNoConsent,
			SessionCommandBuilder.ShadowMode.ControlNoConsent);

		Assert.True(decision.ShouldLaunch);
		Assert.Equal(ShadowGateOutcome.AllowOverridingStaleService, decision.Outcome);
	}

	[Fact]
	public void Evaluate_ServiceRefuses_AndLocalPolicyAlsoForbids_Denies()
	{
		ShadowGateDecision decision = ShadowGate.Evaluate(
			ShadowServiceDecision.FromRefusal("policy says no"),
			ShadowPolicyMode.NoShadow,
			SessionCommandBuilder.ShadowMode.ControlNoConsent);

		Assert.False(decision.ShouldLaunch);
		Assert.Equal(ShadowGateOutcome.Deny, decision.Outcome);
	}

	[Theory]
	[InlineData(0, ShadowPolicyMode.NoShadow)]
	[InlineData(1, ShadowPolicyMode.FullControlWithConsent)]
	[InlineData(2, ShadowPolicyMode.FullControlNoConsent)]
	[InlineData(3, ShadowPolicyMode.ViewWithConsent)]
	[InlineData(4, ShadowPolicyMode.ViewNoConsent)]
	public void ShadowPolicyModel_FromRawValue_HonorsMicrosoftMapping(int raw, ShadowPolicyMode expected)
	{
		Assert.Equal(expected, ShadowPolicyModel.FromRawValue(raw));
	}

	[Theory]
	[InlineData(ShadowPolicyMode.FullControlNoConsent, SessionCommandBuilder.ShadowMode.ControlNoConsent, true)]
	[InlineData(ShadowPolicyMode.FullControlNoConsent, SessionCommandBuilder.ShadowMode.Control, true)]
	[InlineData(ShadowPolicyMode.FullControlNoConsent, SessionCommandBuilder.ShadowMode.ViewOnly, true)]
	[InlineData(ShadowPolicyMode.FullControlWithConsent, SessionCommandBuilder.ShadowMode.ControlNoConsent, false)]
	[InlineData(ShadowPolicyMode.FullControlWithConsent, SessionCommandBuilder.ShadowMode.Control, true)]
	[InlineData(ShadowPolicyMode.ViewNoConsent, SessionCommandBuilder.ShadowMode.ControlNoConsent, false)]
	[InlineData(ShadowPolicyMode.ViewNoConsent, SessionCommandBuilder.ShadowMode.ViewOnly, true)]
	[InlineData(ShadowPolicyMode.NoShadow, SessionCommandBuilder.ShadowMode.ViewOnly, false)]
	public void ShadowPolicyModel_AllowsMode_MatchesMicrosoftSemantics(
		ShadowPolicyMode policy,
		SessionCommandBuilder.ShadowMode requested,
		bool expected)
	{
		Assert.Equal(expected, ShadowPolicyModel.AllowsMode(policy, requested));
	}
}
