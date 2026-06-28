// File:    src/RdpAudit.Core/Util/ShadowGateDecision.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure two-tier gating decision for the Configurator's "Shadow this session"
//          action. Combines an upstream service-side approval (when reachable) with the
//          locally-observed Microsoft Terminal Services Shadow registry policy. The
//          local fallback exists so the operator is not refused when the service IPC is
//          unreachable but the OS policy in fact permits the action (the same reason
//          plain <c>mstsc /shadow:N /control /noConsentPrompt /admin</c> succeeds when
//          launched manually). All inputs are simple data — the decision is pure and
//          unit-tested off-Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>What the gating logic recommends the UI do with the shadow request.</summary>
public enum ShadowGateOutcome
{
	/// <summary>Default — no decision yet (reserved zero member required by CA1008).</summary>
	None = 0,

	/// <summary>Service approved the request — proceed to launch mstsc.</summary>
	AllowByService = 1,

	/// <summary>Service unreachable, but the locally-observed Shadow registry value
	/// permits the requested mode. UI may proceed (with a warning about IPC).</summary>
	AllowByLocalPolicy = 2,

	/// <summary>Service refused but the locally-observed Shadow registry value clearly
	/// permits the requested mode. UI may proceed; the service-side refusal is treated
	/// as stale because the OS policy is the authoritative gate.</summary>
	AllowOverridingStaleService = 3,

	/// <summary>No source allowed the request — show the explanation in <see cref="ShadowGateDecision.Reason"/>.</summary>
	Deny = 9,
}

/// <summary>Result of a shadow-gate evaluation.</summary>
public sealed record ShadowGateDecision(ShadowGateOutcome Outcome, string Reason)
{
	/// <summary>True when the UI should proceed to launch mstsc.</summary>
	public bool ShouldLaunch =>
		Outcome == ShadowGateOutcome.AllowByService
		|| Outcome == ShadowGateOutcome.AllowByLocalPolicy
		|| Outcome == ShadowGateOutcome.AllowOverridingStaleService;
}

/// <summary>Input describing the upstream service-side approval result for the request.</summary>
public sealed record ShadowServiceDecision(bool Reachable, bool Approved, string? Message)
{
	/// <summary>Service unreachable (IPC returned null / threw / timed out).</summary>
	public static ShadowServiceDecision FromUnreachable(string? detail = null) =>
		new(Reachable: false, Approved: false, Message: detail);

	/// <summary>Service reachable and approved the request.</summary>
	public static ShadowServiceDecision FromApproval(string? detail = null) =>
		new(Reachable: true, Approved: true, Message: detail);

	/// <summary>Service reachable but refused.</summary>
	public static ShadowServiceDecision FromRefusal(string? detail) =>
		new(Reachable: true, Approved: false, Message: detail);
}

/// <summary>Pure evaluator that picks an outcome from upstream and local-policy facts.</summary>
public static class ShadowGate
{
	/// <summary>Decide whether to launch mstsc /shadow for the requested mode.</summary>
	public static ShadowGateDecision Evaluate(
		ShadowServiceDecision service,
		ShadowPolicyMode localPolicy,
		SessionCommandBuilder.ShadowMode requested)
	{
		ArgumentNullException.ThrowIfNull(service);

		if (service.Reachable && service.Approved)
		{
			return new ShadowGateDecision(
				ShadowGateOutcome.AllowByService,
				service.Message ?? "approved by service");
		}

		bool localAllows = ShadowPolicyModel.AllowsMode(localPolicy, requested);

		if (!service.Reachable)
		{
			if (localAllows)
			{
				return new ShadowGateDecision(
					ShadowGateOutcome.AllowByLocalPolicy,
					"service unreachable; local Shadow policy '"
						+ ShadowPolicyModel.Describe(localPolicy)
						+ "' permits the requested mode "
						+ requested);
			}

			return new ShadowGateDecision(
				ShadowGateOutcome.Deny,
				"service unreachable and local Shadow policy '"
					+ ShadowPolicyModel.Describe(localPolicy)
					+ "' does not permit mode " + requested);
		}

		if (localAllows)
		{
			return new ShadowGateDecision(
				ShadowGateOutcome.AllowOverridingStaleService,
				"service refused ('"
					+ (service.Message ?? "(no message)")
					+ "') but local Shadow policy '"
					+ ShadowPolicyModel.Describe(localPolicy)
					+ "' permits mode " + requested);
		}

		return new ShadowGateDecision(
			ShadowGateOutcome.Deny,
			"service refused: " + (service.Message ?? "(no message)"));
	}
}
