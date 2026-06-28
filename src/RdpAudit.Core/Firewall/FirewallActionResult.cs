// File:    src/RdpAudit.Core/Firewall/FirewallActionResult.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Result DTO returned by IFirewallProvider Block / Unblock / List operations. Carries a
//          stable status discriminator plus an operator-facing message free of secret data.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Outcome discriminator for firewall actions.</summary>
/// <remarks>Append-only enum: values must never be reused or reordered.</remarks>
public enum FirewallActionStatus
{
	Success = 0,
	NotImplemented = 1,
	Unavailable = 2,
	Refused = 3,
	InvalidRequest = 4,
	AlreadyExists = 5,
	NotFound = 6,
}

/// <summary>Result DTO returned by <c>IFirewallProvider</c> Block / Unblock / List operations.</summary>
public sealed class FirewallActionResult
{
	public FirewallActionStatus Status { get; init; } = FirewallActionStatus.Success;

	public string ProviderId { get; init; } = string.Empty;

	/// <summary>Operator-facing message; never contains plaintext secrets.</summary>
	public string? Message { get; init; }

	/// <summary>Concrete rule identifier created or removed by the provider, when applicable.</summary>
	public string? RuleId { get; init; }

	/// <summary>Backend handle / object id of the created rule (e.g. netsh rule name or CIM instance id),
	/// distinct from the logical <see cref="RuleId"/> when the backend assigns its own identifier.</summary>
	public string? RuleHandle { get; init; }

	/// <summary>Full backend-command detail of the last block / verify invocation, when the provider
	/// captured it. Null for providers that do not spawn an external command (e.g. the no-op provider).</summary>
	public BackendCommandAttempt? BackendAttempt { get; init; }

	/// <summary>Human-readable reason the post-block verifier reached its verdict, when applicable.</summary>
	public string? VerifierReason { get; init; }

	public static FirewallActionResult NotImplementedFor(string providerId, string action) =>
		new()
		{
			Status = FirewallActionStatus.NotImplemented,
			ProviderId = providerId,
			Message = string.Concat(action, " is not implemented in this build for provider ", providerId, "."),
		};

	public static FirewallActionResult UnavailableFor(string providerId, string reason) =>
		new()
		{
			Status = FirewallActionStatus.Unavailable,
			ProviderId = providerId,
			Message = reason,
		};
}
