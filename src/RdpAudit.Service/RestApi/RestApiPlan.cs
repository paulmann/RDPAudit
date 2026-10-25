/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiPlan.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Domain model for the fail-closed REST API startup decision. RestApiPlanBuilder
//          evaluates ApiOptions + the secret protector + certificate resolution ONCE before the
//          host is built; the resulting plan either arms the Kestrel listener or installs a no-op
//          server so the process exposes zero TCP surface.
// Depends: RdpAudit.Core.Config, System.Net, System.Security.Cryptography.X509Certificates
// Extends: Add per-endpoint policies (rate-limit overrides) as fields when introduced.

using System.Net;
using System.Security.Cryptography.X509Certificates;
using RdpAudit.Core.Config;

namespace RdpAudit.Service.RestApi;

/// <summary>Terminal state of the REST API plan.</summary>
public enum RestApiPlanState
{
	/// <summary>Api.Enabled is false: no listener, no middleware, no endpoints.</summary>
	Disabled = 0,

	/// <summary>Kestrel is armed with TLS and the middleware pipeline is active.</summary>
	Listening = 1,

	/// <summary>Api is enabled but a prerequisite failed: no listener (fail-closed).</summary>
	FailClosed = 2,
}

/// <summary>Outcome of resolving the server TLS certificate.</summary>
/// <param name="Certificate">The store certificate, or null when resolution failed.</param>
/// <param name="FailureReason">Human-readable reason (no secrets) when null certificate.</param>
public sealed record RestApiCertificateResolution(X509Certificate2? Certificate, string? FailureReason)
{
	public bool Succeeded => Certificate is not null;
}

/// <summary>
/// Immutable startup decision for the read-only REST API. Exactly one terminal state applies;
/// <see cref="Reason"/> always carries the operator-facing explanation (never a secret).
/// </summary>
public sealed class RestApiPlan
{
	private RestApiPlan(
		RestApiPlanState state,
		string reason,
		string resolvedAddress,
		int port,
		int maxConnections,
		int rateLimitPerMinute,
		X509Certificate2? certificate,
		bool warnNonLoopback,
		bool acceptedSelfSigned)
	{
		State = state;
		Reason = reason;
		ResolvedAddress = resolvedAddress;
		Port = port;
		MaxConnections = maxConnections;
		RateLimitPerMinute = rateLimitPerMinute;
		Certificate = certificate;
		WarnNonLoopback = warnNonLoopback;
		AcceptedSelfSigned = acceptedSelfSigned;
	}

	public RestApiPlanState State { get; }

	/// <summary>Operator-facing explanation of the decision (never contains the token).</summary>
	public string Reason { get; }

	/// <summary>Resolved listen address (IP literal). Meaningful only when <see cref="State"/> is Listening.</summary>
	public string ResolvedAddress { get; }

	/// <summary>Clamped listen port. Meaningful only when Listening.</summary>
	public int Port { get; }

	/// <summary>Clamped Kestrel MaxConcurrentConnections.</summary>
	public int MaxConnections { get; }

	/// <summary>Clamped per-IP request budget per minute for the fixed-window limiter.</summary>
	public int RateLimitPerMinute { get; }

	/// <summary>Resolved server certificate with private key; null when not Listening.</summary>
	public X509Certificate2? Certificate { get; }

	/// <summary>True when the resolved listen address is not loopback: hosting logs a risk warning.</summary>
	public bool WarnNonLoopback { get; }

	/// <summary>True when a self-signed / unvalidated certificate was accepted under AllowInsecureLoopback.</summary>
	public bool AcceptedSelfSigned { get; }

	public bool IsListening => State == RestApiPlanState.Listening;

	public static RestApiPlan Disabled(string reason) => new(
		RestApiPlanState.Disabled, reason, string.Empty, 0, 0, 0, null, false, false);

	public static RestApiPlan FailClosed(string reason) => new(
		RestApiPlanState.FailClosed, reason, string.Empty, 0, 0, 0, null, false, false);

	public static RestApiPlan Listening(
		string resolvedAddress,
		int port,
		int maxConnections,
		int rateLimitPerMinute,
		X509Certificate2 certificate,
		bool warnNonLoopback,
		bool acceptedSelfSigned) => new(
			RestApiPlanState.Listening,
			$"listening on https://{resolvedAddress}:{port}",
			resolvedAddress,
			port,
			maxConnections,
			rateLimitPerMinute,
			certificate ?? throw new ArgumentNullException(nameof(certificate)),
			warnNonLoopback,
			acceptedSelfSigned);
}
