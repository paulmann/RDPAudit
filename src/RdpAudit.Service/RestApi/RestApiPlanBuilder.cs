/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiPlanBuilder.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Turns ApiOptions plus runtime facts (secret-protector availability, certificate in
//          LocalMachine\My, chain trust) into a single immutable startup decision for the read-only
//          REST API. Fail-closed: any missing prerequisite produces FailClosed and NO listener.
// Depends: RdpAudit.Core.Config, RdpAudit.Core.Security, System.Net, System.Security.Cryptography.X509Certificates
// Extends: Add per-endpoint options evaluation when introduced.

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;

namespace RdpAudit.Service.RestApi;

/// <summary>
/// Builds the fail-closed startup decision for the REST API. The resolved token is returned only
/// on the Listening path and is deliberately excluded from the plan itself.
/// </summary>
public static class RestApiPlanBuilder
{
	/// <summary>Evaluates the supplied API configuration and returns the startup decision.</summary>
	/// <param name="api">ApiOptions bound from appsettings.json.</param>
	/// <param name="protector">Secret protector used to unwrap the protected token envelope.</param>
	/// <param name="certificateResolver">Certificate resolver; defaults to the LocalMachine\My resolver.</param>
	/// <param name="logger">Logger for risk warnings; never receives secret values.</param>
	public static RestApiPlanBuildResult Build(
		ApiOptions api,
		ISecretProtector protector,
		IRestApiCertificateResolver? certificateResolver = null,
		ILogger? logger = null)
	{
		ArgumentNullException.ThrowIfNull(api);
		ArgumentNullException.ThrowIfNull(protector);
		certificateResolver ??= new RestApiCertificateResolver();

		if (!api.Enabled)
		{
			RestApiPlan disabled = RestApiPlan.Disabled("RdpAudit.Api.Enabled is false (default); the REST API exposes no listener.");
			logger?.LogInformation("REST API plan: {State}. {Reason}", disabled.State, disabled.Reason);
			return new RestApiPlanBuildResult(disabled, null);
		}

		string listenAddress = api.ResolveListenAddress();
		if (!IsValidListenAddress(listenAddress))
		{
			return Fail($"the configured Api.ListenAddress '{Sanitize(listenAddress)}' is not a valid IP address or DNS host name", logger);
		}

		string? token = ResolveToken(api.Token, protector, logger);
		if (token is null)
		{
			return Fail("the configured Api.Token is missing or could not be unprotected", logger);
		}

		RestApiCertificateResolution certificateResolution;
		try
		{
			certificateResolution = certificateResolver.Resolve(api.CertificateThumbprint, api.CertificateSubject);
		}
		catch (Exception ex)
		{
			logger?.LogWarning("REST API certificate resolution failed: {Reason}", ex.Message);
			certificateResolution = new RestApiCertificateResolution(null, ex.Message);
		}

		if (!certificateResolution.Succeeded || certificateResolution.Certificate is null)
		{
			return Fail(certificateResolution.FailureReason ?? "no server certificate resolved", logger);
		}

		X509Certificate2 certificate = certificateResolution.Certificate;
		bool chainTrusted = IsChainTrusted(certificate);
		bool acceptedSelfSigned = false;
		if (!chainTrusted)
		{
			if (!api.AllowInsecureLoopback)
			{
				return Fail("the configured server certificate is not trusted by the system and Api.AllowInsecureLoopback is false", logger);
			}

			if (!api.IsLoopback())
			{
				return Fail("an untrusted (self-signed) certificate is only permitted with a loopback listener when Api.AllowInsecureLoopback is true", logger);
			}

			acceptedSelfSigned = true;
			logger?.LogWarning(
				"REST API: untrusted/self-signed server certificate accepted because Api.AllowInsecureLoopback=true (loopback deployment only).");
		}

		int port = api.ResolvePort();
		int maxConnections = api.ResolveMaxConnections();
		int rateLimit = api.ResolveRateLimitPerMinute();
		bool warnNonLoopback = !api.IsLoopback();
		if (warnNonLoopback)
		{
			logger?.LogWarning(
				"REST API configured to listen on a non-loopback address {Address}. " +
				"Traffic reaches this host over the network - restrict access with a firewall and keep TLS certificates current.",
				listenAddress);
		}

		RestApiPlan plan = RestApiPlan.Listening(
			listenAddress, port, maxConnections, rateLimit, certificate, warnNonLoopback, acceptedSelfSigned);
		logger?.LogInformation("REST API plan: {State}. {Reason}", plan.State, plan.Reason);
		return new RestApiPlanBuildResult(plan, token);
	}

	/// <summary>Unwraps the protected token envelope; null when missing or unprotectable.</summary>
	private static string? ResolveToken(string configuredToken, ISecretProtector protector, ILogger? logger)
	{
		if (string.IsNullOrWhiteSpace(configuredToken))
		{
			logger?.LogWarning("REST API: Api.Token is empty.");
			return null;
		}

		try
		{
			string resolved = protector.Unprotect(configuredToken.Trim());
			if (string.IsNullOrWhiteSpace(resolved))
			{
				logger?.LogWarning("REST API: Api.Token resolved to an empty value.");
				return null;
			}

			return resolved;
		}
		catch (SecretProtectionException ex)
		{
			logger?.LogWarning("REST API: Api.Token could not be unprotected: {Reason}", ex.Message);
			return null;
		}
	}

	private static RestApiPlanBuildResult Fail(string reason, ILogger? logger)
	{
		RestApiPlan failed = RestApiPlan.FailClosed(reason);
		logger?.LogWarning("REST API plan: {State}. {Reason}", failed.State, failed.Reason);
		return new RestApiPlanBuildResult(failed, null);
	}

	private static bool IsValidListenAddress(string address)
		=> IPAddress.TryParse(address, out _) || Uri.CheckHostName(address) == UriHostNameType.Dns;

	private static bool IsChainTrusted(X509Certificate2 certificate)
	{
		using X509Chain chain = new();
		chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
		chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

		if (chain.Build(certificate))
		{
			return true;
		}

		// Revocation lookups are unreliable in isolated deployments; accept ONLY revocation-status
		// noise and reject real policy failures (untrusted root, partial chain, expired leaf...).
		foreach (X509ChainStatus status in chain.ChainStatus)
		{
			if (status.Status is X509ChainStatusFlags.RevocationStatusUnknown
				or X509ChainStatusFlags.OfflineRevocation)
			{
				continue;
			}

			if (status.Status == X509ChainStatusFlags.NoError)
			{
				continue;
			}

			return false;
		}

		return true;
	}

	private static string Sanitize(string value)
		=> value.Length > 96 ? value[..96] + "..." : value;
}
