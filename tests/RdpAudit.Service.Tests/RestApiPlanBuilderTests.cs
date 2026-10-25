// File:    tests/RdpAudit.Service.Tests/RestApiPlanBuilderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the fail-closed REST API startup decision: disabled state, invalid
//          listen addresses, missing/unprotectable tokens, certificate resolution failures,
//          untrusted certificates with and without the loopback opt-in, and a successful
//          Listening plan with a self-signed loopback certificate.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Config;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public class RestApiPlanBuilderTests
{
	private const string TestToken = "rdp-api-plan-token";

	private static ApiOptions BaseApi(Action<ApiOptions>? configure = null)
	{
		ApiOptions api = new()
		{
			Enabled = true,
			Token = "protected-envelope-placeholder",
			AllowInsecureLoopback = true,
		};
		configure?.Invoke(api);
		return api;
	}

	private static RestApiPlanBuildResult Build(
		ApiOptions api,
		StubSecretProtector protector,
		IRestApiCertificateResolver? resolver = null)
		=> RestApiPlanBuilder.Build(
			api,
			protector,
			resolver ?? new StubCertificateResolver(RestApiTestCertificateFactory.CreateSelfSigned()),
			NullLogger.Instance);

	[Fact]
	public void Build_WithDisabledApi_ReturnsDisabledPlanWithoutToken()
	{
		ApiOptions api = BaseApi();
		api.Enabled = false;

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.Disabled, result.Plan.State);
		Assert.False(result.HasToken);
		Assert.Null(result.ResolvedToken);
		Assert.Contains("Enabled is false", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithNullApi_Throws()
	{
		Assert.Throws<ArgumentNullException>(
			() => RestApiPlanBuilder.Build(null!, StubSecretProtector.Returning(TestToken), null, null));
	}

	[Fact]
	public void Build_WithNullProtector_Throws()
	{
		Assert.Throws<ArgumentNullException>(
			() => RestApiPlanBuilder.Build(BaseApi(), null!, null, null));
	}

	[Theory]
	[InlineData("https://127.0.0.1")]
	[InlineData("not a valid address!")]
	[InlineData("?")]
	public void Build_WithInvalidListenAddress_FailsClosedWithoutToken(string listenAddress)
	{
		ApiOptions api = BaseApi();
		api.ListenAddress = listenAddress;

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.False(result.HasToken);
		Assert.Contains("not a valid IP address or DNS host name", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithBlankToken_FailsClosed()
	{
		ApiOptions api = BaseApi();
		api.Token = "   ";

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.False(result.HasToken);
		Assert.Contains("Api.Token is missing or could not be unprotected", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithThrowingProtector_FailsClosed()
	{
		RestApiPlanBuildResult result = Build(BaseApi(), StubSecretProtector.Throwing());

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.False(result.HasToken);
		Assert.Contains("Api.Token is missing or could not be unprotected", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WhenProtectorResolvesBlankToken_FailsClosed()
	{
		RestApiPlanBuildResult result = Build(BaseApi(), StubSecretProtector.Returning(""));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.False(result.HasToken);
	}

	[Fact]
	public void Build_WithFailedCertificateResolver_FailsClosed()
	{
		RestApiPlanBuildResult result = Build(
			BaseApi(),
			StubSecretProtector.Returning(TestToken),
			StubCertificateResolver.Failed("no matching certificate"));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.False(result.HasToken);
		Assert.Contains("no matching certificate", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithNoThumbprintAndNoSubject_FailsClosed()
	{
		// The real resolver short-circuits on missing selector fields without touching the store,
		// so this assertion is deterministic in any environment.
		RestApiPlanBuildResult result = RestApiPlanBuilder.Build(
			BaseApi(),
			StubSecretProtector.Returning(TestToken),
			certificateResolver: null,
			logger: null);

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.Contains(
			"no Api.CertificateThumbprint and no Api.CertificateSubject configured",
			result.Plan.Reason,
			StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithUntrustedCertificateWithoutOptIn_FailsClosed()
	{
		ApiOptions api = BaseApi();
		api.AllowInsecureLoopback = false;

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.Contains("not trusted by the system", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithUntrustedCertificateOnNonLoopbackAddress_FailsClosed()
	{
		ApiOptions api = BaseApi();
		api.ListenAddress = "example.local";
		api.AllowInsecureLoopback = true;

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.FailClosed, result.Plan.State);
		Assert.Contains("only permitted with a loopback listener", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithSelfSignedLoopbackOptIn_ReturnsListeningPlanWithToken()
	{
		X509Certificate2 certificate = RestApiTestCertificateFactory.CreateSelfSigned();
		StubCertificateResolver resolver = new(certificate);

		RestApiPlanBuildResult result = Build(BaseApi(), StubSecretProtector.Returning(TestToken), resolver);

		Assert.Equal(RestApiPlanState.Listening, result.Plan.State);
		Assert.True(result.HasToken);
		Assert.Equal(TestToken, result.ResolvedToken);
		Assert.True(result.Plan.IsListening);
		Assert.True(result.Plan.AcceptedSelfSigned);
		Assert.False(result.Plan.WarnNonLoopback);
		Assert.Same(certificate, result.Plan.Certificate);
		Assert.Equal("127.0.0.1", result.Plan.ResolvedAddress);
		Assert.Equal(ApiOptions.DefaultPort, result.Plan.Port);
		Assert.Contains("https://127.0.0.1:8443", result.Plan.Reason, StringComparison.Ordinal);
	}

	[Fact]
	public void Build_WithLocalhostName_IsTreatedAsLoopback()
	{
		ApiOptions api = BaseApi();
		api.ListenAddress = "LOCALHOST";

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.Equal(RestApiPlanState.Listening, result.Plan.State);
		Assert.True(result.Plan.AcceptedSelfSigned);
		Assert.False(result.Plan.WarnNonLoopback);
	}

	[Fact]
	public void Build_ListeningPlan_PropagatesClampedValues()
	{
		ApiOptions api = BaseApi();
		api.Port = 8080;
		api.MaxConnections = 25;
		api.RateLimitPerMinute = 30;

		RestApiPlanBuildResult result = Build(api, StubSecretProtector.Returning(TestToken));

		Assert.True(result.Plan.IsListening);
		Assert.Equal(8080, result.Plan.Port);
		Assert.Equal(25, result.Plan.MaxConnections);
		Assert.Equal(30, result.Plan.RateLimitPerMinute);
	}
}
