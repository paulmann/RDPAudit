/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiHostedService.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Owns the lifecycle of the read-only REST API. When the fail-closed plan says Listening,
//          it builds and starts an inner Kestrel WebApplication with the server certificate,
//          connection limits, the security-headers + bearer-auth middleware chain and the /healthz
//          endpoint. Otherwise it starts no listener at all while the service continues to run.
// Depends: RdpAudit.Core.Config, RdpAudit.Core.Security, Microsoft.AspNetCore.Builder/Hosting/Http,
//          Microsoft.Extensions.*
// Extends: Add more endpoints by extending the pipeline built in CreateApiApplication.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;

namespace RdpAudit.Service.RestApi;

/// <summary>
/// Hosted service for the read-only REST API. Built and resolved from the service's own DI
/// container; the inner WebApplication is deliberately separate so the API's security perimeter
/// (own listener, own middleware chain, own certificate) never leaks into the worker host.
/// </summary>
public sealed class RestApiHostedService : IHostedService
{
	private readonly IServiceScopeFactory _scopeFactory;
	private readonly ILoggerFactory _loggerFactory;
	private readonly ILogger<RestApiHostedService> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ISecretProtector _protector;
	private readonly IRestApiCertificateResolver _certificateResolver;

	private WebApplication? _apiApp;
	private RestApiPlan? _plan;

	public RestApiHostedService(
		IServiceScopeFactory scopeFactory,
		ILoggerFactory loggerFactory,
		ILogger<RestApiHostedService> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		ISecretProtector protector,
		IRestApiCertificateResolver certificateResolver)
	{
		_scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
		_loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_options = options ?? throw new ArgumentNullException(nameof(options));
		_protector = protector ?? throw new ArgumentNullException(nameof(protector));
		_certificateResolver = certificateResolver ?? throw new ArgumentNullException(nameof(certificateResolver));
	}

	/// <summary>The startup plan resolved at StartAsync (null before start). Exposed for diagnostics/tests.</summary>
	public RestApiPlan? Plan => _plan;

	/// <summary>Builds the fail-closed plan; when Listening, starts the inner Kestrel host. A bind
	/// failure is fail-closed: the service continues WITHOUT the API listener.</summary>
	public async Task StartAsync(CancellationToken cancellationToken)
	{
		ApiOptions api = _options.CurrentValue.Api;
		RestApiPlanBuildResult buildResult = RestApiPlanBuilder.Build(
			api, _protector, _certificateResolver, _logger);
		_plan = buildResult.Plan;

		if (_plan.State == RestApiPlanState.Disabled)
		{
			_logger.LogInformation("REST API disabled: {Reason}. No listener is started.", _plan.Reason);
			return;
		}

		if (_plan.State == RestApiPlanState.FailClosed)
		{
			_logger.LogWarning("REST API fail-closed: {Reason}. No listener is started.", _plan.Reason);
			return;
		}

		if (!buildResult.HasToken)
		{
			_logger.LogWarning("REST API fail-closed: no resolved bearer token. No listener is started.");
			return;
		}

		await StartInnerSafelyAsync(buildResult.ResolvedToken!, cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Stops and disposes the inner Kestrel host when it was started.</summary>
	public async Task StopAsync(CancellationToken cancellationToken)
	{
		WebApplication? apiApp = _apiApp;
		_apiApp = null;
		if (apiApp is null)
		{
			return;
		}

		try
		{
			await apiApp.StopAsync(cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			await apiApp.DisposeAsync().ConfigureAwait(false);
		}
	}

	private async Task StartInnerSafelyAsync(string token, CancellationToken cancellationToken)
	{
		try
		{
			_apiApp = CreateApiApplication(_plan!, token, _scopeFactory, _loggerFactory);
			await _apiApp.StartAsync(cancellationToken).ConfigureAwait(false);
			_logger.LogInformation(
				"REST API listening: {Reason} (MaxConcurrentConnections={MaxConnections}, RateLimitPerMinute={RateLimit}).",
				_plan!.Reason, _plan.MaxConnections, _plan.RateLimitPerMinute);
		}
		catch (Exception ex)
		{
			_logger.LogCritical(
				ex,
				"REST API listener failed to start: {Reason}. Continuing without the API (fail-closed).",
				_plan!.Reason);
			DisposeInner();
		}
	}

	private void DisposeInner()
	{
		WebApplication? apiApp = _apiApp;
		_apiApp = null;
		if (apiApp is null)
		{
			return;
		}

		try
		{
			apiApp.DisposeAsync().AsTask().GetAwaiter().GetResult();
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "REST API inner host disposal failed during fail-closed shutdown.");
		}
	}

	/// <summary>
	/// Builds (but does not start) the inner minimal WebApplication for the read-only REST API:
	/// Kestrel with the server certificate and connection limits, the per-request service-scope
	/// bridge to the outer container, the security-header + bearer-auth middleware, and the
	/// anonymous /healthz endpoint.
	/// </summary>
	/// <param name="configureBuilder">Optional post-creation hook (e.g. UseTestServer in tests).</param>
	public static WebApplication CreateApiApplication(
		RestApiPlan plan,
		string token,
		IServiceScopeFactory engineScopes,
		ILoggerFactory loggerFactory,
		Action<WebApplicationBuilder>? configureBuilder = null)
	{
		ArgumentNullException.ThrowIfNull(plan);
		if (string.IsNullOrEmpty(token))
		{
			throw new ArgumentException("The resolved bearer token must not be empty.", nameof(token));
		}

		ArgumentNullException.ThrowIfNull(engineScopes);
		ArgumentNullException.ThrowIfNull(loggerFactory);

		WebApplicationBuilder apiBuilder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
		{
			ApplicationName = "RdpAudit.Service.RestApi",
			Args = Array.Empty<string>(),
		});
		configureBuilder?.Invoke(apiBuilder);

		// The inner host must not read the service's appsettings.json (it has its own configuration
		// surface owned by RestApiPlan) and must not create a parallel logging pipeline.
		apiBuilder.Configuration.Sources.Clear();
		apiBuilder.Logging.ClearProviders();
		apiBuilder.Logging.AddProvider(new RestApiLogForwarder(loggerFactory));

		apiBuilder.WebHost.ConfigureKestrel(options =>
		{
			options.AddServerHeader = false;
			options.Limits.MaxConcurrentConnections = plan.MaxConnections;
			// The API is read-only (GET/HEAD only); a 1 MiB body cap is generous and hostile bodies
			// are rejected by Kestrel before reaching handlers.
			options.Limits.MaxRequestBodySize = 1_048_576;
			options.ConfigureHttpsDefaults(https => https.ServerCertificate = plan.Certificate);
		});

		WebApplication apiApp = apiBuilder.Build();
		apiApp.Urls.Clear();
		apiApp.Urls.Add(BuildListenUrl(plan.ResolvedAddress, plan.Port));

		// Bridge: every REST request runs against a scope of the SERVICE container, so endpoint
		// handlers can resolve IpcDispatcher / IDbContextFactory with the same lifetimes as IPC.
		apiApp.Use(async (context, next) =>
		{
			IServiceScope scope = engineScopes.CreateScope();
			context.RequestServices = scope.ServiceProvider;
			try
			{
				await next(context).ConfigureAwait(false);
			}
			finally
			{
				scope.Dispose();
			}
		});

		RestApiProblem.MapStatusCodePages(apiApp);

		apiApp.UseMiddleware<RestApiSecurityHeadersMiddleware>();
		apiApp.UseMiddleware<RestApiRateLimitMiddleware>(plan.RateLimitPerMinute);
		apiApp.UseMiddleware<RestApiBearerAuthMiddleware>(new ApiTokenResolver(token));

		string displayBinding = BuildListenUrl(plan.ResolvedAddress, plan.Port);
		RestApiHealthService.MapHealth(apiApp, new RestApiHealthService([displayBinding]));
		RestApiEndpoints.Map(apiApp);
		return apiApp;
	}

	internal static string BuildListenUrl(string address, int port)
	{
		string host = address.Contains(':', StringComparison.Ordinal)
			? $"[{address}]"
			: address;
		return $"https://{host}:{port}";
	}
}
