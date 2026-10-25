// File:    src/RdpAudit.Web/Hosting/WebUiProxyApp.cs
// Module:  RdpAudit.Web
// Purpose: Hosting entry of the IIS web-UI proxy, factored so integration tests can boot the
//          exact production pipeline on a TestServer with an overridden token provider. The
//          production entry (Program.cs) uses <see cref="RunAsync"/>, which additionally FAILS
//          FAST when the shared bearer token cannot be read; tests use <see cref="Build"/>
//          directly and control that behavior themselves.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using RdpAudit.Core.Security;
using RdpAudit.Web.Config;
using RdpAudit.Web.Proxy;
using Yarp.ReverseProxy.Forwarder;

namespace RdpAudit.Web.Hosting;

/// <summary>Builds and runs the web-UI proxy application.</summary>
internal static class WebUiProxyApp
{
	/// <summary>Runs the production web-UI proxy: builds the app, fails fast on an unreadable
	/// token vault, then blocks serving requests (IIS in-process hosting keeps it alive).</summary>
	public static async Task RunAsync(string[] args)
	{
		WebApplication app = Build(args);
		WebUiProxyOptions resolved = app.Services.GetRequiredService<WebUiProxyOptions>();
		IWebUiTokenProvider tokenProvider = app.Services.GetRequiredService<IWebUiTokenProvider>();
		try
		{
			_ = await tokenProvider.GetTokenAsync(app.Lifetime.ApplicationStopping);
		}
		catch (SecretProtectionException ex)
		{
			app.Logger.LogCritical(ex,
				"RdpAudit.Web refuses to start: the shared bearer token could not be read from the vault. "
				+ "Configure web access (Configurator -> Web Access) before installing the IIS site.");
			throw;
		}

		app.Logger.LogInformation(
			"RdpAudit.Web proxy started for backend {BackendBaseUrl}; token vault readable.",
			resolved.ResolvedBackendBaseUrl);
		await app.RunAsync();
	}

	/// <summary>Builds the web-UI proxy application without starting it. When
	/// <paramref name="webApplicationOptions"/> is null, defaults preserve the production layout (args from
	/// the command line); tests pass a <see cref="WebApplicationOptions"/> to pin the web root
	/// BEFORE the builder is created (host settings cannot change afterwards).
	/// <paramref name="configureBuilder"/> runs before options binding;
	/// <paramref name="overrideServices"/> runs after the production registrations (last
	/// registration wins in the default container).</summary>
	internal static WebApplication Build(
		string[] args,
		WebApplicationOptions? webApplicationOptions = null,
		Action<WebApplicationBuilder>? configureBuilder = null,
		Action<IServiceCollection>? overrideServices = null)
	{
		WebApplicationOptions hostOptions = webApplicationOptions is null
			? new WebApplicationOptions { Args = args }
			: webApplicationOptions;
		WebApplicationBuilder builder = WebApplication.CreateBuilder(hostOptions);
		configureBuilder?.Invoke(builder);

		WebUiProxyOptions options = new();
		builder.Configuration.GetSection("WebUiProxy").Bind(options);
		options.Resolve();
		builder.Services.AddSingleton(options);
		builder.Services.AddHttpForwarder();
		builder.Services.AddSingleton<IWebUiTokenProvider, VaultTokenProvider>(
			_ => new VaultTokenProvider(options.ResolvedTokenVaultPath));
		overrideServices?.Invoke(builder.Services);

		WebApplication app = builder.Build();
		WebUiProxyOptions resolved = app.Services.GetRequiredService<WebUiProxyOptions>();

		HttpMessageInvoker backendClient = BackendHttpClientFactory.Create(resolved);
		IHttpForwarder forwarder = app.Services.GetRequiredService<IHttpForwarder>();
		WebUiProxyTransformer transformer = new();
		ForwarderRequestConfig requestConfig = new()
		{
			ActivityTimeout = TimeSpan.FromSeconds(60),
			AllowResponseBuffering = true,
		};

		// DNS-rebinding defense: a foreign Host must be rejected before ANY other middleware
		// (static files, health, or the token-injecting /api proxy) can answer it.
		app.UseLoopbackHostFilter();
		app.UseSecurityHeaders();

		// In production IIS serves the static wwwroot files directly (its static-file module is
		// authoritative). The same pipeline is enabled here so the TestServer integration path and
		// 'dotnet run' development expose identical behavior; IIS never forwards a static request
		// it can serve itself, so no double-serving occurs.
		app.UseDefaultFiles();
		app.UseStaticFiles();

		if (resolved.AllowInlineScripts)
		{
			app.Logger.LogWarning(
				"CSP relaxed: inline scripts and styles are allowed because WebUiProxy:AllowInlineScripts is true. "
				+ "Use this only for development of the dashboard, not for production installs.");
		}

		app.UseWhen(
			static context => context.Request.Path.StartsWithSegments("/api"),
			api =>
		{
			api.UseMiddleware<BearerHeaderSettingMiddleware>();
			api.Run(async context =>
			{
				ForwarderError error = await forwarder.SendAsync(
					context,
					resolved.ResolvedBackendBaseUrl,
					backendClient,
					requestConfig,
					transformer);
				if (error != ForwarderError.None)
				{
					IForwarderErrorFeature? feature = context.Features.Get<IForwarderErrorFeature>();
					app.Logger.LogWarning(feature?.Exception,
						"Proxying {Path} to {Backend} failed with {ForwarderError}.",
						context.Request.Path, resolved.ResolvedBackendBaseUrl, error);
					if (!context.Response.HasStarted)
					{
						context.Response.Clear();
						context.Response.StatusCode = StatusCodes.Status502BadGateway;
						context.Response.ContentType = "application/problem+json";
						// WriteAsJsonAsync would rewrite ContentType to application/json;
						// serialize manually so the RFC 7807 problem+json media type stays intact.
						await JsonSerializer.SerializeAsync(context.Response.Body, new
						{
							type = "about:blank",
							title = "Bad Gateway",
							status = 502,
							detail = "The RdpAudit service is unreachable; its REST endpoint may be stopped.",
							instance = context.Request.Path.Value,
						});
					}
				}
			});
		});

		app.MapGet("/proxy/health", () => Results.Ok(new
		{
			status = "ok",
			backend = resolved.ResolvedBackendBaseUrl,
		}));

		return app;
	}
}
