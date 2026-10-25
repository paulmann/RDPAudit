/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : InertWebServer.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: IServer implementation that binds NO sockets. The worker host runs over it so the
//          WebApplication host exposes zero TCP surface; the read-only REST API owns its own
//          Kestrel listener inside RestApiHostedService. Verified experimentally: with this server
//          registered there is no fallback bind to http://localhost:5000 (unlike an empty URL
//          collection, which Kestrel silently re-defaults).
// Depends: Microsoft.AspNetCore.Hosting.Server, Microsoft.AspNetCore.Http.Features
// Extends: none.

using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;

namespace RdpAudit.Service.Infrastructure;

/// <summary>Host server that never listens. Used by the worker host so it starts and stops as
/// a WebApplication without exposing any network endpoint.</summary>
public sealed class InertWebServer : IServer
{
	public InertWebServer()
	{
		Features.Set<IServerAddressesFeature>(new ServerAddressesFeature());
	}

	public IFeatureCollection Features { get; } = new FeatureCollection();

	public void Dispose()
	{
		// No resources.
	}

	public Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken)
		where TContext : notnull
		=> Task.CompletedTask;

	public Task StopAsync(CancellationToken cancellationToken)
		=> Task.CompletedTask;
}
