/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiHealthService.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Serves the anonymous /healthz endpoint of the read-only REST API. Responds with a
//          JSON object carrying the human-readable bindings so operators can confirm the listener.
// Depends: Microsoft.AspNetCore.Builder/Routing/Http, System.Text.Json
// Extends: Add semantic depth ("degraded" state) when healthz grows DB probes.

using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace RdpAudit.Service.RestApi;

/// <summary>Anonymous health endpoint of the read-only REST API.</summary>
public sealed class RestApiHealthService
{
	private readonly IReadOnlyList<string> _bindings;

	/// <summary>Creates the health service for the supplied display bindings.</summary>
	/// <param name="bindings">Human-readable bindings (e.g. "https://127.0.0.1:8443").</param>
	public RestApiHealthService(IReadOnlyList<string> bindings)
	{
		ArgumentNullException.ThrowIfNull(bindings);
		_bindings = bindings
			.Where(static b => !string.IsNullOrWhiteSpace(b))
			.Select(static b => b!.Trim())
			.ToArray();
	}

	/// <summary>Responds 200 with <c>{"status":"ok","bindings":[...]}</c>.</summary>
	public Task ServeAsync(HttpContext context)
	{
		ArgumentNullException.ThrowIfNull(context);

		string json = JsonSerializer.Serialize(new
		{
			status = "ok",
			bindings = _bindings,
		});

		context.Response.StatusCode = StatusCodes.Status200OK;
		context.Response.ContentType = "application/json; charset=utf-8";
		return context.Response.WriteAsync(json, context.RequestAborted);
	}

	/// <summary>Maps GET /healthz (and HEAD /healthz) to the health endpoint.</summary>
	public static void MapHealth(IEndpointRouteBuilder endpoints, RestApiHealthService service)
	{
		ArgumentNullException.ThrowIfNull(endpoints);
		ArgumentNullException.ThrowIfNull(service);

		RequestDelegate handler = service.ServeAsync;
		endpoints.MapGet("/healthz", handler);
		endpoints.MapMethods("/healthz", ["HEAD"], handler);
	}
}
