// File:    src/RdpAudit.Service/RestApi/RestApiProblem.cs
// Module:  RdpAudit.Service.RestApi
// Purpose: Central writer for RFC 9457 problem responses ("application/problem+json") and the
//          StatusCodePages hook that gives otherwise-empty framework errors (404, 405) the same
//          shape, so every REST error is machine-consumable and consistent.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace RdpAudit.Service.RestApi;

/// <summary>Produces RFC 9457 problem+json bodies for REST error responses.</summary>
public static class RestApiProblem
{
	/// <summary>Canonical media type for problem responses.</summary>
	public const string MediaType = "application/problem+json; charset=utf-8";

	private static readonly JsonSerializerOptions Json = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	};

	/// <summary>
	/// Writes the supplied problem as the complete response body (status code, content type and
	/// an RFC 9457 JSON object carrying type/title/status/detail/instance).
	/// </summary>
	public static Task WriteAsync(
		HttpContext context,
		int status,
		string title,
		string? detail,
		string type = "about:blank")
	{
		ArgumentNullException.ThrowIfNull(context);

		context.Response.StatusCode = status;
		context.Response.ContentType = MediaType;
		string json = JsonSerializer.Serialize(new
		{
			type,
			title,
			status,
			detail,
			instance = context.Request.Path.HasValue ? context.Request.Path.Value : null,
		}, Json);
		return context.Response.WriteAsync(json, context.RequestAborted);
	}

	/// <summary>
	/// Converts otherwise-empty framework error responses (404, 405, ...) into problem+json bodies.
	/// Pass-through middleware: responses that already carry a body or a 2xx/3xx status are
	/// untouched.
	/// </summary>
	public static void MapStatusCodePages(WebApplication app)
	{
		ArgumentNullException.ThrowIfNull(app);

		app.UseStatusCodePages(async statusContext =>
		{
			HttpContext http = statusContext.HttpContext;
			if (http.Response.HasStarted)
			{
				return;
			}

			string title = ReasonPhrases.GetReasonPhrase(http.Response.StatusCode);
			string instance = http.Request.Path.HasValue ? http.Request.Path.Value! : string.Empty;
			string detail = http.Response.StatusCode == StatusCodes.Status405MethodNotAllowed
				? $"HTTP method {http.Request.Method} is not allowed for {instance}."
				: title;

			http.Response.ContentType = MediaType;
			await http.Response.WriteAsync(
				JsonSerializer.Serialize(new
				{
					type = "about:blank",
					title,
					status = http.Response.StatusCode,
					detail,
					instance,
				}, Json),
				http.RequestAborted).ConfigureAwait(false);
		});
	}
}
