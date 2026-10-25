// File:    src/RdpAudit.Service/RestApi/RestApiEndpoints.cs
// Module:  RdpAudit.Service.RestApi
// Purpose: Maps the read-only REST API endpoints onto the existing IPC dispatcher surface and the
//          read-only event reader. GET/HEAD surfaced here are strictly read operations: every read
//          reuses the exact command implementations already audited for the IPC channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.RestApi;
using RdpAudit.Core.Util;
using CoreJsonOptions = RdpAudit.Core.Util.JsonOptions;
using RdpAudit.Service.Ipc;

namespace RdpAudit.Service.RestApi;

public static class RestApiEndpoints
{
	private static readonly JsonSerializerOptions Json = CoreJsonOptions.Default;

	/// <summary>Maps the read-only REST endpoints (GET and HEAD) onto the supplied application.</summary>
	public static void Map(WebApplication app)
	{
		ArgumentNullException.ThrowIfNull(app);

		app.MapMethods("/api/status", ["GET", "HEAD"], async ([FromServices] IpcDispatcher dispatcher, HttpContext http) =>
			await http.Response.WriteAsJsonAsync(
				await GetStatusPayloadAsync(dispatcher, http.RequestAborted).ConfigureAwait(false),
				Json,
				http.RequestAborted).ConfigureAwait(false));
		app.MapMethods("/api/alerts", ["GET", "HEAD"], async ([FromServices] IpcDispatcher dispatcher, HttpContext http) =>
			await http.Response.WriteAsJsonAsync(
				await GetAlertsPayloadAsync(dispatcher, http.RequestAborted).ConfigureAwait(false),
				Json,
				http.RequestAborted).ConfigureAwait(false));
	app.MapMethods("/api/sessions", ["GET", "HEAD"], async ([FromServices] IpcDispatcher dispatcher, HttpContext http) =>
		await http.Response.WriteAsJsonAsync(
			await GetSessionsPayloadAsync(dispatcher, http.RequestAborted).ConfigureAwait(false),
			Json,
			http.RequestAborted).ConfigureAwait(false));
	app.MapMethods("/api/addresses", ["GET", "HEAD"], async ([FromServices] IpcDispatcher dispatcher, HttpContext http) =>
		await http.Response.WriteAsJsonAsync(
			await GetAddressesPayloadAsync(dispatcher, http.RequestAborted).ConfigureAwait(false),
			Json,
			http.RequestAborted).ConfigureAwait(false));
	app.MapMethods("/api/attacks", ["GET", "HEAD"], GetAttacksAsync);
	app.MapMethods("/api/config", ["GET", "HEAD"], async ([FromServices] IpcDispatcher dispatcher, HttpContext http) =>
			await http.Response.WriteAsJsonAsync(
				await GetConfigPayloadAsync(dispatcher, http.RequestAborted).ConfigureAwait(false),
				Json,
				http.RequestAborted).ConfigureAwait(false));
		app.MapMethods("/api/events", ["GET", "HEAD"], GetEventsAsync);
		app.MapMethods("/openapi/v1.json", ["GET", "HEAD"], async (HttpContext http) =>
		{
			http.Response.ContentType = "application/json";
			await http.Response.WriteAsync(RestApiOpenApiDocument.Content, http.RequestAborted)
				.ConfigureAwait(false);
		});
	}

	internal static async Task<object?> GetStatusPayloadAsync(IpcDispatcher dispatcher, CancellationToken ct)
		=> ComplectPayload(await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetStatus }, ct).ConfigureAwait(false));

	internal static async Task<object?> GetAlertsPayloadAsync(IpcDispatcher dispatcher, CancellationToken ct)
		=> ComplectPayload(await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetRecentAlerts }, ct).ConfigureAwait(false));

	internal static async Task<object?> GetSessionsPayloadAsync(IpcDispatcher dispatcher, CancellationToken ct)
		=> ComplectPayload(await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetSessions }, ct).ConfigureAwait(false));

	internal static async Task<object?> GetConfigPayloadAsync(IpcDispatcher dispatcher, CancellationToken ct)
		=> ComplectPayload(await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetSettings }, ct).ConfigureAwait(false));

	internal static async Task<object?> GetAddressesPayloadAsync(IpcDispatcher dispatcher, CancellationToken ct)
		=> ComplectPayload(await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetAddresses }, ct).ConfigureAwait(false));

	internal static async Task GetEventsAsync(HttpContext http)
	{
		IPagedEventReader? reader = http.RequestServices.GetService(typeof(IPagedEventReader)) as IPagedEventReader;
		if (reader is null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status500InternalServerError,
				"The event reader is unavailable.",
				"The read-only event store could not be reached.").ConfigureAwait(false);
			return;
		}

		IQueryCollection query = http.Request.Query;
		string? bindError = ValidateEventsQuery(
			query["channel"].ToString(),
			query["sourceIp"].ToString(),
			query["userName"].ToString());
		if (bindError is not null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status400BadRequest,
				"Invalid /api/events query parameters.",
				bindError).ConfigureAwait(false);
			return;
		}

		DateTime? since = ParseInstant(query["sinceUtc"].ToString());
		if (query.ContainsKey("sinceUtc") && query["sinceUtc"].ToString().Length > 0 && since is null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status400BadRequest,
				"Invalid /api/events query parameters.",
				"Parameter 'sinceUtc' must be a UTC instant.").ConfigureAwait(false);
			return;
		}

		DateTime? to = ParseInstant(query["toUtc"].ToString());
		if (query.ContainsKey("toUtc") && query["toUtc"].ToString().Length > 0 && to is null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status400BadRequest,
				"Invalid /api/events query parameters.",
				"Parameter 'toUtc' must be a UTC instant.").ConfigureAwait(false);
			return;
		}

		PagedEventsQuery request = new()
		{
			Limit = ParseInt(query["limit"].ToString()) ?? PagedEventsQuery.DefaultPageSize,
			Offset = ParseInt(query["offset"].ToString()) ?? 0,
			Channel = NormalizeText(query["channel"].ToString(), PagedEventsQuery.MaxChannelLength),
			EventId = ParseInt(query["eventId"].ToString()),
			SourceIp = query["sourceIp"].ToString(),
			UserNameContains = NormalizeText(query["userName"].ToString(), PagedEventsQuery.MaxUserNameLength),
			SinceUtc = since,
			ToUtc = to,
			IncludeExplain = ParseBool(query["includeExplain"].ToString()),
			IncludeDetails = ParseBool(query["includeDetails"].ToString()),
		};

		PagedEventPage page = await reader.ReadPageAsync(request, http.RequestAborted).ConfigureAwait(false);
		http.Response.StatusCode = StatusCodes.Status200OK;
		await http.Response.WriteAsJsonAsync(page, Json, http.RequestAborted).ConfigureAwait(false);
	}

	internal static async Task GetAttacksAsync(HttpContext http)
	{
		IpcDispatcher? dispatcher = http.RequestServices.GetService(typeof(IpcDispatcher)) as IpcDispatcher;
		if (dispatcher is null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status500InternalServerError,
				"The attack statistics provider is unavailable.",
				"The read-only attack statistics store could not be reached.").ConfigureAwait(false);
			return;
		}

		IQueryCollection query = http.Request.Query;
		string? bindError = ValidateAttacksQuery(
			query["minThreatScore"].ToString(),
			query["sinceUtc"].ToString(),
			query["untilUtc"].ToString(),
			query["limit"].ToString());
		if (bindError is not null)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status400BadRequest,
				"Invalid /api/attacks query parameters.",
				bindError).ConfigureAwait(false);
			return;
		}

		AttackStatsRequest request = new()
		{
			IpQuery = NormalizeText(query["ipQuery"].ToString(), AttackStatsMaxIpQueryLength),
			MinThreatScore = ParseDouble(query["minThreatScore"].ToString()),
			OnlyBlocked = ParseBool(query["onlyBlocked"].ToString()),
			SinceUtc = ParseInstant(query["sinceUtc"].ToString()),
			UntilUtc = ParseInstant(query["untilUtc"].ToString()),
			Limit = ParseInt(query["limit"].ToString()) ?? 0,
		};

		string payload = JsonSerializer.Serialize(request, Json);
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetAttackStats, Payload = payload },
			http.RequestAborted).ConfigureAwait(false);
		if (!response.Success)
		{
			await RestApiProblem.WriteAsync(
				http,
				StatusCodes.Status500InternalServerError,
				"Attack statistics could not be read.",
				response.Error ?? "IPC read failed.").ConfigureAwait(false);
			return;
		}

		http.Response.StatusCode = StatusCodes.Status200OK;
		await http.Response.WriteAsJsonAsync(
			ComplectPayload(response),
			Json,
			http.RequestAborted).ConfigureAwait(false);
	}

	/// <summary>Maximum accepted length for the /api/attacks ipQuery filter. Longer values keep the
	/// LIKE query bounded and prevent accidental full-table scans.</summary>
	private const int AttackStatsMaxIpQueryLength = 256;

	/// <summary>Highest accepted threat-score threshold: the score is a 0..100 scale.</summary>
	private const int MaxThreatScore = 100;

	/// <summary>Longest window the attack-statistics summary will aggregate in one request.</summary>
	/// <remarks>
	/// The window selects the fact rows the summary is computed over, so an unbounded window turns one
	/// request into a full-table aggregation. It is refused rather than clamped: answering a narrower
	/// window than the caller asked for would be a wrong answer presented as a right one.
	/// </remarks>
	private const int MaxAttacksWindowDays = 366;

	/// <summary>Earliest instant accepted as a window bound.</summary>
	private static readonly DateTime MinWindowInstantUtc = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	/// <summary>Latest instant accepted as a window bound.</summary>
	private static readonly DateTime MaxWindowInstantUtc = new(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	internal static string? ValidateAttacksQuery(string? minThreatScore, string? sinceUtc, string? untilUtc, string? limit)
	{
		if (!string.IsNullOrWhiteSpace(minThreatScore))
		{
			// NaN and the infinities parse successfully and then compare false against every bound, so
			// a "< 0" test alone lets them through and the request fails later, while being
			// serialised for IPC, as an unhandled exception instead of a 400.
			if (!double.TryParse(minThreatScore, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsedScore)
				|| !double.IsFinite(parsedScore)
				|| parsedScore < 0
				|| parsedScore > MaxThreatScore)
			{
				return "Parameter 'minThreatScore' must be a finite number between 0 and "
					+ MaxThreatScore.ToString(CultureInfo.InvariantCulture) + ".";
			}
		}

		DateTime? since = ParseWindowInstant("sinceUtc", sinceUtc, out string? sinceError);
		if (sinceError is not null)
		{
			return sinceError;
		}

		DateTime? until = ParseWindowInstant("untilUtc", untilUtc, out string? untilError);
		if (untilError is not null)
		{
			return untilError;
		}

		if (since.HasValue && until.HasValue)
		{
			if (until.Value < since.Value)
			{
				return "Parameter 'untilUtc' must not be earlier than 'sinceUtc'.";
			}

			if (until.Value - since.Value > TimeSpan.FromDays(MaxAttacksWindowDays))
			{
				return "The window between 'sinceUtc' and 'untilUtc' must not exceed "
					+ MaxAttacksWindowDays.ToString(CultureInfo.InvariantCulture) + " days.";
			}
		}

		if (!string.IsNullOrWhiteSpace(limit)
			&& (!int.TryParse(limit, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedLimit)
				|| parsedLimit < 0))
		{
			return "Parameter 'limit' must be a non-negative integer.";
		}

		return null;
	}

	/// <summary>Parses one window bound and rejects instants outside the auditable range.</summary>
	/// <remarks>
	/// The bounds come straight from the query string. Anything before
	/// <see cref="MinWindowInstantUtc"/> or after <see cref="MaxWindowInstantUtc"/> is treated as
	/// malformed: those values are outside any store this product can hold, and 0001-01-01 in
	/// particular makes the dispatcher's default-window arithmetic underflow.
	/// </remarks>
	private static DateTime? ParseWindowInstant(string name, string? value, out string? error)
	{
		error = null;
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		DateTime? parsed = ParseInstant(value);
		if (parsed is null)
		{
			error = "Parameter '" + name + "' must be a UTC instant.";
			return null;
		}

		if (parsed.Value < MinWindowInstantUtc || parsed.Value > MaxWindowInstantUtc)
		{
			error = "Parameter '" + name + "' must be between 2000-01-01 and 2100-01-01.";
			return null;
		}

		return parsed;
	}

	private static double? ParseDouble(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed)
			? parsed
			: null;
	}

	private static object? ComplectPayload(IpcResponse response)
	{
		if (!response.Success)
		{
			return new { error = response.Error ?? "IPC read failed." };
		}

		if (response.Payload is null)
		{
			return new { error = "IPC returned an empty payload." };
		}

		using JsonDocument document = JsonDocument.Parse(response.Payload, new JsonDocumentOptions
		{
			MaxDepth = 230,
		});
		return document.RootElement.Clone();
	}

	internal static string? ValidateEventsQuery(string? channel, string? sourceIp, string? userName)
	{
		if (channel is not null && channel.Length > PagedEventsQuery.MaxChannelLength)
		{
			return "Parameter 'channel' exceeds " + PagedEventsQuery.MaxChannelLength.ToString(CultureInfo.InvariantCulture) + " characters.";
		}

		if (userName is not null && userName.Length > PagedEventsQuery.MaxUserNameLength)
		{
			return "Parameter 'userName' exceeds " + PagedEventsQuery.MaxUserNameLength.ToString(CultureInfo.InvariantCulture) + " characters.";
		}

		if (!string.IsNullOrWhiteSpace(sourceIp))
		{
			string? normalized = IpNormalizer.Normalize(sourceIp);
			if (normalized is null || normalized.Length > PagedEventsQuery.MaxSourceIpLength)
			{
				return "Parameter 'sourceIp' must be a valid IP address literal.";
			}
		}

		return null;
	}

	private static string? NormalizeText(string? value, int maxLength)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		// Control characters are stripped before the length test: a line break inside a filter value
		// would otherwise reach the SQL text generator, where parameter directives are handled line by
		// line (see PagedEventReader.StripParamDirectives).
		string trimmed = PagedEventsQuery.StripControlCharacters(value.Trim());
		return trimmed.Length == 0 || trimmed.Length > maxLength ? null : trimmed;
	}

	private static int? ParseInt(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
			? parsed
			: null;
	}

	private static bool ParseBool(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		if (bool.TryParse(value, out bool parsed))
		{
			return parsed;
		}

		if (value.Trim() == "1")
		{
			return true;
		}

		return false;
	}

	private static DateTime? ParseInstant(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string trimmed = value.Trim();
		if (!DateTime.TryParse(
			trimmed,
			CultureInfo.InvariantCulture,
			DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
			out DateTime parsed))
		{
			return null;
		}

		return parsed;
	}
}
