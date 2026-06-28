// File:    src/RdpAudit.Service/Firewall/MikroTikClient.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: HttpClient-backed implementation of IMikroTikClient targeting the MikroTik RouterOS v7
//          REST API. Uses HTTP Basic Auth with the configured user / DPAPI-protected password,
//          honours the ValidateServerCertificate option, sanitises credentials out of logs, and
//          surfaces structured MikroTikOperationResult values for every code path.
//
//          Safety contract:
//          • Never logs the API password (only the user name and endpoint).
//          • Only deletes rules whose comment starts with the configured CommentPrefix.
//          • Idempotent: when an RdpAudit rule already exists for the source IP it is reused.
//          • Bounded body reads — never copies large response bodies into log lines.
// Extends: RdpAudit.Core.MikroTik.IMikroTikClient
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Security;

namespace RdpAudit.Service.Firewall;

/// <summary>HttpClient-backed implementation of <see cref="IMikroTikClient"/>.</summary>
public sealed class MikroTikClient : IMikroTikClient, IDisposable
{
	internal const string HttpClientName = "MikroTik";
	internal const string HttpClientNameInsecure = "MikroTik.Insecure";
	private const string UserAgent = "RdpAudit/1.0 (+https://github.com/paulmann/RDPAudit)";
	private const int MaxResponseSnippetChars = 256;

	private static readonly JsonSerializerOptions s_jsonOptions = new()
	{
		PropertyNameCaseInsensitive = true,
	};

	private readonly IHttpClientFactory _httpFactory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ISecretProtector _protector;
	private readonly ILogger<MikroTikClient> _logger;

	public MikroTikClient(
		IHttpClientFactory httpFactory,
		IOptionsMonitor<RdpAuditOptions> options,
		ISecretProtector protector,
		ILogger<MikroTikClient> logger)
	{
		ArgumentNullException.ThrowIfNull(httpFactory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(protector);
		ArgumentNullException.ThrowIfNull(logger);
		_httpFactory = httpFactory;
		_options = options;
		_protector = protector;
		_logger = logger;
	}

	/// <inheritdoc />
	public async Task<MikroTikOperationResult> PingAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		PreparedRequest? prep = Prepare(opts);
		if (prep is null)
		{
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.NotConfigured,
				Message = "MikroTik provider is not fully configured.",
			};
		}

		string url = MikroTikUrlBuilder.CombineRestPath(prep.BaseUrl, "system/resource");
		using HttpClient http = CreateHttpClient(opts);
		using HttpRequestMessage message = BuildRequest(HttpMethod.Get, url, prep.AuthHeader);

		return await SendAndClassifyAsync(http, message, "Ping", ct).ConfigureAwait(false);
	}

	/// <inheritdoc />
	public async Task<(MikroTikOperationResult Result, IReadOnlyList<MikroTikRule> Rules)> ListOwnedRulesAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		PreparedRequest? prep = Prepare(opts);
		if (prep is null)
		{
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.NotConfigured,
				Message = "MikroTik provider is not fully configured.",
			}, Array.Empty<MikroTikRule>());
		}

		string url = MikroTikUrlBuilder.CombineRestPath(prep.BaseUrl, "ip/firewall/filter");
		using HttpClient http = CreateHttpClient(opts);
		using HttpRequestMessage message = BuildRequest(HttpMethod.Get, url, prep.AuthHeader);

		(MikroTikOperationResult result, string? body) = await SendAndClassifyWithBodyAsync(http, message, "ListOwned", ct).ConfigureAwait(false);
		if (result.Outcome != MikroTikOutcome.Accepted || string.IsNullOrEmpty(body))
		{
			return (result, Array.Empty<MikroTikRule>());
		}

		List<MikroTikRule> owned = new();
		string prefix = string.IsNullOrWhiteSpace(opts.CommentPrefix) ? "RdpAudit" : opts.CommentPrefix.Trim();

		try
		{
			List<MikroTikFilterRow>? rows = JsonSerializer.Deserialize<List<MikroTikFilterRow>>(body!, s_jsonOptions);
			if (rows is not null)
			{
				foreach (MikroTikFilterRow row in rows)
				{
					if (row.Comment is null || !row.Comment.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}

					owned.Add(new MikroTikRule
					{
						Id = row.Id ?? string.Empty,
						Ip = row.SrcAddress ?? string.Empty,
						Chain = row.Chain ?? string.Empty,
						Action = row.Action ?? string.Empty,
						Comment = row.Comment ?? string.Empty,
					});
				}
			}
		}
		catch (JsonException ex)
		{
			_logger.LogWarning(ex, "MikroTik filter list response is not parseable JSON");
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.ServerError,
				ResponseCode = result.ResponseCode,
				Message = "MikroTik filter list response was not valid JSON.",
			}, Array.Empty<MikroTikRule>());
		}

		return (result, owned);
	}

	/// <inheritdoc />
	public async Task<MikroTikOperationResult> AddBlockAsync(MikroTikBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		PreparedRequest? prep = Prepare(opts);
		if (prep is null)
		{
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.NotConfigured,
				Message = "MikroTik provider is not fully configured.",
			};
		}

		if (!IsValidIpLiteral(request.Ip))
		{
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.Rejected,
				Message = "Source IP is not a valid literal.",
			};
		}

		// Idempotency: query existing owned rules first and reuse the row when present.
		(MikroTikOperationResult listResult, IReadOnlyList<MikroTikRule> existing) =
			await ListOwnedRulesAsync(ct).ConfigureAwait(false);

		if (listResult.Outcome == MikroTikOutcome.Accepted)
		{
			MikroTikRule? match = null;
			foreach (MikroTikRule rule in existing)
			{
				if (string.Equals(rule.Ip, request.Ip, StringComparison.OrdinalIgnoreCase)
					&& string.Equals(rule.Chain, request.Chain, StringComparison.OrdinalIgnoreCase))
				{
					match = rule;
					break;
				}
			}

			if (match is not null && !string.IsNullOrEmpty(match.Id))
			{
				_logger.LogInformation(
					"MikroTik existing block rule reused for {Ip} id={Id}",
					request.Ip,
					match.Id);
				return new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.AlreadyExists,
					ResponseCode = listResult.ResponseCode,
					Message = "An RdpAudit-owned block rule already existed and was reused.",
					RuleId = match.Id,
				};
			}
		}

		string url = MikroTikUrlBuilder.CombineRestPath(prep.BaseUrl, "ip/firewall/filter");
		using HttpClient http = CreateHttpClient(opts);
		MikroTikAddFilterRequest body = new()
		{
			Chain = string.IsNullOrWhiteSpace(request.Chain) ? "input" : request.Chain,
			Action = string.IsNullOrWhiteSpace(request.Action) ? "drop" : request.Action,
			SrcAddress = request.Ip,
			Comment = SanitizeComment(request.Comment),
		};

		using HttpRequestMessage message = BuildRequest(HttpMethod.Put, url, prep.AuthHeader);
		message.Content = new StringContent(
			JsonSerializer.Serialize(body, s_jsonOptions),
			Encoding.UTF8,
			"application/json");

		(MikroTikOperationResult result, string? responseBody) = await SendAndClassifyWithBodyAsync(http, message, "AddBlock", ct).ConfigureAwait(false);

		if (result.Outcome == MikroTikOutcome.Accepted)
		{
			string? id = TryExtractRuleId(responseBody);
			result.RuleId = id;
			result.Message = id is null
				? "MikroTik accepted the rule (no id surfaced)."
				: "MikroTik accepted the rule.";
		}
		return result;
	}

	/// <inheritdoc />
	public async Task<MikroTikOperationResult> RemoveBlockAsync(string? ruleId, string ip, CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		PreparedRequest? prep = Prepare(opts);
		if (prep is null)
		{
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.NotConfigured,
				Message = "MikroTik provider is not fully configured.",
			};
		}

		string? resolvedId = ruleId;
		if (string.IsNullOrWhiteSpace(resolvedId))
		{
			if (string.IsNullOrWhiteSpace(ip) || !IsValidIpLiteral(ip))
			{
				return new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.Rejected,
					Message = "Cannot remove rule without ruleId or valid source IP.",
				};
			}

			(MikroTikOperationResult listResult, IReadOnlyList<MikroTikRule> owned) =
				await ListOwnedRulesAsync(ct).ConfigureAwait(false);
			if (listResult.Outcome != MikroTikOutcome.Accepted)
			{
				return listResult;
			}

			foreach (MikroTikRule rule in owned)
			{
				if (string.Equals(rule.Ip, ip, StringComparison.OrdinalIgnoreCase))
				{
					resolvedId = rule.Id;
					break;
				}
			}

			if (string.IsNullOrWhiteSpace(resolvedId))
			{
				return new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.NotFound,
					Message = "No RdpAudit-owned rule matched the requested IP.",
				};
			}
		}

		// Verify the candidate row really is RdpAudit-owned before deleting.
		string verifyUrl = MikroTikUrlBuilder.CombineRestPath(prep.BaseUrl, "ip/firewall/filter/" + Uri.EscapeDataString(resolvedId!));
		using HttpClient http = CreateHttpClient(opts);
		using HttpRequestMessage verifyMsg = BuildRequest(HttpMethod.Get, verifyUrl, prep.AuthHeader);
		(MikroTikOperationResult verifyResult, string? verifyBody) =
			await SendAndClassifyWithBodyAsync(http, verifyMsg, "RemoveBlock.Verify", ct).ConfigureAwait(false);

		if (verifyResult.Outcome == MikroTikOutcome.Rejected && verifyResult.ResponseCode == 404)
		{
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.NotFound,
				ResponseCode = 404,
				Message = "MikroTik rule does not exist.",
			};
		}
		if (verifyResult.Outcome != MikroTikOutcome.Accepted)
		{
			return verifyResult;
		}

		string prefix = string.IsNullOrWhiteSpace(opts.CommentPrefix) ? "RdpAudit" : opts.CommentPrefix.Trim();
		if (!IsOwnedRule(verifyBody, prefix))
		{
			_logger.LogWarning(
				"MikroTik delete refused for id={Id} — comment does not start with prefix '{Prefix}'",
				resolvedId,
				prefix);
			return new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.Rejected,
				Message = "Refusing to delete a rule that is not owned by RdpAudit.",
			};
		}

		string deleteUrl = verifyUrl;
		using HttpRequestMessage deleteMsg = BuildRequest(HttpMethod.Delete, deleteUrl, prep.AuthHeader);
		MikroTikOperationResult result = await SendAndClassifyAsync(http, deleteMsg, "RemoveBlock", ct).ConfigureAwait(false);
		if (result.Outcome == MikroTikOutcome.Accepted)
		{
			result.RuleId = resolvedId;
			result.Message = "MikroTik rule deleted.";
		}
		return result;
	}

	private PreparedRequest? Prepare(MikroTikOptions opts)
	{
		if (string.IsNullOrWhiteSpace(opts.UserName))
		{
			return null;
		}

		if (string.IsNullOrWhiteSpace(opts.Password))
		{
			return null;
		}

		MikroTikUrlBuilder.Result built = MikroTikUrlBuilder.Build(opts);
		if (!built.Ok)
		{
			return null;
		}

		string? plaintextPassword = TryUnprotect(opts.Password);
		if (string.IsNullOrEmpty(plaintextPassword))
		{
			return null;
		}

		string raw = string.Concat(opts.UserName, ":", plaintextPassword);
		string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
		return new PreparedRequest(built.Url, new AuthenticationHeaderValue("Basic", b64));
	}

	private string? TryUnprotect(string passwordField)
	{
		try
		{
			string raw = _protector.Unprotect(passwordField);
			return string.IsNullOrEmpty(raw) ? null : raw;
		}
		catch (SecretProtectionException ex)
		{
			_logger.LogWarning("Failed to unprotect MikroTik password envelope: {Type}", ex.GetType().Name);
			return null;
		}
	}

	private HttpClient CreateHttpClient(MikroTikOptions opts)
	{
		string name = opts.ValidateServerCertificate ? HttpClientName : HttpClientNameInsecure;
		HttpClient http = _httpFactory.CreateClient(name);
		int timeoutSeconds = opts.TimeoutSeconds <= 0 ? 15 : Math.Min(opts.TimeoutSeconds, 60);
		http.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
		return http;
	}

	private static HttpRequestMessage BuildRequest(HttpMethod method, string url, AuthenticationHeaderValue auth)
	{
		HttpRequestMessage message = new(method, url);
		message.Headers.Authorization = auth;
		message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
		message.Headers.UserAgent.ParseAdd(UserAgent);
		return message;
	}

	private async Task<MikroTikOperationResult> SendAndClassifyAsync(
		HttpClient http,
		HttpRequestMessage message,
		string operationTag,
		CancellationToken ct)
	{
		(MikroTikOperationResult result, _) = await SendAndClassifyWithBodyAsync(http, message, operationTag, ct).ConfigureAwait(false);
		return result;
	}

	private async Task<(MikroTikOperationResult Result, string? Body)> SendAndClassifyWithBodyAsync(
		HttpClient http,
		HttpRequestMessage message,
		string operationTag,
		CancellationToken ct)
	{
		try
		{
			using HttpResponseMessage response = await http.SendAsync(message, ct).ConfigureAwait(false);
			int code = (int)response.StatusCode;
			TimeSpan? retryAfter = ExtractRetryAfter(response);
			string? body = await ReadLimitedAsync(response, ct).ConfigureAwait(false);

			if (response.IsSuccessStatusCode)
			{
				return (new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.Accepted,
					ResponseCode = code,
					Message = "MikroTik accepted the request.",
				}, body);
			}

			if (code == (int)HttpStatusCode.TooManyRequests)
			{
				_logger.LogWarning("MikroTik op {Op} returned 429", operationTag);
				return (new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.RateLimited,
					ResponseCode = code,
					Message = "MikroTik returned 429 Too Many Requests.",
					RetryAfter = retryAfter,
				}, body);
			}

			if (code >= 500)
			{
				_logger.LogWarning("MikroTik op {Op} returned server error {Code}", operationTag, code);
				return (new MikroTikOperationResult
				{
					Outcome = MikroTikOutcome.ServerError,
					ResponseCode = code,
					Message = string.Format(CultureInfo.InvariantCulture, "MikroTik server error {0}.", code),
					RetryAfter = retryAfter,
				}, body);
			}

			_logger.LogWarning("MikroTik op {Op} rejected with HTTP {Code}", operationTag, code);
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.Rejected,
				ResponseCode = code,
				Message = string.Format(CultureInfo.InvariantCulture,
					"MikroTik rejected the request with HTTP {0}.{1}",
					code,
					string.IsNullOrEmpty(body) ? string.Empty : " " + Snippet(body!)),
			}, body);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (HttpRequestException ex)
		{
			_logger.LogWarning("MikroTik op {Op} transport failure: {Type}", operationTag, ex.GetType().Name);
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.TransportError,
				ResponseCode = 0,
				Message = "MikroTik transport error: " + ex.GetType().Name,
			}, null);
		}
		catch (TaskCanceledException)
		{
			_logger.LogWarning("MikroTik op {Op} timed out", operationTag);
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.TransportError,
				ResponseCode = 0,
				Message = "MikroTik request timed out.",
			}, null);
		}
		catch (AuthenticationException ex)
		{
			_logger.LogWarning("MikroTik op {Op} TLS auth failure: {Type}", operationTag, ex.GetType().Name);
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.TransportError,
				ResponseCode = 0,
				Message = "MikroTik TLS authentication failed.",
			}, null);
		}
		catch (SocketException ex)
		{
			_logger.LogWarning("MikroTik op {Op} socket failure: {Code}", operationTag, ex.SocketErrorCode);
			return (new MikroTikOperationResult
			{
				Outcome = MikroTikOutcome.TransportError,
				ResponseCode = 0,
				Message = "MikroTik socket error: " + ex.SocketErrorCode,
			}, null);
		}
	}

	private static async Task<string?> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
	{
		if (response.Content is null)
		{
			return null;
		}

		try
		{
			string text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
			return text;
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static TimeSpan? ExtractRetryAfter(HttpResponseMessage response)
	{
		if (response.Headers.RetryAfter is null)
		{
			return null;
		}

		if (response.Headers.RetryAfter.Delta is TimeSpan delta && delta > TimeSpan.Zero)
		{
			return delta;
		}

		if (response.Headers.RetryAfter.Date is DateTimeOffset when)
		{
			TimeSpan diff = when - DateTimeOffset.UtcNow;
			if (diff > TimeSpan.Zero)
			{
				return diff;
			}
		}
		return null;
	}

	private static bool IsValidIpLiteral(string ip)
	{
		return !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip.Trim(), out _);
	}

	private static string Snippet(string body)
	{
		string trimmed = body.Trim();
		if (trimmed.Length <= MaxResponseSnippetChars)
		{
			return trimmed;
		}
		return trimmed[..MaxResponseSnippetChars] + "…";
	}

	private static string SanitizeComment(string comment)
	{
		if (string.IsNullOrWhiteSpace(comment))
		{
			return "RdpAudit";
		}

		// Drop control characters and limit length so a malformed comment can't break RouterOS.
		StringBuilder sb = new(comment.Length);
		foreach (char c in comment)
		{
			if (char.IsControl(c))
			{
				continue;
			}
			sb.Append(c);
			if (sb.Length >= 200)
			{
				break;
			}
		}
		return sb.Length == 0 ? "RdpAudit" : sb.ToString();
	}

	internal static string? TryExtractRuleId(string? body)
	{
		if (string.IsNullOrWhiteSpace(body))
		{
			return null;
		}

		try
		{
			MikroTikFilterRow? row = JsonSerializer.Deserialize<MikroTikFilterRow>(body!, s_jsonOptions);
			if (row?.Id is null || row.Id.Length == 0)
			{
				return null;
			}
			return row.Id;
		}
		catch (JsonException)
		{
			return null;
		}
	}

	internal static bool IsOwnedRule(string? body, string prefix)
	{
		if (string.IsNullOrWhiteSpace(body) || string.IsNullOrWhiteSpace(prefix))
		{
			return false;
		}

		try
		{
			MikroTikFilterRow? row = JsonSerializer.Deserialize<MikroTikFilterRow>(body!, s_jsonOptions);
			return row?.Comment is not null
				&& row.Comment.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
		}
		catch (JsonException)
		{
			return false;
		}
	}

	public void Dispose()
	{
	}

	private sealed record PreparedRequest(string BaseUrl, AuthenticationHeaderValue AuthHeader);
}
