// File:    src/RdpAudit.Service/ThreatIntel/AbuseIpDbThreatIntelClient.cs
// Module:  RdpAudit.Service.ThreatIntel
// Purpose: HttpClient-backed implementation of IThreatIntelligenceClient for the Backlog #5
//          reputation lookup. Issues GET /api/v2/check?ipAddress=...&maxAgeInDays=...&verbose
//          against the configured AbuseIPDB BaseUrl, sends the unprotected API key ONLY in the
//          Key header (never logged), and maps the provider response into a fail-closed
//          ThreatIntelLookupResult. All parse failures fold into MalformedResponse; transport
//          failures fold into TransportError. Never throws for HTTP / transport / parse problems.
// Extends: RdpAudit.Core.ThreatIntel.IThreatIntelligenceClient
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.ThreatIntel;

/// <summary>HttpClient-backed <see cref="IThreatIntelligenceClient"/> for AbuseIPDB /api/v2/check.</summary>
public sealed class AbuseIpDbThreatIntelClient : IThreatIntelligenceClient
{
	private const string UserAgent = "RdpAudit/1.0 (+https://github.com/paulmann/RDPAudit)";
	private const int UsageTypeMaxLength = 128;
	private const int CountryCodeMaxLength = 8;

	private readonly IHttpClientFactory _httpFactory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ISecretProtector _protector;
	private readonly ILogger<AbuseIpDbThreatIntelClient> _logger;

	public AbuseIpDbThreatIntelClient(
		IHttpClientFactory httpFactory,
		IOptionsMonitor<RdpAuditOptions> options,
		ISecretProtector protector,
		ILogger<AbuseIpDbThreatIntelClient> logger)
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
	public async Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct)
	{
		if (string.IsNullOrWhiteSpace(ip) || !IpClassifier.IsPublicIp(ip))
		{
			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.Rejected,
				Ip = ip ?? string.Empty,
				Message = "Refusing reputation lookup for a non-public IP.",
			};
		}

		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		if (!opts.Enabled || !opts.CheckEnabled || !opts.CacheLookups)
		{
			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.NotConfigured,
				Ip = ip,
				Message = "Threat-intelligence lookup is not enabled.",
			};
		}

		string? plaintextKey = TryUnprotectKey(opts);
		if (string.IsNullOrEmpty(plaintextKey))
		{
			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.NotConfigured,
				Ip = ip,
				Message = "AbuseIPDB API key is not configured.",
			};
		}

		string baseUrl = string.IsNullOrWhiteSpace(opts.BaseUrl)
			? "https://api.abuseipdb.com"
			: opts.BaseUrl.TrimEnd('/');
		int maxAge = ThreatIntelLimits.ClampMaxAgeInDays(opts.CheckMaxAgeInDays);
		string requestUri = string.Format(
			CultureInfo.InvariantCulture,
			"{0}/api/v2/check?ipAddress={1}&maxAgeInDays={2}&verbose", baseUrl, Uri.EscapeDataString(ip), maxAge);

		try
		{
			using HttpClient http = CreateHttpClient(opts);
			using HttpRequestMessage message = new(HttpMethod.Get, requestUri);
			message.Headers.TryAddWithoutValidation("Key", plaintextKey);
			message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			message.Headers.UserAgent.ParseAdd(UserAgent);

			using HttpResponseMessage response = await http.SendAsync(message, ct).ConfigureAwait(false);
			int code = (int)response.StatusCode;

			if (response.IsSuccessStatusCode)
			{
				string content = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
				return MapSuccessPayload(ip, content);
			}

			if (code == (int)HttpStatusCode.TooManyRequests)
			{
				return new ThreatIntelLookupResult
				{
					Outcome = ThreatIntelLookupOutcome.RateLimited,
					Ip = ip,
					ResponseCode = code,
					RetryAfter = ExtractRetryAfter(response),
					Message = "AbuseIPDB returned 429 Too Many Requests.",
				};
			}

			if (code >= 500)
			{
				return new ThreatIntelLookupResult
				{
					Outcome = ThreatIntelLookupOutcome.ServerError,
					Ip = ip,
					ResponseCode = code,
					RetryAfter = ExtractRetryAfter(response),
					Message = string.Format(CultureInfo.InvariantCulture,
						"AbuseIPDB returned server error {0}.", code),
				};
			}

			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.Rejected,
				Ip = ip,
				ResponseCode = code,
				Message = string.Format(CultureInfo.InvariantCulture,
					"AbuseIPDB rejected the lookup with HTTP {0}.", code),
			};
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (HttpRequestException ex)
		{
			_logger.LogWarning("Threat-intel lookup transport failure: {Type}", ex.GetType().Name);
			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.TransportError,
				Ip = ip,
				Message = "AbuseIPDB transport error: " + ex.GetType().Name,
			};
		}
		catch (TaskCanceledException ex)
		{
			_logger.LogWarning("Threat-intel lookup timed out: {Type}", ex.GetType().Name);
			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.TransportError,
				Ip = ip,
				Message = "AbuseIPDB request timed out.",
			};
		}
	}

	private HttpClient CreateHttpClient(AbuseIpDbOptions opts)
	{
		HttpClient http = _httpFactory.CreateClient("AbuseIpDb");
		int timeoutSeconds = opts.TimeoutSeconds <= 0 ? 15 : Math.Min(opts.TimeoutSeconds, 60);
		http.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
		return http;
	}

	private string? TryUnprotectKey(AbuseIpDbOptions opts)
	{
		if (string.IsNullOrWhiteSpace(opts.ApiKey))
		{
			return null;
		}

		try
		{
			string plaintext = _protector.Unprotect(opts.ApiKey);
			return string.IsNullOrWhiteSpace(plaintext) ? null : plaintext;
		}
		catch (SecretProtectionException ex)
		{
			_logger.LogWarning("Failed to unprotect AbuseIPDB API key envelope: {Type}", ex.GetType().Name);
			return null;
		}
	}

	private static ThreatIntelLookupResult MapSuccessPayload(string ip, string content)
	{
		if (string.IsNullOrWhiteSpace(content))
		{
			return Malformed(ip, "provider returned an empty body");
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(content);
			if (doc.RootElement.ValueKind != JsonValueKind.Object
				|| !doc.RootElement.TryGetProperty("data", out JsonElement data)
				|| data.ValueKind != JsonValueKind.Object)
			{
				return Malformed(ip, "provider body has no data object");
			}

			ThreatIntelLookupResult result = new()
			{
				Outcome = ThreatIntelLookupOutcome.Success,
				Ip = ip,
				Message = "AbuseIPDB returned a reputation snapshot.",
			};

			if (data.TryGetProperty("abuseConfidenceScore", out JsonElement scoreEl) && scoreEl.TryGetInt32(out int score))
			{
				result.AbuseConfidenceScore = Math.Clamp(score, 0, 100);
			}

			if (data.TryGetProperty("totalReports", out JsonElement reportsEl) && reportsEl.ValueKind == JsonValueKind.Number)
			{
				if (reportsEl.TryGetInt64(out long total) && total >= 0)
				{
					result.TotalReports = total;
				}
			}

			if (data.TryGetProperty("isWhitelisted", out JsonElement whitelistEl) && whitelistEl.ValueKind is JsonValueKind.True or JsonValueKind.False)
			{
				result.IsWhitelisted = whitelistEl.GetBoolean();
			}

			if (data.TryGetProperty("isPublic", out JsonElement publicEl) && publicEl.ValueKind is JsonValueKind.True or JsonValueKind.False)
			{
				result.IsPublic = publicEl.GetBoolean();
			}

			if (data.TryGetProperty("usageType", out JsonElement usageEl) && usageEl.ValueKind == JsonValueKind.String)
			{
				string usage = usageEl.GetString() ?? string.Empty;
				result.UsageType = usage.Length > UsageTypeMaxLength ? usage[..UsageTypeMaxLength] : usage;
			}

			if (data.TryGetProperty("countryCode", out JsonElement countryEl) && countryEl.ValueKind == JsonValueKind.String)
			{
				string country = countryEl.GetString() ?? string.Empty;
				result.CountryCode = country.Length > CountryCodeMaxLength ? country[..CountryCodeMaxLength] : country;
			}

			return result;
		}
		catch (JsonException)
		{
			return Malformed(ip, "provider body is not valid JSON");
		}
	}

	private static ThreatIntelLookupResult Malformed(string ip, string reason)
	{
		return new ThreatIntelLookupResult
		{
			Outcome = ThreatIntelLookupOutcome.MalformedResponse,
			Ip = ip,
			Message = "Malformed AbuseIPDB response: " + reason,
		};
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
}
