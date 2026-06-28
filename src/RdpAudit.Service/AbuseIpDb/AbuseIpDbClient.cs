// File:    src/RdpAudit.Service/AbuseIpDb/AbuseIpDbClient.cs
// Module:  RdpAudit.Service.AbuseIpDb
// Purpose: HttpClient-backed implementation of IAbuseIpDbClient. Constructs the AbuseIPDB v2 report
//          submission against /api/v2/report using the configured Key header and a sanitised
//          form-urlencoded body. Never logs the API key. Handles 2xx / 4xx / 429 / 5xx with a
//          structured result and honours Retry-After hints for back-off.
// Extends: RdpAudit.Core.AbuseIpDb.IAbuseIpDbClient
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;

namespace RdpAudit.Service.AbuseIpDb;

/// <summary>HttpClient-backed implementation of <see cref="IAbuseIpDbClient"/>.</summary>
public sealed class AbuseIpDbClient : IAbuseIpDbClient
{
	private const string UserAgent = "RdpAudit/1.0 (+https://github.com/paulmann/RDPAudit)";

	private readonly IHttpClientFactory _httpFactory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ISecretProtector _protector;
	private readonly ILogger<AbuseIpDbClient> _logger;

	public AbuseIpDbClient(
		IHttpClientFactory httpFactory,
		IOptionsMonitor<RdpAuditOptions> options,
		ISecretProtector protector,
		ILogger<AbuseIpDbClient> logger)
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
	public async Task<AbuseIpDbReportResult> ReportAsync(AbuseIpDbReportRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);

		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		if (!opts.Enabled || !opts.ReportAttacks)
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.NotConfigured,
				ResponseCode = 0,
				Message = "AbuseIPDB reporting is not enabled.",
			};
		}

		string? plaintextKey = TryUnprotectKey(opts);
		if (string.IsNullOrEmpty(plaintextKey))
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.NotConfigured,
				ResponseCode = 0,
				Message = "AbuseIPDB API key is not configured.",
			};
		}

		string endpoint = string.IsNullOrWhiteSpace(opts.EndpointUrl)
			? "https://api.abuseipdb.com/api/v2/report"
			: opts.EndpointUrl;

		try
		{
			using HttpClient http = CreateHttpClient(opts);
			using HttpRequestMessage message = BuildReportMessage(endpoint, plaintextKey, request);

			using HttpResponseMessage response = await http.SendAsync(message, ct).ConfigureAwait(false);
			int code = (int)response.StatusCode;
			TimeSpan? retryAfter = ExtractRetryAfter(response);

			if (response.IsSuccessStatusCode)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.Accepted,
					ResponseCode = code,
					Message = "AbuseIPDB accepted the report.",
				};
			}

			if (code == (int)HttpStatusCode.TooManyRequests)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.RateLimited,
					ResponseCode = code,
					Message = "AbuseIPDB returned 429 Too Many Requests.",
					RetryAfter = retryAfter,
				};
			}

			if (code >= 500)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.ServerError,
					ResponseCode = code,
					Message = string.Format(CultureInfo.InvariantCulture,
						"AbuseIPDB returned server error {0}.", code),
					RetryAfter = retryAfter,
				};
			}

			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.Rejected,
				ResponseCode = code,
				Message = string.Format(CultureInfo.InvariantCulture,
					"AbuseIPDB rejected the report with HTTP {0}.", code),
			};
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (HttpRequestException ex)
		{
			_logger.LogWarning("AbuseIPDB report transport failure: {Type}", ex.GetType().Name);
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.TransportError,
				ResponseCode = 0,
				Message = "AbuseIPDB transport error: " + ex.GetType().Name,
			};
		}
		catch (TaskCanceledException ex)
		{
			_logger.LogWarning("AbuseIPDB report timed out: {Type}", ex.GetType().Name);
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.TransportError,
				ResponseCode = 0,
				Message = "AbuseIPDB request timed out.",
			};
		}
	}

	/// <inheritdoc />
	public async Task<AbuseIpDbReportResult> ValidateKeyAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;

		string? plaintextKey = TryUnprotectKey(opts);
		if (string.IsNullOrEmpty(plaintextKey))
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.NotConfigured,
				ResponseCode = 0,
				Message = "AbuseIPDB API key is not configured.",
			};
		}

		if (!AbuseIpDbApiKeyValidator.IsLikelyValid(plaintextKey))
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.Rejected,
				ResponseCode = 0,
				Message = "AbuseIPDB API key format check failed.",
			};
		}

		// Use the public read-only /check endpoint on the loopback IP. This is safe — it returns the
		// reputation snapshot for the supplied IP without ever submitting a fake abuse report. A 2xx
		// response means the key was accepted; 401/403 means the key is invalid.
		string baseUrl = string.IsNullOrWhiteSpace(opts.BaseUrl) ? "https://api.abuseipdb.com" : opts.BaseUrl.TrimEnd('/');
		string checkUrl = baseUrl + "/api/v2/check?ipAddress=127.0.0.1&maxAgeInDays=30";

		try
		{
			using HttpClient http = CreateHttpClient(opts);
			using HttpRequestMessage message = new(HttpMethod.Get, checkUrl);
			message.Headers.TryAddWithoutValidation("Key", plaintextKey);
			message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			message.Headers.UserAgent.ParseAdd(UserAgent);

			using HttpResponseMessage response = await http.SendAsync(message, ct).ConfigureAwait(false);
			int code = (int)response.StatusCode;
			if (response.IsSuccessStatusCode)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.Accepted,
					ResponseCode = code,
					Message = "AbuseIPDB accepted the API key.",
				};
			}

			if (code == (int)HttpStatusCode.Unauthorized || code == (int)HttpStatusCode.Forbidden)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.Rejected,
					ResponseCode = code,
					Message = "AbuseIPDB rejected the API key.",
				};
			}

			if (code == (int)HttpStatusCode.TooManyRequests)
			{
				return new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.RateLimited,
					ResponseCode = code,
					Message = "AbuseIPDB returned 429 during key validation.",
				};
			}

			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.ServerError,
				ResponseCode = code,
				Message = string.Format(CultureInfo.InvariantCulture, "AbuseIPDB key validation HTTP {0}.", code),
			};
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (HttpRequestException ex)
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.TransportError,
				ResponseCode = 0,
				Message = "AbuseIPDB transport error during key validation: " + ex.GetType().Name,
			};
		}
		catch (TaskCanceledException)
		{
			return new AbuseIpDbReportResult
			{
				Outcome = AbuseIpDbReportOutcome.TransportError,
				ResponseCode = 0,
				Message = "AbuseIPDB key validation timed out.",
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

	private static HttpRequestMessage BuildReportMessage(string endpoint, string apiKey, AbuseIpDbReportRequest request)
	{
		HttpRequestMessage message = new(HttpMethod.Post, endpoint);
		message.Headers.TryAddWithoutValidation("Key", apiKey);
		message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
		message.Headers.UserAgent.ParseAdd(UserAgent);

		List<KeyValuePair<string, string>> formFields = new()
		{
			new("ip", request.Ip),
			new("categories", request.Categories),
			new("comment", request.Comment),
		};
		message.Content = new FormUrlEncodedContent(formFields);
		return message;
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
