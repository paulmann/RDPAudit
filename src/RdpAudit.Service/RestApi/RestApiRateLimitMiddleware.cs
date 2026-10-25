// File:    src/RdpAudit.Service/RestApi/RestApiRateLimitMiddleware.cs
// Module:  RdpAudit.Service.RestApi
// Purpose: Fixed-window per-minute request budget per client IP for the read-only REST API.
//          Installed after the security-header middleware and before the bearer auth, so even an
//          unauthenticated caller burns its budget. Exhausting the budget returns RFC 6585 429
//          with a Retry-After header and an RFC 9457 problem+json body.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace RdpAudit.Service.RestApi;

/// <summary>Per-IP fixed-window rate limiter for the read-only REST API.</summary>
public sealed class RestApiRateLimitMiddleware
{
	private static readonly TimeSpan WindowDuration = TimeSpan.FromMinutes(1);

	private readonly RequestDelegate _next;
	private readonly int _budgetPerMinute;
	private readonly TimeProvider _clock;
	private readonly object _gate = new();
	private readonly Dictionary<string, WindowBucket> _buckets = new(StringComparer.Ordinal);
	private int _acquisitionsSincePrune;

	public RestApiRateLimitMiddleware(RequestDelegate next, int budgetPerMinute)
		: this(next, budgetPerMinute, TimeProvider.System)
	{
	}

	public RestApiRateLimitMiddleware(RequestDelegate next, int budgetPerMinute, TimeProvider clock)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
		_budgetPerMinute = Math.Max(1, budgetPerMinute);
		_clock = clock ?? throw new ArgumentNullException(nameof(clock));
	}

	public async Task InvokeAsync(HttpContext context)
	{
		ArgumentNullException.ThrowIfNull(context);

		if (!TryAcquire(GetClientKey(context), out int retryAfterSeconds))
		{
			context.Response.Headers[HeaderNames.RetryAfter] =
				retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
			await RestApiProblem.WriteAsync(
				context,
				StatusCodes.Status429TooManyRequests,
				"Too Many Requests",
				"The per-minute request budget for this client has been exhausted. Retry later.").ConfigureAwait(false);
			return;
		}

		await _next(context);
	}

	/// <summary>Rate-limit key: the client's remote IP literal, or "unknown" when not available.</summary>
	internal static string GetClientKey(HttpContext context)
		=> context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

	private bool TryAcquire(string key, out int retryAfterSeconds)
	{
		DateTimeOffset now = _clock.GetUtcNow();
		lock (_gate)
		{
			// Bound the dictionary of a long-lived listener: roughly every 1024 acquisitions,
			// drop buckets whose window expired long ago. Infrequent O(n) passes keep the
			// common path O(1) while preventing unbounded growth from rotating client IPs.
			if (++_acquisitionsSincePrune >= 1024)
			{
				_acquisitionsSincePrune = 0;
				List<string> stale = [];
				foreach ((string staleKey, WindowBucket staleBucket) in _buckets)
				{
					if (now - staleBucket.WindowStartedUtc >= WindowDuration + WindowDuration)
					{
						stale.Add(staleKey);
					}
				}

				foreach (string staleKey in stale)
				{
					_buckets.Remove(staleKey);
				}
			}

			if (!_buckets.TryGetValue(key, out WindowBucket? bucket))
			{
				bucket = new WindowBucket(now);
				_buckets.Add(key, bucket);
			}

			if (now - bucket.WindowStartedUtc >= WindowDuration)
			{
				bucket.WindowStartedUtc = now;
				bucket.Count = 0;
			}

			if (bucket.Count >= _budgetPerMinute)
			{
				retryAfterSeconds = Math.Max(
					1,
					(int)Math.Ceiling((WindowDuration - (now - bucket.WindowStartedUtc)).TotalSeconds));
				return false;
			}

			bucket.Count++;
			retryAfterSeconds = 0;
			return true;
		}
	}

	private sealed class WindowBucket
	{
		public WindowBucket(DateTimeOffset windowStartedUtc) => WindowStartedUtc = windowStartedUtc;

		public DateTimeOffset WindowStartedUtc { get; set; }

		public int Count { get; set; }
	}
}
