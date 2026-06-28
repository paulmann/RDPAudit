// File:    src/RdpAudit.Service/Workers/AbuseIpDbReportWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Stage 8 background worker that periodically scans high-threat unreported IPs in the
//          AttackStats table and submits AbuseIPDB reports honouring the configured dedup window,
//          hourly / daily rate-limits, whitelist precedence and threshold policy. Honours
//          CancellationToken, guards against concurrent re-entry and never logs the API key.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Workers;

/// <summary>Stage 8 background worker that submits AbuseIPDB reports for high-threat hostile IPs.</summary>
public sealed class AbuseIpDbReportWorker : BackgroundService
{
	/// <summary>Initial delay before the first pass — let other workers settle first.</summary>
	internal static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);

	/// <summary>Period between successive passes; matches the AttackStats refresh cadence.</summary>
	internal static readonly TimeSpan Period = TimeSpan.FromMinutes(5);

	/// <summary>Upper bound on rows considered for reporting per pass.</summary>
	internal const int MaxCandidatesPerPass = 25;

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IAbuseIpDbClient _client;
	private readonly ILogger<AbuseIpDbReportWorker> _logger;
	private readonly SemaphoreSlim _gate = new(1, 1);

	private DateTime _rateLimitedUntilUtc = DateTime.MinValue;

	public AbuseIpDbReportWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IAbuseIpDbClient client,
		ILogger<AbuseIpDbReportWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(client);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_client = client;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(AbuseIpDbReportWorker));
		try
		{
			try
			{
				await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
			{
				return;
			}

			while (!stoppingToken.IsCancellationRequested)
			{
				await SafeRunAsync(stoppingToken).ConfigureAwait(false);
				try
				{
					await Task.Delay(Period, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(AbuseIpDbReportWorker));
		}
	}

	/// <summary>Runs a single pass deterministically. Exposed for tests; honours the concurrency gate.</summary>
	public async Task<int> RunOnceAsync(CancellationToken ct)
	{
		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			_logger.LogDebug("{Worker} skipped: previous pass still running", nameof(AbuseIpDbReportWorker));
			return 0;
		}

		try
		{
			return await RunPassAsync(ct).ConfigureAwait(false);
		}
		finally
		{
			_gate.Release();
		}
	}

	private async Task SafeRunAsync(CancellationToken ct)
	{
		try
		{
			int submitted = await RunOnceAsync(ct).ConfigureAwait(false);
			_logger.LogDebug("{Worker} pass complete, submitted={Submitted}", nameof(AbuseIpDbReportWorker), submitted);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// Quiet shutdown.
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "{Worker} pass failed", nameof(AbuseIpDbReportWorker));
		}
	}

	private async Task<int> RunPassAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		if (!opts.Enabled || !opts.ReportAttacks)
		{
			return 0;
		}

		if (string.IsNullOrWhiteSpace(opts.ApiKey))
		{
			return 0;
		}

		DateTime nowUtc = DateTime.UtcNow;
		if (nowUtc < _rateLimitedUntilUtc)
		{
			_logger.LogDebug("AbuseIPDB worker paused until {Until}", _rateLimitedUntilUtc);
			return 0;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		int reportsInHour = await db.AbuseReports.AsNoTracking()
			.CountAsync(r => r.ReportedUtc >= nowUtc.AddHours(-1) && r.ResponseCode >= 200 && r.ResponseCode < 300, ct)
			.ConfigureAwait(false);
		int reportsInDay = await db.AbuseReports.AsNoTracking()
			.CountAsync(r => r.ReportedUtc >= nowUtc.AddDays(-1) && r.ResponseCode >= 200 && r.ResponseCode < 300, ct)
			.ConfigureAwait(false);

		int hourlyCap = Math.Max(1, opts.MaxReportsPerHour);
		int dailyCap = Math.Max(1, opts.MaxReportsPerDay);
		if (reportsInHour >= hourlyCap || reportsInDay >= dailyCap)
		{
			return 0;
		}

		HashSet<string> whitelistDb = (await db.WhitelistEntries.AsNoTracking()
			.Select(w => w.Ip)
			.ToListAsync(ct)
			.ConfigureAwait(false))
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		List<AttackStat> candidates = await db.AttackStats.AsNoTracking()
			.Where(s => s.ThreatScore >= opts.MinThreatScore
				&& s.Failed >= opts.MinFailedAttempts
				&& !string.IsNullOrEmpty(s.Ip))
			.OrderByDescending(s => s.ThreatScore)
			.ThenByDescending(s => s.LastSeenUtc)
			.Take(MaxCandidatesPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		string categories = FormatCategoryList(opts.ReportCategories);
		int submitted = 0;

		foreach (AttackStat candidate in candidates)
		{
			ct.ThrowIfCancellationRequested();

			DateTime? lastReportUtc = await db.AbuseReports.AsNoTracking()
				.Where(r => r.Ip == candidate.Ip)
				.OrderByDescending(r => r.ReportedUtc)
				.Select(r => (DateTime?)r.ReportedUtc)
				.FirstOrDefaultAsync(ct)
				.ConfigureAwait(false);

			string normalizedIp = IpNormalizer.Normalize(candidate.Ip) ?? candidate.Ip;

			// Success-filtered cooldown lookup: only the most recent SUCCESSFUL report gates re-reporting.
			DateTime? lastSuccessfulReportUtc = opts.ReportDedupeEnabled
				? await db.AbuseIpDbReportHistory.AsNoTracking()
					.Where(h => h.IpAddress == normalizedIp && h.Succeeded)
					.OrderByDescending(h => h.ReportedAtUtc)
					.Select(h => (DateTime?)h.ReportedAtUtc)
					.FirstOrDefaultAsync(ct)
					.ConfigureAwait(false)
				: null;

			bool isWhitelisted = whitelistDb.Contains(candidate.Ip);

			AbuseIpDbReportDecision decision = AbuseIpDbPolicy.Decide(
				opts,
				hasApiKey: true,
				ip: candidate.Ip,
				threatScore: candidate.ThreatScore,
				failedAttempts: candidate.Failed,
				isWhitelisted: isWhitelisted,
				lastReportUtc: lastReportUtc,
				reportsInHour: reportsInHour,
				reportsInDay: reportsInDay,
				nowUtc: nowUtc,
				lastSuccessfulReportUtc: lastSuccessfulReportUtc);

			if (!decision.ShouldReport)
			{
				_logger.LogDebug("AbuseIPDB skip ip={Ip} reason={Reason}", candidate.Ip, decision.Reason);
				continue;
			}

			AbuseIpDbEvidence evidence = BuildEvidence(candidate);
			AbuseIpDbReportRequest request = new()
			{
				Ip = candidate.Ip,
				Categories = categories,
				Comment = AbuseIpDbCommentBuilder.Build(evidence),
			};

			AbuseIpDbReportResult result;
			try
			{
				result = await _client.ReportAsync(request, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "AbuseIPDB report threw for {Ip}", candidate.Ip);
				result = new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.TransportError,
					ResponseCode = 0,
					Message = "Exception submitting report: " + ex.GetType().Name,
				};
			}

			db.AbuseReports.Add(new AbuseReport
			{
				Ip = candidate.Ip,
				ReportedUtc = nowUtc,
				Categories = categories,
				ResponseCode = result.ResponseCode,
				Error = string.IsNullOrWhiteSpace(result.Message) ? null : Truncate(result.Message, 2000),
			});

			bool accepted = result.Outcome == AbuseIpDbReportOutcome.Accepted;
			IpReportabilityResult classification = IpReportability.Classify(candidate.Ip, isWhitelisted: ip => whitelistDb.Contains(ip));
			DateTime? cooldownExpiresUtc = accepted && opts.ReportDedupeEnabled
				? nowUtc.AddHours(Math.Clamp(opts.ReportCooldownHours, 1, 8760))
				: null;
			db.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
			{
				IpAddress = normalizedIp,
				ReportedAtUtc = nowUtc,
				Succeeded = accepted,
				HttpStatusCode = result.ResponseCode,
				ResultCode = result.Outcome.ToString(),
				ErrorMessage = string.IsNullOrWhiteSpace(result.Message) ? null : Truncate(result.Message, 2000),
				AbuseCategories = categories,
				CommentHash = HashComment(request.Comment),
				Source = "worker",
				Action = accepted ? AbuseIpDbReportAction.Sent : AbuseIpDbReportAction.Failed,
				Reason = accepted ? null : Truncate(result.Outcome.ToString(), 64),
				Classification = classification.Classification,
				CooldownExpiresUtc = cooldownExpiresUtc,
				FailedCount = candidate.Failed,
				SuccessfulCount = candidate.Successful,
				FirstSeenUtc = candidate.FirstSeenUtc,
				LastSeenUtc = candidate.LastSeenUtc,
				UsernamesSample = FormatUsernamesSample(candidate.Top10AttemptedLogins),
				CommentPreview = Truncate(request.Comment, 512),
			});

			if (result.Outcome == AbuseIpDbReportOutcome.Accepted)
			{
				submitted++;
				reportsInHour++;
				reportsInDay++;
				_logger.LogInformation("AbuseIPDB accepted report for {Ip} (HTTP {Code})", candidate.Ip, result.ResponseCode);
			}
			else if (result.Outcome == AbuseIpDbReportOutcome.RateLimited)
			{
				TimeSpan back = result.RetryAfter ?? TimeSpan.FromMinutes(5);
				if (back < TimeSpan.FromMinutes(1))
				{
					back = TimeSpan.FromMinutes(1);
				}
				_rateLimitedUntilUtc = nowUtc.Add(back);
				_logger.LogWarning("AbuseIPDB rate-limited; pausing worker until {Until}", _rateLimitedUntilUtc);
				break;
			}
			else if (result.Outcome == AbuseIpDbReportOutcome.ServerError)
			{
				_rateLimitedUntilUtc = nowUtc.Add(TimeSpan.FromMinutes(10));
				_logger.LogWarning("AbuseIPDB server error (HTTP {Code}); pausing worker until {Until}",
					result.ResponseCode, _rateLimitedUntilUtc);
				break;
			}
			else if (result.Outcome == AbuseIpDbReportOutcome.TransportError)
			{
				_logger.LogWarning("AbuseIPDB transport error for {Ip}: {Message}", candidate.Ip, result.Message);
			}
			else
			{
				_logger.LogWarning("AbuseIPDB rejected report for {Ip} (HTTP {Code})", candidate.Ip, result.ResponseCode);
			}

			if (reportsInHour >= hourlyCap || reportsInDay >= dailyCap)
			{
				break;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return submitted;
	}

	internal static AbuseIpDbEvidence BuildEvidence(AttackStat stat)
	{
		ArgumentNullException.ThrowIfNull(stat);
		List<string> logins = ParseTopLogins(stat.Top10AttemptedLogins);
		return new AbuseIpDbEvidence
		{
			Ip = stat.Ip,
			Hostname = string.Empty,
			FailedAttempts = stat.Failed,
			SuccessfulLogins = stat.Successful,
			FirstSeenUtc = stat.FirstSeenUtc,
			LastSeenUtc = stat.LastSeenUtc,
			UsernamesAttempted = logins,
			EvidenceEventIds = DeriveEvidenceEventIds(stat.Failed, stat.Successful),
		};
	}

	/// <summary>Derives the evidence Windows event IDs from observed failed/successful counts.</summary>
	internal static List<int> DeriveEvidenceEventIds(long failed, long successful)
	{
		List<int> ids = new(4);
		if (failed > 0)
		{
			ids.Add(4625);
			ids.Add(4776);
		}
		if (successful > 0)
		{
			ids.Add(4624);
			ids.Add(4648);
		}
		return ids;
	}

	/// <summary>Formats up to 10 attempted usernames into a sanitised comma-separated sample for the report log.</summary>
	internal static string? FormatUsernamesSample(string? topLoginsJson)
	{
		List<string> logins = ParseTopLogins(topLoginsJson);
		if (logins.Count == 0)
		{
			return null;
		}

		List<string> sample = new(10);
		foreach (string login in logins)
		{
			if (string.IsNullOrWhiteSpace(login))
			{
				continue;
			}
			sample.Add(login.Trim());
			if (sample.Count >= 10)
			{
				break;
			}
		}

		return sample.Count == 0 ? null : Truncate(string.Join(", ", sample), 512);
	}

	internal static List<string> ParseTopLogins(string? json)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			return new List<string>();
		}

		try
		{
			string[]? parsed = System.Text.Json.JsonSerializer.Deserialize<string[]>(json);
			if (parsed is null)
			{
				return new List<string>();
			}
			return new List<string>(parsed);
		}
		catch (System.Text.Json.JsonException)
		{
			return new List<string>();
		}
	}

	internal static string FormatCategoryList(List<int> categories)
	{
		if (categories is null || categories.Count == 0)
		{
			return "18,22";
		}

		List<string> sanitised = new(categories.Count);
		foreach (int category in categories)
		{
			if (category > 0 && category < 100)
			{
				sanitised.Add(category.ToString(CultureInfo.InvariantCulture));
			}
		}

		return sanitised.Count == 0 ? "18,22" : string.Join(",", sanitised);
	}

	private static string Truncate(string value, int max)
	{
		if (value.Length <= max)
		{
			return value;
		}
		return value[..(max - 3)] + "...";
	}

	/// <summary>SHA-256 hex hash of the submitted comment; lets history detect duplicate evidence without storing it.</summary>
	internal static string? HashComment(string? comment)
	{
		if (string.IsNullOrEmpty(comment))
		{
			return null;
		}

		byte[] bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(comment));
		return Convert.ToHexString(bytes);
	}

	public override void Dispose()
	{
		_gate.Dispose();
		base.Dispose();
	}
}
