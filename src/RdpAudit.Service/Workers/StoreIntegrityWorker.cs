// File:    src/RdpAudit.Service/Workers/StoreIntegrityWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Captures the durable store fingerprint as the service stops. It is registered FIRST in the hosted
//          chain, which is the entire reason it exists as a separate worker: the Generic Host stops hosted
//          services in reverse registration order, so being registered first makes this worker's StopAsync
//          the LAST thing that runs - after the ingestion, processing, retention and maintenance workers have
//          all stopped. A fingerprint taken any earlier would be taken while writers were still active, and
//          the next start would then report those writes as offline tampering.
//          StartAsync is deliberately a no-op: the database is migrated by DatabaseInitializationWorker, which
//          runs after this worker, so there is nothing safe to inspect yet. The start-up COMPARISON therefore
//          lives in DatabaseInitializationWorker (after EnsureCreatedAsync) and the periodic capture in
//          MaintenanceWorker; both call the same singleton StoreIntegrityService.
// Extends: IHostedService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Config;
using Microsoft.Extensions.Options;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Captures the store fingerprint after every other worker has stopped.</summary>
public sealed class StoreIntegrityWorker : IHostedService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Wall-clock budget for the shutdown capture. The host's own shutdown timeout bounds the whole
	/// stop sequence; exceeding it here would leave the service in a stopping state the SCM reports as a
	/// timeout, which is worse than losing one fingerprint.</summary>
	private static readonly TimeSpan ShutdownCaptureBudget = TimeSpan.FromSeconds(10);

	private readonly StoreIntegrityService _integrity;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<StoreIntegrityWorker> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the worker over the singleton store-integrity service.</summary>
	public StoreIntegrityWorker(
		StoreIntegrityService integrity,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<StoreIntegrityWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(integrity);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_integrity = integrity;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>No-op by contract: see the file header for why the capture cannot happen here.</summary>
	public Task StartAsync(CancellationToken cancellationToken)
	{
		_logger.LogInformation(
			"Store-integrity worker registered; fingerprint cadence: {Cadence}",
			_options.CurrentValue.Storage.Integrity.Describe());
		return Task.CompletedTask;
	}

	/// <summary>Captures the clean-shutdown fingerprint. Runs last in the stop sequence because this worker is
	/// registered first. Never throws: a failed fingerprint costs a future comparison, and failing shutdown
	/// would keep the service from stopping.</summary>
	public async Task StopAsync(CancellationToken cancellationToken)
	{
		try
		{
			using CancellationTokenSource budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			budget.CancelAfter(ShutdownCaptureBudget);
			await _integrity.CaptureAtShutdownAsync(budget.Token).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			_logger.LogWarning(
				"The shutdown store fingerprint was not captured within {Seconds} s; the next start will compare "
					+ "against the last periodic fingerprint instead of a clean-shutdown baseline.",
				ShutdownCaptureBudget.TotalSeconds);
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The shutdown store fingerprint could not be captured");
		}
	}
}
