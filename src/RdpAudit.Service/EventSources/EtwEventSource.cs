/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EtwEventSource.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Real-time ETW consumer implementing IEventSource. Skeleton (v0.1.0): the source
//          transitions to Unsupported on StartAsync so the DI swap and IngestionMode selection
//          logic can be exercised end-to-end while the actual TraceEventSession wiring and
//          zero-alloc XML emission land in follow-up commits (see P0 step 3). This lets
//          Program.cs, MonitoringConfigRepair and the Auto fallback probe be shipped, tested
//          and reverted independently of the ETW payload work.
// Depends: IEventSource, IEventPipe, EventSourceStatus, EventSourceStatusChangedEventArgs, ILogger
// Extends: v0.2.0 will replace StartAsync() with a real TraceEventSession lifecycle
//          (Kernel + user-mode providers, real-time buffering, PayloadNames -> XML emission,
//          backfill hand-off from EventLogWatcher). Adding a new ETW provider means enrolling
//          it inside StartAsync's provider list; the outer contract does not change.

using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Real-time ETW-backed <see cref="IEventSource"/>. Placeholder implementation that reports
/// <see cref="EventSourceStatus.Unsupported"/> until the TraceEventSession backend lands
/// in commit 3 of the P0 ETW-ingestion series.
/// </summary>
/// <remarks>
/// The type is annotated <see cref="SupportedOSPlatformAttribute"/> "windows" because the ETW
/// APIs are Windows-only. Unit tests on non-Windows CI still exercise the Unsupported branch
/// through the shared contract — the <see cref="StartAsync"/> path never touches native code
/// in this skeleton.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class EtwEventSource : IEventSource
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ILogger<EtwEventSource> _logger;
	private readonly string _sessionName;
	private int _statusInt = (int)EventSourceStatus.Idle;
	private readonly object _statusLock = new();

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Create a new ETW source.</summary>
	/// <param name="sessionName">Identifier used both as <see cref="Name"/> and as the trace
	/// session name once the real backend is wired. Must be non-empty.</param>
	/// <param name="pipe">Downstream pipe every produced DTO is written to. Bound at
	/// construction and never re-bound.</param>
	/// <param name="logger">Structured logger. Never null in production; tests inject a
	/// no-op logger.</param>
	public EtwEventSource(string sessionName, IEventPipe pipe, ILogger<EtwEventSource> logger)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sessionName);
		ArgumentNullException.ThrowIfNull(pipe);
		ArgumentNullException.ThrowIfNull(logger);

		_sessionName = sessionName;
		Pipe = pipe;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public string Name => _sessionName;

	/// <inheritdoc />
	public IEventPipe Pipe { get; }

	/// <inheritdoc />
	public EventSourceStatus Status => (EventSourceStatus)Volatile.Read(ref _statusInt);

	/// <inheritdoc />
	public event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

	/// <inheritdoc />
	public Task StartAsync(CancellationToken ct)
	{
		// Skeleton: refuse to start with a clean Unsupported transition. The DI probe in
		// Program.cs treats Unsupported as "ETW is not usable on this host" and, when
		// IngestionMode=Auto, transparently falls back to EventLog. When IngestionMode=Etw
		// the host will surface this as a startup fault, which is the documented
		// fail-fast behaviour for the Etw setting.
		TransitionTo(EventSourceStatus.Unsupported,
			"EtwEventSource skeleton — real-time TraceEventSession backend lands in commit 3.");

		_logger.LogInformation(
			"ETW source '{Session}' declared Unsupported: skeleton build, TraceEventSession backend not yet wired.",
			_sessionName);

		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken ct)
	{
		TransitionTo(EventSourceStatus.Stopped, "Stop requested.");
		return Task.CompletedTask;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void TransitionTo(EventSourceStatus target, string? reason)
	{
		EventSourceStatus previous;
		lock (_statusLock)
		{
			previous = (EventSourceStatus)_statusInt;
			if (previous == target)
			{
				return;
			}
			Volatile.Write(ref _statusInt, (int)target);
		}

		try
		{
			StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(previous, target, reason));
		}
		catch (Exception ex)
		{
			// Contract: subscribers MUST NOT block or throw. If one does, log and swallow —
			// the source itself cannot go back to Running because of a subscriber bug.
			_logger.LogWarning(ex, "StatusChanged subscriber threw for ETW source '{Session}'", _sessionName);
		}
	}
}
