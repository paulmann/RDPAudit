/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EventSourceFactorySelector.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Pure selection logic that picks the concrete IEventSourceFactory implementation from
//          the configured IngestionMode. Isolated in its own type so Program.cs stays readable
//          and the selection matrix can be unit-tested without spinning up the DI container.
// Depends: IngestionMode, EventSourceFactorySelection
// Extends: Add a new IngestionMode branch here when introducing a new transport (EVTX replay,
//          IPC shim, kernel driver). The selection function is deliberately side-effect-free —
//          logging happens in Program.cs so operators see the decision at Information level
//          exactly once per service start.

using RdpAudit.Core.Config;

namespace RdpAudit.Service.EventSources;

/// <summary>Result of an <see cref="EventSourceFactorySelector.Select"/> call.</summary>
/// <param name="ChosenTransport">The transport actually selected after fallback rules.
/// Equals <see cref="IngestionMode.EventLog"/> or <see cref="IngestionMode.Etw"/> — never
/// <see cref="IngestionMode.Auto"/>, because Auto resolves to a concrete transport.</param>
/// <param name="RequestedMode">The value read from configuration, preserved for logging.</param>
/// <param name="FallbackReason">When <see cref="RequestedMode"/> was <see cref="IngestionMode.Auto"/>
/// or <see cref="IngestionMode.Etw"/> and the ETW probe was declined, this carries the reason.
/// Null when the requested mode was honoured verbatim.</param>
public readonly record struct EventSourceFactorySelection(
	IngestionMode ChosenTransport,
	IngestionMode RequestedMode,
	string? FallbackReason);

/// <summary>Pure selector used by Program.cs to pick the IEventSourceFactory implementation.</summary>
public static class EventSourceFactorySelector
{
	/// <summary>Decide which transport to use for the given <paramref name="requested"/> mode.</summary>
	/// <param name="requested">The mode read from MonitoringOptions.IngestionMode.</param>
	/// <param name="etwProbe">Callback returning true when ETW is usable on this host. Called at
	/// most once, only when <paramref name="requested"/> is <see cref="IngestionMode.Etw"/> or
	/// <see cref="IngestionMode.Auto"/>. Skeleton (P0 step 2) always returns false because the
	/// TraceEventSession backend has not landed yet; commit 3 replaces the callback with a real
	/// privilege / manifest probe.</param>
	public static EventSourceFactorySelection Select(
		IngestionMode requested,
		Func<(bool Ok, string? Reason)> etwProbe)
	{
		ArgumentNullException.ThrowIfNull(etwProbe);

		switch (requested)
		{
			case IngestionMode.EventLog:
				return new EventSourceFactorySelection(IngestionMode.EventLog, requested, null);

			case IngestionMode.Etw:
			{
				var probe = etwProbe();
				if (probe.Ok)
				{
					return new EventSourceFactorySelection(IngestionMode.Etw, requested, null);
				}
				// Etw was requested explicitly. Do NOT silently fall back — the operator asked
				// for fail-fast. Callers translate this into a startup exception.
				return new EventSourceFactorySelection(
					IngestionMode.Etw,
					requested,
					probe.Reason ?? "ETW probe failed and IngestionMode=Etw requires fail-fast.");
			}

			case IngestionMode.Auto:
			{
				var probe = etwProbe();
				if (probe.Ok)
				{
					return new EventSourceFactorySelection(IngestionMode.Etw, requested, null);
				}
				return new EventSourceFactorySelection(
					IngestionMode.EventLog,
					requested,
					probe.Reason ?? "ETW probe declined \u2014 falling back to EventLog.");
			}

			default:
				// Defense in depth: MonitoringConfigRepair clamps out-of-range values before this
				// point. If a future refactor bypasses the repair, still degrade gracefully.
				return new EventSourceFactorySelection(
					IngestionMode.EventLog,
					requested,
					$"Unknown IngestionMode value '{requested}' \u2014 defaulting to EventLog.");
		}
	}
}
