/*
 * File   : UiEventArgs.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: EventArgs-derived payload carriers for the wizard UI events. The framework event
 *          pattern (CA1003) requires the second event delegate parameter to derive from
 *          System.EventArgs, so each strongly-typed UI signal carries its data through one of
 *          these immutable wrappers instead of raising EventHandler<TRawPayload> directly.
 * Depends: System.EventArgs, ConnectionEndpoint, WorkflowStep
 * Extends: When a new UI control needs to raise a strongly-typed event, add a small sealed
 *          EventArgs-derived class here (one immutable property) and raise
 *          EventHandler<ThatType> from the control.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Carries the endpoint the operator asked to probe.</summary>
public sealed class ProbeRequestedEventArgs : EventArgs
{
	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a new instance wrapping the requested <paramref name="endpoint"/>.</summary>
	public ProbeRequestedEventArgs(ConnectionEndpoint endpoint)
	{
		Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>The endpoint to probe.</summary>
	public ConnectionEndpoint Endpoint { get; }
}

/// <summary>Carries the human-readable reason a wizard step failed.</summary>
public sealed class StepFailedEventArgs : EventArgs
{
	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a new instance wrapping the failure <paramref name="message"/>.</summary>
	public StepFailedEventArgs(string message)
	{
		Message = message ?? throw new ArgumentNullException(nameof(message));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>The failure message to surface to the operator.</summary>
	public string Message { get; }
}

/// <summary>Carries the workflow step the operator selected.</summary>
public sealed class StepSelectedEventArgs : EventArgs
{
	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a new instance wrapping the selected <paramref name="step"/>.</summary>
	public StepSelectedEventArgs(WorkflowStep step) => Step = step;

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>The selected workflow step.</summary>
	public WorkflowStep Step { get; }
}
