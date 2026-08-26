/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EventChannelHealth.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Pure classification of a Windows event-log channel prerequisite into Ok / Disabled /
//          Missing, consumed by the Configurator's PrerequisiteChecker so the Prerequisites tab can
//          tell a channel that merely needs enabling (fixable via wevtutil sl /enabled:true) apart
//          from one that is entirely absent on this Windows build / SKU (not fixable, and must not
//          offer a wevtutil enable button).
// Depends: nothing - pure data, unit-testable on any platform.
// Extends: To add a new health state, extend the enum and update Classify. Keep this module free of
//          any Windows dependency so RdpAudit.Core.Tests can exercise it off-Windows (D7).
// Notes  : EventLogConfiguration throws EventLogNotFoundException for a missing channel; catching
//          that and classifying it here is what lets the UI suppress the Fix button instead of
//          offering a wevtutil command that would fail.

namespace RdpAudit.Core.Events;

/// <summary>Health classification of a monitored event-log channel prerequisite (D7).</summary>
public enum EventChannelHealth
{
	/// <summary>The channel exists and logging is enabled.</summary>
	Ok,

	/// <summary>The channel exists but is currently disabled. Fixable via wevtutil.</summary>
	Disabled,

	/// <summary>The channel does not exist on this Windows build / SKU. Not fixable.</summary>
	Missing,
}

/// <summary>Pure fold from the two raw observations (does the channel exist, is it enabled) to a
/// single <see cref="EventChannelHealth"/> verdict. Deterministic and dependency-free.</summary>
public static class EventChannelClassifier
{
	/// <summary>Combines the existence and enabled observations into one three-state verdict.</summary>
	public static EventChannelHealth Classify(bool exists, bool enabled) =>
		!exists ? EventChannelHealth.Missing
		: enabled ? EventChannelHealth.Ok
		: EventChannelHealth.Disabled;
}
