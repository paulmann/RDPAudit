// File:    src/RdpAudit.Core/Config/MonitoringConfigRepair.cs
// Module:  RdpAudit.Core.Config
// Purpose: Repairs stale appsettings.json so the Security channel and the v3 authentication
//          event-ID set are always present in the effective MonitoringOptions, regardless of
//          what an older config file persisted on disk. Without this fix, upgrades from a pre-v3
//          build that pruned EnabledChannels / EnabledEventIds in operator-edited appsettings.json
//          leave the Security watcher disarmed and the Configurator UI shows Failed=0 even when
//          PowerShell can see Security 4625 events.
//          Pure, OS-agnostic, unit-testable. Applied at service startup by Program.Main before
//          the EventCollectorWorker arms its channels, and surfaced via diagnostics so operators
//          can confirm the repair fired.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;

namespace RdpAudit.Core.Config;

/// <summary>Outcome of a single <see cref="MonitoringConfigRepair.Repair"/> invocation, useful for
/// telemetry and the Diagnostic tab. <see cref="Changed"/> is the only contract bit operators need;
/// the per-list reports are for forensic logging.</summary>
public sealed record MonitoringConfigRepairReport(
	bool Changed,
	IReadOnlyList<string> AddedChannels,
	IReadOnlyList<int> AddedEventIds,
	string? Reason);

/// <summary>Pure repair helper that injects the Security channel and required authentication
/// event IDs into a <see cref="MonitoringOptions"/> instance when an older appsettings.json
/// persisted a partial list. Idempotent: a second invocation on an already-repaired options
/// instance returns <see cref="MonitoringConfigRepairReport.Changed"/>=false.</summary>
public static class MonitoringConfigRepair
{
	/// <summary>Minimum authentication event IDs the service must observe to keep
	/// AuthAttemptFact counters honest: 4624 / 4625 / 4648 / 4768 / 4769 / 4771 / 4776 / 4825.
	/// Mirrors Detect_Attack_Strategy_v3.md §6.3 outcome-authority hierarchy and the
	/// <c>AuthAttemptFactUpserter.IsAuthoritativeAuthEvent</c> contract.</summary>
	public static readonly IReadOnlyList<int> RequiredSecurityEventIds = new[]
	{
		4624, 4625, 4648, 4768, 4769, 4771, 4776, 4825,
	};

	/// <summary>Apply the repair to <paramref name="options"/> in place. Always preserves any
	/// user-added channels / event IDs; only ever ADDS the missing required ones. Returns a
	/// report describing what was changed.</summary>
	public static MonitoringConfigRepairReport Repair(MonitoringOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);

		options.EnabledChannels ??= new List<string>();
		options.EnabledEventIds ??= new List<int>();

		List<string> addedChannels = new();
		List<int> addedEventIds = new();
		string? reason = null;

		bool hasSecurity = options.EnabledChannels.Any(c => string.Equals(c, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase));
		if (!hasSecurity)
		{
			options.EnabledChannels.Add(EventCatalog.ChannelSecurity);
			addedChannels.Add(EventCatalog.ChannelSecurity);
			reason = "Security channel was missing from EnabledChannels — re-added so authentication telemetry can flow.";
		}

		// EnabledEventIds is a *filter*: an empty list means "all events from EnabledChannels".
		// If operators wrote an explicit non-empty list, ensure the required Security event IDs
		// are present so 4624/4625/.../4825 are not silently dropped. If the list is empty we
		// leave it empty — that already means "everything from the catalog".
		if (options.EnabledEventIds.Count > 0)
		{
			HashSet<int> existing = new(options.EnabledEventIds);
			foreach (int id in RequiredSecurityEventIds)
			{
				if (existing.Add(id))
				{
					options.EnabledEventIds.Add(id);
					addedEventIds.Add(id);
				}
			}

			if (addedEventIds.Count > 0 && reason is null)
			{
				reason = "Stale EnabledEventIds filter was missing required Security authentication events — added 4624/4625/4648/4768/4769/4771/4776/4825 as needed.";
			}
		}

		bool changed = addedChannels.Count > 0 || addedEventIds.Count > 0;
		return new MonitoringConfigRepairReport(changed, addedChannels, addedEventIds, reason);
	}
}
