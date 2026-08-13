/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventLayer.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Typed layer classification for a monitored Windows event id. Complements the string
//          Layer field on EventDescriptor (kept for UI-backward-compatibility) with a byte-
//          sized enum suitable for persistence in RawEvents.EventLayer and shard records.
// Depends: (none)
// Extends: When a new layer is required, append it at the end of the enum. Never renumber
//          existing values — persisted rows compare against them.

namespace RdpAudit.Core.Events;

/// <summary>Typed layer classification for a monitored Windows event id. Fits in one byte so
/// it can live in a shard record without inflating the fixed-size struct.</summary>
public enum EventLayer : byte
{
	/// <summary>Layer not classified. Never persisted for known events — indicates a lookup miss
	/// or an intentionally uncategorised event.</summary>
	Unknown = 0,

	/// <summary>Windows authentication events (Security channel): 4624, 4625, 4648, 4776, 4672, 4825.</summary>
	Authentication = 1,

	/// <summary>Kerberos events (Security channel): 4768, 4769, 4770, 4771.</summary>
	Kerberos = 2,

	/// <summary>Session lifecycle (LocalSessionManager channel): 21, 22, 23, 24, 25, 39, 40.</summary>
	Session = 3,

	/// <summary>Window-station reconnect / disconnect (Security channel): 4778, 4779.</summary>
	Reconnect = 4,

	/// <summary>Pre-auth RDP network events (RemoteConnectionManager channel): 1148, 1149, 1150,
	/// 1158, 261.</summary>
	Network = 5,

	/// <summary>RDP transport core (RdpCoreTS channel): 65, 82, 131, 140, 141.</summary>
	RdpCore = 6,

	/// <summary>Process auditing (Security channel): 4688, 4689, 4697.</summary>
	Process = 7,

	/// <summary>Persistence footprint (Security channel): 4698..4702 scheduled-task events.</summary>
	Persistence = 8,

	/// <summary>Account management (Security channel): 4720, 4722, 4724, 4725, 4726, 4728, 4732,
	/// 4740, 4756.</summary>
	Account = 9,

	/// <summary>Anti-forensics / audit-policy tampering (Security channel): 4719, 1102.</summary>
	Tampering = 10,

	/// <summary>Object access via SACL (Security channel): 4656, 4657, 4663.</summary>
	ObjectAccess = 11,

	/// <summary>User- and session-initiated logoff plus workstation lock/unlock
	/// (Security channel): 4634, 4647, 4800, 4801.</summary>
	Logoff = 12,

	/// <summary>Remote Desktop Gateway events (TS-Gateway channel): 302, 303, 304, 305.</summary>
	Gateway = 13,

	/// <summary>Remote Desktop client-side events (TS-Client channel): 1024.</summary>
	Client = 14,

	/// <summary>System-scope events (System channel): 9009.</summary>
	System = 15,
}

/// <summary>Two-way conversion between the string <c>Layer</c> field on <c>EventDescriptor</c>
/// and the typed <see cref="EventLayer"/> enum. Kept as a static utility instead of enum
/// extensions so callers can use it in `switch` and `ref struct` contexts without allocating.</summary>
public static class EventLayers
{
	/// <summary>Parses the legacy string layer used in <c>EventDescriptor.Layer</c> into the
	/// typed enum. Case-insensitive, returns <see cref="EventLayer.Unknown"/> for unrecognised
	/// values instead of throwing.</summary>
	public static EventLayer Parse(string? layer)
	{
		if (string.IsNullOrEmpty(layer))
		{
			return EventLayer.Unknown;
		}

		// String comparison uses OrdinalIgnoreCase so tests that lower-case the label still work.
		if (string.Equals(layer, "Authentication", StringComparison.OrdinalIgnoreCase)) return EventLayer.Authentication;
		if (string.Equals(layer, "Kerberos", StringComparison.OrdinalIgnoreCase)) return EventLayer.Kerberos;
		if (string.Equals(layer, "Session", StringComparison.OrdinalIgnoreCase)) return EventLayer.Session;
		if (string.Equals(layer, "Reconnect", StringComparison.OrdinalIgnoreCase)) return EventLayer.Reconnect;
		if (string.Equals(layer, "Network", StringComparison.OrdinalIgnoreCase)) return EventLayer.Network;
		if (string.Equals(layer, "RdpCore", StringComparison.OrdinalIgnoreCase)) return EventLayer.RdpCore;
		if (string.Equals(layer, "Process", StringComparison.OrdinalIgnoreCase)) return EventLayer.Process;
		if (string.Equals(layer, "Persistence", StringComparison.OrdinalIgnoreCase)) return EventLayer.Persistence;
		if (string.Equals(layer, "Account", StringComparison.OrdinalIgnoreCase)) return EventLayer.Account;
		if (string.Equals(layer, "Tampering", StringComparison.OrdinalIgnoreCase)) return EventLayer.Tampering;
		if (string.Equals(layer, "ObjectAccess", StringComparison.OrdinalIgnoreCase)) return EventLayer.ObjectAccess;
		if (string.Equals(layer, "Logoff", StringComparison.OrdinalIgnoreCase)) return EventLayer.Logoff;
		if (string.Equals(layer, "Gateway", StringComparison.OrdinalIgnoreCase)) return EventLayer.Gateway;
		if (string.Equals(layer, "Client", StringComparison.OrdinalIgnoreCase)) return EventLayer.Client;
		if (string.Equals(layer, "System", StringComparison.OrdinalIgnoreCase)) return EventLayer.System;

		return EventLayer.Unknown;
	}

	/// <summary>Returns the canonical string label for the typed layer. Guaranteed to round-trip
	/// through <see cref="Parse"/>.</summary>
	public static string ToLabel(EventLayer layer) => layer switch
	{
		EventLayer.Authentication => "Authentication",
		EventLayer.Kerberos       => "Kerberos",
		EventLayer.Session        => "Session",
		EventLayer.Reconnect      => "Reconnect",
		EventLayer.Network        => "Network",
		EventLayer.RdpCore        => "RdpCore",
		EventLayer.Process        => "Process",
		EventLayer.Persistence    => "Persistence",
		EventLayer.Account        => "Account",
		EventLayer.Tampering      => "Tampering",
		EventLayer.ObjectAccess   => "ObjectAccess",
		EventLayer.Logoff         => "Logoff",
		EventLayer.Gateway        => "Gateway",
		EventLayer.Client         => "Client",
		EventLayer.System         => "System",
		_                         => "Unknown",
	};
}
