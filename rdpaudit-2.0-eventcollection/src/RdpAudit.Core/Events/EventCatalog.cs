/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCatalog.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Static catalog of every Windows event id monitored by RdpAudit. Each entry carries
//          channel, layer, preset memberships, criticality, correlation dependencies, and a
//          default retention window that the Configurator and RetentionWorker consult.
// Depends: EventDescriptor, EventPreset, EventCriticality
// Extends: To add a new event id: (1) append a `new(...)` line in the appropriate layer block
//          with a completed initializer; (2) if the event is a hard prerequisite for other rules,
//          add its id to their RequiredEventIds; (3) if it belongs in Minimal or Essential,
//          set the corresponding Preset bits; (4) leave DefaultRetentionDays at 180 unless a
//          forensic or compliance obligation demands otherwise.
// Notes  : Backward compatibility — the constants ChannelSecurity, ChannelSystem, etc., and the
//          methods AllChannels() and EventIdsForChannel(string) are preserved bit-for-bit.

using System.Collections.Frozen;
using System.Collections.Immutable;

namespace RdpAudit.Core.Events;

/// <summary>
/// Static catalog of every Windows event id monitored by RdpAudit. Enriched with preset
/// memberships, criticality, correlation prerequisites, and per-event default retention.
/// </summary>
public static class EventCatalog
{
	// ── Channel constants (public API — do not rename) ───────────────────────────

	public const string ChannelSecurity = "Security";

	public const string ChannelSystem = "System";

	public const string ChannelTsLocal = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

	public const string ChannelTsRemote = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	public const string ChannelRdpCore = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

	public const string ChannelTsGateway = "Microsoft-Windows-TerminalServices-Gateway/Operational";

	public const string ChannelTsClient = "Microsoft-Windows-TerminalServices-RDPClient/Operational";

	// ── Preset composition helpers ───────────────────────────────────────────────

	// Every event participates in `Full` (by definition). Events that participate in Essential
	// also participate in Full; events that participate in Minimal also participate in Essential
	// and Full. We spell out the bit combinations explicitly so the presets nest cleanly.
	private const EventPreset MinEssFull = EventPreset.Minimal | EventPreset.Essential | EventPreset.Full;
	private const EventPreset EssFull = EventPreset.Essential | EventPreset.Full;
	private const EventPreset FullOnly = EventPreset.Full;

	// ── Catalog data ─────────────────────────────────────────────────────────────

	/// <summary>Every monitored event id, in a stable declaration order.</summary>
	public static readonly IReadOnlyList<EventDescriptor> All = BuildCatalog();

	private static List<EventDescriptor> BuildCatalog()
	{
		List<EventDescriptor> list = new(64)
		{
			// ── Authentication layer ─────────────────────────────────────────────
			new(4624, ChannelSecurity, "Successful logon", "Authentication")
			{
				Preset = MinEssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
				Purpose = "Records a successful account logon. Foundational correlation anchor.",
			},
			new(4625, ChannelSecurity, "Failed logon", "Authentication")
			{
				Preset = MinEssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
				Purpose = "Records a failed logon attempt with sub-status codes. Primary brute-force signal.",
			},
			new(4648, ChannelSecurity, "Explicit credential logon", "Authentication")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
				RequiredEventIds = ImmutableArray.Create(4624),
				Purpose = "Logon attempted using explicit credentials. Common in lateral movement.",
			},
			new(4776, ChannelSecurity, "NTLM credential validation", "Authentication")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
				Purpose = "NTLM credential validation attempt. Catches legacy-auth abuse.",
			},
			new(4672, ChannelSecurity, "Special privileges assigned", "Authentication")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 30,
				RequiredEventIds = ImmutableArray.Create(4624),
				Purpose = "High-privilege token issued at logon. Volume can be high; keep short by default.",
			},

			// ── Kerberos ─────────────────────────────────────────────────────────
			new(4768, ChannelSecurity, "TGT requested", "Kerberos")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
				Purpose = "Kerberos TGT request. High volume on domain controllers.",
			},
			new(4769, ChannelSecurity, "Service ticket requested", "Kerberos")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
				Purpose = "Kerberos service ticket request. Kerberoasting detection input.",
			},
			new(4770, ChannelSecurity, "Service ticket renewed", "Kerberos")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(4771, ChannelSecurity, "Kerberos pre-auth failed", "Kerberos")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 365,
				Purpose = "Kerberos pre-authentication failure. Password-spray and AS-REP roasting signal.",
			},

			// ── Session lifecycle (LocalSessionManager) ──────────────────────────
			new(21, ChannelTsLocal, "Session logon succeeded", "Session")
			{
				Preset = MinEssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
				Purpose = "RDP session logon succeeded; carries source network address.",
			},
			new(22, ChannelTsLocal, "Shell start notification", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
				Purpose = "Interactive shell started inside the session. Confirms full RDP desktop, not just auth.",
			},
			new(23, ChannelTsLocal, "Session logoff succeeded", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
			},
			new(24, ChannelTsLocal, "Session disconnected", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
			},
			new(25, ChannelTsLocal, "Session reconnection succeeded", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
			},
			new(39, ChannelTsLocal, "Session disconnected by another session", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
				Purpose = "One RDP session forcibly disconnected another. Session-hijack indicator.",
			},
			new(40, ChannelTsLocal, "Session disconnected with reason code", "Session")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(21),
			},

			// ── Network / pre-auth (RemoteConnectionManager) ─────────────────────
			new(1148, ChannelTsRemote, "RDP listener authentication failure", "Network")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 365,
				Purpose = "RDP listener rejected authentication. Pairs with pre-auth brute-force detection.",
			},
			new(1149, ChannelTsRemote, "RDP network connection (pre-auth)", "Network")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
				Purpose = "Pre-auth RDP connection reached the host; carries source user + IP.",
			},
			new(1150, ChannelTsRemote, "RDP user authentication failed", "Network")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 365,
				Purpose = "Remote Desktop Services authentication failed for the user.",
			},
			new(1158, ChannelTsRemote, "RDP TCP connection accepted", "Network")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				Purpose = "Remote Desktop Services accepted a TCP connection from a remote IP (pre-auth). "
					+ "Fires per accepted socket; volume can be high under a scanner.",
			},
			new(261, ChannelTsRemote, "RDP listener received connection", "Network")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},

			// ── RDP core (RdpCoreTS) — Detect_Attack_Strategy_v3 §5.2 ────────────
			new(65, ChannelRdpCore, "RDP TLS handshake completed", "RdpCore")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(82, ChannelRdpCore, "RDP listener bound on transport", "RdpCore")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(131, ChannelRdpCore, "RDP connection attempt", "RdpCore")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
			},
			new(140, ChannelRdpCore, "RDP authentication failure", "RdpCore")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 365,
				Purpose = "RDP core authentication failed. Distinct from Security 4625.",
			},
			new(141, ChannelRdpCore, "RDP credential validation failed", "RdpCore")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
			},

			// ── Privilege & process ──────────────────────────────────────────────
			new(4688, ChannelSecurity, "Process created", "Process")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 30,
				Purpose = "Process creation. Extremely high volume; enable only when process auditing is scoped.",
			},
			new(4689, ChannelSecurity, "Process exited", "Process")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 30,
			},
			new(4697, ChannelSecurity, "Service installed", "Process")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
				Purpose = "New service registered. Post-compromise persistence indicator.",
			},

			// ── Persistence — scheduled tasks ────────────────────────────────────
			new(4698, ChannelSecurity, "Scheduled task created", "Persistence")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4699, ChannelSecurity, "Scheduled task deleted", "Persistence")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
			},
			new(4700, ChannelSecurity, "Scheduled task enabled", "Persistence")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
			},
			new(4701, ChannelSecurity, "Scheduled task disabled", "Persistence")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
			},
			new(4702, ChannelSecurity, "Scheduled task updated", "Persistence")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 365,
			},

			// ── Account management ───────────────────────────────────────────────
			new(4720, ChannelSecurity, "User account created", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4722, ChannelSecurity, "User account enabled", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4724, ChannelSecurity, "Account password reset", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4725, ChannelSecurity, "User account disabled", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 730,
			},
			new(4726, ChannelSecurity, "User account deleted", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4728, ChannelSecurity, "Member added to global group", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},
			new(4732, ChannelSecurity, "Member added to local group", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
				Purpose = "Local group membership change. Watch for Remote Desktop Users additions.",
			},
			new(4740, ChannelSecurity, "User account locked out", "Account")
			{
				Preset = MinEssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
				RequiredEventIds = ImmutableArray.Create(4625),
				Purpose = "Account lockout. Direct downstream signal of brute-force.",
			},
			new(4756, ChannelSecurity, "Member added to universal group", "Account")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 730,
			},

			// ── Infrastructure tampering / authorization (v3 §9.10) ──────────────
			new(4719, ChannelSecurity, "System audit policy changed", "Tampering")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Critical,
				DefaultRetentionDays = 0,
				Purpose = "Audit policy changed. Retained forever — attackers disable auditing to hide.",
			},
			new(4825, ChannelSecurity, "RDP access denied — not in Remote Desktop Users", "Authentication")
			{
				Preset = EssFull,
				Criticality = EventCriticality.High,
				DefaultRetentionDays = 365,
			},

			// ── Object access (SACL) ─────────────────────────────────────────────
			new(4656, ChannelSecurity, "Object handle requested", "ObjectAccess")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 30,
			},
			new(4657, ChannelSecurity, "Registry value modified", "ObjectAccess")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
			},
			new(4663, ChannelSecurity, "Object accessed", "ObjectAccess")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 30,
			},

			// ── Reconnect & logoff ───────────────────────────────────────────────
			new(4634, ChannelSecurity, "Account logged off", "Logoff")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 180,
			},
			new(4647, ChannelSecurity, "User-initiated logoff", "Logoff")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 180,
			},
			new(4778, ChannelSecurity, "Session reconnected to Window Station", "Reconnect")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(4624),
				Purpose = "Session reconnect to a Window Station. Pairs with 4779 for reconnect timeline.",
			},
			new(4779, ChannelSecurity, "Session disconnected from Window Station", "Reconnect")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Medium,
				DefaultRetentionDays = 180,
				RequiredEventIds = ImmutableArray.Create(4624),
			},
			new(4800, ChannelSecurity, "Workstation locked", "Logoff")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(4801, ChannelSecurity, "Workstation unlocked", "Logoff")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},

			// ── Gateway / client (v3 §5.2 — full TS-Gateway set) ─────────────────
			new(302, ChannelTsGateway, "RD Gateway connect", "Gateway")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
			},
			new(303, ChannelTsGateway, "RD Gateway disconnect", "Gateway")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(304, ChannelTsGateway, "RD Gateway tunnel created", "Gateway")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Low,
				DefaultRetentionDays = 180,
			},
			new(305, ChannelTsGateway, "RD Gateway tunnel closed", "Gateway")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(1024, ChannelTsClient, "RDP client connection", "Client")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 90,
			},
			new(1102, ChannelSecurity, "Audit log cleared", "Tampering")
			{
				Preset = EssFull,
				Criticality = EventCriticality.Critical,
				DefaultRetentionDays = 0,
				Purpose = "Security log cleared. Retained forever — direct anti-forensics evidence.",
			},

			// ── System ───────────────────────────────────────────────────────────
			new(9009, ChannelSystem, "Desktop Window Manager exited", "System")
			{
				Preset = FullOnly,
				Criticality = EventCriticality.Informational,
				DefaultRetentionDays = 30,
			},
		};

		return list;
	}

	// ── Fast lookup indices ──────────────────────────────────────────────────────

	private static readonly FrozenDictionary<int, EventDescriptor> ByEventId
		= All.ToFrozenDictionary(d => d.EventId);

	private static readonly FrozenSet<string> ChannelSet
		= All.Select(d => d.Channel).ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	// ── Public API — legacy (do not rename) ──────────────────────────────────────

	/// <summary>Returns the unique channels referenced by the catalog.</summary>
	public static IEnumerable<string> AllChannels()
		=> ChannelSet;

	/// <summary>Returns the event ids registered for a given channel.</summary>
	public static IEnumerable<int> EventIdsForChannel(string channel)
	{
		ArgumentNullException.ThrowIfNull(channel);

		for (int i = 0; i < All.Count; i++)
		{
			EventDescriptor d = All[i];
			if (string.Equals(d.Channel, channel, StringComparison.OrdinalIgnoreCase))
			{
				yield return d.EventId;
			}
		}
	}

	// ── Public API — 2.0 additions ───────────────────────────────────────────────

	/// <summary>Attempts to resolve a descriptor by event id in O(1).</summary>
	public static bool TryGet(int eventId, out EventDescriptor descriptor)
		=> ByEventId.TryGetValue(eventId, out descriptor!);

	/// <summary>Returns the descriptors that participate in a preset. Membership follows the
	/// nested rule: Minimal ⊂ Essential ⊂ Full.</summary>
	public static IEnumerable<EventDescriptor> ByPreset(EventPreset preset)
	{
		for (int i = 0; i < All.Count; i++)
		{
			EventDescriptor d = All[i];
			if ((d.Preset & preset) != 0)
			{
				yield return d;
			}
		}
	}

	/// <summary>Returns the event ids that participate in a preset.</summary>
	public static IEnumerable<int> EventIdsByPreset(EventPreset preset)
	{
		foreach (EventDescriptor d in ByPreset(preset))
		{
			yield return d.EventId;
		}
	}

	/// <summary>Returns the default retention window in days for the given event id. Returns
	/// <c>-1</c> if the event id is not in the catalog. <c>0</c> means "keep forever".</summary>
	public static int DefaultRetentionFor(int eventId)
		=> ByEventId.TryGetValue(eventId, out EventDescriptor? d) ? d.DefaultRetentionDays : -1;

	/// <summary>Returns the criticality of the given event id, defaulting to <see cref="EventCriticality.Low"/>
	/// when the event id is unknown.</summary>
	public static EventCriticality CriticalityOf(int eventId)
		=> ByEventId.TryGetValue(eventId, out EventDescriptor? d) ? d.Criticality : EventCriticality.Low;

	/// <summary>Returns the string layer label of the given event id, or <c>"Unknown"</c> when the
	/// event id is not in the catalog. Kept as a stable string for the Configurator UI.</summary>
	public static string LayerOf(int eventId)
		=> ByEventId.TryGetValue(eventId, out EventDescriptor? d) ? d.Layer : "Unknown";

	/// <summary>Returns the typed layer of the given event id, or <see cref="EventLayer.Unknown"/>
	/// when the event id is not in the catalog. Suitable for persistence and shard records.</summary>
	public static EventLayer LayerKindOf(int eventId)
		=> ByEventId.TryGetValue(eventId, out EventDescriptor? d) ? d.LayerKind : EventLayer.Unknown;

	/// <summary>Returns the closure of prerequisite event ids for the given seed events: every
	/// event that must also be enabled for the seed events to be useful. Includes the seeds
	/// themselves. Deterministic ordering: the seed order is preserved, prerequisites appear
	/// immediately after their dependent. Duplicates are removed.</summary>
	public static IReadOnlyList<int> RequiredClosure(IEnumerable<int> seedEventIds)
	{
		ArgumentNullException.ThrowIfNull(seedEventIds);

		List<int> ordered = new(32);
		HashSet<int> seen = new(32);

		foreach (int id in seedEventIds)
		{
			VisitClosure(id, ordered, seen);
		}

		return ordered;
	}

	private static void VisitClosure(int eventId, List<int> ordered, HashSet<int> seen)
	{
		if (!seen.Add(eventId))
		{
			return;
		}

		ordered.Add(eventId);

		if (!ByEventId.TryGetValue(eventId, out EventDescriptor? d))
		{
			return;
		}

		ImmutableArray<int> deps = d.RequiredEventIds;
		for (int i = 0; i < deps.Length; i++)
		{
			VisitClosure(deps[i], ordered, seen);
		}
	}

	/// <summary>Convenience: returns the event ids that a preset expands to, including every
	/// prerequisite implied by the members' <see cref="EventDescriptor.RequiredEventIds"/>.</summary>
	public static IReadOnlyList<int> ExpandPreset(EventPreset preset)
		=> RequiredClosure(EventIdsByPreset(preset));

	/// <summary>Given a currently-enabled set, returns the tightest named preset that matches
	/// exactly, or <see cref="EventPreset.Custom"/> if the set diverges from every named preset.
	/// Uses set equality; ordering is irrelevant.</summary>
	public static EventPreset ClassifyActiveSet(IEnumerable<int> enabledEventIds)
	{
		ArgumentNullException.ThrowIfNull(enabledEventIds);

		FrozenSet<int> active = enabledEventIds.ToFrozenSet();

		if (active.SetEquals(EventIdsByPreset(EventPreset.Minimal)))
		{
			return EventPreset.Minimal;
		}

		if (active.SetEquals(EventIdsByPreset(EventPreset.Essential)))
		{
			return EventPreset.Essential;
		}

		if (active.SetEquals(EventIdsByPreset(EventPreset.Full)))
		{
			return EventPreset.Full;
		}

		return EventPreset.Custom;
	}
}
