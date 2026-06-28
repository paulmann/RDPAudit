// File:    src/RdpAudit.Core/Events/EventCatalog.cs
// Module:  RdpAudit.Core.Events
// Purpose: Static catalog of every event id monitored by RdpAudit, grouped by channel and layer.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Events;

/// <summary>
/// Static catalog of every event id monitored by RdpAudit, grouped by channel and layer.
/// </summary>
public static class EventCatalog
{
	public const string ChannelSecurity = "Security";

	public const string ChannelSystem = "System";

	public const string ChannelTsLocal = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

	public const string ChannelTsRemote = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	public const string ChannelRdpCore = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

	public const string ChannelTsGateway = "Microsoft-Windows-TerminalServices-Gateway/Operational";

	public const string ChannelTsClient = "Microsoft-Windows-TerminalServices-RDPClient/Operational";

	public static readonly IReadOnlyList<EventDescriptor> All = new List<EventDescriptor>
	{
		// Authentication layer
		new(4624, ChannelSecurity, "Successful logon", "Authentication"),
		new(4625, ChannelSecurity, "Failed logon", "Authentication"),
		new(4648, ChannelSecurity, "Explicit credential logon", "Authentication"),
		new(4776, ChannelSecurity, "NTLM credential validation", "Authentication"),
		new(4672, ChannelSecurity, "Special privileges assigned", "Authentication"),

		// Kerberos
		new(4768, ChannelSecurity, "TGT requested", "Kerberos"),
		new(4769, ChannelSecurity, "Service ticket requested", "Kerberos"),
		new(4770, ChannelSecurity, "Service ticket renewed", "Kerberos"),
		new(4771, ChannelSecurity, "Kerberos pre-auth failed", "Kerberos"),

		// Session lifecycle
		new(21, ChannelTsLocal, "Session logon succeeded", "Session"),
		new(22, ChannelTsLocal, "Shell start notification", "Session"),
		new(23, ChannelTsLocal, "Session logoff succeeded", "Session"),
		new(24, ChannelTsLocal, "Session disconnected", "Session"),
		new(25, ChannelTsLocal, "Session reconnection succeeded", "Session"),
		new(39, ChannelTsLocal, "Session disconnected by another session", "Session"),
		new(40, ChannelTsLocal, "Session disconnected with reason code", "Session"),

		// Network / pre-auth
		new(1148, ChannelTsRemote, "RDP listener authentication failure", "Network"),
		new(1149, ChannelTsRemote, "RDP network connection (pre-auth)", "Network"),
		new(261, ChannelTsRemote, "RDP listener received connection", "Network"),

		// RDP core (Detect_Attack_Strategy_v3.md §5.2 — full RdpCoreTS set)
		new(65, ChannelRdpCore, "RDP TLS handshake completed", "RdpCore"),
		new(82, ChannelRdpCore, "RDP listener bound on transport", "RdpCore"),
		new(131, ChannelRdpCore, "RDP connection attempt", "RdpCore"),
		new(140, ChannelRdpCore, "RDP authentication failure", "RdpCore"),
		new(141, ChannelRdpCore, "RDP credential validation failed", "RdpCore"),

		// Privilege & process
		new(4688, ChannelSecurity, "Process created", "Process"),
		new(4689, ChannelSecurity, "Process exited", "Process"),
		new(4697, ChannelSecurity, "Service installed", "Process"),

		// Persistence — scheduled tasks
		new(4698, ChannelSecurity, "Scheduled task created", "Persistence"),
		new(4699, ChannelSecurity, "Scheduled task deleted", "Persistence"),
		new(4700, ChannelSecurity, "Scheduled task enabled", "Persistence"),
		new(4701, ChannelSecurity, "Scheduled task disabled", "Persistence"),
		new(4702, ChannelSecurity, "Scheduled task updated", "Persistence"),

		// Account management
		new(4720, ChannelSecurity, "User account created", "Account"),
		new(4722, ChannelSecurity, "User account enabled", "Account"),
		new(4724, ChannelSecurity, "Account password reset", "Account"),
		new(4725, ChannelSecurity, "User account disabled", "Account"),
		new(4726, ChannelSecurity, "User account deleted", "Account"),
		new(4728, ChannelSecurity, "Member added to global group", "Account"),
		new(4732, ChannelSecurity, "Member added to local group", "Account"),
		new(4740, ChannelSecurity, "User account locked out", "Account"),
		new(4756, ChannelSecurity, "Member added to universal group", "Account"),

		// Infrastructure tampering / authorization (v3 §9.10)
		new(4719, ChannelSecurity, "System audit policy changed", "Tampering"),
		new(4825, ChannelSecurity, "RDP access denied — user is not a member of Remote Desktop Users", "Authentication"),

		// Object access (SACL)
		new(4656, ChannelSecurity, "Object handle requested", "ObjectAccess"),
		new(4657, ChannelSecurity, "Registry value modified", "ObjectAccess"),
		new(4663, ChannelSecurity, "Object accessed", "ObjectAccess"),

		// Reconnect & logoff
		new(4634, ChannelSecurity, "Account logged off", "Logoff"),
		new(4647, ChannelSecurity, "User-initiated logoff", "Logoff"),
		new(4778, ChannelSecurity, "Session reconnected to Window Station", "Logoff"),
		new(4779, ChannelSecurity, "Session disconnected from Window Station", "Logoff"),
		new(4800, ChannelSecurity, "Workstation locked", "Logoff"),
		new(4801, ChannelSecurity, "Workstation unlocked", "Logoff"),

		// Gateway / client (Detect_Attack_Strategy_v3.md §5.2 — full TS-Gateway set)
		new(302, ChannelTsGateway, "RD Gateway connect", "Gateway"),
		new(303, ChannelTsGateway, "RD Gateway disconnect", "Gateway"),
		new(304, ChannelTsGateway, "RD Gateway tunnel created", "Gateway"),
		new(305, ChannelTsGateway, "RD Gateway tunnel closed", "Gateway"),
		new(1024, ChannelTsClient, "RDP client connection", "Client"),
		new(1102, ChannelSecurity, "Audit log cleared", "Tampering"),

		// System
		new(9009, ChannelSystem, "Desktop Window Manager exited", "System"),
	};

	/// <summary>Returns the unique channels referenced by the catalog.</summary>
	public static IEnumerable<string> AllChannels()
		=> All.Select(d => d.Channel).Distinct(StringComparer.OrdinalIgnoreCase);

	/// <summary>Returns the event ids registered for a given channel.</summary>
	public static IEnumerable<int> EventIdsForChannel(string channel)
		=> All.Where(d => string.Equals(d.Channel, channel, StringComparison.OrdinalIgnoreCase))
			.Select(d => d.EventId)
			.Distinct();
}
