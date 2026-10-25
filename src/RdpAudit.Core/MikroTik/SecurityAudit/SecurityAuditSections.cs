// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditSections.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: The exact RouterOS menus the security audit reads, with their REST paths and the shape
//          each one answers with. A menu that is absent on the device (package not installed) is
//          reported as "unavailable" and is not a finding; a menu that exists but could not be read
//          becomes S-00, because silence in a security report reads as "compliant".
//          Paths are relative to the REST root (<c>https://host/rest/</c>); the Service composes the
//          full URL through MikroTikUrlBuilder.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>One menu the audit reads.</summary>
/// <param name="Key">Stable section key used by rules and by the report (e.g. <c>services</c>).</param>
/// <param name="RestPath">REST path below the API root (e.g. <c>ip/service</c>).</param>
/// <param name="Singleton">True when the menu answers with one object instead of an array.</param>
/// <param name="ConsolePath">Console notation shown to the operator (e.g. <c>/ip/service</c>).</param>
public sealed record SecurityAuditSection(string Key, string RestPath, bool Singleton, string ConsolePath);

/// <summary>The menu set of the security audit.</summary>
public static class SecurityAuditSections
{
	private static SecurityAuditSection Section(string key, string restPath, string consolePath, bool singleton)
		=> new(key, restPath, singleton, consolePath);

	/// <summary>
	/// Every menu the catalogue can need. Ordering is the read order: the cheap identity/resource
	/// reads come first so a failed run still produces a pasport with the device name in it.
	/// </summary>
	public static IReadOnlyList<SecurityAuditSection> All { get; } =
	[
		Section("identity", "system/identity", "/system/identity", true),
		Section("resource", "system/resource", "/system/resource", true),
		Section("routerboard", "system/routerboard", "/system/routerboard", true),
		Section("clock", "system/clock", "/system/clock", true),
		Section("ntp", "system/ntp/client", "/system/ntp/client", true),
		Section("note", "system/note", "/system/note", true),
		Section("watchdog", "system/watchdog", "/system/watchdog", true),
		Section("services", "ip/service", "/ip/service", false),
		Section("users", "user", "/user", false),
		Section("groups", "user/group", "/user/group", false),
		Section("addresses", "ip/address", "/ip/address", false),
		Section("routes", "ip/route", "/ip/route", false),
		Section("dns", "ip/dns", "/ip/dns", true),
		Section("fw_filter", "ip/firewall/filter", "/ip/firewall/filter", false),
		Section("fw_nat", "ip/firewall/nat", "/ip/firewall/nat", false),
		Section("service_ports", "ip/firewall/service-port", "/ip/firewall/service-port", false),
		Section("snmp", "snmp", "/snmp", true),
		Section("snmp_community", "snmp/community", "/snmp/community", false),
		Section("mac_server", "tool/mac-server", "/tool/mac-server", true),
		Section("bandwidth_server", "tool/bandwidth-server", "/tool/bandwidth-server", true),
		Section("neighbor_discovery", "ip/neighbor/discovery-settings", "/ip/neighbor/discovery-settings", true),
		Section("socks", "ip/socks", "/ip/socks", true),
		Section("upnp", "ip/upnp", "/ip/upnp", true),
		Section("smb", "ip/smb", "/ip/smb", true),
		Section("cloud", "ip/cloud", "/ip/cloud", true),
		Section("romon", "tool/romon", "/tool/romon", true),
		Section("ssh_settings", "ip/ssh", "/ip/ssh", true),
		Section("certificates", "certificate", "/certificate", false),
		Section("packages", "system/package", "/system/package", false),
		Section("logging", "system/logging", "/system/logging", false),
		Section("logging_action", "system/logging/action", "/system/logging/action", false),
		Section("netwatch", "tool/netwatch", "/tool/netwatch", false),
		Section("ipv6_settings", "ipv6/settings", "/ipv6/settings", true),
		Section("ipv6_filter", "ipv6/firewall/filter", "/ipv6/firewall/filter", false),
		Section("wireless", "interface/wireless", "/interface/wireless", false),
		Section("wireless_profiles", "interface/wireless/security-profiles", "/interface/wireless/security-profiles", false),
		Section("containers", "container", "/container", false),
		Section("apps", "app", "/app", false),
		Section("scripts", "system/script", "/system/script", false),
		Section("scheduler", "system/scheduler", "/system/scheduler", false),
		Section("files", "file", "/file", false),
	];

	/// <summary>Finds a section by key, or null when the key is not part of the audit.</summary>
	public static SecurityAuditSection? Find(string key)
	{
		foreach (SecurityAuditSection section in All)
		{
			if (string.Equals(section.Key, key, StringComparison.Ordinal))
			{
				return section;
			}
		}
		return null;
	}
}
