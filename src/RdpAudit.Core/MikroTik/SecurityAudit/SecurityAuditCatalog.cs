// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditCatalog.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: The rule catalogue of the RouterOS security audit — one entry per check, carrying its
//          id, severity, menu, why-it-matters, what-to-do and autofix class. The catalogue is data,
//          not code: SecurityAuditEvaluator produces findings against it, and a drift test asserts
//          that every catalogue entry is reachable, that ids are unique and that the severity of
//          each id matches the weights the report relies on.
//          Ported from the Python reference (rosctl/security.py, rules S-00…S-35 plus S-27b) on
//          23.10.2026. Behaviour, thresholds and the autofix classes are the reference's; the text
//          is English because every operator-facing string in this product is English-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>The rule catalogue.</summary>
public static class SecurityAuditCatalog
{
	private static SecurityAuditRule Rule(
		string id,
		SecurityAuditSeverity severity,
		string menu,
		string title,
		string why,
		string recommendation,
		SecurityAuditAutofix autofix)
		=> new(id, severity, menu, title, why, recommendation, autofix);

	/// <summary>Every rule, in id order. The evaluator must be able to raise each of them.</summary>
	public static IReadOnlyList<SecurityAuditRule> All { get; } =
	[
		Rule(
			"S-00", SecurityAuditSeverity.High, "(unread)",
			"Menu could not be read, so its rules were not evaluated",
			"Rules over a menu that could not be read have NOT run; the absence of findings there means nothing.",
			"Repeat the audit with sufficient rights, or record the reason by hand.",
			SecurityAuditAutofix.None),

		Rule(
			"S-01", SecurityAuditSeverity.Critical, "/user",
			"Full administrator accepts connections from any address",
			"Anyone who learns the password signs in from any address: the address restriction is the second factor that is missing here.",
			"Restrict the account to the management network: /user set [find name=<name>] address=<mgmt-nets>.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-02", SecurityAuditSeverity.High, "/user",
			"Account with the factory name admin is present",
			"admin is the first name every scanner tries; attempts blend into legitimate activity in the log.",
			"Create an account under another name, verify sign-in, then disable admin. Never done automatically: a password typo in the new account locks the device out.",
			SecurityAuditAutofix.Risky),

		Rule(
			"S-03", SecurityAuditSeverity.Medium, "/user",
			"Only one account holds full rights",
			"A wrong password or an over-tight address restriction leaves the device without management until a physical reset.",
			"Keep a second full account as the way out of a lockout (the wizard's user-ensure --emergency does this).",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-04", SecurityAuditSeverity.Critical, "/ip/service",
			"FTP server is enabled",
			"FTP sends the password in clear text and has no remaining use on RouterOS v7.",
			"Disable it: /ip/service disable [find name=ftp].",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-05", SecurityAuditSeverity.Critical, "/ip/service",
			"Telnet is enabled",
			"Telnet sends the password in clear text.",
			"Disable it: /ip/service disable [find name=telnet].",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-06", SecurityAuditSeverity.High, "/ip/service",
			"HTTP management interface is enabled",
			"Password and session travel unencrypted, and the interface is visible to scanners.",
			"Disable it: /ip/service disable [find name=www].",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-07", SecurityAuditSeverity.High, "/ip/service",
			"API without TLS is enabled",
			"The binary API without TLS carries the user name and password in clear text. Disabling it can cut the very channel the tool is using, so it is never automatic.",
			"Disable only while api-ssl or ssh stays reachable: /ip/service disable [find name=api].",
			SecurityAuditAutofix.Risky),

		Rule(
			"S-08", SecurityAuditSeverity.High, "/ip/service",
			"Management service accepts connections from any address",
			"A management service reachable from any network that routes to the device is exposed to the whole internet path.",
			"Restrict it: /ip/service set [find name=<service>] address=<mgmt-nets>.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-09", SecurityAuditSeverity.Medium, "/ip/service",
			"reverse-proxy service is enabled",
			"The service listens on 443 and is not bound to any container — pure attack surface.",
			"Disable it when no container needs it: /ip/service disable [find name=reverse-proxy].",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-10", SecurityAuditSeverity.Low, "/tool/bandwidth-server",
			"Bandwidth-test server is enabled",
			"Anyone who knows the address can generate traffic through the device.",
			"Disable the server: /tool bandwidth-server set enabled=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-11", SecurityAuditSeverity.Low, "/tool/mac-server",
			"MAC server and MAC-Winbox are allowed on every interface",
			"MAC-based management (MAC-telnet, MAC-WinBox) is reachable from any port, including the WAN.",
			"Limit it to the LAN list: /tool mac-server set allowed-interface-list=LAN.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-12", SecurityAuditSeverity.Low, "/ip/neighbor/discovery-settings",
			"Neighbour discovery is open on every interface",
			"MNDP/LLDP/CDP hand out model, version and device name to everyone in the segment.",
			"Limit it to the LAN list: /ip/neighbor discovery-settings set discover-interface-list=LAN.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-13", SecurityAuditSeverity.High, "/ip/socks",
			"SOCKS proxy is enabled",
			"An open proxy for the whole network and for anyone outside it.",
			"Disable it: /ip socks set enabled=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-14", SecurityAuditSeverity.High, "/ip/upnp",
			"UPnP is enabled",
			"Any device in the network can open ports to the outside on its own.",
			"Disable it: /ip upnp set enabled=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-15", SecurityAuditSeverity.High, "/ip/smb",
			"SMB shares are enabled",
			"The device serves files over SMB: network access to the router's flash.",
			"Disable it: /ip smb set enabled=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-16", SecurityAuditSeverity.Medium, "/tool/romon",
			"RoMON is enabled",
			"A separate management protocol that is easy to forget about.",
			"Disable it: /tool romon set enabled=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-17", SecurityAuditSeverity.Medium, "/ip/cloud",
			"IP Cloud (DDNS) is enabled",
			"The device publishes its name and external address to MikroTik's cloud: existence and address are visible to a third party.",
			"RouterOS 7.23 rejects ddns-enabled=no (\"must be either yes or auto\"), so disable it in WebFig by hand.",
			SecurityAuditAutofix.None),

		Rule(
			"S-18", SecurityAuditSeverity.High, "/snmp/community",
			"SNMP community is open to any network",
			"SNMP v1/v2c is neither encrypted nor authenticated: the community string is a clear-text password.",
			"Narrow the addresses to the monitoring host: /snmp community set [find name=<name>] addresses=<mgmt-nets>.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-19", SecurityAuditSeverity.Medium, "/ip/dns",
			"Device answers DNS requests from the network",
			"An open recursive resolver is used for DNS amplification, and its cache and log belong to someone else.",
			"Disable it when another server provides DNS: /ip dns set allow-remote-requests=no.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-20", SecurityAuditSeverity.Critical, "/ip/firewall/filter",
			"Input chain has no default policy (no drop)",
			"Everything not explicitly denied is allowed: management and discovery services are open to any source that can reach them.",
			"Add to the end of input: accept established,related; drop invalid; accept from MGMT; drop all. Rule order is the owner's decision and is never applied automatically.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-21", SecurityAuditSeverity.High, "/ip/firewall/filter",
			"Forward traffic is not restricted",
			"The network behind the router is not isolated: traffic between segments and to the outside flows without a policy.",
			"Add accept established,related and a final drop in forward. This requires knowing the network layout.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-22", SecurityAuditSeverity.Medium, "/ip/firewall/filter",
			"No password-guessing protection on management services",
			"Password guessing against ssh/winbox/api is not limited by attempt count or time.",
			"Add \"4 attempts per minute -> list for a day\" plus a drop on that list in input. Not automatic: thresholds are a decision.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-23", SecurityAuditSeverity.High, "/ipv6/firewall/filter",
			"IPv6 is enabled but has no input policy",
			"IPv6 is often enabled by default and left uncovered: fe80::/64 and global addresses bypass the IPv4 policy.",
			"Either disable IPv6 entirely, or repeat the input policy in /ipv6/firewall/filter.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-24", SecurityAuditSeverity.Medium, "/ip/ssh",
			"SSH runs without strong-crypto",
			"Weak key-exchange algorithms and ciphers stay enabled; with strong-crypto=yes RouterOS moves off rsa 2048.",
			"Enable it: /ip ssh set strong-crypto=yes (sessions reconnect).",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-25", SecurityAuditSeverity.Medium, "/ip/service",
			"www-ssl serves without a dedicated certificate",
			"A client cannot verify the device: REST and WebFig run on a self-signed or temporary certificate.",
			"Import a certificate and bind it: /ip/service set www-ssl certificate=<name>.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-26", SecurityAuditSeverity.Medium, "/system/routerboard",
			"RouterBOOT firmware is older than the installed RouterOS",
			"RouterBOOT is the bootloader: updating it closes pre-boot vulnerabilities and fixes compatibility with newer RouterOS.",
			"Run /system routerboard upgrade, then /system reboot. Needs a maintenance window; never automatic.",
			SecurityAuditAutofix.None),

		Rule(
			"S-27", SecurityAuditSeverity.Medium, "/system/ntp/client",
			"NTP client is disabled",
			"Time drifts: certificates look expired, logs and event correlation lose their order, and time-based blocks become wrong.",
			"Enable it with servers by IP: /system ntp client set enabled=yes servers=<ntp-servers>.",
			SecurityAuditAutofix.Auto),

		Rule(
			"S-27b", SecurityAuditSeverity.Medium, "/system/clock",
			"Device clock drifts from local time",
			"With this skew certificate validity and block windows are wrong; the cause is often the time zone rather than the clock.",
			"Check the time zone and NTP synchronisation.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-28", SecurityAuditSeverity.Low, "/system/logging/action",
			"Logs never leave the device",
			"After a reboot or an attack the log exists only on the device — and that is exactly what gets wiped first.",
			"Configure a remote (syslog) action to a collector and send topics=critical,error,warning there.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-29", SecurityAuditSeverity.Critical, "/system/script",
			"Credentials are stored in scripts or the scheduler",
			"A script is readable by anyone with read access, lands in exports and in backups. The value itself is never printed in this report.",
			"Move the secret to a limited-privilege account or use keys instead of a password, then rewrite the script.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-30", SecurityAuditSeverity.High, "/file",
			"Configuration backups and exports are left on flash",
			"/export show-sensitive and .backup files contain passwords, WireGuard keys and certificates: a ready kit for whoever reaches the files.",
			"Download the copies to a workstation and remove them from the device: /file remove [find name~\".(backup|rsc)$\"].",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-31", SecurityAuditSeverity.Medium, "/system/note",
			"/system note carries text",
			"The note often collects Wi-Fi passwords, addresses and accounts: it is visible in every export and on the login screen.",
			"Read it and clear it: /system note set note=\"\".",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-32", SecurityAuditSeverity.Low, "/ip/firewall/service-port",
			"NAT helpers (service-port) are enabled",
			"Helpers open dynamic ports around the static policy and rewrite traffic content.",
			"Disable the ones you do not need: /ip/firewall/service-port disable [find name=ftp].",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-33", SecurityAuditSeverity.High, "/interface/wireless/security-profiles",
			"A wireless profile without encryption is used by an enabled interface",
			"An open access point: anyone in radio range joins the network without a password.",
			"Switch the profile to WPA2/WPA3: /interface wireless security-profiles set [find name=<name>] mode=dynamic-keys.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-34", SecurityAuditSeverity.Medium, "/container",
			"Containers are present on the device",
			"A container is a full process with access to the device network; images and environment variables need their own control.",
			"Review images and environment variables, and bound resources and network access.",
			SecurityAuditAutofix.Manual),

		Rule(
			"S-35", SecurityAuditSeverity.Info, "/system/watchdog",
			"No automatic link recovery is configured",
			"After a lost route or a hung tunnel the device does not come back on its own. This is availability, not a vulnerability.",
			"Configure watch-address or netwatch with a reboot action when the site is critical.",
			SecurityAuditAutofix.None),
	];

	/// <summary>Looks a rule up by id. Returns null for an unknown id — the evaluator may not invent rules.</summary>
	public static SecurityAuditRule? Find(string id)
	{
		foreach (SecurityAuditRule rule in All)
		{
			if (string.Equals(rule.Id, id, System.StringComparison.Ordinal))
			{
				return rule;
			}
		}
		return null;
	}
}
