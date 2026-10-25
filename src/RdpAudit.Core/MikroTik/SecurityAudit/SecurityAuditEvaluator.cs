// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditEvaluator.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: The checks themselves: pure functions over MikroTikSecuritySnapshot that produce a
//          SecurityAuditReport. Nothing here touches HTTP, the clock or the file system, so every
//          rule is covered by xunit against a fabricated snapshot — a security rule that can only
//          be proven on a live router is a rule nobody regression-tests.
//
//          Two behaviours are deliberate and differ from the Python reference:
//          • a rule whose menu is absent on the device (package not installed) or unreadable does
//            not fire; the unreadable case is reported once as S-00, so silence never reads as
//            "compliant";
//          • the SNMP community string and the note text are never printed — the reference prints
//            the community name, which is the password itself in v1/v2c.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>Runs the rule catalogue over one snapshot.</summary>
public static class SecurityAuditEvaluator
{
	/// <summary>Credential-looking assignment inside a script body. The value is never captured for the report.</summary>
	private static readonly Regex CredentialAssignment = new(
		@"\b(password|passwd|pwd|secret|token|api-?key|private-?key|pre-shared-key)\s*=",
		RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
		TimeSpan.FromSeconds(2));

	/// <summary>Address-list names that look like a ban list; S-22 treats any of them as brute-force protection.</summary>
	private static readonly Regex BanListName = new(
		@"(ban|black|block|drop)",
		RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
		TimeSpan.FromSeconds(2));

	/// <summary>Evaluates every check and returns the report in presentation order.</summary>
	/// <param name="snapshot">Facts read from the device. Never null.</param>
	/// <param name="profile">Operator profile; defaults are the reference implementation's.</param>
	/// <param name="nowLocal">Local time used by S-27b; null disables the clock-skew check (as in the reference).</param>
	public static SecurityAuditReport Evaluate(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile? profile = null,
		DateTime? nowLocal = null)
	{
		ArgumentNullException.ThrowIfNull(snapshot);
		profile ??= new SecurityAuditProfile();

		List<SecurityAuditFinding> findings = new();

		AddUnreadMenus(snapshot, findings);
		AddAccountFindings(snapshot, profile, findings);
		AddServiceFindings(snapshot, profile, findings);
		AddUnneededServiceFindings(snapshot, profile, findings);
		AddNetworkFindings(snapshot, profile, findings);
		AddPlatformFindings(snapshot, profile, nowLocal, findings);
		AddSecretFindings(snapshot, findings);

		findings.Sort(static (left, right) =>
		{
			int bySeverity = ((int)left.Severity).CompareTo((int)right.Severity);
			if (bySeverity != 0)
			{
				return bySeverity;
			}

			int byId = string.CompareOrdinal(left.RuleId, right.RuleId);
			return byId != 0 ? byId : string.CompareOrdinal(left.Evidence, right.Evidence);
		});

		return new SecurityAuditReport
		{
			DeviceName = snapshot.DeviceName,
			RouterOsVersion = snapshot.RouterOsVersion,
			BoardName = snapshot.BoardName,
			Uptime = snapshot.Uptime,
			CapturedUtc = snapshot.CapturedUtc,
			Findings = findings,
			UnavailableMenus = snapshot.UnavailableMenus.OrderBy(k => k, StringComparer.Ordinal).ToList(),
		};
	}

	// ── S-00: unread menus ───────────────────────────────────────────────────────

	private static void AddUnreadMenus(MikroTikSecuritySnapshot snapshot, List<SecurityAuditFinding> findings)
	{
		foreach (KeyValuePair<string, string> error in snapshot.Errors.OrderBy(pair => pair.Key, StringComparer.Ordinal))
		{
			findings.Add(Build(
				"S-00",
				subject: error.Key,
				evidence: string.Format(CultureInfo.InvariantCulture, "{0} :: {1}", error.Key, error.Value)));
		}
	}

	// ── S-01..S-03: accounts ─────────────────────────────────────────────────────

	private static void AddAccountFindings(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile profile,
		List<SecurityAuditFinding> findings)
	{
		if (!Usable(snapshot, "users"))
		{
			return;
		}

		int fullAccounts = 0;
		foreach (IReadOnlyDictionary<string, string> user in snapshot.Rows("users"))
		{
			string name = MikroTikSecuritySnapshot.Field(user, "name");
			string group = MikroTikSecuritySnapshot.Field(user, "group");
			string address = MikroTikSecuritySnapshot.Field(user, "address").Trim();
			if (string.Equals(group, "full", StringComparison.OrdinalIgnoreCase))
			{
				fullAccounts++;
			}

			if (string.Equals(name, profile.BackupUser, StringComparison.Ordinal))
			{
				continue;
			}

			if (string.Equals(group, "full", StringComparison.OrdinalIgnoreCase) && address.Length == 0)
			{
				findings.Add(Build(
					"S-01",
					subject: name,
					evidence: string.Format(CultureInfo.InvariantCulture, "/user :: {0} group=full address=\"\"", name),
					commands: [string.Format(CultureInfo.InvariantCulture, "/user set [find name={0}] address={1}", name, profile.ManagementNetworks)]));
			}

			if (string.Equals(name, "admin", StringComparison.OrdinalIgnoreCase))
			{
				findings.Add(Build(
					"S-02",
					subject: name,
					evidence: string.Format(
						CultureInfo.InvariantCulture,
						"/user :: admin group={0} disabled={1}",
						group,
						MikroTikSecuritySnapshot.Field(user, "disabled")),
					commands:
					[
						string.Format(CultureInfo.InvariantCulture, "/user add name=<new-name> group=full password=<password> address={0}", profile.ManagementNetworks),
						"/user disable [find name=admin]",
					]));
			}
		}

		if (fullAccounts < 2)
		{
			findings.Add(Build(
				"S-03",
				subject: string.Empty,
				evidence: string.Format(CultureInfo.InvariantCulture, "/user :: accounts with group=full: {0}", fullAccounts)));
		}
	}

	// ── S-04..S-12: management services ─────────────────────────────────────────

	private static void AddServiceFindings(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile profile,
		List<SecurityAuditFinding> findings)
	{
		(string Name, string RuleId)[] switches =
		[
			("ftp", "S-04"),
			("telnet", "S-05"),
			("www", "S-06"),
			("api", "S-07"),
			("reverse-proxy", "S-09"),
		];

		foreach ((string name, string ruleId) in switches)
		{
			List<IReadOnlyDictionary<string, string>> enabled = ServiceRows(snapshot, name);
			if (enabled.Count == 0)
			{
				continue;
			}

			findings.Add(Build(
				ruleId,
				subject: name,
				evidence: string.Format(
					CultureInfo.InvariantCulture,
					"/ip/service :: {0} disabled=false port={1}",
					name,
					MikroTikSecuritySnapshot.Field(enabled[0], "port")),
				commands: [string.Format(CultureInfo.InvariantCulture, "/ip/service disable [find name={0}]", name)]));
		}

		foreach (string name in new[] { "ssh", "winbox", "api-ssl" })
		{
			List<IReadOnlyDictionary<string, string>> open = ServiceRows(snapshot, name)
				.Where(row => MikroTikSecuritySnapshot.Field(row, "address").Trim().Length == 0)
				.ToList();
			if (open.Count == 0)
			{
				continue;
			}

			findings.Add(Build(
				"S-08",
				subject: name,
				evidence: string.Format(CultureInfo.InvariantCulture, "/ip/service :: {0} disabled=false address=\"\"", name),
				commands: [string.Format(CultureInfo.InvariantCulture, "/ip/service set [find name={0}] address={1}", name, profile.ManagementNetworks)]));
		}

		if (Usable(snapshot, "bandwidth_server") && MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(snapshot.Single("bandwidth_server"), "enabled")))
		{
			findings.Add(Build(
				"S-10",
				subject: string.Empty,
				evidence: "/tool/bandwidth-server :: enabled=true",
				commands: ["/tool bandwidth-server set enabled=no"]));
		}

		if (Usable(snapshot, "mac_server")
			&& string.Equals(MikroTikSecuritySnapshot.Field(snapshot.Single("mac_server"), "allowed-interface-list").Trim(), "all", StringComparison.OrdinalIgnoreCase))
		{
			findings.Add(Build(
				"S-11",
				subject: string.Empty,
				evidence: "/tool/mac-server :: allowed-interface-list=all",
				commands: ["/tool mac-server set allowed-interface-list=LAN"]));
		}

		if (Usable(snapshot, "neighbor_discovery"))
		{
			string scope = MikroTikSecuritySnapshot.Field(snapshot.Single("neighbor_discovery"), "discover-interface-list").Trim();
			if (string.Equals(scope, "all", StringComparison.OrdinalIgnoreCase)
				|| string.Equals(scope, "*all", StringComparison.OrdinalIgnoreCase))
			{
				findings.Add(Build(
					"S-12",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/ip/neighbor/discovery-settings :: discover-interface-list={0}", scope),
					commands: ["/ip/neighbor discovery-settings set discover-interface-list=LAN"]));
			}
		}

	}

	private static List<IReadOnlyDictionary<string, string>> ServiceRows(MikroTikSecuritySnapshot snapshot, string name)
	{
		List<IReadOnlyDictionary<string, string>> rows = new();
		if (!Usable(snapshot, "services"))
		{
			return rows;
		}

		foreach (IReadOnlyDictionary<string, string> row in snapshot.Rows("services"))
		{
			if (string.Equals(MikroTikSecuritySnapshot.Field(row, "name"), name, StringComparison.Ordinal)
				&& MikroTikSecuritySnapshot.Enabled(row))
			{
				rows.Add(row);
			}
		}
		return rows;
	}

	// ── S-13..S-18: unneeded services and SNMP ──────────────────────────────────

	private static void AddUnneededServiceFindings(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile profile,
		List<SecurityAuditFinding> findings)
	{
		(string Section, string RuleId, string ConsolePath, string Command)[] switches =
		[
			("socks", "S-13", "/ip/socks", "/ip socks set enabled=no"),
			("upnp", "S-14", "/ip/upnp", "/ip upnp set enabled=no"),
			("romon", "S-16", "/tool/romon", "/tool romon set enabled=no"),
		];

		foreach ((string section, string ruleId, string consolePath, string command) in switches)
		{
			if (!Usable(snapshot, section)
				|| !MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(snapshot.Single(section), "enabled")))
			{
				continue;
			}

			findings.Add(Build(
				ruleId,
				subject: string.Empty,
				evidence: string.Format(CultureInfo.InvariantCulture, "{0} :: enabled=true", consolePath),
				commands: [command]));
		}

		if (Usable(snapshot, "smb"))
		{
			IReadOnlyDictionary<string, string> smb = snapshot.Single("smb");
			string status = MikroTikSecuritySnapshot.Field(smb, "status").Trim();
			string enabled = MikroTikSecuritySnapshot.Field(smb, "enabled").Trim();
			bool disabledByStatus = string.Equals(status, "disabled", StringComparison.OrdinalIgnoreCase) || status.Length == 0;
			if (!disabledByStatus && !string.Equals(enabled, "no", StringComparison.OrdinalIgnoreCase))
			{
				findings.Add(Build(
					"S-15",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/ip/smb :: enabled={0} status={1}", enabled, status),
					commands: ["/ip smb set enabled=no"]));
			}
		}

		if (Usable(snapshot, "cloud"))
		{
			string ddns = MikroTikSecuritySnapshot.Field(snapshot.Single("cloud"), "ddns-enabled").Trim();
			if (string.Equals(ddns, "yes", StringComparison.OrdinalIgnoreCase)
				|| string.Equals(ddns, "true", StringComparison.OrdinalIgnoreCase)
				|| string.Equals(ddns, "auto", StringComparison.OrdinalIgnoreCase))
			{
				bool hardOn = string.Equals(ddns, "yes", StringComparison.OrdinalIgnoreCase)
					|| string.Equals(ddns, "true", StringComparison.OrdinalIgnoreCase);
				findings.Add(Build(
					"S-17",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/ip/cloud :: ddns-enabled={0}", ddns),
					severity: hardOn ? SecurityAuditSeverity.Medium : SecurityAuditSeverity.Info));
			}
		}

		if (!Usable(snapshot, "snmp") || !MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(snapshot.Single("snmp"), "enabled")))
		{
			return;
		}

		int index = 0;
		foreach (IReadOnlyDictionary<string, string> community in snapshot.Rows("snmp_community"))
		{
			index++;
			string addresses = MikroTikSecuritySnapshot.Field(community, "addresses").Trim();
			bool unrestricted = addresses.Length == 0
				|| string.Equals(addresses, "::/0", StringComparison.Ordinal)
				|| string.Equals(addresses, "0.0.0.0/0", StringComparison.Ordinal);
			if (!unrestricted)
			{
				continue;
			}

			// The community string IS the password in SNMP v1/v2c, so the report names the entry by
			// its position and never prints the value itself.
			findings.Add(Build(
				"S-18",
				subject: string.Format(CultureInfo.InvariantCulture, "community #{0}", index),
				evidence: string.Format(
					CultureInfo.InvariantCulture,
					"/snmp/community :: name=<redacted> addresses={0} security={1}",
					addresses.Length == 0 ? "(empty)" : addresses,
					MikroTikSecuritySnapshot.Field(community, "security")),
				commands: [string.Format(CultureInfo.InvariantCulture, "/snmp community set [find name=<name>] addresses={0}", profile.ManagementNetworks)]));
		}
	}

	// ── S-19..S-23: network and firewall ────────────────────────────────────────

	private static void AddNetworkFindings(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile profile,
		List<SecurityAuditFinding> findings)
	{
		if (Usable(snapshot, "dns")
			&& MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(snapshot.Single("dns"), "allow-remote-requests")))
		{
			findings.Add(Build(
				"S-19",
				subject: string.Empty,
				evidence: "/ip/dns :: allow-remote-requests=true",
				commands: ["/ip dns set allow-remote-requests=no"]));
		}

		if (Usable(snapshot, "fw_filter"))
		{
			List<IReadOnlyDictionary<string, string>> filters = snapshot.Rows("fw_filter")
				.Where(MikroTikSecuritySnapshot.Enabled)
				.ToList();

			List<IReadOnlyDictionary<string, string>> inputRules = filters
				.Where(row => string.Equals(MikroTikSecuritySnapshot.Field(row, "chain"), "input", StringComparison.OrdinalIgnoreCase))
				.ToList();
			if (!inputRules.Any(row => string.Equals(MikroTikSecuritySnapshot.Field(row, "action"), "drop", StringComparison.OrdinalIgnoreCase)))
			{
				findings.Add(Build(
					"S-20",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/ip/firewall/filter :: chain=input, rules={0}, no drop", inputRules.Count),
					commands:
					[
						"/ip/firewall/filter add chain=input action=accept connection-state=established,related",
						"/ip/firewall/filter add chain=input action=drop connection-state=invalid",
						string.Format(CultureInfo.InvariantCulture, "/ip/firewall/filter add chain=input action=accept src-address={0}", profile.ManagementNetworks),
						"/ip/firewall/filter add chain=input action=drop",
					]));
			}

			List<IReadOnlyDictionary<string, string>> forwardRules = filters
				.Where(row => string.Equals(MikroTikSecuritySnapshot.Field(row, "chain"), "forward", StringComparison.OrdinalIgnoreCase))
				.ToList();
			bool hasEstablished = forwardRules.Any(row =>
				MikroTikSecuritySnapshot.Field(row, "connection-state").Contains("established", StringComparison.OrdinalIgnoreCase));
			bool hasForwardDrop = forwardRules.Any(row =>
				string.Equals(MikroTikSecuritySnapshot.Field(row, "action"), "drop", StringComparison.OrdinalIgnoreCase));
			if (!hasEstablished || !hasForwardDrop)
			{
				List<string> missing = new();
				if (!hasEstablished)
				{
					missing.Add("accept established,related");
				}
				if (!hasForwardDrop)
				{
					missing.Add("drop");
				}

				findings.Add(Build(
					"S-21",
					subject: string.Empty,
					evidence: string.Format(
						CultureInfo.InvariantCulture,
						"/ip/firewall/filter :: chain=forward, missing: {0}",
						string.Join(", ", missing))));
			}

			bool bruteForceGuard = filters.Any(row => BanListName.IsMatch(MikroTikSecuritySnapshot.Field(row, "src-address-list")));
			if (!bruteForceGuard)
			{
				findings.Add(Build(
					"S-22",
					subject: string.Empty,
					evidence: "/ip/firewall/filter :: no rule uses a ban/blacklist src-address-list"));
			}
		}

		if (Usable(snapshot, "ipv6_settings")
			&& !MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(snapshot.Single("ipv6_settings"), "disable-ipv6")))
		{
			bool hasV6InputDrop = false;
			if (Usable(snapshot, "ipv6_filter"))
			{
				hasV6InputDrop = snapshot.Rows("ipv6_filter").Any(row =>
					MikroTikSecuritySnapshot.Enabled(row)
					&& string.Equals(MikroTikSecuritySnapshot.Field(row, "chain"), "input", StringComparison.OrdinalIgnoreCase)
					&& string.Equals(MikroTikSecuritySnapshot.Field(row, "action"), "drop", StringComparison.OrdinalIgnoreCase));
			}

			if (!hasV6InputDrop)
			{
				findings.Add(Build(
					"S-23",
					subject: string.Empty,
					evidence: "/ipv6/settings :: disable-ipv6=false; /ipv6/firewall/filter :: no enabled input drop"));
			}
		}
	}

	// ── S-24..S-28: platform ────────────────────────────────────────────────────

	private static void AddPlatformFindings(
		MikroTikSecuritySnapshot snapshot,
		SecurityAuditProfile profile,
		DateTime? nowLocal,
		List<SecurityAuditFinding> findings)
	{
		if (Usable(snapshot, "ssh_settings"))
		{
			IReadOnlyDictionary<string, string> ssh = snapshot.Single("ssh_settings");
			if (ssh.Count > 0 && !MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(ssh, "strong-crypto")))
			{
				findings.Add(Build(
					"S-24",
					subject: string.Empty,
					evidence: string.Format(
						CultureInfo.InvariantCulture,
						"/ip/ssh :: strong-crypto={0} host-key-type={1} host-key-size={2}",
						MikroTikSecuritySnapshot.Field(ssh, "strong-crypto"),
						MikroTikSecuritySnapshot.Field(ssh, "host-key-type"),
						MikroTikSecuritySnapshot.Field(ssh, "host-key-size")),
					commands: ["/ip ssh set strong-crypto=yes"]));
			}
		}

		List<IReadOnlyDictionary<string, string>> wwwSsl = ServiceRows(snapshot, "www-ssl");
		if (wwwSsl.Count > 0 && MikroTikSecuritySnapshot.Field(wwwSsl[0], "certificate").Trim().Length == 0)
		{
			findings.Add(Build(
				"S-25",
				subject: string.Empty,
				evidence: "/ip/service :: www-ssl disabled=false certificate=\"\""));
		}

		if (Usable(snapshot, "routerboard"))
		{
			IReadOnlyDictionary<string, string> board = snapshot.Single("routerboard");
			string current = MikroTikSecuritySnapshot.Field(board, "current-firmware").Trim();
			string upgrade = MikroTikSecuritySnapshot.Field(board, "upgrade-firmware").Trim();
			if (current.Length > 0 && upgrade.Length > 0 && CompareVersions(current, upgrade) < 0)
			{
				findings.Add(Build(
					"S-26",
					subject: string.Format(CultureInfo.InvariantCulture, "{0} -> {1}", current, upgrade),
					evidence: string.Format(CultureInfo.InvariantCulture, "/system/routerboard :: current-firmware={0} upgrade-firmware={1}", current, upgrade),
					commands: ["/system routerboard upgrade", "/system reboot"]));
			}
		}

		if (Usable(snapshot, "ntp"))
		{
			IReadOnlyDictionary<string, string> ntp = snapshot.Single("ntp");
			if (!MikroTikSecuritySnapshot.Truthy(MikroTikSecuritySnapshot.Field(ntp, "enabled")))
			{
				findings.Add(Build(
					"S-27",
					subject: string.Empty,
					evidence: string.Format(
						CultureInfo.InvariantCulture,
						"/system/ntp/client :: enabled={0} servers={1}",
						MikroTikSecuritySnapshot.Field(ntp, "enabled"),
						MikroTikSecuritySnapshot.Field(ntp, "servers")),
					commands: [string.Format(CultureInfo.InvariantCulture, "/system ntp client set enabled=yes servers={0}", profile.NtpServers)]));
			}
			else if (nowLocal.HasValue && Usable(snapshot, "clock"))
			{
				IReadOnlyDictionary<string, string> clock = snapshot.Single("clock");
				DateTime? deviceTime = ParseRouterOsTime(
					MikroTikSecuritySnapshot.Field(clock, "date"),
					MikroTikSecuritySnapshot.Field(clock, "time"));
				if (deviceTime.HasValue)
				{
					double skew = Math.Abs((nowLocal.Value - deviceTime.Value).TotalSeconds);
					if (skew > profile.ClockToleranceSeconds)
					{
						findings.Add(Build(
							"S-27b",
							subject: string.Empty,
							evidence: string.Format(
								CultureInfo.InvariantCulture,
								"/system/clock :: {0} {1} (zone {2}, {3}); skew {4}s",
								MikroTikSecuritySnapshot.Field(clock, "date"),
								MikroTikSecuritySnapshot.Field(clock, "time"),
								MikroTikSecuritySnapshot.Field(clock, "time-zone-name"),
								MikroTikSecuritySnapshot.Field(clock, "gmt-offset"),
								(int)skew)));
					}
				}
			}
		}

		if (Usable(snapshot, "logging_action"))
		{
			IReadOnlyList<IReadOnlyDictionary<string, string>> actions = snapshot.Rows("logging_action");
			bool remote = actions.Any(row =>
			{
				string target = MikroTikSecuritySnapshot.Field(row, "target");
				if (target.Length == 0)
				{
					target = "memory";
				}
				return !string.Equals(target, "memory", StringComparison.OrdinalIgnoreCase)
					&& !string.Equals(target, "disk", StringComparison.OrdinalIgnoreCase)
					&& !string.Equals(target, "echo", StringComparison.OrdinalIgnoreCase);
			});

			if (!remote)
			{
				findings.Add(Build(
					"S-28",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/system/logging/action :: actions={0}, no remote target", actions.Count)));
			}
		}
	}

	// ── S-29..S-35: secrets, files, the rest ────────────────────────────────────

	private static void AddSecretFindings(MikroTikSecuritySnapshot snapshot, List<SecurityAuditFinding> findings)
	{
		bool scriptsUsable = Usable(snapshot, "scripts");
		bool schedulerUsable = Usable(snapshot, "scheduler");
		if (scriptsUsable || schedulerUsable)
		{
			List<string> exposed = new();
			CollectSecretUse(snapshot, scriptsUsable, "scripts", "script", exposed);
			CollectSecretUse(snapshot, schedulerUsable, "scheduler", "scheduler", exposed);
			if (exposed.Count > 0)
			{
				findings.Add(Build(
					"S-29",
					subject: string.Empty,
					evidence: "/system/script :: " + string.Join(", ", exposed)));
			}
		}

		if (Usable(snapshot, "files"))
		{
			List<string> backups = snapshot.Rows("files")
				.Select(row => MikroTikSecuritySnapshot.Field(row, "name"))
				.Where(name => name.EndsWith(".backup", StringComparison.OrdinalIgnoreCase)
					|| name.EndsWith(".rsc", StringComparison.OrdinalIgnoreCase))
				.ToList();
			if (backups.Count > 0)
			{
				string shown = string.Join(", ", backups.Take(5));
				if (backups.Count > 5)
				{
					shown += string.Format(CultureInfo.InvariantCulture, " (+{0})", backups.Count - 5);
				}

				findings.Add(Build(
					"S-30",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/file :: {0} files: {1}", backups.Count, shown),
					commands: ["/file remove [find name~\".(backup|rsc)$\"]"]));
			}
		}

		if (Usable(snapshot, "note"))
		{
			string note = MikroTikSecuritySnapshot.Field(snapshot.Single("note"), "note").Trim();
			if (note.Length > 0)
			{
				// Length only: the note is exactly where passwords end up.
				findings.Add(Build(
					"S-31",
					subject: string.Empty,
					evidence: string.Format(CultureInfo.InvariantCulture, "/system/note :: {0} characters", note.Length),
					commands: ["/system note print", "/system note set note=\"\""]));
			}
		}

		if (Usable(snapshot, "service_ports"))
		{
			List<string> helpers = snapshot.Rows("service_ports")
				.Where(MikroTikSecuritySnapshot.Enabled)
				.Select(row => MikroTikSecuritySnapshot.Field(row, "name"))
				.Where(name => name.Length > 0)
				.ToList();
			if (helpers.Count > 0)
			{
				findings.Add(Build(
					"S-32",
					subject: string.Empty,
					evidence: "/ip/firewall/service-port :: enabled " + string.Join(", ", helpers)));
			}
		}

		if (Usable(snapshot, "wireless_profiles"))
		{
			List<string> openProfiles = snapshot.Rows("wireless_profiles")
				.Where(row =>
				{
					string mode = MikroTikSecuritySnapshot.Field(row, "mode");
					if (mode.Length == 0)
					{
						mode = "none";
					}
					return string.Equals(mode, "none", StringComparison.OrdinalIgnoreCase)
						&& !string.Equals(MikroTikSecuritySnapshot.Field(row, "default"), "true", StringComparison.OrdinalIgnoreCase);
				})
				.Select(row => MikroTikSecuritySnapshot.Field(row, "name"))
				.Where(name => name.Length > 0)
				.ToList();

			bool wirelessInUse = Usable(snapshot, "wireless")
				&& snapshot.Rows("wireless").Any(MikroTikSecuritySnapshot.Enabled);
			if (openProfiles.Count > 0 && wirelessInUse)
			{
				findings.Add(Build(
					"S-33",
					subject: string.Empty,
					evidence: "/interface/wireless/security-profiles :: mode=none profiles: " + string.Join(", ", openProfiles)));
			}
		}

		if (Usable(snapshot, "containers") && snapshot.Rows("containers").Count > 0)
		{
			findings.Add(Build(
				"S-34",
				subject: string.Empty,
				evidence: string.Format(CultureInfo.InvariantCulture, "/container :: {0} entries", snapshot.Rows("containers").Count)));
		}

		if (Usable(snapshot, "watchdog"))
		{
			string watchAddress = MikroTikSecuritySnapshot.Field(snapshot.Single("watchdog"), "watch-address").Trim();
			if (watchAddress.Length == 0)
			{
				watchAddress = "none";
			}

			bool hasNetwatch = Usable(snapshot, "netwatch") && snapshot.Rows("netwatch").Count > 0;
			if (string.Equals(watchAddress, "none", StringComparison.OrdinalIgnoreCase) && !hasNetwatch)
			{
				findings.Add(Build(
					"S-35",
					subject: string.Empty,
					evidence: string.Format(
						CultureInfo.InvariantCulture,
						"/system/watchdog :: watch-address={0}, /tool/netwatch empty",
						watchAddress)));
			}
		}
	}

	private static void CollectSecretUse(
		MikroTikSecuritySnapshot snapshot,
		bool usable,
		string section,
		string label,
		List<string> exposed)
	{
		if (!usable)
		{
			return;
		}

		foreach (IReadOnlyDictionary<string, string> row in snapshot.Rows(section))
		{
			string text = MikroTikSecuritySnapshot.Field(row, "source") + " " + MikroTikSecuritySnapshot.Field(row, "on-event");
			Match match = CredentialAssignment.Match(text);
			if (!match.Success)
			{
				continue;
			}

			// Name and kind of secret only: the value must never reach the report or the log.
			exposed.Add(string.Format(
				CultureInfo.InvariantCulture,
				"{0}:{1} ({2})",
				label,
				MikroTikSecuritySnapshot.Field(row, "name"),
				match.Groups[1].Value.ToLowerInvariant()));
		}
	}

	// ── helpers ─────────────────────────────────────────────────────────────────

	private static bool Usable(MikroTikSecuritySnapshot snapshot, string key)
		=> snapshot.Has(key) && !snapshot.Failed(key) && !snapshot.Missing(key);

	private static SecurityAuditFinding Build(
		string ruleId,
		string subject,
		string evidence,
		IReadOnlyList<string>? commands = null,
		SecurityAuditSeverity? severity = null)
	{
		SecurityAuditRule rule = SecurityAuditCatalog.Find(ruleId)
			?? throw new InvalidOperationException("Unknown security audit rule: " + ruleId);

		string title = string.IsNullOrEmpty(subject) ? rule.Title : rule.Title + ": " + subject;
		return new SecurityAuditFinding
		{
			RuleId = rule.Id,
			Severity = severity ?? rule.Severity,
			Title = title,
			Menu = rule.Menu,
			Evidence = evidence,
			Why = rule.Why,
			Recommendation = rule.Recommendation,
			Autofix = rule.Autofix,
			Commands = commands ?? [],
		};
	}

	/// <summary>Compares RouterOS version strings the way the reference does: digits only, first four groups.</summary>
	internal static int CompareVersions(string left, string right)
	{
		int[] a = Digits(left);
		int[] b = Digits(right);
		for (int i = 0; i < 4; i++)
		{
			int delta = a[i].CompareTo(b[i]);
			if (delta != 0)
			{
				return delta;
			}
		}
		return 0;
	}

	private static int[] Digits(string text)
	{
		int[] result = new int[4];
		int index = 0;
		foreach (Match match in Regex.Matches(text ?? string.Empty, @"\d+"))
		{
			if (index >= 4)
			{
				break;
			}
			// The firmware strings come from the device, so a digit run longer than an int can hold
			// must not throw: an unparsable component degrades to 0, which compares as "older" and
			// surfaces as a finding instead of aborting the whole audit.
			result[index++] = int.TryParse(
				match.Value,
				NumberStyles.Integer,
				CultureInfo.InvariantCulture,
				out int component)
				? component
				: 0;
		}
		return result;
	}

	/// <summary>
	/// Parses the RouterOS clock pair. Two formats occur: the REST API returns ISO ("2026-10-20") and
	/// the console export returns "oct/20/2026"; an unusable value returns null rather than throwing,
	/// because a rule may not crash the audit.
	/// </summary>
	internal static DateTime? ParseRouterOsTime(string date, string time)
	{
		string dateText = (date ?? string.Empty).Trim();
		string timeText = (time ?? string.Empty).Trim();
		if (dateText.Length == 0 || timeText.Length == 0)
		{
			return null;
		}

		string[] timeParts = timeText.Split(':');
		if (timeParts.Length < 2
			|| !int.TryParse(timeParts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int hour)
			|| !int.TryParse(timeParts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int minute))
		{
			return null;
		}

		int second = 0;
		if (timeParts.Length >= 3)
		{
			int.TryParse(timeParts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out second);
		}

		string[] formats = ["yyyy-MM-dd", "MMM/d/yyyy", "MMM/dd/yyyy"];
		if (!DateTime.TryParseExact(
			dateText,
			formats,
			CultureInfo.InvariantCulture,
			DateTimeStyles.None,
			out DateTime parsedDate))
		{
			return null;
		}

		if (hour is < 0 or > 23 || minute is < 0 or > 59 || second is < 0 or > 59)
		{
			return null;
		}

		return new DateTime(parsedDate.Year, parsedDate.Month, parsedDate.Day, hour, minute, second, DateTimeKind.Unspecified);
	}
}
