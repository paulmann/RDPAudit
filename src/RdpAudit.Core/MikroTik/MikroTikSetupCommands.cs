// File:    src/RdpAudit.Core/MikroTik/MikroTikSetupCommands.cs
// Module:  RdpAudit.Core.MikroTik
// Purpose: Pure helper that exposes the RouterOS v7 shell command bundle used by the
//          Configurator MikroTik tab. The bundle is split into named sections so unit tests can
//          assert that required placeholders are present and that no plaintext secret values are
//          ever embedded. Operators substitute the placeholders before pasting into Winbox /
//          terminal — the helper itself only emits placeholder tokens.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using System.Text;

namespace RdpAudit.Core.MikroTik;

/// <summary>Builds the RouterOS v7 shell command bundle shown on the Configurator MikroTik tab.</summary>
public static class MikroTikSetupCommands
{
	/// <summary>Placeholder for the RdpAudit host IP literal. Operators substitute before pasting.</summary>
	public const string HostPlaceholder = "<RDPAUDIT-HOST-IP>";

	/// <summary>Placeholder for the strong password chosen by the operator.</summary>
	public const string PasswordPlaceholder = "<STRONG-PASSWORD>";

	/// <summary>Placeholder for the imported HTTPS certificate name.</summary>
	public const string CertificatePlaceholder = "<rdpaudit-cert>";

	/// <summary>Section header text emitted at the top of the bundle.</summary>
	public const string BundleHeader = "# RdpAudit — RouterOS v7 setup";

	/// <summary>
	/// Address-list the blocking contour is built on. Kept equal to
	/// <see cref="Config.MikroTikOptions.AddressList"/>'s default on purpose: the bundle and the
	/// Service must name the same list, or the contour silently protects nothing. A test asserts the
	/// equality, so changing one without the other turns red.
	/// </summary>
	public const string DefaultAddressList = "rdpaudit-block";

	/// <summary>Builds the full setup bundle as a single CRLF-delimited string.</summary>
	public static string BuildAll()
	{
		StringBuilder sb = new();
		foreach (string line in EnumerateLines())
		{
			sb.Append(line).Append("\r\n");
		}

		return sb.ToString();
	}

	/// <summary>Enumerates the lines of the setup bundle without trailing newlines.</summary>
	public static IEnumerable<string> EnumerateLines()
	{
		yield return BundleHeader;
		yield return "# Replace " + HostPlaceholder + " with the IP of the RdpAudit host,";
		yield return "# and " + PasswordPlaceholder + " with a long random password (>= 24 chars).";
		yield return string.Empty;

		yield return "# 1. Create a least-privilege group: REST + firewall write access only,";
		yield return "#    nothing else (no ssh, ftp, winbox, web, policy, password, sniff, sensitive, romon).";
		yield return "/user/group/add name=rdpaudit \\";
		yield return "    policy=read,write,api,rest-api,!ssh,!ftp,!telnet,!winbox,!web,!policy,!password,!sniff,!sensitive,!romon";
		yield return string.Empty;

		yield return "# 2. Create the dedicated service user. Substitute " + PasswordPlaceholder + ".";
		yield return "#    address= is not optional: a full account without an address restriction is the";
		yield return "#    S-01 finding (critical) of this product's own RouterOS audit.";
		yield return "/user/add group=rdpaudit name=rdpaudit \\";
		yield return "    password=\"" + PasswordPlaceholder + "\" \\";
		yield return "    address=" + HostPlaceholder + "/32 \\";
		yield return "    comment=\"RdpAudit service account\"";
		yield return string.Empty;

		yield return "# 3. Enable the REST endpoint. Prefer www-ssl in production; www is acceptable for lab only.";
		yield return "/ip/service/set www-ssl disabled=no";
		yield return "# Lab fallback (HTTP — no TLS, do NOT use over untrusted networks):";
		yield return "# /ip/service/set www disabled=no";
		yield return string.Empty;

		yield return "# 4. Restrict allowed-address on the REST service so only the RdpAudit host";
		yield return "#    can authenticate. Replace " + HostPlaceholder + ".";
		yield return "/ip/service/set www-ssl address=" + HostPlaceholder + "/32";
		yield return "# Lab fallback (HTTP):";
		yield return "# /ip/service/set www  address=" + HostPlaceholder + "/32";
		yield return string.Empty;

		yield return "# 5. Production HTTPS certificate. Import a certificate first (/certificate/import),";
		yield return "#    then bind it to the REST service and pin the minimum TLS version.";
		yield return "# /ip/service/set www-ssl certificate=" + CertificatePlaceholder + " tls-version=only-1.2";
		yield return string.Empty;

		yield return "# 6. Verification — REST endpoint reachable, user provisioned, RdpAudit-owned";
		yield return "#    firewall filter rules visible (none yet on a fresh install).";
		yield return "/ip/service/print where name~\"www\"";
		yield return "/user/print where name=rdpaudit";
		yield return "/ip/firewall/filter/print where comment~\"^RdpAudit\"";
		yield return string.Empty;
		yield return "# 7. Blocking contour. The Service inserts one filter rule per attacker by default";
		yield return "#    (src-address + place-before=0), so nothing else is required for it to work.";
		yield return "#    The contour below is what the standalone wizard installs: one address-list plus a";
		yield return "#    single drop rule. Install it if you prefer list-driven blocking.";
		yield return "#    Placement decides what is protected — read both lines:";
		yield return "#      chain=forward drops attacker traffic aimed at the HOSTS behind the router;";
		yield return "#      chain=input   drops traffic aimed at the ROUTER itself, and nothing else.";
		yield return "/ip/firewall/address-list/add list=" + DefaultAddressList + " address=" + HostPlaceholder + " timeout=00:01:00 comment=\"RdpAudit list anchor\"";
		yield return "/ip/firewall/filter/add chain=forward action=drop src-address-list=" + DefaultAddressList + " comment=\"RdpAudit block list\" place-before=0";
		yield return "#    Use /ip/firewall/raw add chain=prerouting ... instead of filter when fasttrack is on.";
	}
}
