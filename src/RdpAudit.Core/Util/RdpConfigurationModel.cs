// File:    src/RdpAudit.Core/Util/RdpConfigurationModel.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI- and OS-agnostic model describing the configurable Windows Terminal Services
//          surface that the new RDP Configuration tab manages — listener port, fDenyTSConnections,
//          UserAuthentication (NLA), SecurityLayer, fSingleSessionPerUser, the "hide users on
//          logon screen" policy values, and the Session Shadowing mode. The model contains only
//          enumeration / description helpers so it can be unit-tested without a live registry,
//          mirroring the pattern already used by <see cref="ShadowPolicyModel"/>.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Microsoft <c>UserAuthentication</c> (NLA toggle) semantics for the RDP-Tcp listener.</summary>
/// <remarks>
/// 0 = Network Level Authentication NOT required — clients may negotiate weaker auth (less safe).
/// 1 = Network Level Authentication required before a session is established (recommended).
/// </remarks>
public enum RdpUserAuthenticationMode
{
	Unknown = -1,
	NlaNotRequired = 0,
	NlaRequired = 1,
}

/// <summary>Microsoft <c>SecurityLayer</c> semantics for the RDP-Tcp listener.</summary>
/// <remarks>
/// 0 = RDP Security Layer (legacy, weakest).
/// 1 = Negotiate — the most secure layer supported by client/server is chosen at handshake time.
/// 2 = SSL/TLS — TLS is required for the channel (recommended).
/// </remarks>
public enum RdpSecurityLayerMode
{
	Unknown = -1,
	RdpSecurity = 0,
	Negotiate = 1,
	SslTls = 2,
}

/// <summary>Pure helpers describing the canonical Windows RDP configuration surface.</summary>
public static class RdpConfigurationModel
{
	/// <summary>HKLM-rooted Terminal Server key (per-machine).</summary>
	public const string TerminalServerKey =
		@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

	/// <summary>HKLM-rooted RDP-Tcp WinStation key (per-listener).</summary>
	public const string RdpTcpListenerKey =
		@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

	/// <summary>HKLM-rooted Winlogon key (per-machine, controls the logon UI behaviour).</summary>
	public const string WinlogonKey =
		@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI";

	/// <summary>HKLM-rooted System policy key — controls "Do not enumerate connected users" group policy.</summary>
	public const string SystemPolicyKey =
		@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

	/// <summary>HKLM-rooted Terminal Services policy key — shared with <see cref="ShadowPolicyModel"/>.</summary>
	public const string TerminalServicesPolicyKey =
		ShadowPolicyModel.TerminalServicesPolicyKey;

	/// <summary><c>PortNumber</c> DWORD under <see cref="RdpTcpListenerKey"/>.</summary>
	public const string PortNumberValueName = "PortNumber";

	/// <summary><c>fDenyTSConnections</c> DWORD under <see cref="TerminalServerKey"/> — 0 enabled, 1 disabled.</summary>
	public const string DenyTsConnectionsValueName = "fDenyTSConnections";

	/// <summary><c>fSingleSessionPerUser</c> DWORD under <see cref="TerminalServerKey"/>.</summary>
	public const string SingleSessionPerUserValueName = "fSingleSessionPerUser";

	/// <summary><c>UserAuthentication</c> DWORD under <see cref="RdpTcpListenerKey"/> — 1 NLA required, 0 not required.</summary>
	public const string UserAuthenticationValueName = "UserAuthentication";

	/// <summary><c>SecurityLayer</c> DWORD under <see cref="RdpTcpListenerKey"/> — 0/1/2 per Microsoft docs.</summary>
	public const string SecurityLayerValueName = "SecurityLayer";

	/// <summary><c>dontdisplaylastusername</c> DWORD under <see cref="SystemPolicyKey"/> — 1 hides last user.</summary>
	public const string DontDisplayLastUserNameValueName = "dontdisplaylastusername";

	/// <summary><c>DontEnumerateConnectedUsers</c> DWORD under <see cref="SystemPolicyKey"/> — 1 hides
	/// the connected-user picker on the logon screen.</summary>
	public const string DontEnumerateConnectedUsersValueName = "DontEnumerateConnectedUsers";

	/// <summary><c>fPromptForPassword</c> DWORD — when 1 the host always asks for credentials on
	/// every connection (server-side enforcement of the "Always prompt for password upon connection"
	/// policy). Lives under <see cref="TerminalServicesPolicyKey"/> when configured by Group Policy
	/// and under <see cref="RdpTcpListenerKey"/> as a per-listener fallback. The policy key is the
	/// authoritative source when present.</summary>
	public const string PromptForPasswordValueName = "fPromptForPassword";

	/// <summary>Default Windows RDP TCP port when no override has been written to the registry.</summary>
	public const int DefaultRdpPort = 3389;

	/// <summary>Lowest RFC-valid TCP port number. Validated by <see cref="IsValidPort"/>.</summary>
	public const int MinPort = 1;

	/// <summary>Highest RFC-valid TCP port number. Validated by <see cref="IsValidPort"/>.</summary>
	public const int MaxPort = 65535;

	/// <summary>True when the raw value represents a valid TCP port in the inclusive range 1..65535.</summary>
	public static bool IsValidPort(int value) => value >= MinPort && value <= MaxPort;

	/// <summary>Maps a raw <c>UserAuthentication</c> registry value to its enum.</summary>
	public static RdpUserAuthenticationMode AuthenticationFromRaw(int? raw) => raw switch
	{
		0 => RdpUserAuthenticationMode.NlaNotRequired,
		1 => RdpUserAuthenticationMode.NlaRequired,
		_ => RdpUserAuthenticationMode.Unknown,
	};

	/// <summary>Maps a raw <c>SecurityLayer</c> registry value to its enum.</summary>
	public static RdpSecurityLayerMode SecurityLayerFromRaw(int? raw) => raw switch
	{
		0 => RdpSecurityLayerMode.RdpSecurity,
		1 => RdpSecurityLayerMode.Negotiate,
		2 => RdpSecurityLayerMode.SslTls,
		_ => RdpSecurityLayerMode.Unknown,
	};

	/// <summary>Maps a raw <c>fDenyTSConnections</c> registry value to "RDP enabled".</summary>
	/// <remarks>0 = enabled, 1 = disabled. Any other value (including missing) is reported as
	/// <c>null</c> so the UI can render "unknown" rather than silently defaulting to enabled.</remarks>
	public static bool? RdpEnabledFromRaw(int? raw) => raw switch
	{
		0 => true,
		1 => false,
		_ => null,
	};

	/// <summary>Maps a raw "hide users on logon" registry value (treats null and 0 as not hidden).</summary>
	public static bool BoolFlagFromRaw(int? raw) => raw is int v && v != 0;

	/// <summary>Human-readable description for the Authentication Mode selector.</summary>
	public static string DescribeAuthenticationMode(RdpUserAuthenticationMode mode) => mode switch
	{
		RdpUserAuthenticationMode.NlaRequired =>
			"Network Level Authentication (NLA) required — Windows authenticates the user "
			+ "before the RDP session is created. Recommended; blocks anonymous probing of the listener.",
		RdpUserAuthenticationMode.NlaNotRequired =>
			"NLA NOT required — clients can connect before authenticating. Permits weaker auth and "
			+ "increases attack surface against the listener. Not recommended on Internet-facing hosts.",
		_ =>
			"Authentication mode could not be determined from the registry. Treat as unknown until "
			+ "the listener is re-queried.",
	};

	/// <summary>Human-readable description for the Security Layer selector.</summary>
	public static string DescribeSecurityLayer(RdpSecurityLayerMode mode) => mode switch
	{
		RdpSecurityLayerMode.SslTls =>
			"SSL/TLS — TLS is required for the RDP channel. Recommended.",
		RdpSecurityLayerMode.Negotiate =>
			"Negotiate — server and client pick the strongest mutually-supported layer at handshake. "
			+ "Usually TLS but may fall back when a client is old.",
		RdpSecurityLayerMode.RdpSecurity =>
			"RDP Security Layer — legacy in-protocol crypto. Weakest option; avoid on production hosts.",
		_ =>
			"Security layer could not be determined from the registry.",
	};

	/// <summary>Human-readable description for "Single session per user".</summary>
	public const string DescribeSingleSession =
		"When enabled, each user account may have only one active RDP session at a time on this host; "
		+ "a new logon kicks the previous one. Disable only when shared service accounts need multiple "
		+ "concurrent sessions. Stored at HKLM\\…\\Terminal Server\\fSingleSessionPerUser.";

	/// <summary>Human-readable description for "Hide users on logon screen".</summary>
	public const string DescribeHideUsersOnLogon =
		"When enabled, Windows does not list cached or connected user accounts on the secure logon "
		+ "screen — the operator must type the user name. Reduces username enumeration and shoulder "
		+ "surfing. RdpAudit manages two related policy values: dontdisplaylastusername and "
		+ "DontEnumerateConnectedUsers under HKLM\\…\\Policies\\System.";

	/// <summary>Human-readable description for "Session Shadowing mode".</summary>
	public const string DescribeShadowMode =
		"Controls whether helpdesk administrators may observe or take control of an active RDP "
		+ "session, and whether the end user must consent first. Stored at HKLM\\…\\Policies\\…\\"
		+ "Terminal Services\\Shadow. Use the consent-required modes on user workstations.";

	/// <summary>Human-readable description for the configured listener port.</summary>
	public const string DescribePortNumber =
		"TCP port the Terminal Services listener binds to. Read from HKLM\\…\\WinStations\\RDP-Tcp\\"
		+ "PortNumber. Defaults to 3389 when no override is written. Changing this requires a service "
		+ "restart and a matching firewall rule — RdpAudit only reports the value, it does not change it.";

	/// <summary>Human-readable description for the RDP enabled / disabled flag.</summary>
	public const string DescribeRdpEnabled =
		"Whether the host accepts incoming RDP connections. Stored at HKLM\\…\\Terminal Server\\"
		+ "fDenyTSConnections (0 = enabled, 1 = disabled). When disabled, the listener is unloaded "
		+ "and remote desktop is unreachable on all ports.";

	/// <summary>Human-readable description for the "Always prompt for password" toggle.</summary>
	public const string DescribePromptForPassword =
		"When enabled, this RDS host asks for credentials on every RDP connection and may prevent "
		+ "use of saved client credentials (the server overrides the client and re-prompts). When "
		+ "disabled or not configured, saved credentials can be used if client-side Credential "
		+ "Delegation/CredSSP and NLA policy allow it. This is server-side only; if prompts continue "
		+ "after disabling it, check client-side policies such as \"Do not allow passwords to be "
		+ "saved\" and Credential Delegation/CredSSP settings. Stored at HKLM\\SOFTWARE\\Policies\\"
		+ "Microsoft\\Windows NT\\Terminal Services\\fPromptForPassword (policy key — authoritative) "
		+ "with a per-listener fallback at HKLM\\…\\WinStations\\RDP-Tcp\\fPromptForPassword.";

	/// <summary>Resolves the effective "Always prompt for password" state given the policy value
	/// and the per-listener fallback. The policy key wins when present (any 0/1 value); the
	/// listener fallback is consulted only when the policy value is absent. Returns null when
	/// neither source has a usable value so the UI can render "not configured".</summary>
	/// <param name="policyRaw">Raw DWORD under the Terminal Services policy key, or null when absent.</param>
	/// <param name="listenerRaw">Raw DWORD under the RDP-Tcp listener key, or null when absent.</param>
	public static bool? EffectivePromptForPassword(int? policyRaw, int? listenerRaw)
	{
		if (policyRaw is int p)
		{
			return p != 0;
		}

		if (listenerRaw is int l)
		{
			return l != 0;
		}

		return null;
	}
}
