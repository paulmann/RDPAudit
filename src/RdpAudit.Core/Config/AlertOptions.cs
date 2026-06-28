// File:    src/RdpAudit.Core/Config/AlertOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Tunable thresholds and toggles for the alert detection rules.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Tunable thresholds and toggles for the alert detection rules.</summary>
public sealed class AlertOptions
{
	public bool EnableBruteForceDetection { get; set; } = true;

	public int BruteForceThreshold { get; set; } = 10;

	public int BruteForceWindowMinutes { get; set; } = 5;

	public int BruteForceNtlmThreshold { get; set; } = 20;

	public int KerberosSprayThreshold { get; set; } = 20;

	public int RapidReconnectSeconds { get; set; } = 30;

	public int UnknownIpSuccessFailureThreshold { get; set; } = 5;

	public TimeSpan BusinessHoursStart { get; set; } = new(8, 0, 0);

	public TimeSpan BusinessHoursEnd { get; set; } = new(20, 0, 0);

	public bool OffHoursAlertEnabled { get; set; } = true;

	/// <summary>IANA / Windows time-zone id used to evaluate business-hours rules.
	/// Empty value means UTC; "Local" means the host machine's local zone.</summary>
	public string OffHoursTimeZoneId { get; set; } = "UTC";

	/// <summary>Cooldown applied to brute-force / NTLM / Kerberos / threshold rules to avoid
	/// emitting one alert per offending event after the threshold is crossed.</summary>
	public int ThresholdCooldownMinutes { get; set; } = 15;

	/// <summary>If true, ProcessAnomaly suppresses cmd.exe spawned from explorer.exe (interactive use).</summary>
	public bool ProcessAnomalyAllowExplorerCmd { get; set; } = true;

	public string KerberosExpectedEncryptionType { get; set; } = "0x12";

	public List<string> LsassAccessWhitelistProcesses { get; set; } = new()
	{
		"MsMpEng.exe",
		"SearchIndexer.exe",
		"taskhostw.exe",
		"wininit.exe",
	};

	public List<string> WhitelistIps { get; set; } = new();

	public List<string> WhitelistUsers { get; set; } = new();

	public List<string> PrivilegedGroups { get; set; } = new()
	{
		"Administrators",
		"Domain Admins",
		"Remote Desktop Users",
		"Enterprise Admins",
	};
}
