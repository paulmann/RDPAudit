// File:    src/RdpAudit.Core/ThreatIntel/ThreatIntelLimits.cs
// Module:  RdpAudit.Core.ThreatIntel
// Purpose: Pure clamp helpers for the Backlog #5 threat-intel /check configuration values.
//          Centralising the clamps here (instead of scattering Math.Clamp across Service layers)
//          makes the guardrails unit-testable in RdpAudit.Core.Tests without EF Core or a host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.ThreatIntel;

/// <summary>Pure clamp helpers for the threat-intel lookup configuration.</summary>
public static class ThreatIntelLimits
{
	public const int MinLookupsPerMinute = 1;
	public const int MaxLookupsPerMinute = 300;
	public const int DefaultLookupsPerMinute = 30;

	// Upper bound 995 guarantees an int budget counter can never overflow during one day's increments.
	public const int MinLookupsPerDay = 1;
	public const int MaxLookupsPerDay = 995;
	public const int DefaultLookupsPerDay = 500;

	public const int MinMaxAgeInDays = 1;
	public const int MaxMaxAgeInDays = 365;
	public const int DefaultMaxAgeInDays = 30;

	public const int MinWorkerIntervalSeconds = 30;
	public const int MaxWorkerIntervalSeconds = 86400;
	public const int DefaultWorkerIntervalSeconds = 300;

	public static int ClampLookupsPerMinute(int value) => Math.Clamp(value, MinLookupsPerMinute, MaxLookupsPerMinute);

	public static int ClampLookupsPerDay(int value) => Math.Clamp(value, MinLookupsPerDay, MaxLookupsPerDay);

	public static int ClampMaxAgeInDays(int value) => Math.Clamp(value, MinMaxAgeInDays, MaxMaxAgeInDays);

	public static int ClampWorkerIntervalSeconds(int value) => Math.Clamp(value, MinWorkerIntervalSeconds, MaxWorkerIntervalSeconds);
}
