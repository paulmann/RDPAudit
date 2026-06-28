// File:    src/RdpAudit.Service/Services/SecurityVisibilityDiagnosticBuilder.cs
// Module:  RdpAudit.Service.Services
// Purpose: Derives the discrete diagnostic flags surfaced via IPC ServiceStatus —
//          SecurityLogMissing, AuditPolicyMissingLogon, SecurityReadDenied,
//          ChannelDisabled, BookmarkStaleOrLogRetentionGap — from the existing per-process
//          metrics surface. The watchdog already emits a free-text "SecurityCorrelationDiagnostic"
//          string; these flags name the *specific* failure mode so the Configurator can light
//          the right warning chip and the operator can act without parsing the diagnostic
//          paragraph. Pure logic, no I/O. Tested cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Service.Services;

/// <summary>Discrete flags describing why Security visibility is missing.</summary>
public sealed record SecurityVisibilityFlags(
	bool SecurityLogMissing,
	bool AuditPolicyMissingLogon,
	bool SecurityReadDenied,
	bool ChannelDisabled,
	bool BookmarkStaleOrLogRetentionGap);

/// <summary>Inputs the builder needs to derive the visibility flags. The shape mirrors what
/// <see cref="ServiceMetrics"/> already exposes so callers can populate it in one
/// allocation-free hop.</summary>
public sealed record SecurityVisibilityInputs(
	long SecurityEventsRead,
	long Security4624Count,
	long Security4625Count,
	long Security4648Count,
	long RdpCorePreAuthOrphans,
	bool SecurityWatcherEnabled,
	string? LastSecurityChannelError,
	IReadOnlyDictionary<string, string> ChannelStatus,
	DateTime? LastRdpCorePreAuthUtc,
	DateTime? LastSecurityEventUtc,
	DateTime? SecurityBackfillLastRunUtc,
	long SecurityBackfillRecordsRead);

/// <summary>Pure derivation of the visibility flags from the metrics snapshot.</summary>
public static class SecurityVisibilityDiagnosticBuilder
{
	/// <summary>Threshold at which orphan pre-auth events imply audit policy is broken. The
	/// per-channel watchdog already raises its diagnostic at 3 orphans; we use the same number
	/// here so the discrete flag surfaces at the same time as the free-text string.</summary>
	public const int AuditPolicyMissingThreshold = 3;

	/// <summary>Builds the discrete flag set.</summary>
	public static SecurityVisibilityFlags Build(SecurityVisibilityInputs inputs)
	{
		ArgumentNullException.ThrowIfNull(inputs);

		string? error = inputs.LastSecurityChannelError;
		bool channelNotFound = ContainsToken(error, "ChannelNotFound");
		bool accessDenied = ContainsToken(error, "AccessDenied");

		bool channelDisabled = !inputs.SecurityWatcherEnabled
			&& (channelNotFound
				|| ChannelStatusMatches(inputs.ChannelStatus, "ChannelNotFound", "Disabled"));

		bool securityLogMissing = channelNotFound
			|| ChannelStatusMatches(inputs.ChannelStatus, "ChannelNotFound");

		bool securityReadDenied = accessDenied
			|| ChannelStatusMatches(inputs.ChannelStatus, "AccessDenied");

		bool auditPolicyMissingLogon =
			inputs.RdpCorePreAuthOrphans >= AuditPolicyMissingThreshold
			&& inputs.Security4624Count == 0
			&& inputs.Security4625Count == 0
			&& inputs.Security4648Count == 0
			&& !securityLogMissing
			&& !securityReadDenied;

		// Bookmark staleness / retention gap is inferred when:
		//  - a backfill has run, AND
		//  - it scanned the channel (RecordsRead > 0) but only finds events strictly older than
		//    the most recent pre-auth observation, AND
		//  - we have NOT seen any Security event for the live correlation window since the
		//    pre-auth fired (LastRdpCorePreAuthUtc > LastSecurityEventUtc by more than 5 min).
		bool bookmarkStale = inputs.SecurityBackfillLastRunUtc.HasValue
			&& inputs.SecurityBackfillRecordsRead > 0
			&& inputs.LastRdpCorePreAuthUtc is DateTime preAuth
			&& inputs.LastSecurityEventUtc is DateTime sec
			&& (preAuth - sec) > TimeSpan.FromMinutes(15);

		return new SecurityVisibilityFlags(
			SecurityLogMissing: securityLogMissing,
			AuditPolicyMissingLogon: auditPolicyMissingLogon,
			SecurityReadDenied: securityReadDenied,
			ChannelDisabled: channelDisabled,
			BookmarkStaleOrLogRetentionGap: bookmarkStale);
	}

	private static bool ContainsToken(string? haystack, string token)
	{
		return !string.IsNullOrEmpty(haystack)
			&& haystack.Contains(token, StringComparison.OrdinalIgnoreCase);
	}

	private static bool ChannelStatusMatches(
		IReadOnlyDictionary<string, string> map,
		params string[] anyOf)
	{
		foreach (KeyValuePair<string, string> kv in map)
		{
			foreach (string token in anyOf)
			{
				if (string.Equals(kv.Value, token, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
		}

		return false;
	}
}
