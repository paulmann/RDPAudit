// File:    tests/RdpAudit.Service.Tests/SecurityVisibilityDiagnosticBuilderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Pins the derivation rules for the discrete Security visibility diagnostic flags
//          surfaced via IPC ServiceStatus (SecurityLogMissing, AuditPolicyMissingLogon,
//          SecurityReadDenied, ChannelDisabled, BookmarkStaleOrLogRetentionGap). Each test
//          arranges a single failure mode and asserts only the matching flag flips so the UI
//          chip lights for the right reason.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityVisibilityDiagnosticBuilderTests
{
	[Fact]
	public void HealthyService_AllFlagsFalse()
	{
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			security4624Count: 5,
			security4625Count: 3,
			rdpOrphans: 0));

		Assert.False(flags.SecurityLogMissing);
		Assert.False(flags.AuditPolicyMissingLogon);
		Assert.False(flags.SecurityReadDenied);
		Assert.False(flags.ChannelDisabled);
		Assert.False(flags.BookmarkStaleOrLogRetentionGap);
	}

	[Fact]
	public void ChannelNotFoundError_FlagsSecurityLogMissing_AndChannelDisabled()
	{
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: false,
			lastSecurityChannelError: "ChannelNotFound: The specified channel could not be found"));

		Assert.True(flags.SecurityLogMissing);
		Assert.True(flags.ChannelDisabled);
		Assert.False(flags.SecurityReadDenied);
	}

	[Fact]
	public void AccessDeniedError_FlagsSecurityReadDenied()
	{
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			lastSecurityChannelError: "AccessDenied: The service account is missing SeSecurityPrivilege"));

		Assert.True(flags.SecurityReadDenied);
		Assert.False(flags.SecurityLogMissing);
		Assert.False(flags.ChannelDisabled);
	}

	[Fact]
	public void OrphansWithoutSecurityEvents_FlagsAuditPolicyMissingLogon()
	{
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			security4624Count: 0,
			security4625Count: 0,
			rdpOrphans: SecurityVisibilityDiagnosticBuilder.AuditPolicyMissingThreshold + 1));

		Assert.True(flags.AuditPolicyMissingLogon);
		Assert.False(flags.SecurityLogMissing);
		Assert.False(flags.SecurityReadDenied);
	}

	[Fact]
	public void OrphansWithSecurityEventsAlreadyArrived_DoesNotFlagAuditPolicyMissing()
	{
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			security4624Count: 1,
			security4625Count: 0,
			rdpOrphans: SecurityVisibilityDiagnosticBuilder.AuditPolicyMissingThreshold + 1));

		Assert.False(flags.AuditPolicyMissingLogon);
	}

	[Fact]
	public void StaleBookmark_FlagsBookmarkStaleOrLogRetentionGap()
	{
		DateTime preAuth = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);
		DateTime sec = preAuth - TimeSpan.FromMinutes(20);

		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			lastRdpPreAuth: preAuth,
			lastSecurityEvent: sec,
			backfillLastRun: preAuth,
			backfillRecordsRead: 100));

		Assert.True(flags.BookmarkStaleOrLogRetentionGap);
	}

	[Fact]
	public void RecentSecurityCorrelation_DoesNotFlagBookmarkStale()
	{
		DateTime now = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(MakeInputs(
			securityWatcherEnabled: true,
			lastRdpPreAuth: now,
			lastSecurityEvent: now - TimeSpan.FromMinutes(2),
			backfillLastRun: now,
			backfillRecordsRead: 100));

		Assert.False(flags.BookmarkStaleOrLogRetentionGap);
	}

	private static SecurityVisibilityInputs MakeInputs(
		bool securityWatcherEnabled,
		long security4624Count = 0,
		long security4625Count = 0,
		long security4648Count = 0,
		long rdpOrphans = 0,
		string? lastSecurityChannelError = null,
		IReadOnlyDictionary<string, string>? channelStatus = null,
		DateTime? lastRdpPreAuth = null,
		DateTime? lastSecurityEvent = null,
		DateTime? backfillLastRun = null,
		long backfillRecordsRead = 0)
	{
		return new SecurityVisibilityInputs(
			SecurityEventsRead: security4624Count + security4625Count + security4648Count,
			Security4624Count: security4624Count,
			Security4625Count: security4625Count,
			Security4648Count: security4648Count,
			RdpCorePreAuthOrphans: rdpOrphans,
			SecurityWatcherEnabled: securityWatcherEnabled,
			LastSecurityChannelError: lastSecurityChannelError,
			ChannelStatus: channelStatus ?? new Dictionary<string, string>(),
			LastRdpCorePreAuthUtc: lastRdpPreAuth,
			LastSecurityEventUtc: lastSecurityEvent,
			SecurityBackfillLastRunUtc: backfillLastRun,
			SecurityBackfillRecordsRead: backfillRecordsRead);
	}
}
