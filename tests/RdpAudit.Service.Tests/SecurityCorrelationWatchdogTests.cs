// File:    tests/RdpAudit.Service.Tests/SecurityCorrelationWatchdogTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the diagnostic the watchdog raises when TS-RCM 261 / RdpCoreTS 131 fire without
//          a matching Security 4624/4625/4648 inside the correlation window — the operator-
//          visible symptom of disabled audit policy or missing Security log read privilege.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using RdpAudit.Service;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityCorrelationWatchdogTests
{
	private const string TsRcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string RdpCoreTs = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
	private const string SecurityChannel = "Security";

	private static RawEvent Evt(int id, string channel, DateTime utc) =>
		new() { EventId = id, Channel = channel, TimeUtc = utc };

	[Fact]
	public void RdpCoreOnly_NoSecurity_TripsDiagnosticAfterThreshold()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[] { Evt(261, TsRcm, t) });
		Assert.Null(metrics.SecurityCorrelationDiagnostic);

		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(10)) });
		Assert.Null(metrics.SecurityCorrelationDiagnostic);

		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(20)) });
		Assert.NotNull(metrics.SecurityCorrelationDiagnostic);
		Assert.Equal(3, metrics.RdpCorePreAuthOrphans);
		Assert.Contains("auditpol", metrics.SecurityCorrelationDiagnostic!, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("Manage auditing", metrics.SecurityCorrelationDiagnostic!, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Security4625_ResetsOrphanStreak()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[] { Evt(131, RdpCoreTs, t) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(5)) });
		Assert.Null(metrics.SecurityCorrelationDiagnostic);

		// Security 4625 arrives — orphan streak clears.
		wd.Apply(new[] { Evt(4625, SecurityChannel, t.AddSeconds(10)) });
		Assert.Equal(1, metrics.Security4625Count);

		// Two more pre-auth events should NOT trip yet because the streak is back to 0 and the
		// most recent Security event is well inside the correlation window.
		wd.Apply(new[] { Evt(261, TsRcm, t.AddSeconds(20)) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(30)) });
		Assert.Null(metrics.SecurityCorrelationDiagnostic);
	}

	[Fact]
	public void Security4624AndCounters_AreTallied()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[]
		{
			Evt(4624, SecurityChannel, t),
			Evt(4624, SecurityChannel, t.AddSeconds(1)),
			Evt(4625, SecurityChannel, t.AddSeconds(2)),
			Evt(4648, SecurityChannel, t.AddSeconds(3)),
		});

		Assert.Equal(2, metrics.Security4624Count);
		Assert.Equal(1, metrics.Security4625Count);
		Assert.Equal(1, metrics.Security4648Count);
		Assert.NotNull(metrics.LastSecurityEventUtc);
		Assert.Equal(t.AddSeconds(3), metrics.LastSecurityEventUtc);
	}

	[Fact]
	public void EveryOrphanIncrementsCounter_DiagnosticStringSetOncePerGap()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics, TimeSpan.FromMinutes(5), orphanThreshold: 2);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[] { Evt(131, RdpCoreTs, t) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(1)) });
		Assert.Equal(2, metrics.RdpCorePreAuthOrphans);
		Assert.NotNull(metrics.SecurityCorrelationDiagnostic);
		string firstDiagnostic = metrics.SecurityCorrelationDiagnostic!;

		// Further orphans within the same gap keep incrementing the counter so operators can see
		// how many attempts went unanswered, but the diagnostic string itself is set once per gap.
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(2)) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(3)) });
		Assert.Equal(4, metrics.RdpCorePreAuthOrphans);
		Assert.Equal(firstDiagnostic, metrics.SecurityCorrelationDiagnostic);
	}

	[Fact]
	public void SecurityAfterDiagnostic_ClearsDiagnosticString()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[]
		{
			Evt(131, RdpCoreTs, t),
			Evt(131, RdpCoreTs, t.AddSeconds(1)),
			Evt(131, RdpCoreTs, t.AddSeconds(2)),
		});
		Assert.NotNull(metrics.SecurityCorrelationDiagnostic);

		// A real Security event flows through — diagnostic banner clears.
		wd.Apply(new[] { Evt(4625, SecurityChannel, t.AddSeconds(3)) });
		Assert.Null(metrics.SecurityCorrelationDiagnostic);
	}

	[Fact]
	public void PreAuthInsideWindowAfterSecurity_NoOrphan()
	{
		ServiceMetrics metrics = new();
		SecurityCorrelationWatchdog wd = new(metrics);
		DateTime t = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

		wd.Apply(new[] { Evt(4625, SecurityChannel, t) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(30)) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(60)) });
		wd.Apply(new[] { Evt(131, RdpCoreTs, t.AddSeconds(90)) });
		Assert.Equal(0, metrics.RdpCorePreAuthOrphans);
		Assert.Null(metrics.SecurityCorrelationDiagnostic);
	}
}
