// File:    tests/RdpAudit.Service.Tests/SecurityAuthProbeServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.0 probe contract. On non-Windows hosts (Linux CI / dev) the probe must report
//          Outcome=NotWindows with IpcResultStatus.Unavailable rather than throwing — that is
//          the canonical signal a Configurator running against a non-service host receives.
//          The XPath emitted is also verified so a regression that re-widens the probe query
//          fails immediately, plus the exception-classifier path used by the long-running
//          collector to disambiguate AccessDenied / ChannelNotFound / Error.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityAuthProbeServiceTests
{
	[Fact]
	public void Run_ReturnsWellFormedEnvelope_WithNarrowAuthXPath()
	{
		SecurityAuthProbeService svc = new(NullLogger<SecurityAuthProbeService>.Instance);
		SecurityAuthProbeDto dto = svc.Run();

		Assert.NotNull(dto);
		Assert.NotNull(dto.Query);
		Assert.Contains("EventID=4625", dto.Query!, StringComparison.Ordinal);
		Assert.Contains("EventID=4624", dto.Query!, StringComparison.Ordinal);
		// Probe MUST NOT broaden to non-auth ids.
		Assert.DoesNotContain("EventID=4688", dto.Query!, StringComparison.Ordinal);
		Assert.NotEqual(default(DateTime), dto.GeneratedUtc);
		Assert.True(dto.LookbackHours > 0);
	}

	[Fact]
	public void Run_OnNonWindows_ReportsNotWindowsDistinctly()
	{
		if (OperatingSystem.IsWindows())
		{
			// On Windows the probe will actually contact the channel; the NotWindows branch is
			// exercised by Linux CI. This assert just documents the Windows expectation.
			SecurityAuthProbeService svc = new(NullLogger<SecurityAuthProbeService>.Instance);
			SecurityAuthProbeDto dto = svc.Run();
			Assert.NotEqual("NotWindows", dto.Outcome);
			return;
		}

		SecurityAuthProbeService svc2 = new(NullLogger<SecurityAuthProbeService>.Instance);
		SecurityAuthProbeDto dto2 = svc2.Run();
		Assert.Equal("NotWindows", dto2.Outcome);
		Assert.Equal(IpcResultStatus.Unavailable, dto2.Status);
		Assert.Null(dto2.FirstEvent);
	}

	[Fact]
	public void ClassifyChannelException_DistinguishesAccessDeniedFromError()
	{
		(string outcome, string _) = SecurityAuthProbeService.ClassifyChannelException(
			new UnauthorizedAccessException("denied"));
		Assert.Equal("AccessDenied", outcome);

		(string outcome3, string msg) = SecurityAuthProbeService.ClassifyChannelException(
			new InvalidOperationException("boom"));
		Assert.Equal("Error", outcome3);
		Assert.Contains("boom", msg, StringComparison.Ordinal);
	}

	[Fact]
	public void ClassifyChannelException_ChannelNotFound_OnWindowsOnly()
	{
		// EventLogNotFoundException constructor depends on the Windows EventLog API and throws
		// PlatformNotSupportedException on non-Windows hosts. Gate the assertion so this remains
		// a useful regression on Windows CI without breaking the Linux dev build.
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(string outcome, string _) = SecurityAuthProbeService.ClassifyChannelException(
			new EventLogNotFoundException("missing"));
		Assert.Equal("ChannelNotFound", outcome);
	}

	[Fact]
	public void ProbeEventIds_AreNarrowAuthSet()
	{
		// The probe queries 4624 / 4625 only — exactly what PowerShell uses during incident
		// triage. A regression that broadens this list would re-introduce the wide-query
		// timeout symptom the probe was built to disambiguate.
		Assert.Equal(new[] { 4624, 4625 }.OrderBy(x => x), SecurityAuthProbeService.ProbeEventIds.OrderBy(x => x));
	}

	[Fact]
	public void SecurityAuthQuery_BuildXPath_OmitsTimeBound_WhenNotSupplied()
	{
		string xpath = SecurityAuthQuery.BuildXPath();
		Assert.DoesNotContain("TimeCreated", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
	}
}
