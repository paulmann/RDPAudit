// File:    tests/RdpAudit.Service.Tests/EtwAvailabilityProbeTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies the pure ETW availability probe consulted by EventSourceFactorySelector.
//          Cross-platform: on non-Windows hosts the probe must decline with a reason mentioning
//          Windows; on Windows we simply assert that the probe returns a well-formed tuple
//          without throwing.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.InteropServices;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EtwAvailabilityProbeTests
{
	[Fact]
	public void Probe_OnNonWindows_ReturnsFalseWithReasonMentioningWindows()
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return; // Windows-specific behaviour verified in the Windows branch below.
		}

		(bool ok, string? reason) = EtwAvailabilityProbe.Probe();

		Assert.False(ok);
		Assert.NotNull(reason);
		Assert.Contains("Windows", reason, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Probe_OnWindows_ReturnsWellFormedResultWithoutThrowing()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return; // See non-Windows branch above.
		}

		(bool ok, string? reason) = EtwAvailabilityProbe.Probe();

		// We do not assert Ok==true here because the test runner may not be elevated. We only
		// require that: (a) no exception escapes; (b) a failed probe always includes a reason.
		if (!ok)
		{
			Assert.NotNull(reason);
			Assert.False(string.IsNullOrWhiteSpace(reason));
		}
	}
}
