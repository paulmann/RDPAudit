// File:    tests/RdpAudit.Core.Tests/ServiceInstallationInfoTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 2 — locks the Win32_Service PathName / ImagePath parser. SCM emits the
//          executable path either bare or quoted with optional arguments appended, and the
//          Service tab needs the absolute exe path so it can fingerprint the installed
//          binary. Also covers the locale-stable IsRunning / IsTransitioning / IsPaused /
//          IsStopped helpers used by ServiceButtonStateModel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ServiceInstallationInfoTests
{
	private static ServiceInstallationInfo Build(string? imagePath, int? stateCode = null) =>
		new(
			ServiceName: "RdpAuditService",
			Installed: true,
			DisplayName: "RDP Monitor",
			StateCode: stateCode,
			StateName: null,
			ProcessId: null,
			ImagePath: imagePath,
			StartMode: "Auto",
			Status: null,
			Win32ExitCode: 0,
			ServiceSpecificExitCode: 0,
			Diagnostic: null);

	[Theory]
	[InlineData(@"""C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe""", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe")]
	[InlineData(@"""C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe"" --verbose", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe")]
	[InlineData(@"C:\RdpAudit\Service\RdpAudit.Service.exe", @"C:\RdpAudit\Service\RdpAudit.Service.exe")]
	[InlineData(@"C:\RdpAudit\Service\RdpAudit.Service.exe --flag", @"C:\RdpAudit\Service\RdpAudit.Service.exe")]
	// Stage 5 regression: an unquoted Win32_Service.PathName that contains spaces (the canonical
	// "C:\Program Files\..." case) must NOT be split at the first space. The pre-fix resolver
	// returned "C:\Program" which then failed the binary-fingerprint exists check on the
	// Service tab even though the service was running fine from the real path.
	[InlineData(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe")]
	[InlineData(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe --console", @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe")]
	[InlineData(@"C:\Program Files (x86)\Vendor\My Service.exe", @"C:\Program Files (x86)\Vendor\My Service.exe")]
	public void ResolveExecutablePath_Parses(string imagePath, string expected)
	{
		ServiceInstallationInfo info = Build(imagePath);
		Assert.Equal(expected, info.ResolveExecutablePath());
	}

	[Fact]
	public void ResolveExecutablePath_NullOrEmpty_ReturnsNull()
	{
		Assert.Null(Build(null).ResolveExecutablePath());
		Assert.Null(Build("").ResolveExecutablePath());
		Assert.Null(Build("   ").ResolveExecutablePath());
	}

	[Theory]
	[InlineData(1, false, false, false, true)]  // Stopped
	[InlineData(2, false, true, false, false)]  // Start Pending
	[InlineData(3, false, true, false, false)]  // Stop Pending
	[InlineData(4, true, false, false, false)]  // Running
	[InlineData(5, false, true, false, false)]  // Continue Pending
	[InlineData(6, false, true, false, false)]  // Pause Pending
	[InlineData(7, false, false, true, false)]  // Paused
	public void StateHelpers_ReflectCode(int code, bool running, bool transitioning, bool paused, bool stopped)
	{
		ServiceInstallationInfo info = Build(imagePath: null, stateCode: code);
		Assert.Equal(running, info.IsRunning);
		Assert.Equal(transitioning, info.IsTransitioning);
		Assert.Equal(paused, info.IsPaused);
		Assert.Equal(stopped, info.IsStopped);
	}

	[Fact]
	public void StateHelpers_FallBackToStateName_OnRussianLocale()
	{
		// On non-English Windows, sc.exe reports a localized state name. Win32_Service.State
		// is locale-stable (English-only enum), but the helpers also accept the English name
		// as a fallback so a missing numeric code still produces the right run-state.
		ServiceInstallationInfo info = new(
			ServiceName: "RdpAuditService",
			Installed: true,
			DisplayName: "RDP Monitor",
			StateCode: null,
			StateName: "Running",
			ProcessId: 9999,
			ImagePath: null,
			StartMode: null,
			Status: null,
			Win32ExitCode: null,
			ServiceSpecificExitCode: null,
			Diagnostic: null);
		Assert.True(info.IsRunning);
	}
}
