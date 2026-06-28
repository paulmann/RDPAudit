// File:    tests/RdpAudit.Core.Tests/ServiceButtonStateModelTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 2 — locks the Service tab button-state mapping against the authoritative
//          SCM snapshot plus the installed/distribution binary comparison. Install is gated
//          on a usable distribution, Start/Stop reflect the live SCM state, Update only
//          enables when the distribution differs from the installed binary, transitioning
//          states keep lifecycle buttons disabled.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ServiceButtonStateModelTests
{
	private static ServiceInstallationInfo Scm(int? stateCode, bool installed = true, int? processId = null) =>
		new(
			ServiceName: "RdpAuditService",
			Installed: installed,
			DisplayName: installed ? "RDP Monitor" : null,
			StateCode: stateCode,
			StateName: stateCode switch
			{
				1 => "Stopped",
				2 => "Start Pending",
				3 => "Stop Pending",
				4 => "Running",
				5 => "Continue Pending",
				6 => "Pause Pending",
				7 => "Paused",
				_ => null,
			},
			ProcessId: processId,
			ImagePath: installed ? @"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe" : null,
			StartMode: installed ? "Auto" : null,
			Status: installed ? "OK" : null,
			Win32ExitCode: 0,
			ServiceSpecificExitCode: 0,
			Diagnostic: null);

	[Fact]
	public void NotInstalled_OnlyInstallIsEnabled_AndOnlyWhenDistributionUsable()
	{
		ServiceButtonState withDist = ServiceButtonStateModel.Compute(
			Scm(stateCode: null, installed: false),
			InstalledBinaryState.NotInstalled,
			distributionUsable: true);
		Assert.True(withDist.Install);
		Assert.False(withDist.Uninstall);
		Assert.False(withDist.Start);
		Assert.False(withDist.Stop);
		Assert.False(withDist.Restart);
		Assert.False(withDist.Update);

		ServiceButtonState noDist = ServiceButtonStateModel.Compute(
			Scm(stateCode: null, installed: false),
			InstalledBinaryState.NotInstalled,
			distributionUsable: false);
		Assert.False(noDist.Install);
	}

	[Fact]
	public void Installed_Stopped_StartIsEnabled_StopIsDisabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 1),
			InstalledBinaryState.InstalledCurrent,
			distributionUsable: true);
		Assert.False(state.Install);
		Assert.True(state.Uninstall);
		Assert.True(state.Start);
		Assert.False(state.Stop);
		Assert.False(state.Restart);
		Assert.False(state.Update);
	}

	[Fact]
	public void Installed_Running_StartDisabled_StopAndRestartEnabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 4, processId: 1234),
			InstalledBinaryState.InstalledCurrent,
			distributionUsable: true);
		Assert.False(state.Install);
		Assert.True(state.Uninstall);
		Assert.False(state.Start);
		Assert.True(state.Stop);
		Assert.True(state.Restart);
		Assert.False(state.Update);
	}

	[Fact]
	public void Installed_StartPending_StartDisabledStopAllowed()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 2),
			InstalledBinaryState.InstalledCurrent,
			distributionUsable: true);
		Assert.False(state.Start);
		Assert.True(state.Stop);
		Assert.False(state.Restart);
	}

	[Fact]
	public void Installed_StopPending_BothStartAndStopDisabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 3),
			InstalledBinaryState.InstalledCurrent,
			distributionUsable: true);
		Assert.False(state.Start);
		Assert.False(state.Stop);
		Assert.False(state.Restart);
	}

	[Fact]
	public void Installed_Paused_StartEnabledStopDisabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 7),
			InstalledBinaryState.InstalledCurrent,
			distributionUsable: true);
		Assert.True(state.Start);
		Assert.False(state.Stop);
		Assert.False(state.Restart);
	}

	[Fact]
	public void UpdateAvailable_UpdateButtonIsEnabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 4, processId: 1234),
			InstalledBinaryState.UpdateAvailable,
			distributionUsable: true);
		Assert.True(state.Update);
	}

	[Fact]
	public void DistributionMissing_UpdateButtonStaysDisabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(
			Scm(stateCode: 4, processId: 1234),
			InstalledBinaryState.DistributionMissing,
			distributionUsable: false);
		Assert.False(state.Update);
		Assert.False(state.Install);
	}

	[Fact]
	public void BackCompatOverload_ContinuesToWork()
	{
		ServiceButtonState notInstalled = ServiceButtonStateModel.Compute(installed: false, running: false);
		Assert.True(notInstalled.Install);
		Assert.False(notInstalled.Uninstall);
		Assert.False(notInstalled.Start);
		Assert.False(notInstalled.Stop);
		Assert.False(notInstalled.Restart);

		ServiceButtonState running = ServiceButtonStateModel.Compute(installed: true, running: true);
		Assert.False(running.Install);
		Assert.True(running.Uninstall);
		Assert.False(running.Start);
		Assert.True(running.Stop);
		Assert.True(running.Restart);

		ServiceButtonState stopped = ServiceButtonStateModel.Compute(installed: true, running: false);
		Assert.False(stopped.Install);
		Assert.True(stopped.Uninstall);
		Assert.True(stopped.Start);
		Assert.False(stopped.Stop);
		// Note: back-compat overload models a fully stopped installed state, where Restart
		// is not meaningful (you'd Start instead). Newer signature exposes this clearly.
		Assert.False(stopped.Restart);
	}
}
