// File:    src/RdpAudit.Core/Util/ServiceButtonStateModel.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure helper that maps a Windows service state ("Installed" / "Running") to the
//          enabled / disabled state of the Service tab buttons. Lifted out of WinForms so the
//          mapping is unit-testable on any OS. Stage 2 added an explicit "Update installed
//          files" button and a richer state model so transitioning / paused / missing-path
//          situations no longer leave Start enabled when the service is actually working.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Enabled / disabled state of the six Service-tab lifecycle buttons.
/// <see cref="Update"/> is the "copy distribution -&gt; installed" action; it requires an
/// installed service AND a valid distribution AND the binaries to differ.</summary>
public readonly record struct ServiceButtonState(
	bool Install,
	bool Uninstall,
	bool Start,
	bool Stop,
	bool Restart,
	bool Update);

/// <summary>Pure mapping from authoritative SCM state plus installed/distribution binary
/// state to lifecycle button enabled flags. Drives the Service tab.</summary>
public static class ServiceButtonStateModel
{
	/// <summary>Back-compat overload preserved for callers that have not yet upgraded to the
	/// richer state model. <paramref name="installed"/> + <paramref name="running"/> map to
	/// the InstalledCurrent / NotInstalled binary state with no distribution view.</summary>
	public static ServiceButtonState Compute(bool installed, bool running)
	{
		ServiceInstallationInfo scm = installed
			? new ServiceInstallationInfo(
				ServiceName: "RdpAuditService",
				Installed: true,
				DisplayName: null,
				StateCode: running ? 4 : 1,
				StateName: running ? "Running" : "Stopped",
				ProcessId: running ? 0 : null,
				ImagePath: null,
				StartMode: null,
				Status: null,
				Win32ExitCode: null,
				ServiceSpecificExitCode: null,
				Diagnostic: null)
			: new ServiceInstallationInfo(
				ServiceName: "RdpAuditService",
				Installed: false,
				DisplayName: null,
				StateCode: null,
				StateName: null,
				ProcessId: null,
				ImagePath: null,
				StartMode: null,
				Status: null,
				Win32ExitCode: null,
				ServiceSpecificExitCode: null,
				Diagnostic: null);

		return Compute(scm, InstalledBinaryState.InstalledCurrent, distributionUsable: true);
	}

	/// <summary>Computes the button enabled state from the authoritative SCM snapshot and the
	/// resolved <see cref="InstalledBinaryState"/>.
	/// <para>
	/// - <c>Install</c> requires the service to be NOT installed AND the distribution to be usable.<br/>
	/// - <c>Uninstall</c> requires an installed service.<br/>
	/// - <c>Start</c> requires installed + (stopped or paused) and no transition pending.<br/>
	/// - <c>Stop</c> requires installed + running/start-pending/continue-pending; never on stopped.<br/>
	/// - <c>Restart</c> requires installed + running.<br/>
	/// - <c>Update</c> requires installed AND <see cref="InstalledBinaryState.UpdateAvailable"/>.
	/// </para>
	/// </summary>
	public static ServiceButtonState Compute(
		ServiceInstallationInfo scm,
		InstalledBinaryState binaryState,
		bool distributionUsable)
	{
		ArgumentNullException.ThrowIfNull(scm);

		if (!scm.Installed)
		{
			return new ServiceButtonState(
				Install: distributionUsable,
				Uninstall: false,
				Start: false,
				Stop: false,
				Restart: false,
				Update: false);
		}

		bool running = scm.IsRunning;
		bool stopped = scm.IsStopped;
		bool paused = scm.IsPaused;
		bool transitioning = scm.IsTransitioning;

		// Stop: from running, start-pending (2), or continue-pending (5). Pause-pending (6)
		// targets a paused state, so a Stop request would be racing the pause transition;
		// leave Stop disabled there.
		bool canStop = scm.StateCode is 2 or 4 or 5;

		// Start: when fully stopped or paused (paused -> running uses Continue; the SCM
		// runner promotes paused -> running by calling Continue first then Start, so Start
		// is the user-facing action either way).
		bool canStart = stopped || paused;

		// Restart: only meaningful when actually running. Pending transitions are excluded
		// so the user does not fire a second SCM operation on top of one already in flight.
		bool canRestart = running;

		bool canUpdate = binaryState == InstalledBinaryState.UpdateAvailable;

		return new ServiceButtonState(
			Install: false,
			Uninstall: true,
			Start: canStart && !transitioning,
			Stop: canStop,
			Restart: canRestart,
			Update: canUpdate);
	}
}
