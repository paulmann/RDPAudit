// File:    src/RdpAudit.Core/WebUi/WebAccessUIModel.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Pure, UI-agnostic state model behind the Configurator "Web Access" tab. It encodes
//          the two operator checkboxes (show Web Access, allow remote management), the
//          workflow busy/locked flag, and the installation readiness derived from the IIS
//          status snapshot. Lifted out of WinForms so the checkbox / button-enablement
//          contract is unit-testable anywhere, exactly like ServiceButtonStateModel before it.
//
//          SECURITY MODEL (per plan): the management checkbox is intentionally locked (phase
//          gate). Turning management on is a separate, later phase; until then any attempt
//          to persist 'Allow management' is refused by <see cref="TrySetAllowManagementAsync"/>
//          regardless of the UI intent. Show-only mode never requires elevation beyond what
//          the probe itself needs.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Threading;
using System.Threading.Tasks;

namespace RdpAudit.Core.WebUi;

/// <summary>
/// Should the Web Access tab be visible inside the Configurator? Privacy-first default:
/// only activated explicitly by the operator. Implementations persist their own preference;
/// this abstraction keeps the UI model free of storage concerns.
/// </summary>
public interface IWebAccessPreferenceStore
{
	/// <summary>True when the operator opted into showing the web-access surface.</summary>
	bool IsTabEnabled { get; }

	/// <summary>Persists the operator's show/hide choice. Returns true when the value was stored.</summary>
	Task<bool> SetTabEnabledAsync(bool enabled, CancellationToken cancellationToken);

	/// <summary>True when the operator opted into allowing web-based management.</summary>
	bool IsManagementEnabled { get; }

	/// <summary>Persists the operator's management choice. Returns true when the value was stored.</summary>
	Task<bool> SetManagementEnabledAsync(bool enabled, CancellationToken cancellationToken);
}

/// <summary>Computed state of the Web Access tab controls. Pure projection of
/// (<see cref="IisStatusSnapshot"/>, busy flag, preference store); no control references and
/// no I/O of its own.</summary>
public sealed class WebAccessUIState
{
	/// <summary>Whether the operator has opted into showing the web-access surface.</summary>
	public bool ShowWebAccess { get; init; }

	/// <summary>Whether the operator has opted into allowing web-based management.</summary>
	public bool AllowManagement { get; init; }

	/// <summary>Whether the management checkbox may be toggled at all (phase gate).</summary>
	public bool ManagementToggleAllowed { get; init; }

	/// <summary>True while an installation / configuration workflow is running.</summary>
	public bool IsBusy { get; init; }

	/// <summary>True when a status probe is running and controls must not mutate.</summary>
	public bool IsProbing { get; init; }

	/// <summary>True when IIS is known to be installed and the published UI is present.</summary>
	public bool IsWebOperational { get; init; }

	/// <summary>Human-readable status line shown under the controls.</summary>
	public string StatusText { get; init; } = string.Empty;

	/// <summary>Installed / not-installed / unknown verdict for the status panel.</summary>
	public IisStatusSnapshot Snapshot { get; init; } = new();

	/// <summary>Whether Install IIS / Configure IIS may be clicked now: not busy, not probing,
	/// and IIS state is actually known.</summary>
	public bool WorkflowButtonsEnabled => !IsBusy && !IsProbing && Snapshot.CanDeclare;
}

/// <summary>
/// Pure two-tier gating for the Web Access tab. Prefer the platform probe when available,
/// fall back to the local process when probing the web status.
/// </summary>
public static class WebAccessUIStateFactory
{
	/// <summary>Builds the default state for the given inputs: preference store state, current
	/// phase gate and the latest status snapshot.</summary>
	public static WebAccessUIState Build(
		IWebAccessPreferenceStore store,
		bool managementPhaseUnlocked,
		IisStatusSnapshot? snapshot,
		bool isBusy,
		bool isProbing,
		string statusText)
	{
		ArgumentNullException.ThrowIfNull(store);
		IisStatusSnapshot effective = snapshot ?? new IisStatusSnapshot();
		return new WebAccessUIState
		{
			ShowWebAccess = store.IsTabEnabled,
			AllowManagement = store.IsManagementEnabled,
			ManagementToggleAllowed = managementPhaseUnlocked && !isBusy && !isProbing,
			IsBusy = isBusy,
			IsProbing = isProbing,
			IsWebOperational = effective.PublishedWebUiPresent && effective.IisInstalled && effective.W3SvcPresent
				&& effective.IisStateDetermined && effective.W3SvcStateDetermined,
			StatusText = string.IsNullOrEmpty(statusText) ? effective.Summary : statusText,
			Snapshot = effective,
		};
	}
}
