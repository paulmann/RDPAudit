/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : FirewallTabUiResponsivenessScenarioTests.cs
// Project: RdpAudit.ScenarioTests
// Purpose: P2-1 UI-responsiveness regression scenarios. Simulates the Firewall tab flow: the
//          WinForms UI thread calls FirewallProviderDiagnosticsProbe.ProbeAsync; inside, the probe
//          may run netsh / service / WMI checks for seconds. The scenario asserts the call itself
//          returns control to the caller immediately (it must not be a blocking wrapper) and that
//          a diagnostic snapshot eventually lands; a cancelled refresh (tab closed) must surface
//          OperationCanceledException, never a partially baked snapshot.
// Depends: RdpAudit.Configurator (FirewallProviderDiagnosticsProbe), xunit
// Extends: Add scenarios when the probe gains an event/callback completion path or the caller
//          switches to a progress-reporting API.

using System.Diagnostics;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.ScenarioTests;

public sealed class FirewallTabUiResponsivenessScenarioTests
{
	/// <summary>Given an operator opens the Firewall tab on a host where the probe is allowed to run
	/// its full Win32 surface, when the UI thread calls the async probe, then the call must hand
	/// control back to the caller well under any human-noticeable threshold (the offload is a
	/// Task.Run, so the return time is scheduling time, not probe time), and the awaited snapshot
	/// must arrive complete. This is the P2-1 regression: before the fix, RefreshProviderDiagnostics
	/// called the synchronous Probe() which could park the UI thread up to 15 s inside netsh.</summary>
	[Fact]
	public async Task UiThread_ProbeCallReturnsImmediately_AndSnapshotArrives()
	{
		FirewallProviderDiagnosticsProbe probe = new();

		Stopwatch sw = Stopwatch.StartNew();
		Task<FirewallProviderDiagnostics> pending = probe.ProbeAsync();
		sw.Stop();

		// The UI thread must be freed immediately: the call itself is just a Task.Run handoff.
		Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(250),
			"ProbeAsync blocked the caller for " + sw.ElapsedMilliseconds + " ms - the probe must offload, not block the UI thread.");

		FirewallProviderDiagnostics snapshot = await pending;
		Assert.NotNull(snapshot.ProviderName);
		Assert.NotNull(snapshot.Notes);
	}

	/// <summary>Given an operator closes the Firewall tab (or the form is disposed) while a refresh
	/// is outstanding, when the refresh token is cancelled before the probe starts, then the caller
	/// observes OperationCanceledException instead of a snapshot - and the probe never runs its
	/// heavyweight Win32 checks for a caller that has already gone away.</summary>
	[Fact]
	public async Task UiThread_CancelBeforeStart_ThrowsOperationCanceled()
	{
		FirewallProviderDiagnosticsProbe probe = new();
		using CancellationTokenSource cts = new();
		cts.Cancel();

		_ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
			async () => await probe.ProbeAsync(cts.Token));
	}
}
