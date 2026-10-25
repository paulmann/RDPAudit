/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : FirewallProviderDiagnosticsProbeAsyncContractTests.cs
// Project: RdpAudit.Configurator.Tests (RdpAudit.Configurator.Tests)
// Purpose: P2-1 regression tests for the async firewall-provider diagnostics probe contract.
//          Pins that ProbeAsync never blocks the calling thread (it offloads the Win32 probe work
//          to a thread-pool task and respects caller cancellation) and that the probe exposes no
//          synchronous entry point at all - the blocking Probe() wrapper that the Prerequisites path
//          used was removed with that path's own asynchronous entry point. The probe is read-only by
//          design, so the assertions are contract-level (no-throw, run and cancellation) rather than
//          host-state specific.
// Depends: FirewallProviderDiagnosticsProbe, FirewallProviderDiagnostics, xunit
// Extends: Add assertions here when the probe surface gains parameters or changes its
//          cancellation contract.

using RdpAudit.Configurator.Services;
using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class FirewallProviderDiagnosticsProbeAsyncContractTests
{
	/// <summary>Upper bound for one machine probe. The probe's own sub-probes are bounded (the
	/// <c>netsh advfirewall show allprofiles</c> child process carries a 15 s timeout, see
	/// FirewallProviderDiagnosticsProbe), so four times the slowest legitimate step cannot fire while the
	/// probe behaves - and it turns a wedged SCM / WMI / <c>netsh</c> call, or a thread pool starved by
	/// the rest of a parallel solution run, into a NAMED failure of this test instead of a test host that
	/// has to be hung-dumped, where the blamed name is merely whichever test was in flight when the dump
	/// was taken (the 2026-09-15 hangdump under TestResults).</summary>
	private static readonly TimeSpan ProbeDeadline = TimeSpan.FromSeconds(60);

	[Fact]
	public void Probe_ExposesNoSynchronousEntryPoint()
	{
		// The blocking Probe() wrapper was removed in B1's remediation: it existed only for the
		// Prerequisites path, which is now asynchronous, and any synchronous entry point here would be
		// sync-over-async waiting to deadlock a UI thread (docs/30-configurator.md). Pin its absence so
		// a future "convenience" overload cannot quietly reintroduce it.
		FirewallProviderDiagnosticsProbe probe = new();

		Assert.NotNull(probe);
		Assert.DoesNotContain(
			typeof(FirewallProviderDiagnosticsProbe).GetMethods(),
			m => m.ReturnType == typeof(FirewallProviderDiagnostics));
	}

	[Fact]
	public async Task ProbeAsync_CompletesWithoutThrowing()
	{
		FirewallProviderDiagnosticsProbe probe = new();

		Task<FirewallProviderDiagnostics> probing = probe.ProbeAsync();
		Task finished = await Task.WhenAny(probing, Task.Delay(ProbeDeadline)).ConfigureAwait(true);

		Assert.True(
			ReferenceEquals(probing, finished),
			"The firewall-provider probe did not finish within "
				+ ProbeDeadline.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
				+ " s. This probe drives real machine state (ServiceController, root\\SecurityCenter2 WMI and "
				+ "`netsh advfirewall show allprofiles`), so a wedged or starved host - not the assertion - is "
				+ "the finding.");

		FirewallProviderDiagnostics diagnostics = await probing.ConfigureAwait(true);

		Assert.NotNull(diagnostics);
		Assert.NotNull(diagnostics.ProviderName);
		Assert.NotNull(diagnostics.Notes);
	}

	[Fact]
	public void PrerequisiteChecker_ExposesNoSynchronousEntryPoint()
	{
		// The Prerequisites tab used to drive the whole probe set through a synchronous RunAll() that blocked
		// on the probe internally. It now has a single asynchronous entry point, so a future "convenience"
		// overload cannot reintroduce the blocking path on the UI thread.
		bool hasSynchronousRunAll = typeof(PrerequisiteChecker)
			.GetMethods()
			.Any(m => string.Equals(m.Name, "RunAll", StringComparison.Ordinal));

		Assert.False(hasSynchronousRunAll, "PrerequisiteChecker must expose only RunAllAsync.");
		Assert.NotNull(typeof(PrerequisiteChecker).GetMethod("RunAllAsync"));
	}

	[Fact]
	public async Task ProbeAsync_WithCanceledToken_ThrowsTaskCanceled()
	{
		FirewallProviderDiagnosticsProbe probe = new();
		using CancellationTokenSource cts = new();
		cts.Cancel();

		_ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
			async () => await probe.ProbeAsync(cts.Token));
	}
}
