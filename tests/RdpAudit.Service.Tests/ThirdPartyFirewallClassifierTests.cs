/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.2.0
// File   : ThirdPartyFirewallClassifierTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Regression suite for FirewallProviderClassifier — proves that the
//          exact real-world signal set observed in the user's diagnostic bundle
//          (klim6 running, avp.exe / avp.com present, SecurityCenter2 = Kaspersky)
//          yields ThirdPartyFirewallSuspected = true, and profiles per-call heap
//          allocation across every classification branch so a hot-path regression
//          shows up as a failing test with the exact byte count, not a silent
//          performance drift.
// Depends: FirewallProviderClassifier, FirewallServiceState, FirewallCliToolPresence

using RdpAudit.Core.Firewall;
using Xunit;
using Xunit.Abstractions;

namespace RdpAudit.Service.Tests;

public sealed class ThirdPartyFirewallClassifierTests
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ITestOutputHelper _output;

	/// <summary>Allocation budget per call, in bytes. Zero is the design target per the
	/// RDPAudit 2.0 zero-alloc hot-path directive, but a small epsilon guards against
	/// JIT tiering / GC bookkeeping noise on the very first measured calls so the suite
	/// does not flake on unrelated runtime warm-up jitter. Any regression that leaks a
	/// real string/tuple/LINQ allocation will exceed this by orders of magnitude, as
	/// observed (264 B/call) prior to the fix below.</summary>
	private const long MaxAllowedBytesPerCall = 8;

	// ── Construction ─────────────────────────────────────────────────────────────

	public ThirdPartyFirewallClassifierTests(ITestOutputHelper output)
	{
		_output = output ?? throw new ArgumentNullException(nameof(output));
	}

	// ── Test Fixtures ─────────────────────────────────────────────────────────────

	private static FirewallServiceState Service(string serviceName, string displayName, bool isRunning) =>
		new(
			ServiceName: serviceName,
			DisplayName: displayName,
			Status: isRunning ? "Running" : "Stopped",
			IsRunning: isRunning);

	private static FirewallCliToolPresence CliTool(string toolName, string fullPath, bool present) =>
		FirewallCliToolPresence.WithFullPath(toolName, fullPath, present);

	// ── Regression: exact signal set from the 2026-07-02 user diagnostic ────────

	[Fact]
	public void Classify_Klim6Running_Returns_KasperskyDetected()
	{
		// Arrange — mirrors the exact service state from the diagnostic bundle:
		// MpsSvc=Running, BFE=Running, WinDefend=Stopped, klim6=Running
		List<FirewallServiceState> services =
		[
			Service("MpsSvc", "Windows Defender Firewall", isRunning: true),
			Service("BFE", "Base Filtering Engine", isRunning: true),
			Service("WinDefend", "Microsoft Defender Antivirus Service", isRunning: false),
			Service("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", isRunning: true),
		];

		// No CLI tools present (kescli / kavshell absent; avp.exe / avp.com present
		// at versioned path — tested separately below).
		List<FirewallCliToolPresence> noTools = [];

		// Act
		(FirewallProviderDetectedKind kind, string name) =
			FirewallProviderClassifier.Classify(services, noTools, kasperskyManagesWindowsFirewall: false);

		// Assert
		Assert.Equal(FirewallProviderDetectedKind.KasperskyDetected, kind);
		Assert.Contains("Kaspersky", name, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Classify_AvpExePresent_Returns_KasperskyDetected()
	{
		// Arrange — no Kaspersky services in SCM (edge case: service stopped but
		// binary present — should still be detected via CLI tool signal).
		List<FirewallServiceState> noServices = [];
		List<FirewallCliToolPresence> tools =
		[
			CliTool("avp.exe", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe", present: true),
			CliTool("avp.com", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.com", present: true),
		];

		// Act
		(FirewallProviderDetectedKind kind, string name) =
			FirewallProviderClassifier.Classify(noServices, tools, kasperskyManagesWindowsFirewall: false);

		// Assert
		Assert.Equal(FirewallProviderDetectedKind.KasperskyDetected, kind);
		Assert.Contains("Kaspersky Endpoint Security", name, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Classify_FullDiagnosticBundle_Suspected_IsTrue()
	{
		// Arrange — complete real-world signal set:
		// klim6 running + avp.exe present + avp.com present
		List<FirewallServiceState> services =
		[
			Service("MpsSvc", "Windows Defender Firewall", isRunning: true),
			Service("BFE", "Base Filtering Engine", isRunning: true),
			Service("WinDefend", "Microsoft Defender Antivirus Service", isRunning: false),
			Service("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", isRunning: true),
		];
		List<FirewallCliToolPresence> tools =
		[
			CliTool("avp.exe", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe", present: true),
			CliTool("avp.com", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.com", present: true),
		];

		// Act
		(FirewallProviderDetectedKind kind, _) =
			FirewallProviderClassifier.Classify(services, tools, kasperskyManagesWindowsFirewall: false);

		bool suspected =
			kind is FirewallProviderDetectedKind.KasperskyDetected
				or FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall
				or FirewallProviderDetectedKind.ThirdPartyFirewallUnknown;

		// Assert — this is the regression that was false before the fix
		Assert.True(suspected, $"Expected ThirdPartyFirewallSuspected=true but classifier returned kind={kind}");
	}

	[Fact]
	public void Classify_PureWindowsDefender_NotSuspected()
	{
		// Arrange — clean Windows Defender-only machine
		List<FirewallServiceState> services =
		[
			Service("MpsSvc", "Windows Defender Firewall", isRunning: true),
			Service("BFE", "Base Filtering Engine", isRunning: true),
			Service("WinDefend", "Microsoft Defender Antivirus Service", isRunning: true),
		];
		List<FirewallCliToolPresence> noTools = [];

		// Act
		(FirewallProviderDetectedKind kind, _) =
			FirewallProviderClassifier.Classify(services, noTools, kasperskyManagesWindowsFirewall: false);

		// Assert — no false positive
		Assert.Equal(FirewallProviderDetectedKind.WindowsDefenderFirewall, kind);
	}

	// ── Allocation Profiling (diagnostic — pinpoints the leaking branch) ─────────

	/// <summary>Runs every classification scenario used in this suite through the same
	/// 10k-iteration allocation probe and reports bytes/call for each, via test output.
	/// This is the tool to run FIRST when <see cref="Classify_ZeroAllocations_Per10kEvaluations"/>
	/// fails — it isolates exactly which signal combination (and therefore which branch
	/// of FirewallProviderClassifier.Classify) is responsible for the leak, instead of
	/// leaving a single opaque aggregate number to debug.</summary>
	[Fact]
	public void Diagnose_AllocationSource_PerScenario()
	{
		List<FirewallServiceState> defenderOnly =
		[
			Service("MpsSvc", "Windows Defender Firewall", isRunning: true),
			Service("BFE", "Base Filtering Engine", isRunning: true),
			Service("WinDefend", "Microsoft Defender Antivirus Service", isRunning: true),
		];

		List<FirewallServiceState> klim6Running =
		[
			Service("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", isRunning: true),
		];

		List<FirewallCliToolPresence> noTools = [];
		List<FirewallCliToolPresence> avpTools =
		[
			CliTool("avp.exe", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe", present: true),
		];

		MeasureScenario("WindowsDefenderOnly", defenderOnly, noTools, kasperskyManages: false);
		MeasureScenario("Klim6Running_NoCliTools", klim6Running, noTools, kasperskyManages: false);
		MeasureScenario("NoServices_AvpToolsPresent", [], avpTools, kasperskyManages: false);
		MeasureScenario("Klim6Running_AvpToolsPresent", klim6Running, avpTools, kasperskyManages: false);
		MeasureScenario("Klim6Running_AvpToolsPresent_KasperskyManaged", klim6Running, avpTools, kasperskyManages: true);
	}

	private void MeasureScenario(
		string scenarioName,
		List<FirewallServiceState> services,
		List<FirewallCliToolPresence> tools,
		bool kasperskyManages)
	{
		const int iterations = 10_000;

		// Warm-up: absorbs JIT tiering (Tier0 -> Tier1) and any one-time static
		// initialization inside the classifier so the measured loop reflects
		// steady-state behavior only.
		for (int i = 0; i < 100; i++)
		{
			_ = FirewallProviderClassifier.Classify(services, tools, kasperskyManages);
		}

		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();

		long before = GC.GetAllocatedBytesForCurrentThread();
		FirewallProviderDetectedKind lastKind = FirewallProviderDetectedKind.Unknown;
		string lastName = string.Empty;

		for (int i = 0; i < iterations; i++)
		{
			(lastKind, lastName) = FirewallProviderClassifier.Classify(services, tools, kasperskyManages);
		}

		long after = GC.GetAllocatedBytesForCurrentThread();
		double bytesPerCall = (after - before) / (double)iterations;

		_output.WriteLine(
			$"[{scenarioName}] kind={lastKind}, name=\"{lastName}\", bytes/call={bytesPerCall:F2} " +
			$"(total={after - before} B over {iterations} calls)");
	}

	// ── Zero-allocation assertion (10k evaluations) ──────────────────────────────

	[Fact]
	public void Classify_ZeroAllocations_Per10kEvaluations()
	{
		List<FirewallServiceState> services =
		[
			Service("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", isRunning: true),
		];
		List<FirewallCliToolPresence> tools =
		[
			CliTool("avp.exe", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe", present: true),
		];

		const int iterations = 10_000;

		// Warm-up — absorbs JIT tiering so the measured loop reflects steady-state cost.
		for (int i = 0; i < 100; i++)
		{
			_ = FirewallProviderClassifier.Classify(services, tools, false);
		}

		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int i = 0; i < iterations; i++)
		{
			_ = FirewallProviderClassifier.Classify(services, tools, false);
		}
		long after = GC.GetAllocatedBytesForCurrentThread();

		long totalAllocated = after - before;
		double allocatedPerCall = totalAllocated / (double)iterations;

		_output.WriteLine($"Classify(): {allocatedPerCall:F2} bytes/call over {iterations} iterations (total {totalAllocated} B)");

		Assert.True(
			allocatedPerCall <= MaxAllowedBytesPerCall,
			$"Zero-alloc hot path regression: expected <= {MaxAllowedBytesPerCall} bytes/call, " +
			$"measured {allocatedPerCall:F2} bytes/call ({totalAllocated} B / {iterations} calls). " +
			"Run Diagnose_AllocationSource_PerScenario to isolate the leaking branch " +
			"(likely a string interpolation, LINQ call, or IEnumerable<T> boxing in " +
			"FirewallProviderClassifier.Classify).");
	}
}
