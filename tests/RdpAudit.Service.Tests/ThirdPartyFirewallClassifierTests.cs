/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : ThirdPartyFirewallClassifierTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Regression suite for FirewallProviderClassifier — proves that the
//          exact real-world signal set observed in the user's diagnostic bundle
//          (klim6 running, avp.exe / avp.com present, SecurityCenter2 = Kaspersky)
//          yields ThirdPartyFirewallSuspected = true with zero heap allocations
//          per 10k evaluations.
// Depends: FirewallProviderClassifier, FirewallServiceState, FirewallCliToolPresence

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class ThirdPartyFirewallClassifierTests
{
	// ── Regression: exact signal set from the 2026-07-02 user diagnostic ────────

	[Fact]
	public void Classify_Klim6Running_Returns_KasperskyDetected()
	{
		// Arrange — mirrors the exact service state from the diagnostic bundle:
		// MpsSvc=Running, BFE=Running, WinDefend=Stopped, klim6=Running
		List<FirewallServiceState> services =
		[
			new("MpsSvc", "Windows Defender Firewall", Running: true),
			new("BFE", "Base Filtering Engine", Running: true),
			new("WinDefend", "Microsoft Defender Antivirus Service", Running: false),
			new("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", Running: true),
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
			new FirewallCliToolPresence("avp.exe",
				@"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe",
				present: true),
			new FirewallCliToolPresence("avp.com",
				@"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.com",
				present: true),
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
			new("MpsSvc", "Windows Defender Firewall", Running: true),
			new("BFE", "Base Filtering Engine", Running: true),
			new("WinDefend", "Microsoft Defender Antivirus Service", Running: false),
			new("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", Running: true),
		];
		List<FirewallCliToolPresence> tools =
		[
			new FirewallCliToolPresence("avp.exe",
				@"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe",
				present: true),
			new FirewallCliToolPresence("avp.com",
				@"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.com",
				present: true),
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
			new("MpsSvc", "Windows Defender Firewall", Running: true),
			new("BFE", "Base Filtering Engine", Running: true),
			new("WinDefend", "Microsoft Defender Antivirus Service", Running: true),
		];
		List<FirewallCliToolPresence> noTools = [];

		// Act
		(FirewallProviderDetectedKind kind, _) =
			FirewallProviderClassifier.Classify(services, noTools, kasperskyManagesWindowsFirewall: false);

		// Assert — no false positive
		Assert.Equal(FirewallProviderDetectedKind.WindowsDefenderFirewall, kind);
	}

	// ── Zero-allocation assertion (10k evaluations) ──────────────────────────────

	[Fact]
	public void Classify_ZeroAllocations_Per10kEvaluations()
	{
		List<FirewallServiceState> services =
		[
			new("klim6", "Kaspersky Anti-Virus NDIS 6 Filter", Running: true),
		];
		List<FirewallCliToolPresence> tools =
		[
			new FirewallCliToolPresence("avp.exe",
				@"C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe",
				present: true),
		];

		// Warm-up
		FirewallProviderClassifier.Classify(services, tools, false);
		FirewallProviderClassifier.Classify(services, tools, false);

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int i = 0; i < 10_000; i++)
		{
			FirewallProviderClassifier.Classify(services, tools, false);
		}
		long after = GC.GetAllocatedBytesForCurrentThread();

		long allocatedPerCall = (after - before) / 10_000;
		Assert.Equal(0, allocatedPerCall);
	}
}
