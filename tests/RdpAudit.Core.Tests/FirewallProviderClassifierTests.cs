// File:    tests/RdpAudit.Core.Tests/FirewallProviderClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pure-classifier coverage for FirewallProviderClassifier and the diagnostics text
//          formatter. Verifies that Kaspersky-only signals classify as KasperskyDetected,
//          KSWS-style firewall management promotes to KasperskyManagedWindowsFirewall, and
//          third-party services classify into ThirdPartyFirewallUnknown without false-positive
//          Kaspersky labelling. Built without any Win32 / WMI dependency so it runs from any host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pure-classifier coverage for <see cref="FirewallProviderClassifier"/>.</summary>
public class FirewallProviderClassifierTests
{
	[Fact]
	public void Classify_NoSignals_ReturnsWindowsDefenderFirewall()
	{
		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services: Array.Empty<FirewallServiceState>(),
			cliTools: Array.Empty<FirewallCliToolPresence>(),
			kasperskyManagesWindowsFirewall: false);

		Assert.Equal(FirewallProviderDetectedKind.WindowsDefenderFirewall, kind);
		Assert.Equal("Windows Defender Firewall", name);
	}

	[Fact]
	public void Classify_KasperskyEndpointService_ReturnsKasperskyDetected()
	{
		FirewallServiceState[] services = new[]
		{
			new FirewallServiceState("AVP21.3", "Kaspersky Endpoint Security Service", "Running", IsRunning: true),
		};

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services,
			Array.Empty<FirewallCliToolPresence>(),
			kasperskyManagesWindowsFirewall: false);

		Assert.Equal(FirewallProviderDetectedKind.KasperskyDetected, kind);
		Assert.Equal("Kaspersky Endpoint Security for Windows", name);
	}

	[Fact]
	public void Classify_KasperskyServerWithFirewallManagement_PromotesToManaged()
	{
		FirewallServiceState[] services = new[]
		{
			new FirewallServiceState("kavfs", "Kaspersky Security Service", "Running", IsRunning: true),
			new FirewallServiceState("kavfsgt", "Kaspersky Security Management Service", "Running", IsRunning: true),
		};

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services,
			Array.Empty<FirewallCliToolPresence>(),
			kasperskyManagesWindowsFirewall: true);

		Assert.Equal(FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall, kind);
		Assert.Equal("Kaspersky Security for Windows Server", name);
	}

	[Fact]
	public void Classify_CliToolOnlyKasperskyServer_KescliMapsToEndpoint()
	{
		FirewallCliToolPresence[] cli = new[]
		{
			new FirewallCliToolPresence("kescli.exe", @"C:\Program Files (x86)\Kaspersky Lab\KES\kescli.exe", Present: true),
		};

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			Array.Empty<FirewallServiceState>(),
			cli,
			kasperskyManagesWindowsFirewall: false);

		Assert.Equal(FirewallProviderDetectedKind.KasperskyDetected, kind);
		Assert.Equal("Kaspersky Endpoint Security for Windows", name);
	}

	[Fact]
	public void Classify_ThirdPartyEset_ReturnsThirdPartyFirewallUnknown()
	{
		FirewallServiceState[] services = new[]
		{
			new FirewallServiceState("ekrn", "ESET Service", "Running", IsRunning: true),
		};

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services,
			Array.Empty<FirewallCliToolPresence>(),
			kasperskyManagesWindowsFirewall: false);

		Assert.Equal(FirewallProviderDetectedKind.ThirdPartyFirewallUnknown, kind);
		Assert.Equal("Third-party firewall (unclassified)", name);
	}

	[Fact]
	public void BuildDiagnosticsText_IncludesPortServicesCliAndNotes()
	{
		FirewallProviderDiagnostics diag = new()
		{
			ProviderKind = FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall,
			ProviderName = "Kaspersky Security for Windows Server",
			ConfiguredRdpPort = 33890,
			LocalRuleManagementAllowed = false,
			ProviderServices = new[]
			{
				new FirewallServiceState("kavfs", "Kaspersky Security Service", "Running", IsRunning: true),
				new FirewallServiceState("MpsSvc", "Windows Defender Firewall", "Running", IsRunning: true),
			},
			DetectedCliTools = new[]
			{
				new FirewallCliToolPresence("kavshell.exe", @"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security 11\kavshell.exe", Present: true),
				new FirewallCliToolPresence("avp.exe", null, Present: false),
			},
			Notes = new[]
			{
				"netsh advfirewall add rule failed: stderr captured",
			},
		};

		string text = diag.BuildDiagnosticsText();

		Assert.Contains("Kaspersky Security for Windows Server", text);
		Assert.Contains("Configured RDP port: 33890", text);
		Assert.Contains("kavfs", text);
		Assert.Contains("kavshell.exe", text);
		Assert.Contains("avp.exe: not present", text);
		Assert.Contains("Local Windows Firewall rule management allowed: no", text);
		Assert.Contains("netsh advfirewall add rule failed", text);
	}

	[Fact]
	public void NetshDiagnosticsFormatter_Short_IncludesExitPortRule()
	{
		NetshProbeOutcome outcome = new(
			Command: "netsh",
			Arguments: new[] { "advfirewall", "firewall", "show", "rule", "name=all", "verbose" },
			ExitCode: 1,
			StdOut: "No rules match the specified criteria.\n",
			StdErr: string.Empty,
			ConfiguredRdpPort: 33890,
			RuleNameAttempted: "RdpAudit-RDP-Allow-33890",
			TimedOut: false);

		string short_ = NetshDiagnosticsFormatter.FormatShort(outcome);

		Assert.Contains("netsh exit 1", short_);
		Assert.Contains("port=33890", short_);
		Assert.Contains("rule=RdpAudit-RDP-Allow-33890", short_);
		Assert.Contains("No rules match", short_);
	}

	[Fact]
	public void NetshDiagnosticsFormatter_Full_IncludesProviderDiagnostics()
	{
		NetshProbeOutcome outcome = new(
			Command: "netsh",
			Arguments: new[] { "advfirewall", "firewall", "show", "rule", "name=all" },
			ExitCode: 1,
			StdOut: "Listening...\n",
			StdErr: "permission denied",
			ConfiguredRdpPort: 3389,
			RuleNameAttempted: null,
			TimedOut: false);

		FirewallProviderDiagnostics diag = new()
		{
			ProviderKind = FirewallProviderDetectedKind.KasperskyDetected,
			ProviderName = "Kaspersky Endpoint Security for Windows",
		};

		string full = NetshDiagnosticsFormatter.FormatFull(outcome, diag);

		Assert.Contains("permission denied", full);
		Assert.Contains("Listening...", full);
		Assert.Contains("Kaspersky Endpoint Security for Windows", full);
		Assert.Contains("netsh advfirewall firewall show rule name=all", full);
	}
}
