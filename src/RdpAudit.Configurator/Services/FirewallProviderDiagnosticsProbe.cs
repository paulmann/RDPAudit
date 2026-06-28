// File:    src/RdpAudit.Configurator/Services/FirewallProviderDiagnosticsProbe.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Windows-side collector that builds a FirewallProviderDiagnostics snapshot describing
//          the active firewall provider context: Windows Defender Firewall services (MpsSvc /
//          BFE), detected Kaspersky / third-party services, presence of Kaspersky CLI tools
//          (kescli.exe / kavshell.exe / avp.exe), and the configured RDP TCP port. The probe
//          is intentionally read-only — it never starts/stops services, never writes registry
//          values, and never invokes destructive Kaspersky CLI verbs. Used by the Firewall tab
//          UI panel and by the Prerequisites tab's RDP-rule diagnostic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Windows-side collector that builds a <see cref="FirewallProviderDiagnostics"/> snapshot.</summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallProviderDiagnosticsProbe
{
	/// <summary>Short names of Windows services we always probe — Defender stack and the
	/// well-known Kaspersky / third-party services.</summary>
	internal static readonly string[] ProbedServiceNames = new[]
	{
		"MpsSvc",            // Windows Defender Firewall
		"BFE",               // Base Filtering Engine
		"WinDefend",         // Microsoft Defender Antivirus
		"AVP",               // Kaspersky generic AV/EP service
		"AVPCloud",
		"klnagent",          // Kaspersky Security Center Network Agent
		"klflt",
		"klim6",
		"kavfs",             // Kaspersky Security for Windows Server
		"kavfsgt",
		"kavfsmui",
		"kavfsrcn",
		"kavfswh",
		"ekrn",              // ESET
		"BdAgent",           // Bitdefender
		"vsmon",             // Check Point ZoneAlarm
		"SAVService",        // Sophos
		"mfemms",            // McAfee
		"mbamservice",       // Malwarebytes
	};

	/// <summary>Probed third-party CLI tool short names (resolved against common install locations).</summary>
	internal static readonly string[] ProbedCliTools = new[]
	{
		"kescli.exe",
		"kavshell.exe",
		"avp.exe",
		"avp.com",
	};

	/// <summary>Run all probes and return the resulting diagnostic snapshot. Never throws —
	/// every probe is wrapped so a partial failure simply contributes a Note entry.</summary>
	public FirewallProviderDiagnostics Probe()
	{
		List<FirewallServiceState> services = new();
		List<string> notes = new();
		foreach (string svcName in ProbedServiceNames)
		{
			FirewallServiceState? state = ProbeService(svcName, notes);
			if (state is not null)
			{
				services.Add(state);
			}
		}

		List<FirewallCliToolPresence> cliTools = new();
		foreach (string toolName in ProbedCliTools)
		{
			cliTools.Add(ProbeCliTool(toolName));
		}

		int? configuredPort = TryReadConfiguredRdpPort(notes);

		// SecurityCenter2 is additional, best-effort evidence. The probe never depends on it —
		// Windows Server SKUs hide SecurityCenter2 and we still classify correctly via services /
		// CLI presence. When it is available we surface the AntiVirus / Firewall product names as
		// supplemental notes so the diagnostics text matches what AV vendors call themselves.
		IReadOnlyList<SecurityCenter2ProductReading> securityCenterReadings = ProbeSecurityCenter2(notes);
		foreach (SecurityCenter2ProductReading reading in securityCenterReadings)
		{
			notes.Add("SecurityCenter2 " + reading.ProductType + ": " + reading.DisplayName);
		}

		bool kasperskyManagesFirewall = AnyServiceRunning(services, "kavfs", "kavfsgt", "kavfsmui", "kavfsrcn", "kavfswh");

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services, cliTools, kasperskyManagesWindowsFirewall: kasperskyManagesFirewall);

		// SecurityCenter2 evidence: if Kaspersky is registered as the firewall product, promote
		// the unknown classification (no service / CLI signals reached us) to KasperskyDetected
		// so the operator still sees the right provider name on workstation SKUs.
		if (kind == FirewallProviderDetectedKind.WindowsDefenderFirewall
			&& securityCenterReadings.Any(r => ProductMentionsKaspersky(r.DisplayName)))
		{
			kind = FirewallProviderDetectedKind.KasperskyDetected;
			name = securityCenterReadings.First(r => ProductMentionsKaspersky(r.DisplayName)).DisplayName;
		}

		IReadOnlyList<LocalRulePolicyRow> policyRows = ProbeLocalRulePolicy(notes);
		bool gpoStoreOnly = false;
		foreach (LocalRulePolicyRow row in policyRows)
		{
			if (row.Hint == LocalRulePolicyHint.GpoStoreOnly)
			{
				gpoStoreOnly = true;
				break;
			}
		}

		bool? localRulesAllowed = kind switch
		{
			FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall => false,
			FirewallProviderDetectedKind.WindowsDefenderFirewall when gpoStoreOnly => false,
			FirewallProviderDetectedKind.WindowsDefenderFirewall => true,
			_ when gpoStoreOnly => false,
			_ => null,
		};

		return new FirewallProviderDiagnostics
		{
			ProviderKind = kind,
			ProviderName = name,
			ProviderServices = services,
			DetectedCliTools = cliTools,
			WindowsFirewallProfiles = Array.Empty<FirewallProfileState>(),
			LocalRuleManagementAllowed = localRulesAllowed,
			LocalRulePolicyRows = policyRows,
			ConfiguredRdpPort = configuredPort,
			Notes = notes,
		};
	}

	/// <summary>One reading from the SecurityCenter2 WMI provider. <see cref="ProductType"/>
	/// is the human label (`AntiVirusProduct` / `FirewallProduct`); <see cref="DisplayName"/>
	/// is the product's reported name. Both are safe to surface verbatim in diagnostics.</summary>
	internal sealed record SecurityCenter2ProductReading(string ProductType, string DisplayName);

	/// <summary>Best-effort probe of the SecurityCenter2 WMI namespace. Returns an empty list on
	/// hosts where SecurityCenter2 is unavailable (Windows Server SKUs, locked-down hosts) — and
	/// records a single Note when WMI threw, so operators can correlate against partial data.</summary>
	private static List<SecurityCenter2ProductReading> ProbeSecurityCenter2(List<string> notes)
	{
		List<SecurityCenter2ProductReading> readings = new();
		try
		{
			readings.AddRange(QuerySecurityCenter2Class("AntiVirusProduct"));
			readings.AddRange(QuerySecurityCenter2Class("FirewallProduct"));
		}
		catch (System.Management.ManagementException ex)
		{
			notes.Add("SecurityCenter2 probe failed: " + ex.GetType().Name + " — " + ex.Message);
		}
		catch (System.Runtime.InteropServices.COMException ex)
		{
			notes.Add("SecurityCenter2 probe failed: " + ex.GetType().Name + " — " + ex.Message);
		}
		catch (UnauthorizedAccessException ex)
		{
			notes.Add("SecurityCenter2 probe failed: " + ex.GetType().Name + " — " + ex.Message);
		}
		return readings;
	}

	private static IEnumerable<SecurityCenter2ProductReading> QuerySecurityCenter2Class(string className)
	{
		using System.Management.ManagementObjectSearcher searcher = new(
			@"root\SecurityCenter2",
			"SELECT displayName FROM " + className);
		foreach (System.Management.ManagementBaseObject mo in searcher.Get())
		{
			string? display = mo["displayName"] as string;
			mo.Dispose();
			if (!string.IsNullOrWhiteSpace(display))
			{
				yield return new SecurityCenter2ProductReading(className, display.Trim());
			}
		}
	}

	private static bool ProductMentionsKaspersky(string displayName)
		=> !string.IsNullOrEmpty(displayName)
			&& displayName.Contains("kaspersky", StringComparison.OrdinalIgnoreCase);

	/// <summary>Runs <c>netsh advfirewall show allprofiles</c> through the parse-stable English
	/// console and parses every <c>LocalFirewallRules</c> row. On hosts where group policy forces
	/// rules into the GPO store, this surfaces <see cref="LocalRulePolicyHint.GpoStoreOnly"/>.
	/// Returns an empty list when the spawn or parse fails — a Note is appended instead.</summary>
	private static IReadOnlyList<LocalRulePolicyRow> ProbeLocalRulePolicy(List<string> notes)
	{
		try
		{
			EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(TrustedEnglishConsoleTool.NetshShowAllProfilesState);
			System.Text.Encoding encoding = QwinstaConsoleEncoding.Resolve();
			System.Diagnostics.ProcessStartInfo psi = new(spawn.Executable)
			{
				Arguments = spawn.Arguments,
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				StandardOutputEncoding = encoding,
				StandardErrorEncoding = encoding,
			};

			using System.Diagnostics.Process? proc = System.Diagnostics.Process.Start(psi);
			if (proc is null)
			{
				notes.Add("netsh advfirewall show allprofiles: Process.Start returned null");
				return Array.Empty<LocalRulePolicyRow>();
			}

			string stdout = proc.StandardOutput.ReadToEnd();
			string stderr = proc.StandardError.ReadToEnd();
			bool exited = proc.WaitForExit(15_000);
			if (!exited)
			{
				try
				{
					proc.Kill(entireProcessTree: true);
				}
				catch (InvalidOperationException)
				{
				}
				notes.Add("netsh advfirewall show allprofiles: timed out after 15s");
				return Array.Empty<LocalRulePolicyRow>();
			}

			if (proc.ExitCode != 0)
			{
				notes.Add(
					"netsh advfirewall show allprofiles exited " + proc.ExitCode.ToString(CultureInfo.InvariantCulture)
					+ (string.IsNullOrEmpty(stderr) ? string.Empty : "; stderr=" + stderr.Trim()));
				return Array.Empty<LocalRulePolicyRow>();
			}

			return LocalRulePolicyParser.ParseAllProfiles(stdout);
		}
		catch (Exception ex)
		{
			notes.Add("netsh advfirewall show allprofiles failed: " + ex.GetType().Name + " — " + ex.Message);
			return Array.Empty<LocalRulePolicyRow>();
		}
	}

	private static FirewallServiceState? ProbeService(string serviceName, List<string> notes)
	{
		try
		{
			using ServiceController controller = new(serviceName);
			ServiceControllerStatus status = controller.Status;
			string display;
			try
			{
				display = controller.DisplayName;
			}
			catch (InvalidOperationException)
			{
				display = serviceName;
			}

			return new FirewallServiceState(
				ServiceName: serviceName,
				DisplayName: display,
				Status: status.ToString(),
				IsRunning: status == ServiceControllerStatus.Running);
		}
		catch (InvalidOperationException)
		{
			// Service is not installed — that is the common case for product-specific names.
			return null;
		}
		catch (Exception ex)
		{
			notes.Add(string.Format(CultureInfo.InvariantCulture,
				"Service '{0}' probe failed: {1} — {2}", serviceName, ex.GetType().Name, ex.Message));
			return null;
		}
	}

	private static FirewallCliToolPresence ProbeCliTool(string toolName)
	{
		// Common Kaspersky install roots. We never invoke the tool; presence on disk is enough
		// to signal that the operator has the product available.
		string[] candidates = new[]
		{
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Kaspersky Lab", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Kaspersky Lab", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Kaspersky", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Kaspersky", toolName),
		};

		foreach (string candidate in candidates)
		{
			if (TryFindByName(candidate, toolName) is string match)
			{
				return new FirewallCliToolPresence(toolName, match, Present: true);
			}
		}

		string? pathResolved = ResolveOnPath(toolName);
		if (pathResolved is not null)
		{
			return new FirewallCliToolPresence(toolName, pathResolved, Present: true);
		}

		return new FirewallCliToolPresence(toolName, Path: null, Present: false);
	}

	private static string? TryFindByName(string baseDir, string toolName)
	{
		try
		{
			if (File.Exists(baseDir))
			{
				return baseDir;
			}

			string? parent = Path.GetDirectoryName(baseDir);
			if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
			{
				return null;
			}

			foreach (string file in Directory.EnumerateFiles(parent, toolName, SearchOption.AllDirectories))
			{
				return file;
			}
		}
		catch
		{
			// Best-effort — directory not accessible. Treat as not-present.
		}
		return null;
	}

	private static string? ResolveOnPath(string toolName)
	{
		string? pathEnv = Environment.GetEnvironmentVariable("PATH");
		if (string.IsNullOrEmpty(pathEnv))
		{
			return null;
		}

		foreach (string dir in pathEnv.Split(Path.PathSeparator))
		{
			if (string.IsNullOrWhiteSpace(dir))
			{
				continue;
			}

			try
			{
				string candidate = Path.Combine(dir, toolName);
				if (File.Exists(candidate))
				{
					return candidate;
				}
			}
			catch
			{
				// Skip invalid PATH entries.
			}
		}

		return null;
	}

	private static int? TryReadConfiguredRdpPort(List<string> notes)
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
				@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
				writable: false);
			if (key?.GetValue(RdpConfigurationModel.PortNumberValueName) is int dword
				&& RdpConfigurationModel.IsValidPort(dword))
			{
				return dword;
			}
		}
		catch (Exception ex)
		{
			notes.Add("Could not read configured RDP port: " + ex.GetType().Name + " — " + ex.Message);
		}

		return null;
	}

	private static bool AnyServiceRunning(IReadOnlyList<FirewallServiceState> services, params string[] names)
	{
		foreach (FirewallServiceState svc in services)
		{
			if (!svc.IsRunning)
			{
				continue;
			}

			foreach (string name in names)
			{
				if (string.Equals(svc.ServiceName, name, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
		}
		return false;
	}
}
