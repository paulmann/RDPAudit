// File:    src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Implements the 15 prerequisite probes shown on the Prerequisites tab.
//          Object-Access auditing check uses GUID + auditpol /r CSV bitfield (locale-stable).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Result of a single prerequisite probe.</summary>
public sealed record PrerequisiteResult(string Name, bool IsOk, string Detail, PrerequisiteFix? Fix = null);

/// <summary>Optional remediation action for a prerequisite that failed.</summary>
public sealed record PrerequisiteFix(string Description, Func<Task<string>> ApplyAsync);

/// <summary>Implements the 15 prerequisite probes shown on the Prerequisites tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class PrerequisiteChecker
{
	public IReadOnlyList<PrerequisiteResult> RunAll()
	{
		List<PrerequisiteResult> results = new()
		{
			CheckOsVersion(),
			CheckDotNetRuntime(),
			CheckPowerShell(),
			CheckTermService(),
			CheckRdpPort(),
			CheckRdpFirewallRule(),
			CheckSecurityChannel(),
			CheckTsLocalChannel(),
			CheckTsRemoteChannel(),
			CheckRdpCoreChannel(),
			CheckSeSecurityPrivilege(),
			CheckProgramDataWritable(),
			CheckDatabaseAccessible(),
			CheckObjectAccessAuditing(),
			CheckLsassPpl(),
		};
		return results;
	}

	private static PrerequisiteResult CheckOsVersion()
	{
		Version v = Environment.OSVersion.Version;
		bool ok = v.Major >= 10 || (v.Major == 6 && v.Minor >= 3);
		return new PrerequisiteResult("OS version", ok, $"Detected {v}");
	}

	private static PrerequisiteResult CheckDotNetRuntime()
	{
		string fw = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
		bool ok = fw.Contains(".NET 8", StringComparison.OrdinalIgnoreCase) || fw.Contains(".NET 9", StringComparison.OrdinalIgnoreCase);
		return new PrerequisiteResult(".NET 8 runtime", ok, fw);
	}

	private static PrerequisiteResult CheckPowerShell()
	{
		try
		{
			using Process? p = Process.Start(new ProcessStartInfo("pwsh.exe", "-NoLogo -Command $PSVersionTable.PSVersion.Major")
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				CreateNoWindow = true,
			});
			if (p is null)
			{
				return new PrerequisiteResult("PowerShell 7+", false, "pwsh.exe not found");
			}

			p.WaitForExit(5_000);
			string output = p.StandardOutput.ReadToEnd().Trim();
			return new PrerequisiteResult("PowerShell 7+", output is "7" or "8" or "9", $"PSVersion.Major={output}");
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("PowerShell 7+", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckTermService()
	{
		try
		{
			using ServiceController controller = new("TermService");
			ServiceControllerStatus status = controller.Status;
			PrerequisiteFix? fix = status != ServiceControllerStatus.Running
				? new PrerequisiteFix("Start TermService", async () =>
				{
					try
					{
						using ServiceController c = new("TermService");
						c.Start();
						await Task.Run(() => c.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20))).ConfigureAwait(false);
						return "Started";
					}
					catch (Exception ex) { return ex.Message; }
				})
				: null;
			return new PrerequisiteResult(
				"Remote Desktop Services running",
				status == ServiceControllerStatus.Running,
				status.ToString(),
				fix);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("Remote Desktop Services running", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckRdpPort()
	{
		int port = ReadConfiguredRdpPort();
		string name = string.Format(CultureInfo.InvariantCulture, "RDP port {0} listening", port);
		try
		{
			using TcpClient client = new();
			IAsyncResult result = client.BeginConnect(IPAddress.Loopback, port, null, null);
			bool ok = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(2));
			if (ok && client.Connected)
			{
				client.EndConnect(result);
				return new PrerequisiteResult(name, true, string.Format(CultureInfo.InvariantCulture, "Connected to 127.0.0.1:{0}", port));
			}

			return new PrerequisiteResult(name, false, string.Format(CultureInfo.InvariantCulture, "No listener on 127.0.0.1:{0}", port));
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult(name, false, ex.Message);
		}
	}

	/// <summary>Reads the configured RDP TCP port via the central
	/// <see cref="RdpListenerPortResolver"/>. Falls back to
	/// <see cref="RdpConfigurationModel.DefaultRdpPort"/> when the registry value is missing or
	/// out of range — the listener is the source of truth, not the well-known default.</summary>
	private static int ReadConfiguredRdpPort()
		=> RdpListenerPortResolver.Resolve().Port;

	private static PrerequisiteResult CheckRdpFirewallRule()
	{
		// Stage 4: resolve the live RDP listener port via the central resolver so we never drift
		// back to a hard-coded 3389 or to the user's diagnostic 55554. The resolver falls back
		// to the documented default only when the registry value is missing / out of range.
		RdpListenerPortResolution portResolution = RdpListenerPortResolver.Resolve();
		int port = portResolution.Port;
		string portString = port.ToString(CultureInfo.InvariantCulture);
		string ruleName = "RdpAudit-RDP-Allow-" + portString;

		// Provider / Kaspersky / GPO-store context — surfaced regardless of pass/fail so the
		// operator always sees what RdpAudit observed about the firewall stack.
		FirewallProviderDiagnostics providerDiagnostics;
		try
		{
			providerDiagnostics = new FirewallProviderDiagnosticsProbe().Probe();
		}
		catch (Exception ex)
		{
			providerDiagnostics = new FirewallProviderDiagnostics
			{
				Notes = new[] { "Firewall provider probe failed: " + ex.GetType().Name + " — " + ex.Message },
			};
		}

		// Probe for ANY enabled, inbound, allow, TCP rule covering the resolved port. The English
		// console pin keeps the LocalPort / Direction / Action / Protocol tokens stable across
		// localised hosts; we never depend on the localised Windows group name.
		string[] showArgsForDiagnostics = new[]
		{
			"advfirewall", "firewall", "show", "rule", "name=all", "verbose",
		};
		CapturedCommand probe = RunCapturedEnglishConsole(TrustedEnglishConsoleTool.NetshShowAllRulesVerbose);
		bool ruleMatches = NetshRuleScanner.ContainsAllowInboundForPort(probe.StdOut, port);

		NetshProbeOutcome outcome = new(
			Command: "netsh",
			Arguments: showArgsForDiagnostics,
			ExitCode: probe.ExitCode,
			StdOut: probe.StdOut,
			StdErr: probe.StdErr,
			ConfiguredRdpPort: port,
			RuleNameAttempted: ruleName,
			TimedOut: probe.TimedOut);

		bool ok = probe.ExitCode == 0 && ruleMatches;
		string detail = ok
			? BuildPassDetail(port, portResolution, providerDiagnostics)
			: BuildFailDetail(probe, outcome, port, providerDiagnostics);

		PrerequisiteFix? fix = ok ? null : new PrerequisiteFix(
			string.Format(CultureInfo.InvariantCulture, "Add RdpAudit RDP allow rule on TCP/{0}", portString),
			() =>
			{
				if (providerDiagnostics.LocalRulesAreGpoStoreOnly)
				{
					return Task.FromResult(string.Format(CultureInfo.InvariantCulture,
						"Local Windows Firewall writes are blocked by Group Policy (LocalFirewallRules N/A — GPO-store only). "
						+ "Add the allow rule on TCP/{0} through Group Policy or contact the policy administrator. "
						+ "Provider: {1}.", portString, providerDiagnostics.ProviderName));
				}

				if (providerDiagnostics.ProviderKind == FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall)
				{
					return Task.FromResult(string.Format(CultureInfo.InvariantCulture,
						"Kaspersky is managing Windows Firewall on this host ({0}). RdpAudit will not invoke "
						+ "Kaspersky's CLI directly. Use the Kaspersky management console to allow inbound "
						+ "TCP/{1} or contact the Kaspersky administrator.", providerDiagnostics.ProviderName, portString));
				}

				string[] addArgs = new[]
				{
					"advfirewall", "firewall", "add", "rule",
					"name=" + ruleName,
					"dir=in",
					"action=allow",
					"protocol=TCP",
					"localport=" + portString,
				};
				CapturedCommand fixResult = RunCapturedCommand("netsh", addArgs);
				if (fixResult.ExitCode == 0)
				{
					return Task.FromResult(string.Format(CultureInfo.InvariantCulture,
						"Added rule '{0}' for TCP/{1}.", ruleName, portString));
				}

				NetshProbeOutcome fixOutcome = new(
					Command: "netsh",
					Arguments: addArgs,
					ExitCode: fixResult.ExitCode,
					StdOut: fixResult.StdOut,
					StdErr: fixResult.StdErr,
					ConfiguredRdpPort: port,
					RuleNameAttempted: ruleName,
					TimedOut: fixResult.TimedOut);
				return Task.FromResult(NetshDiagnosticsFormatter.FormatShort(fixOutcome)
					+ "; provider=" + providerDiagnostics.ProviderName
					+ "; kind=" + providerDiagnostics.ProviderKind);
			});

		return new PrerequisiteResult("Windows Firewall RDP rule present", ok, detail, fix);
	}

	/// <summary>Builds the pass-case detail string. Includes the resolved port + source (registry
	/// vs default) and the detected provider so the operator can confirm the rule is for the
	/// listener actually in use.</summary>
	private static string BuildPassDetail(
		int port,
		RdpListenerPortResolution portResolution,
		FirewallProviderDiagnostics providerDiagnostics)
	{
		string portString = port.ToString(CultureInfo.InvariantCulture);
		StringBuilder sb = new();
		sb.AppendFormat(CultureInfo.InvariantCulture,
			"Found enabled inbound allow rule for TCP/{0}", portString);
		sb.Append(" (port source: ").Append(portResolution.Source).Append(')');
		if (providerDiagnostics.ProviderKind != FirewallProviderDetectedKind.Unknown)
		{
			sb.Append("; provider=").Append(providerDiagnostics.ProviderName);
		}
		if (providerDiagnostics.LocalRulesAreGpoStoreOnly)
		{
			sb.Append("; note: LocalFirewallRules N/A (GPO-store only) — local writes are blocked by policy, but a GPO-pushed rule already covers the port.");
		}
		return sb.ToString();
	}

	/// <summary>Builds the fail-case detail string. Includes command label, exit code, timeout
	/// flag, stdout/stderr summary, resolved port, proposed RdpAudit rule name, provider kind,
	/// stale-rule hints (port-matched rule blocks that failed an Enabled/Protocol gate), and a
	/// list of enabled inbound allow TCP ports observed elsewhere — so a stale 3389 rule is
	/// immediately recognisable.</summary>
	private static string BuildFailDetail(
		CapturedCommand probe,
		NetshProbeOutcome outcome,
		int port,
		FirewallProviderDiagnostics providerDiagnostics)
	{
		StringBuilder sb = new();
		sb.Append(NetshDiagnosticsFormatter.FormatShort(outcome));

		if (providerDiagnostics.ProviderKind != FirewallProviderDetectedKind.Unknown)
		{
			sb.Append("; provider=").Append(providerDiagnostics.ProviderName);
			sb.Append("; kind=").Append(providerDiagnostics.ProviderKind);
		}
		if (providerDiagnostics.LocalRulesAreGpoStoreOnly)
		{
			sb.Append("; LocalFirewallRules=N/A (GPO-store only) — local netsh writes are blocked by Group Policy");
		}

		// Surface stale / mismatched rules so the operator sees "you have a rule for 3389 while
		// the listener is on 55554" instead of an opaque negative.
		if (probe.ExitCode == 0)
		{
			IReadOnlyList<int> enabledPorts = NetshRuleScanner.EnumerateEnabledAllowInboundTcpPorts(probe.StdOut);
			if (enabledPorts.Count > 0)
			{
				sb.Append("; enabled-allow-tcp-ports=[");
				for (int i = 0; i < enabledPorts.Count; i++)
				{
					if (i > 0)
					{
						sb.Append(',');
					}
					sb.Append(enabledPorts[i].ToString(CultureInfo.InvariantCulture));
				}
				sb.Append(']');

				bool defaultRulePresent = enabledPorts.Contains(RdpConfigurationModel.DefaultRdpPort);
				if (port != RdpConfigurationModel.DefaultRdpPort && defaultRulePresent)
				{
					sb.AppendFormat(CultureInfo.InvariantCulture,
						"; stale-rule-hint: an allow rule exists for TCP/{0} but the live listener is on TCP/{1}",
						RdpConfigurationModel.DefaultRdpPort, port);
				}
			}

			IReadOnlyList<NetshRulePortMatchExplanation> portMatches = NetshRuleScanner.ExplainPortMatches(probe.StdOut, port);
			foreach (NetshRulePortMatchExplanation match in portMatches)
			{
				if (match.EnabledOk && match.DirectionInOk && match.ActionAllowOk && match.ProtocolTcpOk)
				{
					continue;
				}

				sb.Append("; matching-rule-rejected[")
					.Append(string.IsNullOrEmpty(match.RuleName) ? "(unnamed)" : match.RuleName)
					.Append("]: enabled=").Append(match.EnabledOk ? "yes" : "no")
					.Append(",in=").Append(match.DirectionInOk ? "yes" : "no")
					.Append(",allow=").Append(match.ActionAllowOk ? "yes" : "no")
					.Append(",tcp=").Append(match.ProtocolTcpOk ? "yes" : "no");
			}
		}

		return sb.ToString();
	}


	private static PrerequisiteResult CheckSecurityChannel()
		=> CheckEventChannelExists("Security");

	private static PrerequisiteResult CheckTsLocalChannel()
		=> CheckEventChannelExists("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational");

	private static PrerequisiteResult CheckTsRemoteChannel()
		=> CheckEventChannelExists("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational");

	private static PrerequisiteResult CheckRdpCoreChannel()
		=> CheckEventChannelExists("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational");

	private static PrerequisiteResult CheckEventChannelExists(string channel)
	{
		try
		{
			using System.Diagnostics.Eventing.Reader.EventLogSession session = new();
			System.Diagnostics.Eventing.Reader.EventLogConfiguration config = new(channel, session);
			bool enabled = config.IsEnabled;
			PrerequisiteFix? fix = enabled
				? null
				: new PrerequisiteFix("Enable channel via wevtutil", () =>
					Task.FromResult(RunCommand("wevtutil", "sl \"" + channel + "\" /enabled:true") == 0
						? "Enabled" : "wevtutil failed"));
			return new PrerequisiteResult($"Channel: {channel}", enabled, $"Enabled={enabled}", fix);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult($"Channel: {channel}", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckSeSecurityPrivilege()
	{
		bool isAdmin = false;
		try
		{
			using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
			System.Security.Principal.WindowsPrincipal principal = new(identity);
			isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
		}
		catch
		{
			isAdmin = false;
		}

		return new PrerequisiteResult("Service account has SeSecurityPrivilege", isAdmin, isAdmin ? "Administrators" : "Not elevated");
	}

	private static PrerequisiteResult CheckProgramDataWritable()
	{
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string dir = Path.Combine(programData, "RdpAudit");
		try
		{
			Directory.CreateDirectory(dir);
			string probe = Path.Combine(dir, ".write-probe");
			File.WriteAllText(probe, "ok");
			File.Delete(probe);
			return new PrerequisiteResult("ProgramData writable", true, dir);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("ProgramData writable", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckDatabaseAccessible()
	{
		string path = ReadOnlyDb.DatabasePath;
		bool exists = File.Exists(path);
		return new PrerequisiteResult("Audit database accessible", exists, exists ? path : $"Missing: {path}");
	}

	private static PrerequisiteResult CheckObjectAccessAuditing()
	{
		// Use GUIDs and the auditpol /r CSV bit field rather than parsing localized output.
		string[] subcategoryGuids =
		{
			AuditPolicyManager.GuidFileSystem,
			AuditPolicyManager.GuidRegistry,
		};

		List<string> details = new();
		bool ok = true;
		foreach (string guid in subcategoryGuids)
		{
			AuditPolicyState? state = AuditPolicyManager.ReadSubcategoryState(guid);
			if (state is null)
			{
				ok = false;
				details.Add(string.Format(CultureInfo.InvariantCulture, "{0}: read failed", guid));
				continue;
			}

			bool subOk = state.Success && state.Failure;
			ok &= subOk;
			details.Add(string.Format(CultureInfo.InvariantCulture, "{0}: S={1} F={2}",
				guid, state.Success ? "Y" : "N", state.Failure ? "Y" : "N"));
		}

		PrerequisiteFix? fix = ok
			? null
			: new PrerequisiteFix("Apply Object Access auditpol", () =>
			{
				int failures = 0;
				foreach (string guid in subcategoryGuids)
				{
					string args = string.Format(CultureInfo.InvariantCulture,
						"/set /subcategory:{0} /success:enable /failure:enable", guid);
					if (RunCommand("auditpol.exe", args) != 0)
					{
						failures++;
					}
				}
				return Task.FromResult(failures == 0 ? "Applied" : string.Format(CultureInfo.InvariantCulture, "{0} subcategory updates failed", failures));
			});

		return new PrerequisiteResult("Object Access auditing", ok, string.Join("; ", details), fix);
	}

	private static PrerequisiteResult CheckLsassPpl()
	{
		int code = RunCommand("reg.exe",
			"query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL");
		PrerequisiteFix? fix = code != 0
			? new PrerequisiteFix("Enable LSASS RunAsPPL (requires reboot)", () =>
				Task.FromResult(RunCommand("reg.exe",
					"add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f") == 0
					? "Set RunAsPPL=1; reboot to apply"
					: "reg.exe failed"))
			: null;
		return new PrerequisiteResult("LSASS RunAsPPL enabled", code == 0,
			code == 0 ? "Configured" : "Not set (reboot required after enabling)",
			fix);
	}

	private static int RunCommand(string exe, string args)
	{
		try
		{
			ProcessStartInfo psi = new(exe, args)
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return -1;
			}

			proc.WaitForExit(15_000);
			return proc.ExitCode;
		}
		catch
		{
			return -1;
		}
	}

	/// <summary>Captured outcome of one process invocation: exit code + both standard streams.</summary>
	internal readonly record struct CapturedCommand(int ExitCode, string StdOut, string StdErr, bool TimedOut);

	/// <summary>Spawns a whitelisted tool through the parse-stable English console
	/// (<c>cmd /d /c "chcp 437 >nul &amp; ..."</c>). Used for parsed-stdout probes that need
	/// stable Latin-script tokens regardless of the host's UI culture.</summary>
	internal static CapturedCommand RunCapturedEnglishConsole(TrustedEnglishConsoleTool tool)
	{
		try
		{
			EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(tool);
			System.Text.Encoding encoding = QwinstaConsoleEncoding.Resolve();
			ProcessStartInfo psi = new(spawn.Executable)
			{
				Arguments = spawn.Arguments,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
				StandardOutputEncoding = encoding,
				StandardErrorEncoding = encoding,
			};

			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return new CapturedCommand(-1, string.Empty, "Process.Start returned null", TimedOut: false);
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
					// Already exited between WaitForExit and Kill.
				}

				return new CapturedCommand(-1, stdout, stderr, TimedOut: true);
			}

			return new CapturedCommand(proc.ExitCode, stdout, stderr, TimedOut: false);
		}
		catch (Exception ex)
		{
			return new CapturedCommand(-1, string.Empty, ex.GetType().Name + ": " + ex.Message, TimedOut: false);
		}
	}

	/// <summary>Spawns <paramref name="exe"/> using <see cref="ProcessStartInfo.ArgumentList"/> —
	/// arguments are NEVER concatenated into a shell string — and returns both captured
	/// streams along with the process exit code. A hard 15s timeout bounds UI hangs.</summary>
	internal static CapturedCommand RunCapturedCommand(string exe, IReadOnlyList<string> arguments)
	{
		try
		{
			ProcessStartInfo psi = new(exe)
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};
			foreach (string a in arguments)
			{
				psi.ArgumentList.Add(a);
			}

			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return new CapturedCommand(-1, string.Empty, "Process.Start returned null", TimedOut: false);
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
					// Already exited between WaitForExit and Kill.
				}

				return new CapturedCommand(-1, stdout, stderr, TimedOut: true);
			}

			return new CapturedCommand(proc.ExitCode, stdout, stderr, TimedOut: false);
		}
		catch (Exception ex)
		{
			return new CapturedCommand(-1, string.Empty, ex.GetType().Name + ": " + ex.Message, TimedOut: false);
		}
	}
}
