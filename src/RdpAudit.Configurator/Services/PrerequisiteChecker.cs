// File:    src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Implements the 16 prerequisite probes shown on the Prerequisites tab.
//          Audit probes use subcategory GUIDs + auditpol /r CSV bitfield (locale-stable), never localized names.
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
	/// <summary>Runs every prerequisite probe. The firewall-rule probe reaches the network stack, so it
	/// is awaited rather than blocked on; the remaining probes shell out synchronously, which is why the
	/// Prerequisites tab drives this method from a thread-pool task instead of from the UI thread.</summary>
	public async Task<IReadOnlyList<PrerequisiteResult>> RunAllAsync(CancellationToken ct = default)
	{
		// The channel probes are appended in canonical EtwProviderMap order (Security, System,
		// TerminalServices-LocalSessionManager, TerminalServices-RemoteConnectionManager,
		// RemoteDesktopServices-RdpCoreTS, TerminalServices-Gateway, TerminalServices-RDPClient).
		List<PrerequisiteResult> results = new()
		{
			CheckOsVersion(),
			CheckDotNetRuntime(),
			CheckPowerShell(),
			CheckTermService(),
			CheckRdpPort(),
		};
		results.Add(await CheckRdpFirewallRuleAsync(ct).ConfigureAwait(false));
		results.AddRange(CheckEventChannels());
		results.Add(CheckSeSecurityPrivilege());
		results.Add(CheckProgramDataWritable());
		results.Add(CheckDatabaseAccessible());
		results.Add(CheckObjectAccessAuditing());
		results.Add(CheckAuditBaseline());
		results.Add(CheckLsassPpl());
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
		// Run the host the product actually uses (PowerShellHostResolver), not a bare "pwsh.exe" PATH
		// probe: a machine where pwsh sits somewhere off PATH must not be reported as missing it.
		PowerShellHostInfo host = PowerShellHostResolver.Resolve();
		try
		{
			using Process? p = Process.Start(new ProcessStartInfo(host.Path, "-NoLogo -NoProfile -NonInteractive -Command $PSVersionTable.PSVersion.Major")
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			});
			if (p is null)
			{
				return new PrerequisiteResult("PowerShell 7+", false, host.Path + " could not be started");
			}

			// Both streams are read through the ASYNCHRONOUS event pump while the 5 s wait runs: with a
			// redirected pipe, reading only after the wait can block until the child exits (so the deadline
			// was unenforceable), and blocking on a ReadToEndAsync task would be the sync-over-async pattern
			// this project forbids outright. A timeout is reported as a timeout - never as "not found".
			StringBuilder stdout = new();
			StringBuilder stderr = new();
			object gate = new();
			p.OutputDataReceived += (_, e) => AppendLine(gate, stdout, e.Data);
			p.ErrorDataReceived += (_, e) => AppendLine(gate, stderr, e.Data);
			p.BeginOutputReadLine();
			p.BeginErrorReadLine();

			bool exited = p.WaitForExit(5_000);
			if (!exited)
			{
				TryKill(p);
				return new PrerequisiteResult(
					"PowerShell 7+",
					false,
					"the PowerShell host did not answer within 5 s (" + host.Path + ").");
			}

			// Parameterless overload: waits for the asynchronous handlers to drain.
			p.WaitForExit();
			string output;
			lock (gate)
			{
				output = stdout.ToString().Trim();
			}

			// Accept any supported pwsh major (>= 7) instead of a closed 7/8/9 list: a host that
			// reports 10 must not be reported as a failed prerequisite. The host itself is still
			// required to be pwsh, checked below through host.IsPowerShellSeven.
			bool ok = int.TryParse(output, NumberStyles.Integer, CultureInfo.InvariantCulture, out int major)
				&& major >= 7;
			string detail = $"PSVersion.Major={output}";
			if (!ok || !host.IsPowerShellSeven)
			{
				detail += " (" + host.Detail + ")";
			}

			return new PrerequisiteResult("PowerShell 7+", ok && host.IsPowerShellSeven, detail);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("PowerShell 7+", false, host.Path + ": " + ex.Message);
		}
	}

	private static void AppendLine(object gate, StringBuilder target, string? line)
	{
		if (line is null)
		{
			return;
		}

		lock (gate)
		{
			target.AppendLine(line);
		}
	}

	/// <summary>Best-effort kill for a probe process that overran its deadline.</summary>
	private static void TryKill(Process p)
	{
		try
		{
			if (!p.HasExited)
			{
				p.Kill(entireProcessTree: true);
			}
		}
		catch (InvalidOperationException)
		{
			// Already exited between the check and the kill.
		}
		catch (System.ComponentModel.Win32Exception)
		{
			// Best effort only.
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

	private static async Task<PrerequisiteResult> CheckRdpFirewallRuleAsync(CancellationToken ct)
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
			providerDiagnostics = await new FirewallProviderDiagnosticsProbe()
				.ProbeAsync(ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
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


	private static List<PrerequisiteResult> CheckEventChannels()
	{
		// D7: one probe per monitored channel, driven by the unified EtwProviderMap channel list
		// instead of a hand-picked subset. A channel that exists but is disabled offers a wevtutil
		// fix; a channel that does not exist on this Windows build/SKU reports Missing and offers
		// no fix, because "wevtutil sl /enabled:true" cannot create a channel whose provider
		// manifest is not installed.
		List<PrerequisiteResult> results = new();
		foreach (EtwProviderInfo info in EtwProviderMap.Entries)
		{
			results.Add(CheckEventChannelExists(info.Channel));
		}

		return results;
	}

	private static PrerequisiteResult CheckEventChannelExists(string channel)
	{
		try
		{
			using System.Diagnostics.Eventing.Reader.EventLogSession session = new();
			System.Diagnostics.Eventing.Reader.EventLogConfiguration config = new(channel, session);
			bool enabled = config.IsEnabled;
			return BuildChannelResult(channel, EventChannelClassifier.Classify(exists: true, enabled));
		}
		catch (System.Diagnostics.Eventing.Reader.EventLogNotFoundException)
		{
			return BuildChannelResult(channel, EventChannelClassifier.Classify(exists: false, enabled: false));
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult($"Channel: {channel}", false, ex.Message);
		}
	}

	/// <summary>Maps the pure <see cref="EventChannelHealth"/> verdict to a prerequisite row:
	/// Missing channels deliberately carry no Fix, so the Prerequisites tab never offers a wevtutil
	/// enable button for a channel that cannot be created on this Windows build/SKU.</summary>
	private static PrerequisiteResult BuildChannelResult(string channel, EventChannelHealth health)
	{
		switch (health)
		{
			case EventChannelHealth.Ok:
				return new PrerequisiteResult($"Channel: {channel}", true, "Enabled=True");

			case EventChannelHealth.Disabled:
				PrerequisiteFix fix = new("Enable channel via wevtutil", () =>
					Task.FromResult(RunCommand("wevtutil", "sl \"" + channel + "\" /enabled:true") == 0
						? "Enabled" : "wevtutil failed"));
				return new PrerequisiteResult($"Channel: {channel}", false,
					"Enabled=False (channel exists but logging is disabled)", fix);

			case EventChannelHealth.Missing:
			default:
				return new PrerequisiteResult($"Channel: {channel}", false,
					"Missing on this Windows build/SKU (channel not found). No automatic fix available - enable the Windows feature that owns this channel.",
					null);
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
		string dir = RdpAuditPaths.Default.ProgramDataDirectory;
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

	private static PrerequisiteResult CheckAuditBaseline()
	{
		// D6: aggregated probe over the five security-audit baseline subcategories
		// (Logon, Special Logon, Account Lockout, Credential Validation, Kerberos
		// Authentication Service). Each must report BOTH Success and Failure; the
		// decision comes from the pure Core fold EvaluateBaseline so the check stays
		// deterministic and unit-tested, while reading stays GUID-based (locale-stable).
		IReadOnlyDictionary<string, AuditPolicyState?> current = AuditPolicyManager.ReadBaselineStates();
		IReadOnlyList<AuditBaselineResult> verdicts = AuditPolicyManager.EvaluateBaseline(current);

		List<string> details = new(verdicts.Count);
		foreach (AuditBaselineResult v in verdicts)
		{
			AuditPolicyState? state = v.Current;
			details.Add(string.Format(CultureInfo.InvariantCulture, "{0}: {1}",
				v.Subcategory,
				state is null ? "read failed" : string.Format(CultureInfo.InvariantCulture, "S={0} F={1}",
					state.Success ? "Y" : "N", state.Failure ? "Y" : "N")));
		}

		bool ok = verdicts.All(v => v.Ok);
		PrerequisiteFix? fix = ok
			? null
			: new PrerequisiteFix("Enable Success+Failure on audit baseline subcategories", () =>
			{
				IReadOnlyList<AuditPolicyApplyResult> apply = new AuditPolicyManager().ApplyBaseline();
				int failed = apply.Count(r => r.ExitCode != 0);
				return Task.FromResult(failed == 0
					? string.Format(CultureInfo.InvariantCulture, "Applied Success+Failure to {0} subcategories", apply.Count)
					: string.Format(CultureInfo.InvariantCulture, "{0}/{1} subcategory updates failed", failed, apply.Count));
			});

		return new PrerequisiteResult(
			"Audit subcategories Success+Failure enforced",
			ok,
			string.Join("; ", details),
			fix);
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
		ProcessStartInfo psi = new(exe, args)
		{
			UseShellExecute = false,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			CreateNoWindow = true,
		};

		// Same single runner as the captured variants: both streams are drained (the old body only
		// redirected them and never read, so a talkative tool filled the pipe buffer and deadlocked the
		// prerequisite probe) and the 15 s budget is enforced before the kill.
		return RunCapturedCore(psi, PrerequisiteCommandTimeoutMilliseconds).ExitCode;
	}

	/// <summary>Captured outcome of one process invocation: exit code + both standard streams.</summary>
	internal readonly record struct CapturedCommand(int ExitCode, string StdOut, string StdErr, bool TimedOut);

	/// <summary>Spawns a whitelisted tool through the parse-stable English console
	/// (<c>cmd /d /c "chcp 437 >nul &amp; ..."</c>). Used for parsed-stdout probes that need
	/// stable Latin-script tokens regardless of the host's UI culture.</summary>
	internal static CapturedCommand RunCapturedEnglishConsole(TrustedEnglishConsoleTool tool)
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(tool);
		// Decode the code page the spawn just pinned (cp437), not the host's OEM page: decoding cp437
		// output with cp866/cp850 is exactly the mojibake this helper exists to prevent.
		System.Text.Encoding encoding = OemConsoleEncoding.Resolve(spawn.CodePage);
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

		return RunCapturedCore(psi, PrerequisiteCommandTimeoutMilliseconds);
	}

	/// <summary>Spawns <paramref name="exe"/> using <see cref="ProcessStartInfo.ArgumentList"/> —
	/// arguments are NEVER concatenated into a shell string — and returns both captured
	/// streams along with the process exit code. A hard 15s timeout bounds UI hangs.</summary>
	internal static CapturedCommand RunCapturedCommand(string exe, IReadOnlyList<string> arguments)
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

		return RunCapturedCore(psi, PrerequisiteCommandTimeoutMilliseconds);
	}

	/// <summary>Hard limit for one prerequisite probe. Shared by every entry point so none of them can
	/// drift into an unbounded or deadlocking wait.</summary>
	private const int PrerequisiteCommandTimeoutMilliseconds = 15_000;

	/// <summary>The single process-invocation body behind every probe in this file: starts the process,
	/// reads stdout and stderr through the ASYNCHRONOUS event pump (so a full pipe can never deadlock
	/// the wait and no task is ever blocked on), enforces one hard timeout, kills the tree on expiry and
	/// never throws.</summary>
	private static CapturedCommand RunCapturedCore(ProcessStartInfo psi, int timeoutMilliseconds)
	{
		try
		{
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return new CapturedCommand(-1, string.Empty, "Process.Start returned null", TimedOut: false);
			}

			StringBuilder stdout = new();
			StringBuilder stderr = new();
			object gate = new();
			proc.OutputDataReceived += (_, e) => AppendLine(gate, stdout, e.Data);
			proc.ErrorDataReceived += (_, e) => AppendLine(gate, stderr, e.Data);
			proc.BeginOutputReadLine();
			proc.BeginErrorReadLine();

			bool exited = proc.WaitForExit(timeoutMilliseconds);
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
				catch (System.ComponentModel.Win32Exception)
				{
					// Best effort only.
				}
			}
			else
			{
				// Parameterless overload: waits for the asynchronous output handlers to drain, so the buffers
				// are complete before they are read.
				proc.WaitForExit();
			}

			lock (gate)
			{
				return new CapturedCommand(exited ? proc.ExitCode : -1, stdout.ToString(), stderr.ToString(), !exited);
			}
		}
		catch (Exception ex)
		{
			return new CapturedCommand(-1, string.Empty, ex.GetType().Name + ": " + ex.Message, TimedOut: false);
		}
	}
}
