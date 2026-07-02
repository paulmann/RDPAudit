/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : WindowsServiceThirdPartyFirewallProbe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Service-side IThirdPartyFirewallProbe.  Queries Windows SCM via
//          ServiceController to enumerate running services and checks well-known
//          Kaspersky/ESET/Bitdefender/etc. CLI tool paths via File.Exists.
//          Runs ONLY on explicit GetFirewallDiagnostics / GetFirewallStatus
//          on-demand calls — never in background workers.
//          LocalSystem has full SCM enumerate rights; no privilege escalation.
// Depends: IThirdPartyFirewallProbe, FirewallProviderClassifier,
//          FirewallServiceState, FirewallCliToolPresence
// Extends: Add new CLI tool paths to _cliToolCandidates; add new service
//          fragments to FirewallProviderClassifier lists in Core.

using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Windows-SCM-backed <see cref="IThirdPartyFirewallProbe"/> for use
/// inside the RdpAudit Windows Service.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceThirdPartyFirewallProbe(
	ILogger<WindowsServiceThirdPartyFirewallProbe> logger)
	: IThirdPartyFirewallProbe
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────
	private readonly ILogger<WindowsServiceThirdPartyFirewallProbe> _logger = logger;

	/// <summary>Well-known CLI tool paths for Kaspersky products.
	/// avp.exe / avp.com ship with KES for Windows (workstation SKU).
	/// kescli.exe ships with KES managed endpoints.
	/// kavshell.exe ships with KSWS (server SKU).</summary>
	private static readonly string[] _cliToolCandidates =
	[
		@"C:\Program Files (x86)\Kaspersky Lab\avp.exe",
		@"C:\Program Files\Kaspersky Lab\avp.exe",
		@"C:\Program Files (x86)\Kaspersky Lab\avp.com",
		@"C:\Program Files\Kaspersky Lab\avp.com",
		// Pattern-match against versioned install dirs (KES 21.x, 12.x, etc.)
		// resolved below via glob-equivalent directory enumeration.
	];

	// ── Public API ───────────────────────────────────────────────────────────────
	public Task<ThirdPartyFirewallSnapshot> CollectAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// ServiceController.GetServices() is a synchronous SCM call that is
		// fast (~5 ms) and safe under LocalSystem.  We offload it to a thread-
		// pool thread to avoid blocking the async IPC dispatch loop.
		return Task.Run(() => Collect(ct), ct);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────
	private ThirdPartyFirewallSnapshot Collect(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		List<FirewallServiceState> services = CollectServices(ct);
		List<FirewallCliToolPresence> cliTools = CollectCliTools(ct);

		return new ThirdPartyFirewallSnapshot(
			Services: services,
			CliTools: cliTools,
			KasperskyManagesWindowsFirewall: false); // KSWS Firewall Management
			// detection (policy API) is out of scope for this probe;
			// KasperskyDetected already surfaces the correct warning in the report.
	}

	private List<FirewallServiceState> CollectServices(CancellationToken ct)
	{
		List<FirewallServiceState> result = [];
		try
		{
			ServiceController[] all = ServiceController.GetServices();
			foreach (ServiceController svc in all)
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					// We only need name + status; DisplayName requires an extra
					// SCM query but is worth it for the classifier's
					// DescribeKasperskyName heuristic.
					string svcName = svc.ServiceName;
					string displayName = svc.DisplayName;
					bool running = svc.Status == ServiceControllerStatus.Running;

					// Pre-filter: only keep entries whose name/display matches
					// a known fragment — avoids allocating thousands of records
					// for unrelated services on a busy server.
					if (IsRelevant(svcName, displayName))
					{
						result.Add(new FirewallServiceState(svcName, displayName, running));
					}
				}
				catch (InvalidOperationException ex)
				{
					// Individual service query failed (access denied on that
					// specific service, race condition, etc.) — skip silently.
					_logger.LogDebug(ex,
						"ThirdPartyFirewallProbe: skipping service {Name} (query failed)",
						svc.ServiceName);
				}
				finally
				{
					svc.Dispose();
				}
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex,
				"ThirdPartyFirewallProbe: ServiceController.GetServices() failed; " +
				"ThirdPartyFirewallSuspected will fall back to CLI-tool probe only");
		}

		return result;
	}

	private List<FirewallCliToolPresence> CollectCliTools(CancellationToken ct)
	{
		List<FirewallCliToolPresence> result = [];

		// Static candidates first.
		foreach (string path in _cliToolCandidates)
		{
			ct.ThrowIfCancellationRequested();
			string toolName = Path.GetFileName(path);
			bool present = File.Exists(path);
			result.Add(new FirewallCliToolPresence(toolName, path, present));
		}

		// Dynamic: enumerate versioned Kaspersky install dirs under Program Files.
		// Matches paths like:
		//   C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.exe
		//   C:\Program Files (x86)\Kaspersky Lab\Kaspersky Endpoint Security 12.x\avp.exe
		foreach (string programFiles in new[]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
		})
		{
			ct.ThrowIfCancellationRequested();
			string kaspersky = Path.Combine(programFiles, "Kaspersky Lab");
			if (!Directory.Exists(kaspersky))
			{
				continue;
			}

			try
			{
				foreach (string dir in Directory.EnumerateDirectories(kaspersky))
				{
					ct.ThrowIfCancellationRequested();
					foreach (string toolFile in new[] { "avp.exe", "avp.com", "kescli.exe", "kavshell.exe" })
					{
						string candidate = Path.Combine(dir, toolFile);
						if (File.Exists(candidate))
						{
							// Avoid duplicates from the static list above.
							bool alreadyAdded = false;
							foreach (FirewallCliToolPresence existing in result)
							{
								if (string.Equals(existing.FullPath, candidate,
									StringComparison.OrdinalIgnoreCase))
								{
									alreadyAdded = true;
									break;
								}
							}

							if (!alreadyAdded)
							{
								result.Add(new FirewallCliToolPresence(toolFile, candidate, present: true));
							}
						}
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex,
					"ThirdPartyFirewallProbe: directory enumeration under {Dir} failed",
					kaspersky);
			}
		}

		return result;
	}

	/// <summary>Quick pre-filter — only services whose name or display name
	/// contains at least one known AV/EDR fragment are kept.  This avoids
	/// allocating <see cref="FirewallServiceState"/> records for the hundreds
	/// of unrelated services on a typical Windows Server.</summary>
	private static bool IsRelevant(string serviceName, string displayName)
	{
		foreach (string frag in FirewallProviderClassifier.KasperskyServiceFragments)
		{
			if (serviceName.Contains(frag, StringComparison.OrdinalIgnoreCase)
				|| displayName.Contains(frag, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		foreach (string frag in FirewallProviderClassifier.ThirdPartyFirewallServiceFragments)
		{
			if (serviceName.Contains(frag, StringComparison.OrdinalIgnoreCase)
				|| displayName.Contains(frag, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}
}
