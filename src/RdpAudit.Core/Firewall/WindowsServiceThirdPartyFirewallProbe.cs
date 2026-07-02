/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.1.0
// File   : WindowsServiceThirdPartyFirewallProbe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Service-side IThirdPartyFirewallProbe. Queries Windows SCM via ServiceController to enumerate running services and checks well-known Kaspersky CLI tool paths via File.Exists. Runs only on explicit GetFirewallDiagnostics / GetFirewallStatus requests, never in background workers. Lives in RdpAudit.Service because System.ServiceProcess.ServiceController is Windows-only and must not leak into the cross-platform RdpAudit.Core assembly.
// Depends: IThirdPartyFirewallProbe, FirewallProviderClassifier, FirewallServiceState, FirewallCliToolPresence
// Extends: Add new CLI tool paths to _cliToolCandidates; add new service fragments to FirewallProviderClassifier lists in Core.

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

	private static readonly string[] _cliToolCandidates =
	[
		@"C:\Program Files (x86)\Kaspersky Lab\avp.exe",
		@"C:\Program Files\Kaspersky Lab\avp.exe",
		@"C:\Program Files (x86)\Kaspersky Lab\avp.com",
		@"C:\Program Files\Kaspersky Lab\avp.com",
	];

	// ── Public API ───────────────────────────────────────────────────────────────
	public Task<ThirdPartyFirewallSnapshot> CollectAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
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
			KasperskyManagesWindowsFirewall: false);
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
					string svcName = svc.ServiceName;
					string displayName = svc.DisplayName;
					bool running = svc.Status == ServiceControllerStatus.Running;

					if (IsRelevant(svcName, displayName))
					{
						result.Add(new FirewallServiceState(
							ServiceName: svcName,
							DisplayName: displayName,
							Status: running ? "Running" : svc.Status.ToString(),
							IsRunning: running));
					}
				}
				catch (InvalidOperationException ex)
				{
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

		foreach (string path in _cliToolCandidates)
		{
			ct.ThrowIfCancellationRequested();
			string toolName = Path.GetFileName(path);
			bool present = File.Exists(path);
			result.Add(new FirewallCliToolPresence(toolName, path, present));
		}

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
						if (!File.Exists(candidate))
						{
							continue;
						}

						bool alreadyAdded = false;
						foreach (FirewallCliToolPresence existing in result)
						{
							if (string.Equals(existing.FullPath, candidate, StringComparison.OrdinalIgnoreCase))
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
			catch (Exception ex)
			{
				_logger.LogDebug(ex,
					"ThirdPartyFirewallProbe: directory enumeration under {Dir} failed",
					kaspersky);
			}
		}

		return result;
	}

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
