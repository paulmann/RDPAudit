/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : WindowsServiceThirdPartyFirewallProbe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Service-side implementation of IThirdPartyFirewallProbe. Enumerates Windows
//          services via ServiceController and probes well-known Kaspersky CLI tool
//          locations on disk, then hands the raw facts to the shared, pure
//          FirewallProviderClassifier in RdpAudit.Core so Service and Configurator never
//          diverge on third-party firewall detection. Runs only on explicit
//          GetFirewallDiagnostics / GetFirewallStatus IPC requests — never from a
//          background worker — because ServiceController enumeration is a blocking SCM
//          call. LocalSystem has sufficient rights to enumerate services; no privilege
//          escalation is required or attempted.
// Depends: IThirdPartyFirewallProbe, FirewallProviderClassifier, FirewallServiceState,
//          FirewallCliToolPresence, ThirdPartyFirewallSnapshot (RdpAudit.Core.Firewall)
// Extends: Add new CLI tool candidate paths to CliToolCandidates; add new vendor service
//          name fragments to FirewallProviderClassifier in RdpAudit.Core — this probe
//          itself never needs vendor-specific changes.

using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Windows-SCM-backed implementation of <see cref="IThirdPartyFirewallProbe"/>,
/// used exclusively by the RdpAudit Windows Service host. Collects raw facts only —
/// classification is delegated to the shared, pure, unit-tested
/// <see cref="FirewallProviderClassifier"/> in RdpAudit.Core.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceThirdPartyFirewallProbe : IThirdPartyFirewallProbe
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ILogger<WindowsServiceThirdPartyFirewallProbe> _logger;

	/// <summary>Known static install locations for Kaspersky CLI tools that ship at a
	/// fixed path regardless of product version.</summary>
	private static readonly string[] StaticCliToolCandidates =
	[
		@"C:\Program Files (x86)\Kaspersky Lab\avp.exe",
		@"C:\Program Files\Kaspersky Lab\avp.exe",
		@"C:\Program Files (x86)\Kaspersky Lab\avp.com",
		@"C:\Program Files\Kaspersky Lab\avp.com",
	];

	/// <summary>File names probed inside versioned Kaspersky install directories
	/// (e.g. "Kaspersky 21.25", "Kaspersky Endpoint Security 12.x").</summary>
	private static readonly string[] VersionedCliToolFileNames =
	[
		"avp.exe",
		"avp.com",
		"kescli.exe",
		"kavshell.exe",
	];

	// ── Construction ─────────────────────────────────────────────────────────────

	public WindowsServiceThirdPartyFirewallProbe(ILogger<WindowsServiceThirdPartyFirewallProbe> logger)
	{
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public Task<ThirdPartyFirewallSnapshot> CollectAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		// ServiceController.GetServices() is a synchronous, blocking SCM call
		// (typically a few milliseconds but not guaranteed). Offload to the thread
		// pool so the async IPC dispatch loop is never blocked.
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
					string serviceName = svc.ServiceName;
					string displayName = svc.DisplayName;
					bool isRunning = svc.Status == ServiceControllerStatus.Running;

					// Pre-filter against known vendor fragments to avoid allocating a
					// record for every one of the hundreds of unrelated services on a
					// typical Windows Server host.
					if (IsRelevant(serviceName, displayName))
					{
						result.Add(new FirewallServiceState(
							ServiceName: serviceName,
							DisplayName: displayName,
							Status: isRunning ? "Running" : svc.Status.ToString(),
							IsRunning: isRunning));
					}
				}
				catch (InvalidOperationException ex)
				{
					// Individual service query failed (race condition, access denied on
					// that specific service handle, etc.) — skip and continue.
					_logger.LogDebug(
						ex,
						"ThirdPartyFirewallProbe: skipping service {ServiceName} (query failed)",
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
			_logger.LogWarning(
				ex,
				"ThirdPartyFirewallProbe: ServiceController.GetServices() failed; " +
				"third-party firewall detection will fall back to the CLI-tool probe only");
		}

		return result;
	}

	private List<FirewallCliToolPresence> CollectCliTools(CancellationToken ct)
	{
		List<FirewallCliToolPresence> result = [];

		foreach (string path in StaticCliToolCandidates)
		{
			ct.ThrowIfCancellationRequested();

			string toolName = Path.GetFileName(path);
			bool present = File.Exists(path);
			result.Add(new FirewallCliToolPresence(toolName, present ? path : null, present));
		}

		foreach (string programFilesRoot in new[]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
			Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
		})
		{
			ct.ThrowIfCancellationRequested();

			string kasperskyRoot = Path.Combine(programFilesRoot, "Kaspersky Lab");
			if (!Directory.Exists(kasperskyRoot))
			{
				continue;
			}

			try
			{
				foreach (string versionedDir in Directory.EnumerateDirectories(kasperskyRoot))
				{
					ct.ThrowIfCancellationRequested();

					foreach (string toolFileName in VersionedCliToolFileNames)
					{
						string candidate = Path.Combine(versionedDir, toolFileName);
						if (!File.Exists(candidate))
						{
							continue;
						}

						if (!AlreadyPresent(result, candidate))
						{
							result.Add(FirewallCliToolPresence.WithFullPath(toolFileName, candidate, present: true));
						}
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogDebug(
					ex,
					"ThirdPartyFirewallProbe: directory enumeration under {KasperskyRoot} failed",
					kasperskyRoot);
			}
		}

		return result;
	}

	private static bool AlreadyPresent(List<FirewallCliToolPresence> tools, string fullPath)
	{
		foreach (FirewallCliToolPresence existing in tools)
		{
			string existingPath = string.IsNullOrEmpty(existing.FullPath) ? existing.Path ?? string.Empty : existing.FullPath;
			if (string.Equals(existingPath, fullPath, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>Quick pre-filter — only services whose name or display name contains a
	/// known AV/EDR fragment are kept, avoiding allocation for unrelated services.</summary>
	private static bool IsRelevant(string serviceName, string displayName)
	{
		foreach (string fragment in FirewallProviderClassifier.KasperskyServiceFragments)
		{
			if (serviceName.Contains(fragment, StringComparison.OrdinalIgnoreCase) ||
				displayName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		foreach (string fragment in FirewallProviderClassifier.ThirdPartyFirewallServiceFragments)
		{
			if (serviceName.Contains(fragment, StringComparison.OrdinalIgnoreCase) ||
				displayName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}
}
