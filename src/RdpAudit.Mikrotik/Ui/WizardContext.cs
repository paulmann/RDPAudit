/*
 * File   : WizardContext.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Shared, mutable state threaded through the wizard steps: the chosen endpoint, the live
 *          probe summary, collected system info, the contour report, the bootstrap result and the
 *          persisted MikrotikConfig. Each step reads what earlier steps produced and writes its own
 *          output here, so panels stay decoupled and the host form only wires events.
 * Depends: ConnectionEndpoint, ConnectionProbeSummary, MikrotikSystemInfo, BootstrapResult,
 *          RdpAudit.Core.MikroTik.MikrotikConfig
 * Extends: When a step produces a new artifact later steps consume, add a property here rather than
 *          passing it through constructors; keep all cross-step state in this single object.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using RdpAudit.Core.MikroTik;
using RdpAudit.Mikrotik.Core;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Shared, mutable state threaded through the wizard steps.</summary>
public sealed class WizardContext
{
	/// <summary>The endpoint the operator entered and probed.</summary>
	public ConnectionEndpoint? Endpoint { get; set; }

	/// <summary>The most recent connection probe summary.</summary>
	public ConnectionProbeSummary? ProbeSummary { get; set; }

	/// <summary>System info collected from the router, when available.</summary>
	public MikrotikSystemInfo? SystemInfo { get; set; }

	/// <summary>The blocking-contour report, when analysed.</summary>
	public BlockingContourReport? ContourReport { get; set; }

	/// <summary>The completed bootstrap result, when run.</summary>
	public BootstrapResult? BootstrapResult { get; set; }

	/// <summary>The persisted configuration once a bootstrap succeeds.</summary>
	public MikrotikConfig? Config { get; set; }

	/// <summary>This server's local IP used to scope the router service account to a /32.</summary>
	public string ServerLocalIp { get; set; } = string.Empty;
}
