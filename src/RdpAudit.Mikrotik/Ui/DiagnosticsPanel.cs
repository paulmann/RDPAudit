/*
 * File   : DiagnosticsPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Step 1 — probes the router's management ports (SSH / api / api-ssl / https) in parallel
 *          and reports which connection methods are available, recommending the secure path. It
 *          records the probe summary in the shared WizardContext for later steps.
 * Depends: StepPanelBase, ConnectionProber, WizardContext
 * Extends: To diagnose another precondition (e.g. RouterOS reachability latency budget), add a probe
 *          call in RunActionAsync and append its result to the log.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using RdpAudit.Mikrotik.Core;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Step 1: connection-method diagnostics.</summary>
public sealed class DiagnosticsPanel : StepPanelBase
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ConnectionProber _prober;

	// ── Construction ─────────────────────────────────────────────────────────────

	public DiagnosticsPanel(WizardContext context, ConnectionProber prober) : base(context)
	{
		_prober = prober ?? throw new ArgumentNullException(nameof(prober));
		Heading = "Diagnostics";
		Description = "Probe the router's management ports to discover which connection methods are available.";
		ActionText = "Run port diagnostics";
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	protected override async Task RunActionAsync(CancellationToken ct)
	{
		if (Context.Endpoint is null)
		{
			AppendLog("Enter the router IP in the connection bar and click Probe first.");
			FailStep("No endpoint configured.");
			return;
		}

		AppendLog($"Probing {Context.Endpoint.RouterIp} ...");
		ConnectionProbeSummary summary = await _prober.ProbeAsync(Context.Endpoint.RouterIp, ct: ct).ConfigureAwait(false);
		Context.ProbeSummary = summary;

		foreach (PortProbeResult result in summary.Results)
		{
			string state = result.Open ? "OPEN" : "closed";
			AppendLog($"  {result.Port.Service,-8} :{result.Port.Port,-5} {state} ({result.ElapsedMs} ms)");
		}

		AppendLog(summary.Recommendation);

		if (summary.SshAvailable || summary.ApiSslAvailable)
		{
			CompleteStep();
		}
		else
		{
			FailStep("Neither SSH nor api-ssl is reachable.");
		}
	}
}
