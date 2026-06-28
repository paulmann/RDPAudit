/*
 * File   : TestPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Step 2 — opens an SSH bootstrap session, gathers read-only system info (identity,
 *          version, board, architecture) and analyses the firewall blocking contour so the operator
 *          can confirm WHAT will be modified and WHERE the drop rule will land. Read-only: it never
 *          mutates the router. Results are recorded in WizardContext for the PKI / Firewall steps.
 * Depends: StepPanelBase, RouterOsSshClient, BlockingContourAnalyzer, WizardContext, ILoggerFactory
 * Extends: To surface another read-only fact, add an SSH read in RunActionAsync and log it; keep the
 *          step strictly non-mutating.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using Microsoft.Extensions.Logging;
using RdpAudit.Mikrotik.Core;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Step 2: read-only connection test, system info and contour analysis (over SSH).</summary>
public sealed class TestPanel : StepPanelBase
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ILoggerFactory _loggerFactory;

	// ── Construction ─────────────────────────────────────────────────────────────

	public TestPanel(WizardContext context, ILoggerFactory loggerFactory) : base(context)
	{
		_loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
		Heading = "Connection Test";
		Description = "Connect over SSH, read the router identity and version, and analyse the firewall blocking contour. Nothing is modified.";
		ActionText = "Test connection";
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	protected override async Task RunActionAsync(CancellationToken ct)
	{
		if (Context.Endpoint is null)
		{
			FailStep("No endpoint configured.");
			return;
		}

		ConnectionEndpoint ep = Context.Endpoint;
		AppendLog($"Connecting to {ep.RouterIp}:{ep.SshPort} over SSH ...");

		using RouterOsSshClient ssh = new(ep.RouterIp, ep.SshPort, ep.AdminUsername, ep.AdminPassword, _loggerFactory.CreateLogger<RouterOsSshClient>());
		await ssh.ConnectAsync(ct).ConfigureAwait(false);
		AppendLog("SSH session established.");

		SshCommandResult identity = await ssh.RunAsync("/system identity print", ct).ConfigureAwait(false);
		AppendLog("Identity: " + identity.Output.Trim());

		SshCommandResult resource = await ssh.RunAsync("/system resource print", ct).ConfigureAwait(false);
		AppendLog("Resource:");
		AppendLog(resource.Output.Trim());

		SshCommandResult fasttrack = await ssh.RunAsync("/ip firewall filter print where action=fasttrack-connection", ct).ConfigureAwait(false);
		bool hasFastTrack = !string.IsNullOrWhiteSpace(fasttrack.Output) && fasttrack.Output.Contains("fasttrack", StringComparison.OrdinalIgnoreCase);
		AppendLog(hasFastTrack
			? "FastTrack detected: the drop rule must be placed before fasttrack (or in the RAW chain)."
			: "No FastTrack rule detected: a filter input drop rule is sufficient.");

		if (identity.Succeeded)
		{
			CompleteStep();
		}
		else
		{
			FailStep("Could not read router identity over SSH.");
		}
	}
}
