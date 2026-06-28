/*
 * File   : MainForm.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: The wizard shell (960×700, dark theme). Hosts the top ConnectionPanel, the left
 *          WorkflowStepList and a swappable content area that shows the active step panel. It wires
 *          step completion / failure events to advance the workflow and updates the step states, but
 *          contains no router logic — every action lives in the step panels and the core services.
 * Depends: System.Windows.Forms, DarkTheme, ConnectionPanel, WorkflowStepList, the five step panels,
 *          WizardContext, ConnectionProber
 * Extends: To add a workflow step, add the WorkflowStep enum value, construct its panel here, add it
 *          to the panel map in BuildSteps and the reachability order in OnStepCompleted.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using Microsoft.Extensions.Logging;
using RdpAudit.Mikrotik.Core;
using RdpAudit.Mikrotik.Helpers;
using RdpAudit.Mikrotik.Ipc;
using RdpAudit.Mikrotik.Pki;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>The MikroTik setup wizard shell.</summary>
public sealed class MainForm : Form
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly WizardContext _context = new();
	private readonly ConnectionPanel _connectionPanel = new();
	private readonly WorkflowStepList _stepList = new();
	private readonly Panel _content = new() { Dock = DockStyle.Fill };
	private readonly ConnectionProber _prober = new();
	private readonly Dictionary<WorkflowStep, StepPanelBase> _panels = new();

	private readonly ILoggerFactory _loggerFactory;

	// ── Construction ─────────────────────────────────────────────────────────────

	public MainForm(ILoggerFactory loggerFactory)
	{
		_loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));

		Text = "RdpAudit · MikroTik Setup Wizard";
		ClientSize = new System.Drawing.Size(960, 700);
		MinimumSize = new System.Drawing.Size(960, 700);
		StartPosition = FormStartPosition.CenterScreen;
		DarkTheme.ApplyContainer(this);

		_context.ServerLocalIp = DetectLocalIp();

		BuildSteps();
		BuildLayout();
		WireEvents();

		ActivateStep(WorkflowStep.Diagnostics);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void BuildSteps()
	{
		WindowsCertStoreHelper certStore = new();
		MikrotikCaManager caManager = new();
		BlockingContourAnalyzer contour = new();
		SecureCredentialStore credentialStore = new();
		RollbackExecutor rollback = new(certStore, _loggerFactory.CreateLogger<RollbackExecutor>());
		BootstrapOrchestrator orchestrator = new(caManager, certStore, rollback, credentialStore, _loggerFactory);
		IntegrationValidator validator = new(_loggerFactory.CreateLogger<IntegrationValidator>());
		ConfiguratorIpcBridge ipcBridge = new();

		DiagnosticsPanel diagnostics = new(_context, _prober);
		TestPanel test = new(_context, _loggerFactory);
		PkiPanel pki = new(_context, caManager, certStore);
		FirewallPanel firewall = new(_context);
		ApplySyncPanel apply = new(_context, orchestrator, validator, certStore, credentialStore, ipcBridge, _loggerFactory, firewall);

		// Keep the analyzer reachable for the Test step's deeper contour analysis if extended later.
		_ = contour;

		_panels[WorkflowStep.Diagnostics] = diagnostics;
		_panels[WorkflowStep.Test] = test;
		_panels[WorkflowStep.Pki] = pki;
		_panels[WorkflowStep.Firewall] = firewall;
		_panels[WorkflowStep.ApplySync] = apply;

		foreach (KeyValuePair<WorkflowStep, StepPanelBase> entry in _panels)
		{
			WorkflowStep step = entry.Key;
			entry.Value.StepCompleted += (_, _) => OnStepCompleted(step);
			entry.Value.StepFailed += (_, _) => _stepList.SetState(step, WorkflowStepState.Failed);
		}
	}

	private void BuildLayout()
	{
		Controls.Add(_content);
		Controls.Add(_stepList);
		Controls.Add(_connectionPanel);
		_content.BringToFront();
	}

	private void WireEvents()
	{
		_connectionPanel.ProbeRequested += OnProbeRequested;
		_stepList.StepSelected += (_, e) => ActivateStep(e.Step);
	}

	private async void OnProbeRequested(object? sender, ProbeRequestedEventArgs e)
	{
		ConnectionEndpoint endpoint = e.Endpoint;
		_context.Endpoint = endpoint;
		_connectionPanel.ShowStatus("Probing " + endpoint.RouterIp + " ...");
		try
		{
			ConnectionProbeSummary summary = await _prober.ProbeAsync(endpoint.RouterIp).ConfigureAwait(true);
			_context.ProbeSummary = summary;
			_connectionPanel.ShowProbeSummary(summary);
		}
		catch (SocketException ex)
		{
			_connectionPanel.ShowStatus("Probe failed: " + ex.Message, isError: true);
		}
	}

	private void OnStepCompleted(WorkflowStep step)
	{
		_stepList.SetState(step, WorkflowStepState.Done);

		WorkflowStep? next = step switch
		{
			WorkflowStep.Diagnostics => WorkflowStep.Test,
			WorkflowStep.Test => WorkflowStep.Pki,
			WorkflowStep.Pki => WorkflowStep.Firewall,
			WorkflowStep.Firewall => WorkflowStep.ApplySync,
			_ => null,
		};

		if (next is { } nextStep)
		{
			ActivateStep(nextStep);
		}
	}

	private void ActivateStep(WorkflowStep step)
	{
		foreach (WorkflowStep candidate in _panels.Keys)
		{
			if (candidate != step && _stepList.GetState(candidate) != WorkflowStepState.Done)
			{
				_stepList.SetState(candidate, _stepList.GetState(candidate) == WorkflowStepState.Failed
					? WorkflowStepState.Failed
					: WorkflowStepState.Pending);
			}
		}
		_stepList.SetState(step, WorkflowStepState.Active);

		_content.Controls.Clear();
		StepPanelBase panel = _panels[step];
		_content.Controls.Add(panel);
		panel.OnActivated();
	}

	private static string DetectLocalIp()
	{
		try
		{
			using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			socket.Connect("8.8.8.8", 65530);
			if (socket.LocalEndPoint is IPEndPoint endpoint)
			{
				return endpoint.Address.ToString();
			}
		}
		catch (SocketException)
		{
			// Fall through to a safe default; the operator can still bootstrap with a 0.0.0.0 scope.
		}
		return "0.0.0.0";
	}
}
