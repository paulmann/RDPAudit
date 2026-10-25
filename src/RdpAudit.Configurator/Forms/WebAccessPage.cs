// File:    src/RdpAudit.Configurator/Forms/WebAccessPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: «Web Access» Configurator tab. Shows the operator two privacy-first checkboxes
//          (Show Web Access, Allow management), the live web/IIS status, and the Install IIS /
//          Configure IIS entry points. The management checkbox is locked by a phase gate:
//          management is a separate later phase, so the checkbox stays disabled (but visible)
//          and the underlying preference can only ever be false until the gate opens.
//          All async actions are wrapped by SafeAsyncHandler so no exception can escape into
//          the WinForms message loop.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Threading;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Forms;

/// <summary>Web Access tab: checkboxes, status and IIS workflow entry points.</summary>
[SupportedOSPlatform("windows")]
public sealed class WebAccessPage : TabPage
{
	private readonly IWebAccessPreferenceStore _store;
	private readonly IisStatusProbe _probe;
	private readonly bool _managementPhaseUnlocked;
	private IWebAccessWorkflowHost? _workflowHost;

	private CheckBox _showCheck = null!;
	private CheckBox _manageCheck = null!;
	private Button _refreshButton = null!;
	private Button _installButton = null!;
	private Button _configureButton = null!;
	private ToolStripStatusLabel _statusLabel = null!;
	private IisStatusSnapshot _latest = new();
	private bool _busy;
	private bool _probing;
	private bool _syncing;

	public WebAccessPage(
		IWebAccessPreferenceStore store,
		IisStatusProbe probe,
		IWebAccessWorkflowHost? workflowHost = null,
		bool managementPhaseUnlocked = false)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(probe);
		_store = store;
		_probe = probe;
		_workflowHost = workflowHost;
		_managementPhaseUnlocked = managementPhaseUnlocked;
		Text = "Web Access";

		BuildLayout();
		HandleCreated += SafeAsyncHandler.Wrap(async () => await RefreshAsync());
	}

	/// <summary>Windows default wired to the registry-backed preference store, the read-only
	/// platform probe and (Step 10) the production Install IIS workflow host. The workflow
	/// host is injected later (Steps 10-11) via
	/// <see cref="AttachWorkflowHost"/>. <paramref name="tabTitle"/> overrides the tab caption
	/// (default "Web Access"); the Configurator passes its glyph-prefixed fixed-order title.</summary>
	public static WebAccessPage CreateDefault(string? tabTitle = null)
	{
		RdpAuditPaths paths = RdpAuditPaths.Default;
		ExternalCommandRunner runner = new();
		IisStatusProbe probe = new(
			new WindowsIisPlatformProbe(runner),
			paths.WebUiDirectory);
		WebAccessPage page = new(new RegistryWebAccessPreferenceStore(), probe);

		// Step 10-11: production Install IIS / Configure IIS workflow hosts - elevation-guarded,
		// fail-closed and idempotent. Nothing here executes at construction time; DISM / appcmd /
		// netsh run only when the operator clicks Install IIS or Configure IIS.
		ServiceLayoutInfo layout = ServiceLayout.Discover(System.AppContext.BaseDirectory);
		string serviceDistribution = ServiceLayout.ResolveSiblingDistribution(System.AppContext.BaseDirectory);
		string publishWebRoot = System.IO.Path.Combine(
			System.IO.Path.GetDirectoryName(serviceDistribution) ?? ".", "Web");
		IisConfigureService configureService = new(
			new WindowsIisPlatformProbe(runner),
			runner,
			new WindowsWebUiCertificateSource(),
			new DpapiSecretProtector(),
			paths,
			layout.AppSettingsPath,
			publishWebRoot);
		page.AttachWorkflowHost(new IisWebAccessWorkflowHost(
			new IisInstallService(new WindowsIisPlatformProbe(runner), runner),
			layout,
			configureService));

		if (!string.IsNullOrEmpty(tabTitle))
		{
			page.Text = tabTitle;
		}

		return page;
	}

	/// <summary>Attaches the IIS workflows (Step 10-11). Called once; null host keeps the buttons
	/// disabled with an explanatory status so nothing dead-end is clickable.</summary>
	public void AttachWorkflowHost(IWebAccessWorkflowHost host)
	{
		ArgumentNullException.ThrowIfNull(host);
		_workflowHost = host;
		ApplyState();
	}

	private void BuildLayout()
	{
		_showCheck = new CheckBox
		{
			Dock = DockStyle.Top,
			Height = 28,
			Text = "Show Web Access (privacy-first; off by default)",
		};
		_showCheck.CheckedChanged += (_, _) => ApplyState();
		_showCheck.CheckedChanged += SafeAsyncHandler.Wrap(async () => await PersistShowAsync());

		_manageCheck = new CheckBox
		{
			Dock = DockStyle.Top,
			Height = 28,
			Text = "Allow management from the web (phase-gated - not enabled yet)",
			Checked = false,
			Enabled = false,
		};

		GroupBox options = new()
		{
			Dock = DockStyle.Top,
			Height = 110,
			Text = " Access options ",
		};
		options.Controls.Add(_manageCheck);
		options.Controls.Add(_showCheck);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 40,
			FlowDirection = FlowDirection.LeftToRight,
		};
		_refreshButton = new Button { Text = "Refresh status", Width = 130 };
		_installButton = new Button { Text = "Install IIS", Width = 110, Enabled = false };
		_configureButton = new Button { Text = "Configure IIS", Width = 120, Enabled = false };
		toolbar.Controls.AddRange(new Control[] { _refreshButton, _installButton, _configureButton });

		StatusStrip statusStrip = new()
		{
			BackColor = RdpAudit.Configurator.Theming.DarkTheme.StatusBack,
			ForeColor = RdpAudit.Configurator.Theming.DarkTheme.StatusFore,
		};
		_statusLabel = new ToolStripStatusLabel("Loading web status...")
		{
			ForeColor = RdpAudit.Configurator.Theming.DarkTheme.StatusFore,
		};
		statusStrip.Items.Add(_statusLabel);

		Controls.Add(statusStrip);
		Controls.Add(toolbar);
		Controls.Add(options);

		_refreshButton.Click += SafeAsyncHandler.Wrap(async () => await RefreshAsync());
		_installButton.Click += SafeAsyncHandler.Wrap(RunInstallIisAsync);
		_configureButton.Click += SafeAsyncHandler.Wrap(async () => await ConfigureIisAsync());
	}

	internal async Task RefreshAsync()
	{
		if (_probing)
		{
			return;
		}

		SetProbing(true);
		try
		{
			_latest = await _probe.ProbeAsync().ConfigureAwait(true);
			_syncing = true;
			try
			{
				_showCheck.Checked = _store.IsTabEnabled;
				_manageCheck.Checked = _store.IsManagementEnabled && _managementPhaseUnlocked;
				_manageCheck.Enabled = _managementPhaseUnlocked;
			}
			finally
			{
				_syncing = false;
			}

			ApplyState();
			SetStatus(_latest.Summary);
		}
		finally
		{
			SetProbing(false);
		}
	}

	/// <summary>Runs the Install IIS workflow without any window and reports the curated line on the
	/// tab. Used by the pieces that only need the outcome (and by the tests).</summary>
	internal async Task InstallIisAsync()
	{
		if (_workflowHost is null)
		{
			SetStatus("Install IIS workflow is not available yet.", isError: true);
			return;
		}

		SetBusy(true);
		try
		{
			IisInstallRunOutcome outcome = await _workflowHost
				.RunInstallIisAsync()
				.ConfigureAwait(true);
			SetStatus("Install IIS: " + outcome.StatusLine);
		}
		finally
		{
			SetBusy(false);
		}
	}

	/// <summary>Click handler of the Install IIS button: opens the progress window, which lists every
	/// component before anything is installed and marks each one with a tick / cross while the run
	/// proceeds. The workflow is started from the window's Shown event, so the modal loop keeps
	/// pumping and the UI thread is never blocked while the install runs.</summary>
	// Not `async`: the awaited workflow runs inside the dialog's Shown handler wrapped by
	// SafeAsyncHandler, so this method itself has no await. Declaring it async produced CS1998
	// (async without await) under TreatWarningsAsErrors. Returned as a Task so it stays assignable
	// to SafeAsyncHandler.Wrap(Func<Task>) at the call site.
	internal Task RunInstallIisAsync()
	{
		if (_workflowHost is null)
		{
			SetStatus("Install IIS workflow is not available yet.", isError: true);
			return Task.CompletedTask;
		}

		// Whether to run again is the operator's decision (the window's Retry button), so the loop is
		// bounded only to keep repeated clicks from stacking windows without end.
		const int MaxOperatorAttempts = 3;
		for (int attempt = 1; attempt <= MaxOperatorAttempts; attempt++)
		{
			bool retry = false;
			using IisInstallProgressDialog dialog = new(IisInstallPlan.CreatePendingSteps());
			dialog.RetryRequested += (_, _) => retry = true;

			// Progress<T> captures the UI SynchronizationContext here, so every reported item is
			// marshalled back onto the UI thread without hand-rolled Invoke plumbing.
			Progress<IisInstallStepResult> progress = new(dialog.ApplyResult);

			SetBusy(true);
			try
			{
				dialog.Shown += SafeAsyncHandler.Wrap(async () =>
				{
					IisInstallRunOutcome outcome = await _workflowHost
						.RunInstallIisAsync(progress)
						.ConfigureAwait(true);

					// Re-apply the final rows: a progress callback that raced the completion must not leave
					// a row painted as still running.
					foreach (IisInstallStepResult item in outcome.ItemResults)
					{
						dialog.ApplyResult(item);
					}

					dialog.Complete(outcome.StatusLine, outcome.Success, outcome.AlreadyInstalled);
					SetStatus("Install IIS: " + outcome.StatusLine);

					if (outcome.Success)
					{
						// Re-read the machine so the tab reflects what was just installed.
						await RefreshAsync().ConfigureAwait(true);
					}
				});

				dialog.ShowDialog(FindForm());
			}
			finally
			{
				SetBusy(false);
			}

			ApplyState();
			if (!retry)
			{
				break;
			}
		}

		return Task.CompletedTask;
	}

	internal async Task ConfigureIisAsync()
	{
		if (_workflowHost is null)
		{
			SetStatus("Configure IIS workflow is not available yet.", isError: true);
			return;
		}

		SetBusy(true);
		try
		{
			string outcome = await _workflowHost.RunConfigureIisAsync().ConfigureAwait(true);
			SetStatus("Configure IIS: " + outcome);
		}
		finally
		{
			SetBusy(false);
		}
	}

	private void SetProbing(bool value)
	{
		_probing = value;
		ApplyState();
	}

	private void SetBusy(bool value)
	{
		_busy = value;
		ApplyState();
	}

	internal async Task PersistShowAsync(bool? value = null)
	{
		if (_syncing)
		{
			return;
		}

		bool target = value ?? _showCheck.Checked;
		bool persisted = await _store.SetTabEnabledAsync(target, CancellationToken.None)
			.ConfigureAwait(true);
		if (!persisted)
		{
			SetStatus("Could not persist the Web Access visibility choice.", isError: true);
		}
	}

	private void ApplyState()
	{
		WebAccessUIState state = WebAccessUIStateFactory.Build(
			_store, _managementPhaseUnlocked, _latest, _busy, _probing, string.Empty);

		_refreshButton.Enabled = !state.IsProbing && !state.IsBusy;
		_installButton.Enabled = state.WorkflowButtonsEnabled;
		_configureButton.Enabled = state.WorkflowButtonsEnabled;
		_manageCheck.Enabled = state.ManagementToggleAllowed;
		_showCheck.Enabled = !state.IsProbing && !state.IsBusy;
	}

	internal string StatusText => _statusLabel.Text ?? string.Empty;

	internal CheckBox ShowCheck => _showCheck;

	internal CheckBox ManageCheck => _manageCheck;

	internal Button RefreshButton => _refreshButton;

	internal Button InstallButton => _installButton;

	internal Button ConfigureButton => _configureButton;

	private void SetStatus(string text, bool isError = false)
	{
		_statusLabel.Text = text;
		_statusLabel.ForeColor = isError
			? RdpAudit.Configurator.Theming.DarkTheme.StatusDanger
			: RdpAudit.Configurator.Theming.DarkTheme.StatusFore;
	}
}
