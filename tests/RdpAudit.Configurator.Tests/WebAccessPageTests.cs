/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : WebAccessPageTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Step 8 verification for the Configurator "Web Access" tab: the page maps a probe snapshot
//          onto its controls, keeps the management checkbox phase-locked by default, blocks the
//          Install/Configure workflow buttons while a workflow is running, persists the show/hide
//          choice through the preference store and reports curated failure lines. The snapshot comes
//          from the REAL IisStatusProbe over a fake platform probe and a temp web-UI folder, so the
//          fail-closed tri-state semantics are exercised end-to-end; the page never touches the real
//          %ProgramData%. Asynchronous page calls run through StaTestHarness, which pumps the STA
//          thread's message queue (see NotificationsPageTests).
// Depends: WebAccessPage, IisStatusProbe, StaTestHarness, WinForms, xunit

using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using RdpAudit.Configurator.Forms;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class WebAccessPageTests
{
	/// <summary>Per-class STA host (see StaTestHarness): pumps the message queue while a test waits
	/// for asynchronous page work, with deadlines on every wait.</summary>
	private readonly StaTestHarness _ui = new(nameof(WebAccessPageTests));

	[Fact]
	public void Constructor_ThrowsOnNullStore()
	{
		IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: true);
		_ui.Run(() => Assert.Throws<ArgumentNullException>(() => new WebAccessPage(null!, probe)));
	}

	[Fact]
	public void Constructor_ThrowsOnNullProbe()
	{
		_ui.Run(() => Assert.Throws<ArgumentNullException>(() => new WebAccessPage(new FakeStore(), null!)));
	}

	[Fact]
	public void RefreshAsync_Operational_ShowsSummaryAndEnablesWorkflows()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: true);
			using WebAccessPage page = new(new FakeStore(), probe);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.Contains("IIS installed", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.True(page.InstallButton.Enabled);
			Assert.True(page.ConfigureButton.Enabled);
			Assert.True(page.RefreshButton.Enabled);
		});
	}

	[Fact]
	public void RefreshAsync_Undetermined_DisablesWorkflowsAndShowsRefusal()
	{
		_ui.Run(() =>
		{
			// Both platform channels answer null (no rights): the probe must report unknown, not invent facts.
			IisStatusProbe probe = CreateProbe(installed: null, w3svc: null, published: false);
			using WebAccessPage page = new(new FakeStore(), probe);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.Contains("could not be determined", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.False(page.InstallButton.Enabled);
			Assert.False(page.ConfigureButton.Enabled);
			Assert.True(page.RefreshButton.Enabled);
		});
	}

	[Fact]
	public void RefreshAsync_PartiallyKnown_StaysFailClosedAndPrivacyFirst()
	{
		_ui.Run(() =>
		{
			// IIS is installed but W3SVC presence can't be read: snapshot must stay fail-closed.
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: null, published: false);
			using WebAccessPage page = new(new FakeStore(), probe);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.True(page.InstallButton.Enabled, "CanDeclare must be true when at least one fact is known.");
			Assert.False(page.ShowCheck.Checked, "Privacy-first default: show checkbox off.");
			Assert.False(page.ManageCheck.Checked, "Management must stay off while phase-locked.");
			Assert.False(page.ManageCheck.Enabled, "Management checkbox is phase-gated off by default.");
		});
	}

	[Fact]
	public void ManageCheck_PhaseUnlocked_ReflectsStoreAndIsEnabled()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: true);
			FakeStore store = new() { ManagementEnabled = true };
			using WebAccessPage page = new(store, probe, workflowHost: null, managementPhaseUnlocked: true);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");

			Assert.True(page.ManageCheck.Enabled);
			Assert.True(page.ManageCheck.Checked);
		});
	}

	[Fact]
	public void Store_Defaults_SafePrivacyFirst()
	{
		FakeStore store = new();
		Assert.False(store.IsTabEnabled);
		Assert.False(store.IsManagementEnabled);
	}

	[Fact]
	public void InstallIisAsync_NoWorkflowHost_ShowsUnavailable()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: false);
			using WebAccessPage page = new(new FakeStore(), probe);
			_ui.Await(page.InstallIisAsync(), "InstallIisAsync");

			Assert.Contains("not available yet", page.StatusText, StringComparison.OrdinalIgnoreCase);
		});
	}

	[Fact]
	public void ConfigureIisAsync_NoWorkflowHost_ShowsUnavailable()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: false);
			using WebAccessPage page = new(new FakeStore(), probe);
			_ui.Await(page.ConfigureIisAsync(), "ConfigureIisAsync");

			Assert.Contains("not available yet", page.StatusText, StringComparison.OrdinalIgnoreCase);
		});
	}

	[Fact]
	public void InstallIisAsync_WithHost_BlocksButtonsWhileRunningThenCallsHostOnce()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: true);
			using WebAccessPage page = new(new FakeStore(), probe);
			FakeWorkflowHost host = new();
			TaskCompletionSource<string> gate = new();
			host.InstallGate = gate;
			page.AttachWorkflowHost(host);
			_ui.Await(page.RefreshAsync(), "RefreshAsync");
			Assert.True(page.InstallButton.Enabled, "Baseline: workflow button enabled before the run.");

			Task run = page.InstallIisAsync();
			Assert.False(page.InstallButton.Enabled, "Install button must lock while the workflow runs.");
			Assert.False(page.ConfigureButton.Enabled, "Configure button must lock while the workflow runs.");
			Assert.False(page.RefreshButton.Enabled, "Refresh button must lock while the workflow runs.");

			gate.SetResult("installed deterministically");
			_ui.Await(run, "InstallIisAsync completion");

			Assert.Equal(1, host.InstallCalls);
			Assert.Equal("Install IIS: installed deterministically", page.StatusText);
			Assert.True(page.InstallButton.Enabled, "Buttons unlock after the workflow finishes.");
		});
	}

	[Fact]
	public void ConfigureIisAsync_WithHost_DelegatesAndReports()
	{
		_ui.Run(() =>
		{
			IisStatusProbe probe = CreateProbe(installed: true, w3svc: true, published: true);
			using WebAccessPage page = new(new FakeStore(), probe);
			FakeWorkflowHost host = new() { ConfigureOutcome = "site mapped idempotently" };
			page.AttachWorkflowHost(host);

			_ui.Await(page.ConfigureIisAsync(), "ConfigureIisAsync");

			Assert.Equal(1, host.ConfigureCalls);
			Assert.Equal("Configure IIS: site mapped idempotently", page.StatusText);
		});
	}

	[Fact]
	public void PersistShowAsync_Success_StoresValue()
	{
		_ui.Run(() =>
		{
			FakeStore store = new();
			using WebAccessPage page = new(store, CreateProbe(installed: false, w3svc: false, published: false));
			_ui.Await(page.PersistShowAsync(true), "PersistShowAsync");

			Assert.Equal(1, store.TabSetCalls);
			Assert.True(store.LastTabValue ?? false);
		});
	}

	[Fact]
	public void PersistShowAsync_StoreFailure_ReportsRefusal()
	{
		_ui.Run(() =>
		{
			FakeStore store = new() { PersistResult = false };
			using WebAccessPage page = new(store, CreateProbe(installed: false, w3svc: false, published: false));
			_ui.Await(page.PersistShowAsync(false), "PersistShowAsync");

			Assert.Contains("Could not persist", page.StatusText, StringComparison.Ordinal);
		});
	}

	private static IisStatusProbe CreateProbe(bool? installed, bool? w3svc, bool published)
	{
		string dir = Path.Combine(Path.GetTempPath(), "rdpaudit-webaccess-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(dir);
		if (published)
		{
			File.WriteAllText(Path.Combine(dir, "index.html"), "RdpAudit Web Access");
		}

		return new IisStatusProbe(new FakePlatformProbe(installed, w3svc), dir);
	}

	private sealed class FakePlatformProbe : IIisPlatformProbe
	{
		private readonly bool? _installed;
		private readonly bool? _w3svc;

		internal FakePlatformProbe(bool? installed, bool? w3svc)
		{
			_installed = installed;
			_w3svc = w3svc;
		}

		public string Provider => "FakePlatformProbe";

		public Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken)
			=> Task.FromResult(_installed);

		public Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken)
			=> Task.FromResult(_w3svc);
	}

	private sealed class FakeStore : IWebAccessPreferenceStore
	{
		public bool TabEnabled { get; set; }
		public bool ManagementEnabled { get; set; }
		public bool PersistResult { get; set; } = true;
		public int TabSetCalls { get; private set; }
		public bool? LastTabValue { get; private set; }

		public bool IsTabEnabled => TabEnabled;
		public bool IsManagementEnabled => ManagementEnabled;

		public Task<bool> SetTabEnabledAsync(bool enabled, CancellationToken cancellationToken)
		{
			TabSetCalls++;
			LastTabValue = enabled;
			return Task.FromResult(PersistResult);
		}

		public Task<bool> SetManagementEnabledAsync(bool enabled, CancellationToken cancellationToken)
		{
			ManagementEnabled = enabled;
			return Task.FromResult(PersistResult);
		}
	}

	private sealed class FakeWorkflowHost : IWebAccessWorkflowHost
	{
		public int InstallCalls { get; private set; }
		public int ConfigureCalls { get; private set; }
		public string InstallOutcome { get; set; } = "installed";
		public string ConfigureOutcome { get; set; } = "configured";
		public TaskCompletionSource<string>? InstallGate { get; set; }

		/// <summary>Plan rows the fake reports through progress, so a page test can prove the dialog
		/// contract without running a real install.</summary>
		public IReadOnlyList<IisInstallStepResult> ItemResults { get; set; } =
			Array.Empty<IisInstallStepResult>();

		public async Task<IisInstallRunOutcome> RunInstallIisAsync(
			IProgress<IisInstallStepResult>? progress = null,
			System.Threading.CancellationToken ct = default)
		{
			InstallCalls++;
			string line = InstallGate is { } gate ? await gate.Task : InstallOutcome;

			if (progress is not null)
			{
				foreach (IisInstallStepResult item in ItemResults)
				{
					progress.Report(item);
				}
			}

			return new IisInstallRunOutcome(line, ItemResults, Success: true, AlreadyInstalled: false);
		}

		public Task<string> RunConfigureIisAsync()
		{
			ConfigureCalls++;
			return Task.FromResult(ConfigureOutcome);
		}
	}
}
