/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ConfiguratorExceptionGuardTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: F1/B2 regression tests for the Configurator's global safety net. An exception raised by a
//          WinForms event handler has no caller left to catch it, so before the guard existed one
//          malformed service answer could terminate the process and discard unsaved state. These tests
//          pin the three properties the guard must have: a fault is survived, it is written to the
//          journal, and the operator is told (once) - except for the terminating case, which is only
//          recorded because the runtime is already tearing the process down.
//          The wiring tests run on a bare STA thread rather than through StaTestHarness: WinForms latches
//          the unhandled-exception mode once a control exists on a thread, and the harness's
//          WindowsFormsSynchronizationContext creates one. Program.Main has no such control, so the bare
//          thread is the faithful reproduction of the startup sequence.
// Depends: ConfiguratorExceptionGuard, SafeAsyncHandler (both RdpAudit.Configurator.Services), xunit

using System.Runtime.Versioning;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class ConfiguratorExceptionGuardTests : IDisposable
{
	private static readonly TimeSpan StaDeadline = TimeSpan.FromSeconds(20);

	private readonly string _root;
	private readonly List<string> _messages = new();

	public ConfiguratorExceptionGuardTests()
		=> _root = Path.Combine(Path.GetTempPath(), "rdpaudit-guard-" + Guid.NewGuid().ToString("N"));

	public void Dispose()
	{
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
			// Best-effort cleanup.
		}
	}

	/// <summary>A guard whose journal and operator dialog are both observable and test-scoped.</summary>
	private ConfiguratorExceptionGuard NewGuard()
		=> new(new Provider(new RdpAuditPaths(_root)), _messages.Add);

	/// <summary>Everything this guard journalled. Each test gets its own root, so the file starts empty.</summary>
	private static string ReadJournal(ConfiguratorExceptionGuard guard)
	{
		string? path = guard.LogFilePath;
		return path is not null && File.Exists(path) ? File.ReadAllText(path) : string.Empty;
	}

	/// <summary>Runs <paramref name="body"/> on a fresh STA thread with no controls on it - the state
	/// Program.Main installs the guard from - and fails the test (rather than hanging) if it does not
	/// finish, since a broken wiring shows itself as a modal WinForms dialog that never returns.</summary>
	private static void RunOnFreshStaThread(Action body, string description)
	{
		Exception? failure = null;
		Thread sta = new(() =>
		{
			try
			{
				body();
			}
			catch (Exception ex)
			{
				failure = ex;
			}
		})
		{
			IsBackground = true,
			Name = "GuardTest:" + description,
		};
		sta.SetApartmentState(ApartmentState.STA);
		sta.Start();

		if (!sta.Join(StaDeadline))
		{
			Assert.Fail(description + " did not finish within 20 s. The unhandled-exception wiring is broken: "
				+ "the fault most likely reached the WinForms exception dialog instead of the guard's handler.");
		}

		if (failure is not null)
		{
			throw new InvalidOperationException(description + " failed: " + failure.Message, failure);
		}
	}

	[Fact]
	public void HandlerThatThrows_DoesNotEscape_AndLandsInTheJournal()
	{
		string marker = Guid.NewGuid().ToString("N");
		string before = TestPathsIsolation.ReadJournal();
		List<Exception> reported = new();
		int invocations = 0;
		EventHandler handler = SafeAsyncHandler.Wrap(
			() =>
			{
				invocations++;
				throw new InvalidOperationException(marker);
			},
			reported.Add);

		// The message loop invokes an event handler with no caller left to catch it, so this call site is
		// the whole contract: whatever the action throws may not escape into the loop.
		handler(this, EventArgs.Empty);

		Assert.Equal(1, invocations);
		Assert.Equal(marker, Assert.Single(reported).Message);
		Assert.Contains(marker, TestPathsIsolation.ReadJournal()[before.Length..], StringComparison.Ordinal);
	}

	[Fact]
	public void UiThreadFault_IsSurvived_JournalledAndShownToTheOperator()
	{
		string marker = Guid.NewGuid().ToString("N");
		ConfiguratorExceptionGuard guard = NewGuard();

		RunOnFreshStaThread(
			() =>
			{
				guard.Install();
				try
				{
					// Application.OnThreadException is what the WinForms message loop calls for a fault it caught
					// on the UI thread (it is the documented entry point), so routing through it proves the
					// installed wiring rather than the internal handler alone.
					Application.OnThreadException(new InvalidOperationException(marker));
				}
				finally
				{
					guard.Uninstall();
				}
			},
			nameof(UiThreadFault_IsSurvived_JournalledAndShownToTheOperator));

		string message = Assert.Single(_messages);
		Assert.Contains(marker, message, StringComparison.Ordinal);
		Assert.Contains("kept running", message, StringComparison.Ordinal);
		Assert.Contains(marker, ReadJournal(guard), StringComparison.Ordinal);
	}

	[Fact]
	public void ProductionStartupSequence_InstallsTheGuardWithoutThrowing()
	{
		// Program.Main's exact order: initialise WinForms, pin the DPI mode, install the guard, then run the
		// form. (ApplicationConfiguration.Initialize() is the generated equivalent of the two calls below,
		// and cannot be named from a test assembly that generates its own copy of that class.)
		ConfiguratorExceptionGuard guard = NewGuard();

		RunOnFreshStaThread(
			() =>
			{
				Application.EnableVisualStyles();
				Application.SetCompatibleTextRenderingDefault(false);
				Application.SetHighDpiMode(HighDpiMode.SystemAware);
				guard.Install();
				if (!guard.IsInstalled)
				{
					throw new InvalidOperationException("Install() did not report itself as installed.");
				}

				guard.Uninstall();
			},
			nameof(ProductionStartupSequence_InstallsTheGuardWithoutThrowing));

		Assert.False(guard.IsInstalled);
	}

	[Fact]
	public void NonTerminatingUnhandledFault_IsSurvivedAndReported()
	{
		string marker = Guid.NewGuid().ToString("N");
		ConfiguratorExceptionGuard guard = NewGuard();

		guard.HandleUnhandledException(new InvalidOperationException(marker), isTerminating: false);

		Assert.Contains(marker, Assert.Single(_messages), StringComparison.Ordinal);
		Assert.Contains(marker, ReadJournal(guard), StringComparison.Ordinal);
	}

	[Fact]
	public void TerminatingUnhandledFault_IsJournalledWithoutADialog()
	{
		string marker = Guid.NewGuid().ToString("N");
		ConfiguratorExceptionGuard guard = NewGuard();

		guard.HandleUnhandledException(new InvalidOperationException(marker), isTerminating: true);

		// The runtime already ended the process; what must survive is the record, and nothing may block a
		// dying process on a modal dialog.
		Assert.Empty(_messages);
		Assert.Contains(marker, ReadJournal(guard), StringComparison.Ordinal);
	}

	[Fact]
	public void UnobservedTaskFault_IsObserved_AndJournalled()
	{
		string marker = Guid.NewGuid().ToString("N");
		ConfiguratorExceptionGuard guard = NewGuard();
		UnobservedTaskExceptionEventArgs args = new(new AggregateException(new InvalidOperationException(marker)));

		guard.HandleUnobservedTaskException(args);

		Assert.True(args.Observed, "The guard must observe the fault so a stray task cannot escalate to process termination.");
		Assert.Empty(_messages);
		Assert.Contains(marker, ReadJournal(guard), StringComparison.Ordinal);
	}

	[Fact]
	public void RepeatedFaults_ShowAtMostOneDialog()
	{
		ConfiguratorExceptionGuard guard = NewGuard();

		guard.HandleThreadException(new InvalidOperationException("first"));
		guard.HandleThreadException(new InvalidOperationException("second"));

		// The second fault is still journalled, but the cooldown keeps a repeating fault from burying the
		// window behind modal dialogs.
		Assert.Single(_messages);
		Assert.Contains("second", ReadJournal(guard), StringComparison.Ordinal);
	}

	[Fact]
	public void InstallAndUninstall_AreIdempotent()
	{
		ConfiguratorExceptionGuard guard = NewGuard();

		Assert.False(guard.IsInstalled);
		RunOnFreshStaThread(
			() =>
			{
				guard.Install();
				guard.Install();
				if (!guard.IsInstalled)
				{
					throw new InvalidOperationException("Install() must be idempotent.");
				}

				guard.Uninstall();
				guard.Uninstall();
			},
			nameof(InstallAndUninstall_AreIdempotent));

		Assert.False(guard.IsInstalled);
	}

	[Fact]
	public void GuardWithoutAPathsProvider_JournalsNothing_AndStillReports()
	{
		// CrashGuard's discipline: without a registered paths provider the fallback sink no-ops instead of
		// inventing a machine-wide location. The operator message must still be produced.
		ConfiguratorExceptionGuard guard = new(pathsProvider: null, _messages.Add);

		guard.HandleThreadException(new InvalidOperationException("no-provider"));

		Assert.Null(guard.LogFilePath);
		Assert.Single(_messages);
	}

	private sealed class Provider(RdpAuditPaths paths) : IRdpAuditPathsProvider
	{
		public RdpAuditPaths Paths { get; } = paths;
	}
}
