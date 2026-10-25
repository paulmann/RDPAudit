// File:    src/RdpAudit.Configurator/Services/ConfiguratorExceptionGuard.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Process-wide last-resort fault handling for the Configurator. Installs the WinForms
//          ThreadException hook plus AppDomain.UnhandledException and TaskScheduler.UnobservedTaskException
//          so an exception that escapes an event handler - or any other thread - is recorded and
//          reported instead of silently tearing the process down and discarding unsaved state.
//          Mirrors the service-side CrashGuard minus the sinks the Configurator does not own (there is
//          no OperationLog writer and no registered Event Log source in this process): the durable
//          record goes to %ProgramData%\RdpAudit\logs\configurator-unhandled.log through the shared
//          DiagnosticLogRotation helper, and a recoverable fault is also shown to the operator.
//          Every path here is best-effort and self-contained: the guard must never throw.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Installs the Configurator's global unhandled-exception safety net and owns the shared
/// last-resort journal every page writes an escaped handler failure to.</summary>
[SupportedOSPlatform("windows")]
public sealed class ConfiguratorExceptionGuard
{
	private const string MessageBoxTitle = "RdpAudit Configurator — unexpected error";

	/// <summary>Default minimum interval between two operator dialogs. A fault that fires on every
	/// timer tick (for example a service that keeps answering garbage) must not bury the operator in
	/// modal dialogs.</summary>
	public static readonly TimeSpan DefaultOperatorMessageCooldown = TimeSpan.FromSeconds(30);

	private static readonly Lazy<ConfiguratorExceptionGuard> LazyDefault = new(
		static () => new ConfiguratorExceptionGuard(new DefaultRdpAuditPathsProvider()),
		LazyThreadSafetyMode.ExecutionAndPublication);

	private readonly object _gate = new();
	private readonly IRdpAuditPathsProvider? _pathsProvider;
	private readonly Action<string> _operatorMessage;
	private readonly TimeSpan _operatorMessageCooldown;

	private bool _messageOpen;
	private DateTime _lastMessageUtc = DateTime.MinValue;
	private bool _installed;

	/// <summary>Creates a guard. <paramref name="pathsProvider"/> supplies the journal location and may
	/// be null (the journal then silently no-ops, exactly as CrashGuard behaves without a registered
	/// paths provider) so a test can build a guard that touches nothing. <paramref name="operatorMessage"/>
	/// replaces the modal dialog and is how the tests observe what an operator would be told.</summary>
	public ConfiguratorExceptionGuard(
		IRdpAuditPathsProvider? pathsProvider = null,
		Action<string>? operatorMessage = null,
		TimeSpan? operatorMessageCooldown = null)
	{
		_pathsProvider = pathsProvider;
		_operatorMessage = operatorMessage ?? ShowOperatorDialog;
		_operatorMessageCooldown = operatorMessageCooldown ?? DefaultOperatorMessageCooldown;
	}

	/// <summary>The instance <see cref="Program"/> installs, and the one every page's failure report and
	/// the shared <see cref="SafeAsyncHandler"/> write to.</summary>
	public static ConfiguratorExceptionGuard Default => LazyDefault.Value;

	/// <summary>Test seam (the same discipline RdpAuditPaths specifies): the Configurator test suite
	/// redirects the journal into a temporary root here, so no test run can append to the machine's real
	/// %ProgramData%\RdpAudit tree. Null in production, and set once per test process.</summary>
	internal static IRdpAuditPathsProvider? PathsOverrideForTests { get; set; }

	/// <summary>True once <see cref="Install"/> has attached this instance's handlers.</summary>
	public bool IsInstalled => _installed;

	/// <summary>The journal file this guard appends to, or null when no paths provider is configured.</summary>
	public string? LogFilePath => ResolveLogFilePath();

	/// <summary>Attaches the four process-wide hooks. <see cref="Application.SetUnhandledExceptionMode"/>
	/// with <see cref="UnhandledExceptionMode.CatchException"/> is what routes a UI-thread fault to
	/// <see cref="Application.ThreadException"/> (our handler, which survives) instead of the WinForms
	/// thread-exception dialog. Must be called on the UI thread and before the first window is shown.</summary>
	public void Install()
	{
		if (_installed)
		{
			return;
		}

		Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
		Application.ThreadException += OnThreadException;
		AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
		TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
		_installed = true;
	}

	/// <summary>Detaches the handlers again. Used by tests; production installs once and never detaches.</summary>
	public void Uninstall()
	{
		if (!_installed)
		{
			return;
		}

		Application.ThreadException -= OnThreadException;
		AppDomain.CurrentDomain.UnhandledException -= OnAppDomainUnhandledException;
		TaskScheduler.UnobservedTaskException -= OnUnobservedTaskException;
		_installed = false;
	}

	/// <summary>Handles a fault raised on the UI thread. The message loop survives such a fault, so this
	/// records it, tells the operator, and returns - the process keeps running and unsaved state survives.</summary>
	internal void HandleThreadException(Exception? exception)
		=> Report("Application.ThreadException", exception, notifyOperator: true);

	/// <summary>Handles a fault with no catchable context. When <paramref name="isTerminating"/> the
	/// runtime is already shutting the process down: the fault is written to the journal synchronously
	/// (that record is the whole point) and no dialog is attempted - a modal box in a dying process can
	/// hang an unattended host. A non-terminating report is treated like a UI fault: record and survive.</summary>
	internal void HandleUnhandledException(Exception? exception, bool isTerminating)
		=> Report("AppDomain.UnhandledException", exception, notifyOperator: !isTerminating);

	/// <summary>Handles a task fault nobody awaited. The event args are marked observed first, so a stray
	/// faulted task cannot escalate to process termination on its own, then the fault is recorded. No
	/// dialog: the handler runs on the finalizer thread at an arbitrary moment, long after the operator
	/// could act on it.</summary>
	internal void HandleUnobservedTaskException(UnobservedTaskExceptionEventArgs args)
	{
		ArgumentNullException.ThrowIfNull(args);
		args.SetObserved();
		Report("TaskScheduler.UnobservedTaskException", args.Exception, notifyOperator: false);
	}

	/// <summary>Records a fault a page already handled and already rendered on its own status surface.
	/// It must not vanish from the journal, but the operator has been told, so no dialog is shown.</summary>
	public void ReportHandlerFailure(string source, Exception exception)
	{
		ArgumentNullException.ThrowIfNull(exception);
		Report(string.IsNullOrWhiteSpace(source) ? "Configurator" : source, exception, notifyOperator: false);
	}

	private void OnThreadException(object sender, ThreadExceptionEventArgs e)
		=> HandleThreadException(e.Exception);

	private void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
		=> HandleUnhandledException(e.ExceptionObject as Exception, e.IsTerminating);

	private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
		=> HandleUnobservedTaskException(e);

	private void Report(string origin, Exception? exception, bool notifyOperator)
	{
		string summary = origin + ": " + Describe(exception);
		Debug.WriteLine("[ConfiguratorExceptionGuard] " + summary);
		string? logPath = WriteJournalEntry(summary, exception);
		if (notifyOperator)
		{
			NotifyOperator(BuildOperatorMessage(summary, logPath));
		}
	}

	private string? WriteJournalEntry(string summary, Exception? exception)
	{
		string? path = ResolveLogFilePath();
		if (path is null)
		{
			return null;
		}

		try
		{
			string entry = string.Format(
				CultureInfo.InvariantCulture,
				"{0:O} [ERROR] {1}{2}{3}{2}",
				DateTime.UtcNow,
				summary,
				Environment.NewLine,
				exception?.ToString() ?? "(no exception object)");
			DiagnosticLogRotation.AppendLine(path, entry);
			return path;
		}
		catch (Exception)
		{
			// Last-resort sink: the Debug mirror above already carries the fault. Nothing else to do,
			// and throwing from here would recreate exactly the failure this type exists to absorb.
			return null;
		}
	}

	private static string BuildOperatorMessage(string summary, string? logPath)
	{
		string details = logPath is null
			? "The fault could not be written to a log file (no ProgramData layout available)."
			: "Details were written to:" + Environment.NewLine + logPath;
		return "The RdpAudit Configurator hit an unexpected error and kept running."
			+ Environment.NewLine + Environment.NewLine
			+ summary + Environment.NewLine + Environment.NewLine
			+ "Save any unsaved changes and restart the Configurator if the window stops responding."
			+ Environment.NewLine + Environment.NewLine
			+ details;
	}

	/// <summary>Shows at most one dialog at a time and never more often than the cooldown, so a repeating
	/// fault cannot hide the window behind modal dialogs.</summary>
	private void NotifyOperator(string message)
	{
		lock (_gate)
		{
			DateTime now = DateTime.UtcNow;
			if (_messageOpen || now - _lastMessageUtc < _operatorMessageCooldown)
			{
				return;
			}

			_messageOpen = true;
			_lastMessageUtc = now;
		}

		try
		{
			_operatorMessage(message);
		}
		catch (Exception)
		{
			// A failing message sink must never become the fault.
		}
		finally
		{
			lock (_gate)
			{
				_messageOpen = false;
			}
		}
	}

	private string? ResolveLogFilePath()
	{
		// The test override redirects the production sink only. A guard constructed with its own provider
		// (a test) or with none at all - no sink, exactly as CrashGuard behaves without a registered
		// provider - keeps whatever it was given.
		IRdpAuditPathsProvider? provider = _pathsProvider is DefaultRdpAuditPathsProvider
			? PathsOverrideForTests ?? _pathsProvider
			: _pathsProvider;
		try
		{
			return provider?.Paths.ConfiguratorUnhandledLogPath;
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static string Describe(Exception? exception)
		=> exception is null
			? "(no exception object)"
			: exception.GetType().Name + " — " + exception.Message;

	private static void ShowOperatorDialog(string message)
		=> MessageBox.Show(message, MessageBoxTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
}
