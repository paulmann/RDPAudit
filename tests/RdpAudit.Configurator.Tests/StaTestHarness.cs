/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : StaTestHarness.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Deterministic STA host for the WinForms tab-page tests. Constructing a WinForms control
//          installs a WindowsFormsSynchronizationContext on the constructing thread, so the
//          continuation of every `await ... ConfigureAwait(true)` inside a tab page - which is the
//          CORRECT choice for a UI page - is posted back to THAT thread's message queue. A test that
//          blocks the same thread with Wait()/GetAwaiter().GetResult() therefore deadlocks the page
//          against its own continuation. Measured in this repository: with the owning thread blocked,
//          DatabasePage.RefreshOverviewAsync never completed (10 s wait, status still "Ready."); with
//          the queue pumped, the same call completed in 2.03 s (the named-pipe connect timeout) and
//          produced its degraded-service status line. This harness therefore NEVER blocks the owning
//          thread: it pumps Application.DoEvents() in a bounded loop until the awaited task completes,
//          gives every wait an explicit deadline, joins the STA thread WITH a deadline, runs that
//          thread as a background thread and enforces a hard per-test-class time budget - so a
//          regression fails the test with a readable message instead of hanging the whole run.
// Depends: System.Windows.Forms, xunit
// Extends: Use this harness in every new tab-page test that drives an async page method.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Windows.Forms;
using Xunit.Sdk;

namespace RdpAudit.Configurator.Tests;

/// <summary>STA host that pumps the WinForms message queue while a test waits for asynchronous page
/// work. One instance belongs to one test class (create it as a field: <c>new StaTestHarness(nameof(MyPageTests))</c>);
/// the class budget starts with the first instance xunit creates and is never extended.</summary>
[SupportedOSPlatform("windows")]
internal sealed class StaTestHarness
{
	/// <summary>Hard upper bound for one test body. A body that overruns it fails the test instead of
	/// hanging the run; it is also the deadline of the join on the STA thread.</summary>
	internal static readonly TimeSpan TestDeadline = TimeSpan.FromSeconds(30);

	/// <summary>Hard upper bound for a single awaited page operation. The longest legitimate wait here
	/// is one named-pipe connect timeout (2 s) for every failure path, so 20 s only trips on a real
	/// hang.</summary>
	internal static readonly TimeSpan OperationDeadline = TimeSpan.FromSeconds(20);

	/// <summary>Hard upper bound on the total time the harness spends inside one test class. The class
	/// currently needs only a few seconds, and every test is bounded on its own, so this cap exists
	/// purely so a pathological regression cannot turn the class into a 6-minute hang again.</summary>
	internal static readonly TimeSpan ClassBudget = TimeSpan.FromMinutes(2);

	private static readonly object BudgetGate = new();
	private static readonly Dictionary<string, DateTime> ClassBudgetStartedUtc = new(StringComparer.Ordinal);

	private readonly string _className;

	/// <summary>Opens (or resumes) the hard time budget of <paramref name="className"/>.</summary>
	internal StaTestHarness(string className)
	{
		ArgumentException.ThrowIfNullOrEmpty(className);
		_className = className;
		lock (BudgetGate)
		{
			if (!ClassBudgetStartedUtc.ContainsKey(className))
			{
				ClassBudgetStartedUtc[className] = DateTime.UtcNow;
			}
		}
	}

	/// <summary>Runs <paramref name="body"/> on a dedicated STA thread that owns a
	/// WindowsFormsSynchronizationContext, and returns once the body has finished. The calling thread
	/// waits with an explicit deadline, so a body that never returns fails the test instead of
	/// wedging it.</summary>
	internal void Run(Action body, [CallerMemberName] string? testName = null)
	{
		ArgumentNullException.ThrowIfNull(body);
		RequireBudget(testName);

		Exception? failure = null;
		Thread sta = new(() =>
		{
			try
			{
				InstallWinFormsContext();
				body();
			}
			catch (Exception ex)
			{
				failure = ex;
			}
		})
		{
			// Background: even if a future body somehow outlives the deadline below, it can never keep
			// the test host alive.
			IsBackground = true,
			Name = "StaTestHarness:" + (testName ?? "test"),
		};
		sta.SetApartmentState(ApartmentState.STA);
		sta.Start();

		if (!sta.Join(TestDeadline))
		{
			throw new XunitException(string.Format(
				System.Globalization.CultureInfo.InvariantCulture,
				"Test '{0}' did not finish within {1:0} s. The test body must never block the thread that "
					+ "owns the WinForms SynchronizationContext (no Wait(), no GetAwaiter().GetResult(), no "
					+ "Thread.Join()); await page work with StaTestHarness.Await, which pumps the message queue.",
				testName ?? "(unknown)",
				TestDeadline.TotalSeconds));
		}

		RequireBudget(testName);

		if (failure is not null)
		{
			throw new XunitException("STA test body failed: " + failure);
		}
	}

	/// <summary>Pumps the calling thread's message queue until <paramref name="task"/> completes, then
	/// flushes the queue once more and re-throws any exception the page body produced. Must be called on
	/// the STA thread that owns the WindowsFormsSynchronizationContext; never replace it with
	/// <c>Wait()</c> or <c>GetAwaiter().GetResult()</c> on that thread.</summary>
	internal void Await(Task task, string description)
	{
		ArgumentNullException.ThrowIfNull(task);
		ArgumentException.ThrowIfNullOrEmpty(description);
		RequireBudget(description);

		Stopwatch watch = Stopwatch.StartNew();
		while (!task.IsCompleted)
		{
			if (watch.Elapsed > OperationDeadline)
			{
				throw new XunitException(string.Format(
					System.Globalization.CultureInfo.InvariantCulture,
					"{0} did not complete within {1:0} s while the message queue was being pumped. Either the "
						+ "page blocked its own UI thread, or an awaited call lost its deadline.",
					description,
					OperationDeadline.TotalSeconds));
			}

			// DoEvents runs any continuation the page posted back to this thread; the short sleep keeps the
			// pump from spinning a core while an IPC round-trip is in flight.
			Application.DoEvents();
			Thread.Sleep(1);
		}

		// Flush callbacks a thread-pool continuation queued through BeginInvoke - SetStatus takes that path
		// when it is called off the UI thread - so the asserted UI state is settled before the test reads it.
		Application.DoEvents();

		// Re-throws the page's own exception, so a failing operation is never reported as a timeout.
		task.GetAwaiter().GetResult();
	}

	/// <summary>Pumps the calling thread's message queue for <paramref name="duration"/> milliseconds.
	/// Used to prove that no continuation is still pending when a test ends.</summary>
	internal void Pump(int durationMilliseconds)
	{
		Stopwatch watch = Stopwatch.StartNew();
		while (watch.ElapsedMilliseconds < durationMilliseconds)
		{
			Application.DoEvents();
			Thread.Sleep(1);
		}
	}

	private static void InstallWinFormsContext()
	{
		if (SynchronizationContext.Current is WindowsFormsSynchronizationContext)
		{
			return;
		}

		// A real UI thread always has this context, and it is what turns ConfigureAwait(true) into a post
		// back to the message queue. Installing it explicitly keeps the harness independent of the side
		// effect that constructing a control happens to have.
		SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
	}

	private void RequireBudget(string? what)
	{
		DateTime startedUtc;
		lock (BudgetGate)
		{
			if (!ClassBudgetStartedUtc.TryGetValue(_className, out startedUtc))
			{
				return;
			}
		}

		TimeSpan elapsed = DateTime.UtcNow - startedUtc;
		if (elapsed > ClassBudget)
		{
			throw new XunitException(string.Format(
				System.Globalization.CultureInfo.InvariantCulture,
				"Test class '{0}' exceeded its hard budget of {1:0} s while running '{2}' ({3:0.0} s elapsed). "
					+ "The budget is per class and never extended; a page test that needs more than a few "
					+ "seconds of IPC timeouts indicates a regression, not a slow machine.",
				_className,
				ClassBudget.TotalSeconds,
				what ?? "(unknown)",
				elapsed.TotalSeconds));
		}
	}
}
