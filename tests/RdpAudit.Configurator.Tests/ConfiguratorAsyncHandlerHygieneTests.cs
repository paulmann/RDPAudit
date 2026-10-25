/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ConfiguratorAsyncHandlerHygieneTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: B2 regression tests for the shared async-handler contract and for the debt counter that
//          keeps it from growing silently. A lambda attached with `+= async (_, _) => ...` is async void
//          at runtime: an exception that escapes it cannot be caught by any caller, so the only defence
//          is to attach handlers through SafeAsyncHandler (which journals and reports) instead. The four
//          highest-risk pages were migrated in B2/F2 and DatabasePage's private helper was replaced by
//          the shared type; the remaining pages are tracked work, so this class pins the recorded count
//          per file and fails when it grows.
// Depends: SafeAsyncHandler (RdpAudit.Configurator.Services), xunit

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using RdpAudit.Configurator.Services;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class ConfiguratorAsyncHandlerHygieneTests
{
	private static readonly Regex UnguardedSitePattern = new(@"\+=\s*async", RegexOptions.None, TimeSpan.FromSeconds(5));

	private static readonly Regex NamedAsyncVoidPattern = new(@"\basync\s+void\b", RegexOptions.None, TimeSpan.FromSeconds(5));

	/// <summary>Unguarded <c>+= async</c> handler sites recorded right after the B2/F2 migration
	/// (2026-09-15), per file. Every remaining site is tracked debt for the P3 pass: the global safety
	/// net already makes them survivable, and this map makes them visible.</summary>
	private static readonly Dictionary<string, int> RecordedUnguardedSites = new(StringComparer.Ordinal)
	{
		["Forms/AbuseIpDbPage.cs"] = 6,
		["Forms/AttackStatisticsPage.cs"] = 7,
		["Forms/AuditPolicyPage.cs"] = 1,
		["Forms/CrossHostPage.cs"] = 3,
		["Forms/DiagnosticsPage.cs"] = 5,
		["Forms/EventCollectionPage.cs"] = 4,
		["Forms/LiveEventsPage.cs"] = 2,
		["Forms/LogsPage.cs"] = 6,
		["Forms/MainForm.cs"] = 2,
		["Forms/MikroTikPage.cs"] = 4,
		["Forms/NotificationsPage.cs"] = 3,
		["Forms/PrerequisitesPage.cs"] = 5,
		["Forms/ProcessAlertsPage.cs"] = 6,
		["Forms/ProcessObservationDialog.cs"] = 1,
		["Forms/RdpConfigurationPage.cs"] = 2,
		["Forms/SessionMapPage.cs"] = 2,
		["Forms/SettingsPage.cs"] = 3,
		["Forms/ToolsDiagPage.cs"] = 2,
	};

	private const int RecordedUnguardedSiteTotal = 64;

	/// <summary>Named <c>async void</c> methods that are not event-handler lambdas (the same fatal shape,
	/// counted separately because they cannot be migrated by attaching a wrapper).</summary>
	private static readonly Dictionary<string, int> RecordedNamedAsyncVoidMethods = new(StringComparer.Ordinal)
	{
		["Forms/AuditPolicyPage.cs"] = 3,
		["Forms/SettingsPage.cs"] = 1,
	};

	/// <summary>Pages migrated in B2/F2 plus DatabasePage, whose private helper was promoted into the
	/// shared type. None of them may attach a raw async lambda again.</summary>
	private static readonly string[] MigratedFiles =
	{
		"Forms/DatabasePage.cs",
		"Forms/FirewallPage.cs",
		"Forms/OverviewPage.cs",
		"Forms/PurgeBySubjectDialog.cs",
		"Forms/RemoteRdpClientsPage.cs",
		"Forms/ServicePage.cs",
	};

	[Fact]
	public void WrappedHandler_ReportsAFaultedAction_AndNeverRethrows()
	{
		List<Exception> reported = new();
		EventHandler handler = SafeAsyncHandler.Wrap(
			() => Task.FromException(new InvalidOperationException("boom")),
			reported.Add);

		// The faulted task completes synchronously, so the wrapper's catch runs before this returns - and
		// nothing may escape the handler: that is the entire contract with the message loop.
		handler(this, EventArgs.Empty);

		Assert.Equal("boom", Assert.Single(reported).Message);
	}

	[Fact]
	public async Task WrappedHandler_ReportsAFailureThatArrivesAfterAnAwait()
	{
		TaskCompletionSource gate = new();
		TaskCompletionSource<bool> reportedSignal = new();
		List<Exception> reported = new();
		EventHandler handler = SafeAsyncHandler.Wrap(
			async () =>
			{
				await gate.Task.ConfigureAwait(false);
				throw new InvalidOperationException("later");
			},
			ex =>
			{
				reported.Add(ex);
				_ = reportedSignal.TrySetResult(true);
			});

		handler(this, EventArgs.Empty);
		Assert.Empty(reported);

		gate.SetResult();
		Task finished = await Task.WhenAny(reportedSignal.Task, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(true);

		Assert.Same(reportedSignal.Task, finished);
		Assert.Equal("later", Assert.Single(reported).Message);
	}

	[Fact]
	public async Task WrappedKeyHandler_ForwardsTheArguments()
	{
		KeyEventArgs? seen = null;
		KeyEventHandler handler = SafeAsyncHandler.KeyDown(e =>
		{
			seen = e;
			return Task.CompletedTask;
		});
		KeyEventArgs args = new(Keys.Enter);

		handler(this, args);
		await Task.Yield();

		Assert.Same(args, seen);
	}

	[Fact]
	public void Wrap_RejectsANullAction()
	{
		Assert.Throws<ArgumentNullException>(() => SafeAsyncHandler.Wrap(null!));
		Assert.Throws<ArgumentNullException>(() => SafeAsyncHandler.KeyDown(null!));
		Assert.Throws<ArgumentNullException>(() => SafeAsyncHandler.Wrap<EventArgs>(null!));
	}

	[Fact]
	public void MigratedPages_AttachNoRawAsyncHandlers()
	{
		List<string> offenders = new();
		foreach (string file in MigratedFiles)
		{
			string text = StripComments(ReadSource(file));
			int sites = UnguardedSitePattern.Matches(text).Count;
			if (sites > 0)
			{
				offenders.Add(file + " (" + sites.ToString(CultureInfo.InvariantCulture) + " raw `+= async` site(s))");
			}

			if (NamedAsyncVoidPattern.IsMatch(text))
			{
				offenders.Add(file + " (named async void method)");
			}
		}

		Assert.True(offenders.Count == 0,
			"These migrated files must attach async handlers only through SafeAsyncHandler: "
			+ string.Join(", ", offenders));
	}

	[Fact]
	public void UnguardedHandlerDebt_DoesNotGrow()
	{
		Dictionary<string, int> actual = CountUnguardedSites();

		List<string> growth = actual
			.Where(pair => pair.Value > RecordedUnguardedSites.GetValueOrDefault(pair.Key))
			.OrderBy(pair => pair.Key, StringComparer.Ordinal)
			.Select(pair => string.Format(
				CultureInfo.InvariantCulture,
				"{0}: {1} (recorded {2})",
				pair.Key,
				pair.Value,
				RecordedUnguardedSites.GetValueOrDefault(pair.Key)))
			.ToList();

		int total = actual.Values.Sum();
		List<string> snapshot = actual
			.OrderBy(pair => pair.Key, StringComparer.Ordinal)
			.Select(pair => pair.Key + "=" + pair.Value.ToString(CultureInfo.InvariantCulture))
			.ToList();

		Assert.True(growth.Count == 0,
			"The number of unguarded `+= async` handlers grew. Attach new handlers with "
			+ "SafeAsyncHandler.Wrap(...) instead of a raw async lambda, and lower the recorded counts only "
			+ "when a page is migrated. Growth: " + string.Join("; ", growth)
			+ ". Current per-file totals: " + string.Join("; ", snapshot));

		Assert.True(total <= RecordedUnguardedSiteTotal,
			"Remaining unguarded `+= async` handler sites (" + total.ToString(CultureInfo.InvariantCulture)
			+ ") exceed the recorded total of " + RecordedUnguardedSiteTotal.ToString(CultureInfo.InvariantCulture)
			+ ". Current per-file totals: " + string.Join("; ", snapshot));
	}

	[Fact]
	public void NamedAsyncVoidMethods_DoNotGrow()
	{
		Dictionary<string, int> actual = CountMatches(NamedAsyncVoidPattern);

		List<string> growth = actual
			.Where(pair => pair.Value > RecordedNamedAsyncVoidMethods.GetValueOrDefault(pair.Key))
			.OrderBy(pair => pair.Key, StringComparer.Ordinal)
			.Select(pair => pair.Key + "=" + pair.Value.ToString(CultureInfo.InvariantCulture))
			.ToList();

		Assert.True(growth.Count == 0,
			"New `async void` methods appeared. Declare `async Task` and await it, or route the handler "
			+ "through SafeAsyncHandler. Growth: " + string.Join("; ", growth));
	}

	private static Dictionary<string, int> CountUnguardedSites() => CountMatches(UnguardedSitePattern);

	private static Dictionary<string, int> CountMatches(Regex pattern)
	{
		Dictionary<string, int> counts = new(StringComparer.Ordinal);
		foreach (string path in EnumerateConfiguratorSources())
		{
			int matches = pattern.Matches(StripComments(File.ReadAllText(path))).Count;
			if (matches > 0)
			{
				counts[RelativeToConfigurator(path)] = matches;
			}
		}

		return counts;
	}

	/// <summary>Removes line comments (including XML doc lines) so a comment that names the pattern cannot
	/// be counted as a site.</summary>
	private static string StripComments(string text)
		=> Regex.Replace(text, @"//[^\r\n]*", string.Empty, RegexOptions.None, TimeSpan.FromSeconds(5));

	private static string ReadSource(string relativeToConfiguratorProject)
		=> File.ReadAllText(Path.Combine(
			ConfiguratorProjectDirectory(),
			relativeToConfiguratorProject.Replace('/', Path.DirectorySeparatorChar)));

	private static IEnumerable<string> EnumerateConfiguratorSources()
		=> Directory.EnumerateFiles(ConfiguratorProjectDirectory(), "*.cs", SearchOption.AllDirectories)
			.Where(path => !IsBuildArtifact(path));

	private static bool IsBuildArtifact(string path)
	{
		string[] segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		return segments.Contains("bin", StringComparer.Ordinal) || segments.Contains("obj", StringComparer.Ordinal);
	}

	private static string RelativeToConfigurator(string absolutePath)
		=> Path.GetRelativePath(ConfiguratorProjectDirectory(), absolutePath).Replace('\\', '/');

	private static string ConfiguratorProjectDirectory()
		=> Path.Combine(FindRepositoryRoot(), "src", "RdpAudit.Configurator");

	private static string FindRepositoryRoot()
	{
		DirectoryInfo? directory = new(AppContext.BaseDirectory);
		while (directory is not null)
		{
			if (File.Exists(Path.Combine(directory.FullName, "RdpAudit.sln")))
			{
				return directory.FullName;
			}

			directory = directory.Parent;
		}

		throw new InvalidOperationException(
			"Repository root (RdpAudit.sln) not found above " + AppContext.BaseDirectory);
	}
}
