// File:    tests/RdpAudit.Configurator.Tests/IisInstallServiceTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Step 10 verification for the Install IIS workflow: IisInstallService is
//          elevation-guarded, idempotent, fail-closed and routes every installer through the central
//          command runner with the operator-visible argument vectors. Tests inject a fake platform
//          probe, a fake command runner, a fake module probe and a deterministic elevation check, and
//          assert the actual interactions (probe channels, runner arguments, DIDN'T-run guarantees,
//          per-plan-item results and progress delivery) rather than merely exercising the path.
//
//          The workflow now installs everything the web dashboard needs - the IIS feature set, the
//          IIS management tools and the ASP.NET Core Hosting Bundle that carries the native ASP.NET
//          Core Module v2 - and reports one result row per IisInstallPlan item. That is why
//          Run_CleanState expects several runner calls rather than one: components that are already
//          present are skipped, so the number of calls is what proves the idempotency contract.
// Depends: IisInstallService, IisInstallCommandSet, IisInstallPlan, HostingBundleCommandSet,
//          ExternalCommandResult, xUnit

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class IisInstallServiceTests
{
	private const string FeaturesLabel = "DISM IIS feature install";
	private const string ToolsLabel = "DISM IIS management tools install";
	private const string BundleLabel = HostingBundleCommandSet.InstallCommandLabel;

	[Fact]
	public async Task Run_AlreadyInstalled_ReportsNothingToInstallAndRunsNoInstaller()
	{
		FakePlatformProbe platform = new(installed: true, w3svc: true);
		FakeCommandRunner runner = new();
		FakeElevation elevation = new(elevated: true);
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(platform, runner, elevation.Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.True(outcome.Success);
		Assert.True(outcome.AlreadyInstalled);
		Assert.Empty(outcome.Errors);
		Assert.Empty(outcome.Warnings);
		Assert.Empty(runner.DirectCalls);
		Assert.Equal(1, elevation.Calls);

		// The plan ends with a verification step that re-reads the machine, so the probe channels are
		// read twice: once to decide what to install and once to confirm what is there.
		Assert.Equal(2, platform.InstalledCalls);
		Assert.Equal(
			new[] { WindowsIisPlatformProbe.W3SvcServiceName, WindowsIisPlatformProbe.W3SvcServiceName },
			platform.ServiceProbeNames);

		Assert.Equal(
			new[]
			{
				IisStepOutcome.Ok,        // elevation
				IisStepOutcome.Skipped,   // features: already present
				IisStepOutcome.Ok,        // management tools: appcmd.exe present
				IisStepOutcome.Skipped,   // hosting bundle: module already present
				IisStepOutcome.Ok,        // verification
			},
			Outcomes(outcome));
	}

	[Fact]
	public async Task Run_NotElevated_RefusesWithoutProbingOrDism()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		FakeElevation elevation = new(elevated: false);
		IisInstallService service = Build(platform, runner, elevation.Check);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Single(outcome.Errors);
		Assert.Contains("administrator", outcome.Errors[0], StringComparison.OrdinalIgnoreCase);
		Assert.Equal(0, platform.InstalledCalls);
		Assert.Empty(platform.ServiceProbeNames);
		Assert.Empty(runner.DirectCalls);
	}

	[Fact]
	public async Task Run_UndeterminedState_RefusesWithoutInvokingDism()
	{
		FakePlatformProbe platform = new(installed: null, w3svc: true);
		FakeCommandRunner runner = new();
		IisInstallService service = Build(platform, runner, new FakeElevation(true).Check);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.False(outcome.AlreadyInstalled);
		Assert.Single(outcome.Errors);
		Assert.Contains("could not be fully determined", outcome.Errors[0], StringComparison.OrdinalIgnoreCase);
		Assert.Empty(runner.DirectCalls);
	}

	[Fact]
	public async Task Run_CleanMachine_EnablesFeaturesThenToolsThenInstallsTheHostingBundle()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: missingAppCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		// winget reported success but the native module never appeared on disk, so the run must not
		// claim success: the dashboard cannot be hosted until the bundle is really installed. The
		// command sequence below is what this test pins.
		Assert.False(outcome.Success);
		Assert.False(outcome.AlreadyInstalled);
		Assert.Equal(IisStepOutcome.Warning, OutcomeOf(outcome, IisInstallStepId.HostingBundle));
		Assert.Equal(IisStepOutcome.Failed, OutcomeOf(outcome, IisInstallStepId.Verification));

		// Order matters: features, then the management tools the Configure IIS step needs, then the
		// native module - each with the argument vector built from the shared command set.
		Assert.Equal(new[] { FeaturesLabel, ToolsLabel, BundleLabel }, runner.Labels());
		Assert.Equal("dism.exe", runner.DirectCalls[0].Executable);
		Assert.Equal(
			IisInstallCommandSet.BuildDismArguments(IisFeatureCatalog.DismFeatures),
			runner.DirectCalls[0].Arguments);
		Assert.Equal(
			IisInstallCommandSet.BuildDismArguments(IisFeatureCatalog.DismManagementFeatures),
			runner.DirectCalls[1].Arguments);
		Assert.Equal(HostingBundleCommandSet.WingetExecutable, runner.DirectCalls[2].Executable);
		Assert.Equal(HostingBundleCommandSet.BuildInstallArguments(), runner.DirectCalls[2].Arguments);
	}

	[Fact]
	public async Task Run_ManagementToolsPresent_SkipsTheToolsStep()
	{
		FakePlatformProbe platform = new(
			installed: false, w3svc: false, installedAfterInstall: true, w3svcAfterInstall: true);
		FakeCommandRunner runner = new();
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.True(outcome.Success);
		Assert.Equal(new[] { FeaturesLabel }, runner.Labels());
		Assert.Equal(IisStepOutcome.Ok, OutcomeOf(outcome, IisInstallStepId.IisManagementTools));
	}

	[Fact]
	public async Task Run_ModuleAlreadyPresent_DoesNotInvokeWinget()
	{
		FakePlatformProbe platform = new(
			installed: false, w3svc: false, installedAfterInstall: true, w3svcAfterInstall: true);
		FakeCommandRunner runner = new();
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: missingAppCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.True(outcome.Success);
		Assert.DoesNotContain(BundleLabel, runner.Labels());
		Assert.Equal(IisStepOutcome.Skipped, OutcomeOf(outcome, IisInstallStepId.HostingBundle));
	}

	[Fact]
	public async Task Run_FeaturesFail_SkipsEveryDependentStepAndNeverCallsWinget()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[FeaturesLabel] = Failure(FeaturesLabel, 87, "the feature name is unknown");
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: missingAppCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Equal(new[] { FeaturesLabel }, runner.Labels());
		Assert.Equal(IisStepOutcome.Failed, OutcomeOf(outcome, IisInstallStepId.IisFeatures));
		Assert.Equal(IisStepOutcome.Skipped, OutcomeOf(outcome, IisInstallStepId.IisManagementTools));
		Assert.Equal(IisStepOutcome.Skipped, OutcomeOf(outcome, IisInstallStepId.HostingBundle));
		Assert.Equal(IisStepOutcome.Skipped, OutcomeOf(outcome, IisInstallStepId.Verification));
	}

	[Fact]
	public async Task Run_RebootRequired_SucceedsWithWarning()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[FeaturesLabel] = new ExternalCommandResult(
			FeaturesLabel, "dism.exe", IisInstallService.DismSuccessRebootRequired,
			"restart needed", string.Empty, TimedOut: false, TimeSpan.FromSeconds(12), EnglishConsoleMode: false);
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.True(outcome.Success);
		Assert.Equal(IisStepOutcome.Warning, OutcomeOf(outcome, IisInstallStepId.IisFeatures));
		Assert.Single(outcome.Warnings);
		Assert.Contains("reboot", outcome.Warnings[0], StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task Run_ElevationRequiredExit_ReportsActionableError()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[FeaturesLabel] = Failure(
			FeaturesLabel, IisInstallService.DismErrorElevationRequired, "Access is denied");
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: missingAppCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Single(outcome.Errors);
		Assert.Contains("740", outcome.Errors[0], StringComparison.Ordinal);
		Assert.Contains("administrator", outcome.Errors[0], StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task Run_TimedOut_RefusesWithUnknownStateNote()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[FeaturesLabel] = new ExternalCommandResult(
			FeaturesLabel, "dism.exe", -1, string.Empty, string.Empty,
			TimedOut: true, TimeSpan.FromSeconds(100), EnglishConsoleMode: false);
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check,
			appCmd: missingAppCmd.Path, modulePresent: false, dismTimeout: TimeSpan.FromSeconds(100));

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Single(outcome.Errors);
		Assert.Contains("timed out", outcome.Errors[0], StringComparison.OrdinalIgnoreCase);
		Assert.Contains("unknown", outcome.Errors[0], StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task Run_OtherExit_SurfacesDiagnosticSummaryNeverRawOutput()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[FeaturesLabel] = new ExternalCommandResult(
			FeaturesLabel, "dism.exe", 87,
			string.Empty, "line1\nline2\nline3 with a very long error detail beyond the bounded summary",
			TimedOut: false, TimeSpan.FromSeconds(2), EnglishConsoleMode: false);
		using TempFile missingAppCmd = TempFile.CreateMissing();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: missingAppCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		string error = Assert.Single(outcome.Errors);
		Assert.Contains("exit=87", error, StringComparison.Ordinal);
		Assert.DoesNotContain("\n", error);
	}

	[Fact]
	public async Task Run_BundleInstallFails_ReportsActionableErrorAndNoVerificationSuccess()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		runner.Results[BundleLabel] = Failure(BundleLabel, 1, "no package found matching input criteria");
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Equal(IisStepOutcome.Failed, OutcomeOf(outcome, IisInstallStepId.HostingBundle));
		Assert.Contains(
			outcome.Errors,
			error => error.Contains(HostingBundlePackage.WingetPackageId, StringComparison.Ordinal));
		Assert.Equal(IisStepOutcome.Skipped, OutcomeOf(outcome, IisInstallStepId.Verification));
	}

	[Fact]
	public async Task Run_BundleReportsSuccessButModuleStillMissing_WarnsInsteadOfClaimingSuccess()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		using TempFile appCmd = TempFile.Create();
		// The bundle installer succeeds, but the module never appears: this must be a warning with a
		// reboot note, never a silent success.
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: false);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Equal(IisStepOutcome.Warning, OutcomeOf(outcome, IisInstallStepId.HostingBundle));
		Assert.Equal(IisStepOutcome.Failed, OutcomeOf(outcome, IisInstallStepId.Verification));
		Assert.Contains(
			outcome.Warnings,
			warning => warning.Contains("reboot", StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public async Task Run_ResultRows_MirrorThePlanExactly()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync();

		Assert.Equal(IisInstallPlan.OrderedStepIds.Count, outcome.ItemResults.Count);
		for (int i = 0; i < outcome.ItemResults.Count; i++)
		{
			Assert.Equal(IisInstallPlan.OrderedStepIds[i], outcome.ItemResults[i].Id);
			Assert.Equal(IisInstallPlan.TitleFor(IisInstallPlan.OrderedStepIds[i]), outcome.ItemResults[i].Title);
		}
	}

	[Fact]
	public async Task Run_Progress_ReceivesEveryRowOfTheFinishedRun()
	{
		FakePlatformProbe platform = new(installed: false, w3svc: false);
		FakeCommandRunner runner = new();
		using TempFile appCmd = TempFile.Create();
		RecordingProgress progress = new();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync(progress);

		Assert.Equal(IisInstallPlan.OrderedStepIds, progress.ReportedIds());
		Assert.Equal(Outcomes(outcome), progress.FinalOutcomes());
	}

	[Fact]
	public async Task Run_ProgressSinkThrows_NeverBreaksTheInstallation()
	{
		FakePlatformProbe platform = new(
			installed: false, w3svc: false, installedAfterInstall: true, w3svcAfterInstall: true);
		FakeCommandRunner runner = new();
		using TempFile appCmd = TempFile.Create();
		IisInstallService service = Build(
			platform, runner, new FakeElevation(true).Check, appCmd: appCmd.Path, modulePresent: true);

		IisInstallOutcome outcome = await service.RunAsync(new ThrowingProgress());

		// A closed window must never abort an install that is already changing the machine.
		Assert.True(outcome.Success);
	}

	[Fact]
	public void Constructor_RequiresPlatformAndRunner()
	{
		FakeCommandRunner runner = new();
		Assert.Throws<ArgumentNullException>(() => new IisInstallService(null!, runner));
		Assert.Throws<ArgumentNullException>(
			() => new IisInstallService(new FakePlatformProbe(false, false), null!));
	}

	private static IisInstallService Build(
		FakePlatformProbe platform,
		FakeCommandRunner runner,
		Func<ElevationStatus> elevation,
		string? appCmd = null,
		bool modulePresent = false,
		TimeSpan? dismTimeout = null)
		=> new(
			platform,
			runner,
			elevation,
			dismTimeout,
			new AspNetCoreModuleProbe("C:\\rdpaudit-test-inetsrv", _ => modulePresent),
			appCmd,
			TimeSpan.FromSeconds(30));

	private static ExternalCommandResult Failure(string label, int exitCode, string stdErr)
		=> new(label, "tool.exe", exitCode, string.Empty, stdErr, false, TimeSpan.FromSeconds(1), false);

	private static List<IisStepOutcome> Outcomes(IisInstallOutcome outcome)
	{
		List<IisStepOutcome> outcomes = new(outcome.ItemResults.Count);
		foreach (IisInstallStepResult item in outcome.ItemResults)
		{
			outcomes.Add(item.Outcome);
		}

		return outcomes;
	}

	private static IisStepOutcome OutcomeOf(IisInstallOutcome outcome, IisInstallStepId id)
	{
		foreach (IisInstallStepResult item in outcome.ItemResults)
		{
			if (item.Id == id)
			{
				return item.Outcome;
			}
		}

		throw new InvalidOperationException("The plan row is missing: " + id);
	}

	/// <summary>Temporary file that exists for the duration of one test (or, in
	/// <see cref="CreateMissing"/> form, a path that deliberately does not exist).</summary>
	private sealed class TempFile : IDisposable
	{
		private TempFile(string path, bool created)
		{
			Path = path;
			_created = created;
		}

		private readonly bool _created;

		public string Path { get; }

		public static TempFile Create()
		{
			string path = System.IO.Path.Combine(
				System.IO.Path.GetTempPath(), "rdpaudit-appcmd-" + Guid.NewGuid().ToString("N") + ".exe");
			File.WriteAllText(path, string.Empty);
			return new TempFile(path, created: true);
		}

		public static TempFile CreateMissing()
			=> new(System.IO.Path.Combine(
				System.IO.Path.GetTempPath(), "rdpaudit-missing-" + Guid.NewGuid().ToString("N")), created: false);

		public void Dispose()
		{
			if (!_created || !File.Exists(Path))
			{
				return;
			}

			try
			{
				File.Delete(Path);
			}
			catch (IOException)
			{
				// A leftover temp file is harmless.
			}
		}
	}

	private sealed class RecordingProgress : IProgress<IisInstallStepResult>
	{
		private readonly List<IisInstallStepResult> _items = new();

		public void Report(IisInstallStepResult value) => _items.Add(value);

		public List<IisInstallStepId> ReportedIds()
		{
			List<IisInstallStepId> ids = new(_items.Count);
			foreach (IisInstallStepResult item in _items)
			{
				ids.Add(item.Id);
			}

			return ids;
		}

		public List<IisStepOutcome> FinalOutcomes()
		{
			List<IisStepOutcome> outcomes = new(_items.Count);
			foreach (IisInstallStepResult item in _items)
			{
				outcomes.Add(item.Outcome);
			}

			return outcomes;
		}
	}

	private sealed class ThrowingProgress : IProgress<IisInstallStepResult>
	{
		public void Report(IisInstallStepResult value) => throw new InvalidOperationException("window is gone");
	}

	private sealed class FakePlatformProbe : IIisPlatformProbe
	{
		private readonly bool? _installed;
		private readonly bool? _w3svc;
		private readonly bool? _installedAfterInstall;
		private readonly bool? _w3svcAfterInstall;

		internal FakePlatformProbe(
			bool? installed,
			bool? w3svc,
			bool? installedAfterInstall = null,
			bool? w3svcAfterInstall = null)
		{
			_installed = installed;
			_w3svc = w3svc;
			_installedAfterInstall = installedAfterInstall;
			_w3svcAfterInstall = w3svcAfterInstall;
		}

		public int InstalledCalls { get; private set; }

		public List<string> ServiceProbeNames { get; } = new();

		public string Provider => "FakePlatformProbe";

		// The worker reads the machine twice: to decide what to install, then to verify. A real
		// machine reports the feature as present once DISM has enabled it, so the second read is
		// modelled as the post-install state instead of repeating the pre-install one. Omitted
		// post-install values keep the old behaviour, so tests that install nothing are unaffected.
		public Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken)
		{
			InstalledCalls++;
			return Task.FromResult(InstalledCalls > 1
				? _installedAfterInstall ?? _installed
				: _installed);
		}

		public Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken)
		{
			ServiceProbeNames.Add(serviceName);
			return Task.FromResult(ServiceProbeNames.Count > 1
				? _w3svcAfterInstall ?? _w3svc
				: _w3svc);
		}
	}

	private sealed record DirectCall(string Label, string Executable, IReadOnlyList<string> Arguments);

	private sealed class FakeCommandRunner : IExternalCommandRunner
	{
		public List<DirectCall> DirectCalls { get; } = new();

		/// <summary>Per-label canned results; an unlisted label gets a generic success.</summary>
		public Dictionary<string, ExternalCommandResult> Results { get; } = new(StringComparer.Ordinal);

		public List<string> Labels()
		{
			List<string> labels = new(DirectCalls.Count);
			foreach (DirectCall call in DirectCalls)
			{
				labels.Add(call.Label);
			}

			return labels;
		}

		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout, CancellationToken ct)
			=> throw new NotSupportedException("The install workflow must use direct execution only.");

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel, string executable, IReadOnlyList<string> arguments,
			TimeSpan timeout, CancellationToken ct)
		{
			DirectCalls.Add(new DirectCall(commandLabel, executable, arguments));
			return Task.FromResult(Results.TryGetValue(commandLabel, out ExternalCommandResult? canned)
				? canned
				: new ExternalCommandResult(
					commandLabel, executable, 0, "The operation completed successfully.\r\n",
					string.Empty, TimedOut: false, TimeSpan.FromSeconds(8), EnglishConsoleMode: false));
		}
	}

	private sealed class FakeElevation
	{
		private readonly bool _elevated;

		internal FakeElevation(bool elevated)
		{
			_elevated = elevated;
		}

		public int Calls { get; private set; }

		public ElevationStatus Check()
		{
			Calls++;
			return _elevated
				? new ElevationStatus(true, "Process is running elevated (Administrators).")
				: new ElevationStatus(false, "Elevation required - run the Configurator as administrator.");
		}
	}
}
