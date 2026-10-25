// File:    src/RdpAudit.Configurator/Services/IisInstallService.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Worker behind the Web Access "Install IIS" button. Runs the ordered install plan
//          (IisInstallPlan) and reports one result per plan item, so the progress window can show a
//          tick / cross against every component the web dashboard needs:
//
//            1. elevation gate;
//            2. DISM enablement of the static-file IIS feature set;
//            3. DISM enablement of the IIS management tools (appcmd.exe), without which the
//               Configure IIS workflow cannot inspect or register the site at all;
//            4. the ASP.NET Core Hosting Bundle, which carries the native AspNetCoreModuleV2 that
//               in-process hosting of the published dashboard requires - no DISM feature provides it;
//            5. verification of what is actually on the machine afterwards.
//
//          Everything is routed through the central command runner and guarded by ElevationGuard.
//          Idempotent: an already satisfied item is reported Skipped and its installer is not run,
//          so winget never runs when the module is already present. Fail-closed: an undetermined
//          installation state produces a refusal outcome instead of a half-truth, a failed
//          prerequisite stops the items that depend on it, and a failed run surfaces its bounded
//          diagnostic summary (never raw multi-line tool output). Exit code 3010 (success + reboot
//          request) is surfaced as a warning; 740 (ERROR_ELEVATION_REQUIRED) is translated into an
//          actionable elevation message. Progress reporting is best-effort: a reporting failure can
//          never abort an installation that is already running.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of one Install IIS workflow run: curated step lines, warnings (e.g. reboot
/// required) and errors. Never contains raw tool transcripts. <see cref="ItemResults"/> carries the
/// same run as one structured row per plan item, which is what the progress window renders.</summary>
public sealed record IisInstallOutcome(
	bool Success,
	IReadOnlyList<string> Steps,
	IReadOnlyList<string> Warnings,
	IReadOnlyList<string> Errors,
	bool AlreadyInstalled)
{
	/// <summary>Per-item results in plan order. Empty for outcomes built before the plan existed (the
	/// composed-line tests construct such outcomes), which keeps callers that only read the curated
	/// lines working unchanged.</summary>
	public IReadOnlyList<IisInstallStepResult> ItemResults { get; init; } = Array.Empty<IisInstallStepResult>();
}

/// <summary>Fail-closed, idempotent installer for the components the Web Access dashboard needs:
/// the IIS feature set, the IIS management tools and the ASP.NET Core Hosting Bundle.</summary>
[SupportedOSPlatform("windows")]
public sealed class IisInstallService
{
	/// <summary>DISM hard timeout for one /Enable-Feature run. Feature enablement can take
	/// several minutes on a cold Windows image, so the cap is deliberately generous.</summary>
	public static readonly TimeSpan DefaultDismTimeout = TimeSpan.FromMinutes(15);

	/// <summary>DISM exit code meaning success with a reboot requested.</summary>
	public const int DismSuccessRebootRequired = 3010;

	/// <summary>DISM exit code meaning the calling process lacks elevation (740).</summary>
	public const int DismErrorElevationRequired = 740;

	private const string StaticFeaturesCommandLabel = "DISM IIS feature install";
	private const string ManagementToolsCommandLabel = "DISM IIS management tools install";

	private readonly IIisPlatformProbe _platform;
	private readonly IExternalCommandRunner _runner;
	private readonly Func<ElevationStatus> _elevationCheck;
	private readonly AspNetCoreModuleProbe _moduleProbe;
	private readonly string _appCmdExecutablePath;
	private readonly TimeSpan _dismTimeout;
	private readonly TimeSpan _bundleTimeout;

	public IisInstallService(
		IIisPlatformProbe platform,
		IExternalCommandRunner runner,
		Func<ElevationStatus>? elevationCheck = null,
		TimeSpan? dismTimeout = null,
		AspNetCoreModuleProbe? moduleProbe = null,
		string? appCmdExecutablePath = null,
		TimeSpan? bundleTimeout = null)
	{
		_platform = platform ?? throw new ArgumentNullException(nameof(platform));
		_runner = runner ?? throw new ArgumentNullException(nameof(runner));
		_elevationCheck = elevationCheck ?? ElevationGuard.Check;
		_dismTimeout = dismTimeout ?? DefaultDismTimeout;
		_moduleProbe = moduleProbe ?? new AspNetCoreModuleProbe();
		_appCmdExecutablePath = appCmdExecutablePath ?? IisConfigureCommandSet.ResolveAppCmdExecutable();
		_bundleTimeout = bundleTimeout ?? HostingBundleCommandSet.DefaultInstallTimeout;
	}

	/// <summary>Runs the idempotent Install IIS workflow. Never throws except for external
	/// cancellation; every operational failure is reported through the returned outcome and through
	/// <paramref name="progress"/>, which receives one update per plan-item transition.</summary>
	public async Task<IisInstallOutcome> RunAsync(
		IProgress<IisInstallStepResult>? progress = null,
		CancellationToken ct = default)
	{
		List<string> steps = new();
		List<string> warnings = new();
		List<string> errors = new();
		InstallRun run = new(progress);

		ct.ThrowIfCancellationRequested();

		// ── 1. Elevation gate ────────────────────────────────────────────────────────────────────
		ElevationStatus elevation = _elevationCheck();
		if (!elevation.IsElevated)
		{
			run.Report(IisInstallStepId.Elevation, IisStepOutcome.Failed, elevation.Message);
			run.SkipRemaining(IisInstallStepId.Elevation, "Not attempted: administrator rights are required.");
			errors.Add(elevation.Message);
			return Outcome(run, success: false, steps, warnings, errors, alreadyInstalled: false);
		}

		run.Report(IisInstallStepId.Elevation, IisStepOutcome.Ok, elevation.Message);
		steps.Add(elevation.Message);

		bool? installed = await _platform.IsIisInstalledAsync(ct).ConfigureAwait(false);
		ct.ThrowIfCancellationRequested();
		bool? w3svc = await _platform
			.ServiceExistsAsync(WindowsIisPlatformProbe.W3SvcServiceName, ct)
			.ConfigureAwait(false);
		ct.ThrowIfCancellationRequested();

		if (!installed.HasValue || !w3svc.HasValue)
		{
			const string Undetermined =
				"The current IIS state could not be fully determined, so DISM was not invoked. "
				+ "Run the Configurator as administrator, refresh the Web Access status, and retry.";
			run.Report(IisInstallStepId.IisFeatures, IisStepOutcome.Failed, Undetermined);
			run.SkipRemaining(IisInstallStepId.IisFeatures, "Not attempted: the IIS state is undetermined.");
			errors.Add(Undetermined);
			return Outcome(run, success: false, steps, warnings, errors, alreadyInstalled: false);
		}

		// ── 2 and 3. IIS feature set and management tools ───────────────────────────────────────
		bool iisRolePresent = installed == true && w3svc == true;
		bool rebootRequested = false;

		if (iisRolePresent)
		{
			const string AlreadyPresent = "IIS role and W3SVC are already present; nothing to enable.";
			run.Report(IisInstallStepId.IisFeatures, IisStepOutcome.Skipped, AlreadyPresent);
			steps.Add(AlreadyPresent);
		}
		else
		{
			DismStepResult features = await RunDismStepAsync(
				StaticFeaturesCommandLabel, IisFeatureCatalog.DismFeatures, ct).ConfigureAwait(false);
			run.Report(IisInstallStepId.IisFeatures, features.Outcome, features.Detail);
			Collect(features.Outcome, features.StepText, features.Detail, steps, warnings, errors);
			rebootRequested |= features.RebootRequested;

			if (features.Outcome == IisStepOutcome.Failed)
			{
				run.SkipRemaining(IisInstallStepId.IisFeatures, "Not attempted: enabling the IIS feature set failed.");
				return Outcome(run, success: false, steps, warnings, errors, alreadyInstalled: false);
			}
		}

		if (AppCmdPresent())
		{
			run.Report(
				IisInstallStepId.IisManagementTools,
				IisStepOutcome.Ok,
				"appcmd.exe is available to the Configure IIS step.");
		}
		else
		{
			DismStepResult tools = await RunDismStepAsync(
				ManagementToolsCommandLabel, IisFeatureCatalog.DismManagementFeatures, ct).ConfigureAwait(false);
			run.Report(IisInstallStepId.IisManagementTools, tools.Outcome, tools.Detail);
			Collect(tools.Outcome, tools.StepText, tools.Detail, steps, warnings, errors);
			rebootRequested |= tools.RebootRequested;

			if (tools.Outcome == IisStepOutcome.Failed)
			{
				errors.Add(
					"The IIS management tools could not be enabled, so the Configure IIS step cannot run: "
					+ "it drives appcmd.exe. Resolve the DISM failure above and retry.");
				run.SkipRemaining(
					IisInstallStepId.IisManagementTools,
					"Not attempted: the IIS management tools could not be enabled.");
				return Outcome(run, success: false, steps, warnings, errors, alreadyInstalled: false);
			}
		}

		// ── 4. ASP.NET Core Hosting Bundle (native ANCM v2) ─────────────────────────────────────
		bool modulePresentBefore = _moduleProbe.IsModuleInstalled();
		bool bundleInstalledNow = false;

		if (modulePresentBefore)
		{
			run.Report(
				IisInstallStepId.HostingBundle,
				IisStepOutcome.Skipped,
				"ASP.NET Core Module v2 is already present (" + HostingBundlePackage.InProcessModuleFileName + ").");
			steps.Add("The ASP.NET Core Module v2 is already present; the Hosting Bundle was not installed.");
		}
		else
		{
			BundleStepResult bundle = await InstallHostingBundleAsync(ct).ConfigureAwait(false);
			run.Report(IisInstallStepId.HostingBundle, bundle.Outcome, bundle.Detail);
			Collect(bundle.Outcome, bundle.StepText, bundle.Detail, steps, warnings, errors);
			rebootRequested |= bundle.RebootRequested;
			bundleInstalledNow = bundle.Outcome is IisStepOutcome.Ok or IisStepOutcome.Warning;

			if (bundle.Outcome == IisStepOutcome.Failed)
			{
				errors.Add(
					"The ASP.NET Core Hosting Bundle could not be installed, so the Dashboard cannot be "
					+ "hosted by IIS yet. Install it (winget id " + HostingBundlePackage.WingetPackageId
					+ ") and retry Install IIS.");
				run.SkipRemaining(
					IisInstallStepId.HostingBundle,
					"Not attempted: the Hosting Bundle installation failed.");
				return Outcome(run, success: false, steps, warnings, errors, alreadyInstalled: false);
			}
		}

		// ── 5. Verification ─────────────────────────────────────────────────────────────────────
		IisStepOutcome verification = await VerifyAsync(run, rebootRequested, ct).ConfigureAwait(false);
		if (verification == IisStepOutcome.Ok)
		{
			steps.Add("Verification passed: IIS, W3SVC and the ASP.NET Core Module v2 are present.");
		}

		bool alreadyInstalled = iisRolePresent && !bundleInstalledNow && modulePresentBefore;
		bool success = verification != IisStepOutcome.Failed;
		return Outcome(run, success, steps, warnings, errors, alreadyInstalled);
	}

	/// <summary>Runs one DISM feature-enable step and maps its exit code onto a plan outcome. Never
	/// throws for an operational error.</summary>
	private async Task<DismStepResult> RunDismStepAsync(
		string commandLabel,
		IReadOnlyList<string> featureNames,
		CancellationToken ct)
	{
		IReadOnlyList<string> args = IisInstallCommandSet.BuildDismArguments(featureNames);

		ExternalCommandResult result;
		try
		{
			result = await _runner
				.RunDirectAsync(commandLabel, "dism.exe", args, _dismTimeout, ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new DismStepResult(
				IisStepOutcome.Failed,
				"DISM could not be started: " + ex.Message,
				RebootRequested: false,
				StepText: string.Empty);
		}

		if (result.TimedOut)
		{
			return new DismStepResult(
				IisStepOutcome.Failed,
				string.Format(
					CultureInfo.InvariantCulture,
					"DISM timed out after {0:0} seconds. The feature state is unknown; re-run Install IIS once DISM finishes.",
					_dismTimeout.TotalSeconds),
				RebootRequested: false,
				StepText: string.Empty);
		}

		if (result.ExitCode == DismSuccessRebootRequired)
		{
			return new DismStepResult(
				IisStepOutcome.Warning,
				"Enabled, but Windows requires a reboot before IIS can be configured.",
				RebootRequested: true,
				StepText: "DISM enabled the IIS feature set (exit 3010).");
		}

		if (result.ExitCode == DismErrorElevationRequired)
		{
			return new DismStepResult(
				IisStepOutcome.Failed,
				"DISM reported ERROR_ELEVATION_REQUIRED (740). Run the Configurator as administrator and retry.",
				RebootRequested: false,
				StepText: string.Empty);
		}

		if (result.ExitCode != 0)
		{
			return new DismStepResult(
				IisStepOutcome.Failed,
				"DISM failed to enable the IIS feature set. " + result.BuildDiagnosticSummary(),
				RebootRequested: false,
				StepText: string.Empty);
		}

		return new DismStepResult(
			IisStepOutcome.Ok,
			"Feature set enabled.",
			RebootRequested: false,
			StepText: "DISM enabled the IIS feature set.");
	}

	/// <summary>Installs the ASP.NET Core Hosting Bundle through winget (the channel install.ps1
	/// already uses) and confirms the native module afterwards. A successful installer that did not
	/// leave the module on disk is reported as a warning, not as success - a reboot may be pending.</summary>
	private async Task<BundleStepResult> InstallHostingBundleAsync(CancellationToken ct)
	{
		ExternalCommandResult result;
		try
		{
			result = await _runner
				.RunDirectAsync(
					HostingBundleCommandSet.InstallCommandLabel,
					HostingBundleCommandSet.WingetExecutable,
					HostingBundleCommandSet.BuildInstallArguments(),
					_bundleTimeout,
					ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new BundleStepResult(
				IisStepOutcome.Failed,
				"winget could not be started (" + ex.Message + "). Install the ASP.NET Core Hosting Bundle "
				+ "(winget id " + HostingBundlePackage.WingetPackageId + ") manually and retry.",
				RebootRequested: false,
				StepText: string.Empty);
		}

		if (result.TimedOut)
		{
			return new BundleStepResult(
				IisStepOutcome.Failed,
				string.Format(
					CultureInfo.InvariantCulture,
					"winget timed out after {0:0} seconds; the bundle state is unknown. Re-run Install IIS once it finishes.",
					_bundleTimeout.TotalSeconds),
				RebootRequested: false,
				StepText: string.Empty);
		}

		if (result.ExitCode != 0)
		{
			return new BundleStepResult(
				IisStepOutcome.Failed,
				"winget failed to install the ASP.NET Core Hosting Bundle. " + result.BuildDiagnosticSummary(),
				RebootRequested: false,
				StepText: string.Empty);
		}

		IReadOnlyList<string> missing = _moduleProbe.MissingFileNames();
		if (missing.Count > 0)
		{
			return new BundleStepResult(
				IisStepOutcome.Warning,
				"winget reported success, but the module files are not on disk yet (" + string.Join(", ", missing)
				+ "). A reboot may be required before IIS can load the module.",
				RebootRequested: true,
				StepText: "winget installed the ASP.NET Core Hosting Bundle (module binaries not yet on disk).");
		}

		return new BundleStepResult(
			IisStepOutcome.Ok,
			"Installed: " + HostingBundlePackage.ModuleName + " is now present.",
			RebootRequested: false,
			StepText: "winget installed the ASP.NET Core Hosting Bundle.");
	}

	/// <summary>Re-reads what is on the machine after the installers finished and reports honestly.
	/// An unconfirmed component is a warning, never a silent success: a reboot may be pending, and the
	/// operator must know before assuming the web access works.</summary>
	private async Task<IisStepOutcome> VerifyAsync(InstallRun run, bool rebootRequested, CancellationToken ct)
	{
		bool? installed = await _platform.IsIisInstalledAsync(ct).ConfigureAwait(false);
		bool? w3svc = await _platform
			.ServiceExistsAsync(WindowsIisPlatformProbe.W3SvcServiceName, ct)
			.ConfigureAwait(false);
		bool module = _moduleProbe.IsModuleInstalled();

		if (installed == true && w3svc == true && module)
		{
			run.Report(
				IisInstallStepId.Verification,
				IisStepOutcome.Ok,
				"IIS, W3SVC and the ASP.NET Core Module v2 are present.");
			return IisStepOutcome.Ok;
		}

		List<string> unconfirmed = new(3);
		if (installed != true)
		{
			unconfirmed.Add(installed.HasValue
				? "the IIS role was not confirmed"
				: "the IIS role could not be determined");
		}

		if (w3svc != true)
		{
			unconfirmed.Add(w3svc.HasValue ? "W3SVC was not confirmed" : "W3SVC could not be determined");
		}

		if (!module)
		{
			unconfirmed.Add("the ASP.NET Core Module v2 is not on disk");
		}

		// A pending reboot explains an unconfirmed IIS role or W3SVC - both come up after the restart.
		// It cannot explain a module that is not on disk at all: the Hosting Bundle lays its binaries
		// down immediately, so an installer that exited 0 without leaving them is a failure, never a
		// warning the operator may read as "done".
		bool rebootExplains = rebootRequested && module;
		string detail = string.Join("; ", unconfirmed) + ".";
		if (!module)
		{
			detail += " Install the ASP.NET Core Hosting Bundle (winget id "
				+ HostingBundlePackage.WingetPackageId + ") and retry Install IIS.";
		}
		else if (rebootExplains)
		{
			detail += " A reboot was requested, so this is expected to resolve after the restart.";
		}
		else
		{
			detail += " Resolve this before running Configure IIS.";
		}

		IisStepOutcome verdict = rebootExplains ? IisStepOutcome.Warning : IisStepOutcome.Failed;
		run.Report(IisInstallStepId.Verification, verdict, detail);
		return verdict;
	}

	private bool AppCmdPresent()
	{
		try
		{
			return File.Exists(_appCmdExecutablePath);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
			or ArgumentException or NotSupportedException)
		{
			// An unreadable location must never be reported as "the tools are installed".
			return false;
		}
	}

	private static void Collect(
		IisStepOutcome outcome,
		string stepText,
		string detail,
		List<string> steps,
		List<string> warnings,
		List<string> errors)
	{
		if (!string.IsNullOrEmpty(stepText))
		{
			steps.Add(stepText);
		}

		if (outcome == IisStepOutcome.Warning)
		{
			warnings.Add(detail);
		}
		else if (outcome == IisStepOutcome.Failed)
		{
			errors.Add(detail);
		}
	}

	private static IisInstallOutcome Outcome(
		InstallRun run,
		bool success,
		List<string> steps,
		List<string> warnings,
		List<string> errors,
		bool alreadyInstalled)
		=> new(success, steps, warnings, errors, alreadyInstalled) { ItemResults = run.Results };

	/// <summary>Outcome of one DISM feature-enable step.</summary>
	private sealed record DismStepResult(
		IisStepOutcome Outcome,
		string Detail,
		bool RebootRequested,
		string StepText);

	/// <summary>Outcome of the Hosting Bundle install step.</summary>
	private sealed record BundleStepResult(
		IisStepOutcome Outcome,
		string Detail,
		bool RebootRequested,
		string StepText);

	/// <summary>Tracks the plan rows of one run and forwards each transition to the progress sink.
	/// Reporting is best-effort by design: a UI callback that throws (for example because the window
	/// was closed mid-run) must never abort an installation that is already changing the machine.</summary>
	private sealed class InstallRun
	{
		private readonly IProgress<IisInstallStepResult>? _progress;
		private IReadOnlyList<IisInstallStepResult> _steps = IisInstallPlan.CreatePendingSteps();

		internal InstallRun(IProgress<IisInstallStepResult>? progress)
		{
			_progress = progress;
		}

		internal IReadOnlyList<IisInstallStepResult> Results => _steps;

		internal void Report(IisInstallStepId id, IisStepOutcome outcome, string detail)
		{
			_steps = IisInstallPlan.WithResult(_steps, id, outcome, detail);
			Publish(id);
		}

		/// <summary>Marks every still-pending item after <paramref name="after"/> as skipped, so the
		/// window never shows a row that quietly stays "waiting" while the run has already stopped.</summary>
		internal void SkipRemaining(IisInstallStepId after, string detail)
		{
			bool seen = false;
			foreach (IisInstallStepId id in IisInstallPlan.OrderedStepIds)
			{
				if (id == after)
				{
					seen = true;
					continue;
				}

				if (!seen || Find(id) is { Outcome: not IisStepOutcome.Pending })
				{
					continue;
				}

				Report(id, IisStepOutcome.Skipped, detail);
			}
		}

		private IisInstallStepResult? Find(IisInstallStepId id)
		{
			foreach (IisInstallStepResult step in _steps)
			{
				if (step.Id == id)
				{
					return step;
				}
			}

			return null;
		}

		private void Publish(IisInstallStepId id)
		{
			if (_progress is null || Find(id) is not { } row)
			{
				return;
			}

			try
			{
				_progress.Report(row);
			}
			catch (Exception)
			{
				// Reporting must never break an install that is already running.
			}
		}
	}
}
