// File:    src/RdpAudit.Configurator/Services/IisWebAccessWorkflowHost.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Production implementation of the Core contract IWebAccessWorkflowHost for the
//          Web Access tab. The Install IIS workflow is delegated to IisInstallService
//          (elevation-guarded, fail-closed, idempotent DISM); every run is recorded into
//          the canonical install-update transcript (%ProgramData%\RdpAudit\logs). The
//          Configure IIS workflow is delegated to IisConfigureService (plan Step 11) and is
//          recorded to the same transcript; a host built without a configure worker answers
//          a curated not-available line so the button never dead-ends. The contract forbids
//          exceptions crossing this boundary, so a transcript write failure is swallowed
//          (logging must never break the workflow) and an unexpected worker exception is
//          translated into the returned outcome line.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Services;

/// <summary>Production workflow host behind the Web Access tab's Install IIS / Configure IIS
/// buttons. Never throws to the caller.</summary>
public sealed class IisWebAccessWorkflowHost : IWebAccessWorkflowHost
{
	private readonly IisInstallService _installService;
	private readonly IisConfigureService? _configureService;
	private readonly ServiceLayoutInfo _layout;
	private readonly string _operation;

	public IisWebAccessWorkflowHost(
		IisInstallService installService,
		ServiceLayoutInfo layout,
		IisConfigureService? configureService = null)
	{
		_installService = installService ?? throw new ArgumentNullException(nameof(installService));
		_layout = layout ?? throw new ArgumentNullException(nameof(layout));
		_configureService = configureService;
		_operation = "iis-install";
	}

	/// <summary>Runs the Install IIS workflow, recording every plan item to the transcript, and
	/// returns the curated one-line status plus the per-item results the progress window paints.</summary>
	public async Task<IisInstallRunOutcome> RunInstallIisAsync(
		IProgress<IisInstallStepResult>? progress = null,
		CancellationToken ct = default)
	{
		try
		{
			IisInstallOutcome outcome = await _installService.RunAsync(progress, ct).ConfigureAwait(false);
			Record(outcome);
			return new IisInstallRunOutcome(
				ComposeInstall(outcome),
				outcome.ItemResults,
				outcome.Success,
				outcome.AlreadyInstalled);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// The operator cancelled the run: report that honestly instead of masquerading as a failure.
			return new IisInstallRunOutcome(
				"cancelled before completion.",
				Array.Empty<IisInstallStepResult>(),
				false,
				false);
		}
		catch (Exception ex)
		{
			return new IisInstallRunOutcome(
				"could not be completed: " + ex.Message,
				Array.Empty<IisInstallStepResult>(),
				false,
				false);
		}
	}

	/// <summary>Runs the Configure IIS workflow (plan Step 11) and returns the one-line outcome
	/// shown on the tab. A host built without a configure worker answers a curated line so the
	/// button never dead-ends.</summary>
	public async Task<string> RunConfigureIisAsync()
	{
		if (_configureService is null)
		{
			return "Configure IIS is not available in this build.";
		}

		try
		{
			IisConfigureOutcome outcome = await _configureService.RunAsync().ConfigureAwait(false);
			RecordConfigure(outcome);
			return ComposeConfigure(outcome);
		}
		catch (Exception ex)
		{
			return "could not be completed: " + ex.Message;
		}
	}

	/// <summary>Composes the curated one-line Install IIS outcome: success is the enabled state
	/// (or the already-installed state), warnings fold the reboot notice into the line, failures
	/// lead with the first actionable error.</summary>
	public static string ComposeInstall(IisInstallOutcome outcome)
	{
		if (outcome is null)
		{
			return "could not be completed.";
		}

		if (!outcome.Success)
		{
			return outcome.Errors.Count > 0
				? "could not be completed: " + outcome.Errors[0]
				: "could not be completed.";
		}

		if (outcome.AlreadyInstalled)
		{
			return "IIS role and W3SVC are already present - nothing to enable.";
		}

		return outcome.Warnings.Count > 0
			? "feature set enabled - a reboot is required before Configure IIS."
			: "feature set enabled.";
	}

	/// <summary>Composes the curated one-line Configure IIS outcome: success is the live web URL
	/// (with the first warning folded in), failures lead with the first actionable error.</summary>
	public static string ComposeConfigure(IisConfigureOutcome outcome)
	{
		if (outcome is null)
		{
			return "could not be completed.";
		}

		if (!outcome.Success)
		{
			return outcome.Errors.Count > 0
				? "could not be completed: " + outcome.Errors[0]
				: "could not be completed.";
		}

		string live = "web access is live at " + IisWebUiDefaults.HttpsUrl;
		return outcome.Warnings.Count > 0
			? live + " note: " + outcome.Warnings[0]
			: live;
	}

	private void Record(IisInstallOutcome outcome)
	{
		try
		{
			InstallUpdateLogger logger = new(_layout, _operation);
			logger.Info("Install IIS workflow started");
			foreach (string step in outcome.Steps)
			{
				logger.Info(step);
			}

			foreach (string warning in outcome.Warnings)
			{
				logger.Warn(warning);
			}

			foreach (string error in outcome.Errors)
			{
				logger.Fail(error);
			}

			logger.Info(outcome.Success
				? "Install IIS workflow finished - verdict: OK"
				: "Install IIS workflow finished - verdict: see error list");
		}
		catch (Exception)
		{
			// Transcript failure must never surface or break the workflow.
		}
	}

	private void RecordConfigure(IisConfigureOutcome outcome)
	{
		try
		{
			InstallUpdateLogger logger = new(_layout, "iis-configure");
			logger.Info("Configure IIS workflow started");
			foreach (string step in outcome.Steps)
			{
				logger.Info(step);
			}

			foreach (string note in outcome.IdempotentNotes)
			{
				logger.Info(note);
			}

			foreach (string warning in outcome.Warnings)
			{
				logger.Warn(warning);
			}

			foreach (string error in outcome.Errors)
			{
				logger.Fail(error);
			}

			logger.Info(outcome.Success
				? "Configure IIS workflow finished - verdict: OK"
				: "Configure IIS workflow finished - verdict: see error list");
		}
		catch (Exception)
		{
			// Transcript failure must never surface or break the workflow.
		}
	}
}
