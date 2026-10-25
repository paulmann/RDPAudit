// File:    src/RdpAudit.Core/WebUi/IisInstallPlan.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: The operator-visible plan behind the Web Access "Install IIS" action: the ordered list of
//          items that will be installed or verified, and the per-item result shapes the progress
//          window paints as tick / cross. The plan is the SINGLE source of truth for both halves of
//          the workflow - what the dialog lists before the run and what the workflow executes - so
//          the displayed list can never drift from what is actually done (the same discipline the
//          command builders already follow, IisInstallCommandSet.cs:105-109).
//
//          Order matters and is deliberate:
//            1. the static IIS feature set (DISM), which also brings the IIS management tools the
//               Configure IIS workflow needs for its appcmd.exe calls;
//            2. the ASP.NET Core Hosting Bundle, because the published application is hosted
//               in-process and IIS refuses a request without the native AspNetCoreModuleV2;
//            3. verification of what is on the machine after all installers finished.
//
//          Nothing in this file executes a command or changes system state.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;

namespace RdpAudit.Core.WebUi;

/// <summary>Stable identity of one install-plan item. Ordinals are NOT persisted anywhere; the
/// sequence exists only so the UI and the workflow agree on which row is being reported.</summary>
public enum IisInstallStepId
{
	/// <summary>Administrator rights are required before anything can be installed.</summary>
	Elevation = 0,

	/// <summary>The DISM feature set that turns the machine into an IIS static server.</summary>
	IisFeatures = 1,

	/// <summary>The IIS management tools (appcmd.exe), without which Configure IIS cannot run.</summary>
	IisManagementTools = 2,

	/// <summary>The ASP.NET Core Hosting Bundle, which carries the native ASP.NET Core Module v2.</summary>
	HostingBundle = 3,

	/// <summary>Post-install verification: the module is on disk, W3SVC and the IIS role exist.</summary>
	Verification = 4,
}

/// <summary>Outcome of one install-plan item as the progress window paints it.</summary>
public enum IisStepOutcome
{
	/// <summary>Not started yet - the row shows a neutral marker.</summary>
	Pending = 0,

	/// <summary>Currently running - the row shows an in-progress marker.</summary>
	Running = 1,

	/// <summary>Completed successfully - the row shows a tick.</summary>
	Ok = 2,

	/// <summary>Completed with a caveat the operator must know (e.g. a reboot is required).</summary>
	Warning = 3,

	/// <summary>Failed - the row shows a cross and the detail names the reason.</summary>
	Failed = 4,

	/// <summary>Deliberately not attempted (already satisfied, or a predecessor failed).</summary>
	Skipped = 5,
}

/// <summary>One line of the install plan shown in the progress window, paired with its result.</summary>
/// <param name="Id">Which plan item this row is.</param>
/// <param name="Title">Operator-readable item name.</param>
/// <param name="Detail">What the item does or why it ended the way it did. Never raw tool output -
/// it is bounded by the caller, exactly like <c>ExternalCommandResult.BuildDiagnosticSummary</c>.</param>
/// <param name="Outcome">Current state of this row.</param>
public sealed record IisInstallStepResult(
	IisInstallStepId Id,
	string Title,
	string Detail,
	IisStepOutcome Outcome);

/// <summary>The ordered plan the Install IIS action executes and reports.</summary>
public static class IisInstallPlan
{
	/// <summary>Titles in execution order. The workflow reports results in this order and the
	/// progress window renders them in this order, so a row can never be shown for a step the
	/// workflow does not run.</summary>
	public static IReadOnlyList<IisInstallStepId> OrderedStepIds { get; } = new[]
	{
		IisInstallStepId.Elevation,
		IisInstallStepId.IisFeatures,
		IisInstallStepId.IisManagementTools,
		IisInstallStepId.HostingBundle,
		IisInstallStepId.Verification,
	};

	/// <summary>Operator-readable title of one plan item.</summary>
	public static string TitleFor(IisInstallStepId id) => id switch
	{
		IisInstallStepId.Elevation => "Administrator rights",
		IisInstallStepId.IisFeatures => "IIS web server role and static content",
		IisInstallStepId.IisManagementTools => "IIS management tools (appcmd)",
		IisInstallStepId.HostingBundle => "ASP.NET Core Module v2 (Hosting Bundle)",
		IisInstallStepId.Verification => "Verify the installed components",
		_ => "Unknown step",
	};

	/// <summary>What the item installs, shown before the run so the operator knows what will happen.
	/// The feature names come from <see cref="IisFeatureCatalog"/> - the same catalog the DISM command
	/// is built from - so the preview cannot drift from the executed command.</summary>
	public static string DescriptionFor(IisInstallStepId id) => id switch
	{
		IisInstallStepId.Elevation =>
			"DISM feature enablement and the bundle installer both require an elevated Configurator.",
		IisInstallStepId.IisFeatures =>
			"dism /Online /Enable-Feature with /NoRestart: " + string.Join(", ", IisFeatureCatalog.DismFeatures) + ".",
		IisInstallStepId.IisManagementTools =>
			"dism /Online /Enable-Feature with /NoRestart: "
				+ string.Join(", ", IisFeatureCatalog.DismManagementFeatures)
			+ ". They provide appcmd.exe, which the Configure IIS step uses to inspect and register "
			+ "the IIS site.",
		IisInstallStepId.HostingBundle =>
			"winget install --id " + HostingBundlePackage.WingetPackageId
			+ " --exact --silent: the bundle carries the native " + HostingBundlePackage.ModuleName
			+ " module IIS needs for the in-process Dashboard.",
		IisInstallStepId.Verification =>
			"Checks the module binaries on disk and the IIS role / W3SVC service, and reports honestly "
			+ "what could not be confirmed.",
		_ => string.Empty,
	};

	/// <summary>Builds the plan in its initial, not-yet-started state.</summary>
	public static IReadOnlyList<IisInstallStepResult> CreatePendingSteps()
	{
		List<IisInstallStepResult> steps = new(OrderedStepIds.Count);
		foreach (IisInstallStepId id in OrderedStepIds)
		{
			steps.Add(new IisInstallStepResult(id, TitleFor(id), DescriptionFor(id), IisStepOutcome.Pending));
		}

		return steps;
	}

	/// <summary>Replaces one row, leaving the order intact. Pure helper so the workflow does not have
	/// to hand-roll list surgery for every step it reports.</summary>
	public static IReadOnlyList<IisInstallStepResult> WithResult(
		IReadOnlyList<IisInstallStepResult> steps,
		IisInstallStepId id,
		IisStepOutcome outcome,
		string detail)
	{
		ArgumentNullException.ThrowIfNull(steps);

		List<IisInstallStepResult> updated = new(steps.Count);
		foreach (IisInstallStepResult step in steps)
		{
			updated.Add(step.Id == id
				? step with { Outcome = outcome, Detail = detail }
				: step);
		}

		return updated;
	}
}
