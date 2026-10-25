// File:    tests/RdpAudit.Configurator.Tests/IisWebAccessWorkflowHostTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Step 10 verification for the production Web Access workflow host. The host must
//          translate an IisInstallOutcome into the curated one-line status shown on the tab
//          (never a raw multi-line transcript), must never leak an exception to the UI, and
//          must answer the pre-Step-11 Configure IIS button with a curated line. The success
//          / reboot-warning / already-installed / failure composure is exercised through
//          ComposeInstall on synthetic outcomes, so no real elevation, registry or DISM is
//          involved. The install transcript side effect is written under a temp layout path
//          and is not asserted here (the logger is deliberately best-effort; InstallUpdateLogger
//          is covered by its own tests).
// Depends: IisWebAccessWorkflowHost, IisInstallOutcome, ServiceLayoutInfo, xUnit

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class IisWebAccessWorkflowHostTests
{
	[Fact]
	public void ComposeInstall_Success_ReturnsEnabledLine()
	{
		IisInstallOutcome outcome = new(
			Success: true,
			Steps: new[] { "DISM enabled the IIS feature set." },
			Warnings: Array.Empty<string>(),
			Errors: Array.Empty<string>(),
			AlreadyInstalled: false);

		string line = IisWebAccessWorkflowHost.ComposeInstall(outcome);

		Assert.Contains("enabled", line, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("\n", line);
	}

	[Fact]
	public void ComposeInstall_AlreadyInstalled_ReturnsNothingToEnable()
	{
		IisInstallOutcome outcome = new(
			Success: true,
			Steps: new[] { "IIS role and W3SVC are already present." },
			Warnings: Array.Empty<string>(),
			Errors: Array.Empty<string>(),
			AlreadyInstalled: true);

		string line = IisWebAccessWorkflowHost.ComposeInstall(outcome);

		Assert.Contains("already present", line, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("nothing to enable", line, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void ComposeInstall_RebootWarning_FoldsRebootNoticeIntoTheLine()
	{
		IisInstallOutcome outcome = new(
			Success: true,
			Steps: new[] { "DISM enabled the IIS feature set (exit 3010)." },
			Warnings: new[] { "A reboot is required before Configure IIS." },
			Errors: Array.Empty<string>(),
			AlreadyInstalled: false);

		string line = IisWebAccessWorkflowHost.ComposeInstall(outcome);

		Assert.Contains("reboot", line, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("\n", line);
	}

	[Fact]
	public void ComposeInstall_Failure_LeadsWithFirstError()
	{
		IisInstallOutcome outcome = new(
			Success: false,
			Steps: Array.Empty<string>(),
			Warnings: Array.Empty<string>(),
			Errors: new[] { "First actionable error", "Second context detail" },
			AlreadyInstalled: false);

		string line = IisWebAccessWorkflowHost.ComposeInstall(outcome);

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("First actionable error", line, StringComparison.Ordinal);
		Assert.DoesNotContain("\n", line);
		Assert.DoesNotContain("Second context detail", line, StringComparison.Ordinal);
	}

	[Fact]
	public void ComposeInstall_NullOutcome_ReturnscouldNotBeCompleted()
	{
		string line = IisWebAccessWorkflowHost.ComposeInstall(null!);

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void ComposeInstall_NoErrors_StillReportsCompletionFailure()
	{
		IisInstallOutcome outcome = new(
			Success: false,
			Steps: Array.Empty<string>(),
			Warnings: Array.Empty<string>(),
			Errors: Array.Empty<string>(),
			AlreadyInstalled: false);

		string line = IisWebAccessWorkflowHost.ComposeInstall(outcome);

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void ComposeConfigure_Success_ReturnsLiveWebUrlLine()
	{
		IisConfigureOutcome outcome = new(
			Success: true,
			Steps: new[] { "Staged the web application." },
			Warnings: Array.Empty<string>(),
			Errors: Array.Empty<string>(),
			IdempotentNotes: Array.Empty<string>());

		string line = IisWebAccessWorkflowHost.ComposeConfigure(outcome);

		Assert.Contains("web access is live at " + RdpAudit.Core.WebUi.IisWebUiDefaults.HttpsUrl, line);
		Assert.DoesNotContain("\n", line);
	}

	[Fact]
	public void ComposeConfigure_SuccessWithWarning_FoldsFirstWarningIntoTheLine()
	{
		IisConfigureOutcome outcome = new(
			Success: true,
			Steps: new[] { "Generated a self-signed certificate." },
			Warnings: new[] { "A self-signed certificate was generated." },
			Errors: Array.Empty<string>(),
			IdempotentNotes: Array.Empty<string>());

		string line = IisWebAccessWorkflowHost.ComposeConfigure(outcome);

		Assert.Contains("web access is live at " + RdpAudit.Core.WebUi.IisWebUiDefaults.HttpsUrl, line);
		Assert.Contains("note:", line);
		Assert.Contains("self-signed certificate was generated", line);
		Assert.DoesNotContain("\n", line);
	}

	[Fact]
	public void ComposeConfigure_Failure_LeadsWithFirstError()
	{
		IisConfigureOutcome outcome = new(
			Success: false,
			Steps: Array.Empty<string>(),
			Warnings: Array.Empty<string>(),
			Errors: new[] { "First actionable error", "Second context detail" },
			IdempotentNotes: Array.Empty<string>());

		string line = IisWebAccessWorkflowHost.ComposeConfigure(outcome);

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("First actionable error", line, StringComparison.Ordinal);
		Assert.DoesNotContain("\n", line);
		Assert.DoesNotContain("Second context detail", line, StringComparison.Ordinal);
	}

	[Fact]
	public void ComposeConfigure_NullOutcome_ReturnscouldNotBeCompleted()
	{
		string line = IisWebAccessWorkflowHost.ComposeConfigure(null!);

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task RunConfigureIis_ReturnsCuratedNotAvailableLine()
	{
		ServiceLayoutInfo layout = BuildLayout();
		IisInstallService failing = BuildFailingInstallService();
		IisWebAccessWorkflowHost host = new(failing, layout);

		string line = await host.RunConfigureIisAsync();

		Assert.False(string.IsNullOrWhiteSpace(line));
		Assert.DoesNotContain("\n", line);
	}

	[Fact]
	public async Task RunInstallIis_WorkerException_IsTranslatedNeverThrown()
	{
		ServiceLayoutInfo layout = BuildLayout();
		IisInstallService failing = BuildFailingInstallService();
		IisWebAccessWorkflowHost host = new(failing, layout);

		string line = (await host.RunInstallIisAsync()).StatusLine;

		Assert.Contains("could not be completed", line, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Constructor_RequiresServiceAndLayout()
	{
		IisInstallService ok = BuildFailingInstallService();
		Assert.Throws<ArgumentNullException>(() => new IisWebAccessWorkflowHost(null!, BuildLayout()));
		Assert.Throws<ArgumentNullException>(() => new IisWebAccessWorkflowHost(ok, null!));
	}

	private static IisInstallService BuildFailingInstallService()
		=> new(
			new StaticPlatformProbe(),
			new StaticRunner(),
			() => new ElevationStatus(true, "Process is running elevated (Administrators)."));

	private static ServiceLayoutInfo BuildLayout()
	{
		string temp = Path.Combine(Path.GetTempPath(), "rdpaudit-iis-workflow-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(temp);
		return new ServiceLayoutInfo(
			ConfiguratorDirectory: temp,
			DistributionDirectory: temp,
			DistributionExists: true,
			ExpectedServiceExecutable: Path.Combine(temp, ServiceLayout.ServiceExeName),
			ServiceExecutableExists: false,
			InstallDirectory: temp,
			ProgramDataDirectory: temp,
			AppSettingsPath: Path.Combine(temp, "appsettings.json"),
			DefaultDatabasePath: Path.Combine(temp, "rdpaudit.db"));
	}

	private sealed class StaticPlatformProbe : RdpAudit.Core.WebUi.IIisPlatformProbe
	{
		public string Provider => "StaticPlatformProbe";

		public Task<bool?> IsIisInstalledAsync(System.Threading.CancellationToken cancellationToken)
			=> Task.FromResult<bool?>(false);

		public Task<bool?> ServiceExistsAsync(string serviceName, System.Threading.CancellationToken cancellationToken)
			=> Task.FromResult<bool?>(false);
	}

	private sealed class StaticRunner : IExternalCommandRunner
	{
		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout,
			System.Threading.CancellationToken ct)
			=> throw new NotSupportedException();

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel, string executable, IReadOnlyList<string> arguments,
			TimeSpan timeout, System.Threading.CancellationToken ct)
			=> throw new NotSupportedException();
	}
}

/// <summary>The Install IIS run contract added for the per-item progress window: the run returns one
/// row per plan item and the status line the tab shows, and it reports the same rows through the
/// progress sink.</summary>
public sealed class IisInstallRunContractTests
{
	[Fact]
	public void RunOutcome_CarriesEveryPlanRowAndTheCuratedLine()
	{
		IReadOnlyList<IisInstallStepResult> rows = IisInstallPlan.CreatePendingSteps();

		IisInstallRunOutcome outcome = new("feature set enabled.", rows, Success: true, AlreadyInstalled: false);

		Assert.Equal(IisInstallPlan.OrderedStepIds.Count, outcome.ItemResults.Count);
		Assert.True(outcome.Success);
		Assert.False(outcome.AlreadyInstalled);
		Assert.DoesNotContain("\n", outcome.StatusLine);
	}

	[Fact]
	public void InstallPlan_OrdersElevationFirstAndVerificationLast()
	{
		IReadOnlyList<IisInstallStepId> ids = IisInstallPlan.OrderedStepIds;

		Assert.Equal(IisInstallStepId.Elevation, ids[0]);
		Assert.Equal(IisInstallStepId.Verification, ids[ids.Count - 1]);

		// The management tools and the Hosting Bundle row must both exist: those are exactly the
		// components a machine that only ever ran the old installer was missing.
		Assert.Contains(IisInstallStepId.IisManagementTools, ids);
		Assert.Contains(IisInstallStepId.HostingBundle, ids);
	}

	[Fact]
	public void InstallPlan_HostingBundleDescriptionNamesTheWingetPackageAndModule()
	{
		string detail = IisInstallPlan.DescriptionFor(IisInstallStepId.HostingBundle);

		Assert.Contains(HostingBundlePackage.WingetPackageId, detail, StringComparison.Ordinal);
		Assert.Contains(HostingBundlePackage.ModuleName, detail, StringComparison.Ordinal);
	}
}
