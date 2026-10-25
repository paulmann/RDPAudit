// File:    tests/RdpAudit.Configurator.Tests/IisConfigureServiceTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Step 11 verification for the Configure IIS workflow (IisConfigureService). The worker
//          is elevation-guarded, fail-closed, idempotent on a repeat run and routes every command
//          through the central runner with the canonical argument vectors. Tests inject a fake
//          platform probe (IIS installed + W3SVC present), a fake command runner keyed by command
//          label, a deterministic certificate source, elevation check, vault and stager factories,
//          and assert the actual interactions (command labels, argument vectors, DIDN'T-run
//          guarantees on early refusals, final on-disk states of both appsettings surfaces) rather
//          than merely exercising the path. The scenario test walks the production workflow host
//          from the Install IIS outcome to the Configure IIS outcome and asserts the live-URL line,
//          giving the plan's install->configure->open sequence a UI-level regression guard.
//          No test touches the real %ProgramData%, DISM, appcmd, netsh, sc or the machine
//          certificate store: every path is rooted under a temp folder.
// Depends: IisConfigureService, IisConfigureCommandSet, IisWebAccessWorkflowHost, IisInstallService,
//          WebTokenVault, WebUiAppStager, WebUiAppSettingsEditor, ExternalCommandResult, xUnit

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class IisConfigureServiceTests
{
	private const string KnownThumbprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678";

	[Fact]
	public async Task Run_NotElevated_RefusesWithoutProbingOrCommands()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true, elevated: false);

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		string error = Assert.Single(outcome.Errors);
		Assert.Contains("administrator", error, StringComparison.OrdinalIgnoreCase);
		Assert.Empty(context.Runner.DirectCalls);
		Assert.Equal(0, context.Platform.InstalledCalls);
		Assert.Empty(context.Platform.ServiceProbeNames);
	}

	[Fact]
	public async Task Run_IisNotInstalled_ReportsInstallFirstGuidance()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true, iisInstalled: false);

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		string error = Assert.Single(outcome.Errors);
		Assert.Contains("Install IIS first", error, StringComparison.OrdinalIgnoreCase);
		Assert.Empty(context.Runner.DirectCalls);
		Assert.Equal(1, context.Platform.InstalledCalls);
		Assert.Contains(WindowsIisPlatformProbe.W3SvcServiceName, context.Platform.ServiceProbeNames);
	}

	[Fact]
	public async Task Run_W3SvcUndetermined_RefusesWithoutCommands()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true, w3svc: null);

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Contains(outcome.Errors, e => e.Contains("World Wide Web", StringComparison.OrdinalIgnoreCase));
		Assert.Empty(context.Runner.DirectCalls);
	}

	[Fact]
	public async Task Run_AncmMissing_RefusesBeforeAnySiteWork()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true);
		context.Runner.SetResult("appcmd list modules (ANCM check)", BuildSuccess(string.Empty));

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		string error = Assert.Single(outcome.Errors);
		Assert.Contains("ASP.NET Core Module", error, StringComparison.Ordinal);
		// The refusal happens before any site / pool / service command.
		Assert.DoesNotContain(context.Runner.DirectCalls, c => c.Label.StartsWith("IIS site", StringComparison.Ordinal));
		Assert.DoesNotContain(context.Runner.DirectCalls, c => c.Label.StartsWith("IIS app pool", StringComparison.Ordinal));
		Assert.DoesNotContain(context.Runner.DirectCalls, c => c.Label.StartsWith("RdpAuditService", StringComparison.Ordinal));
	}

	[Fact]
	public async Task Run_CertificateGenerationFails_ReportsCuratedError()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: false);
		context.Runner.SetResult(
			"New-SelfSignedCertificate (web site)",
			new ExternalCommandResult(
				"New-SelfSignedCertificate (web site)",
				WebUiSelfSignedCertificateCommandSet.PowerShellExecutable,
				1,
				string.Empty,
				"New-SelfSignedCertificate: access denied",
				TimedOut: false,
				TimeSpan.FromSeconds(2),
				EnglishConsoleMode: false));

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		string error = Assert.Single(outcome.Errors);
		Assert.Contains("could not be generated", error, StringComparison.Ordinal);
		Assert.Contains("exit=1", error, StringComparison.Ordinal);
		Assert.DoesNotContain("\n", error);
		Assert.DoesNotContain("IIS site add", context.Runner.Labels);
	}

	[Fact]
	public async Task Run_SelfSignedCertGenerated_RecordsTrustWarningAndSucceeds()
	{
		(BuildContext context, RdpAuditPaths paths, string publishRoot, _) = BuildFullContext(
			certificateAfterGeneration: new WebUiCertificateInfo(KnownThumbprint, SelfSigned: true));

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.True(outcome.Success);
		Assert.Contains(outcome.Warnings, w => w.Contains("self-signed certificate", StringComparison.OrdinalIgnoreCase));
		Assert.Contains(outcome.Steps, s => s.Contains("Generated a self-signed certificate", StringComparison.Ordinal));
		DirectCall generation = Assert.Single(context.Runner.DirectCalls, c => c.Label == "New-SelfSignedCertificate (web site)");
		Assert.Equal(WebUiSelfSignedCertificateCommandSet.BuildNewSelfSignedCertificateArguments(), generation.Arguments);
		Assert.True(File.Exists(Path.Combine(publishRoot, "web.config")));
		Assert.True(File.Exists(paths.WebUiTokenPath));
	}

	[Fact]
	public async Task Run_SslReservationAddFails_IsFailClosedBeforeSiteStart()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true);
		context.Runner.SetResult(
			"HTTP.sys SSL reservation add",
			new ExternalCommandResult(
				"HTTP.sys SSL reservation add",
				IisConfigureCommandSet.NetshExecutable,
				5,
				string.Empty,
				"access denied",
				TimedOut: false,
				TimeSpan.FromSeconds(1),
				EnglishConsoleMode: false));

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Contains(outcome.Errors, e => e.Contains("reservation", StringComparison.OrdinalIgnoreCase)
			&& e.Contains("could not be created", StringComparison.OrdinalIgnoreCase));
		Assert.DoesNotContain("IIS site start", context.Runner.Labels);
		Assert.DoesNotContain("RdpAuditService start", context.Runner.Labels);
	}

	[Fact]
	public async Task Run_FinalConfirmationMissingSite_ReportsVerificationFailure()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true);
		context.Runner.SetResult("IIS site confirm", BuildSuccess(string.Empty));

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Contains(outcome.Errors, e => e.Contains("Final verification failed", StringComparison.Ordinal));
	}

	[Fact]
	public async Task Run_StageRefused_ReportsStagerFailure()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true, publishWithoutWebConfig: true);

		IisConfigureOutcome outcome = await context.Service.RunAsync();

		Assert.False(outcome.Success);
		Assert.Contains(outcome.Errors, e => e.Contains("web.config", StringComparison.Ordinal));
		Assert.Contains(outcome.Errors, e => e.Contains("staged", StringComparison.OrdinalIgnoreCase)
			|| e.Contains("web application output", StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public async Task RunAsync_PreCancelled_ThrowsOperationCanceledOnly()
	{
		(BuildContext context, _, _, _) = BuildFullContext(certificateFound: true);
		using CancellationTokenSource cts = new();
		cts.Cancel();

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Service.RunAsync(cts.Token));

		Assert.Empty(context.Runner.DirectCalls);
		Assert.Equal(0, context.Platform.InstalledCalls);
	}

	[Fact]
	public async Task Run_HappyPath_WritesBothSettingsSurfacesAndReportsComplete()
	{
		(BuildContext context, RdpAuditPaths paths, _, IisConfigureService service) =
			BuildFullContext(certificateFound: true);

		IisConfigureOutcome outcome = await service.RunAsync();

		Assert.True(outcome.Success);
		Assert.Empty(outcome.Errors);
		Assert.Contains(outcome.Steps, s => s.Contains("Final verification passed", StringComparison.Ordinal));

		DirectCall reservationAdd = Assert.Single(
			context.Runner.DirectCalls, c => c.Label == "HTTP.sys SSL reservation add");
		Assert.Equal(IisConfigureCommandSet.BuildNetshAddSslCertArguments(KnownThumbprint), reservationAdd.Arguments);

		DirectCall serviceStop = Assert.Single(
			context.Runner.DirectCalls, c => c.Label == "RdpAuditService stop");
		Assert.Equal(IisConfigureCommandSet.ScExecutable, serviceStop.Executable);
		Assert.Equal(IisConfigureCommandSet.BuildScStopServiceArguments(InstallationService.ServiceName), serviceStop.Arguments);
		DirectCall serviceStart = Assert.Single(
			context.Runner.DirectCalls, c => c.Label == "RdpAuditService start");
		Assert.Equal(IisConfigureCommandSet.BuildScStartServiceArguments(InstallationService.ServiceName), serviceStart.Arguments);

		DirectCall siteAdd = Assert.Single(context.Runner.DirectCalls, c => c.Label == "IIS site add");
		Assert.Equal(IisConfigureCommandSet.BuildAddSiteArguments(paths.WebUiDirectory), siteAdd.Arguments);

		JsonObject api = ReadSettingsSection(paths.AppSettingsPath, "RdpAudit", "Api");
		Assert.True(api["Enabled"]!.GetValue<bool>());
		string token = api["Token"]!.GetValue<string>();
		Assert.True(ProtectedEnvelope.IsEnvelope(token));

		JsonObject proxy = ReadSettingsSection(
			Path.Combine(paths.WebUiDirectory, RdpAuditPaths.AppSettingsFileName), "WebUiProxy");
		Assert.Equal("https://127.0.0.1:8443", proxy["BackendBaseUrl"]!.GetValue<string>());
		Assert.False(proxy["AllowInlineScripts"]!.GetValue<bool>());
		Assert.Null(proxy["BackendCertificateThumbprint"]);

		Assert.True(File.Exists(Path.Combine(paths.WebUiDirectory, "web.config")));
		Assert.True(File.Exists(Path.Combine(paths.WebUiDirectory, "wwwroot", "index.html")));
		Assert.True(File.Exists(Path.Combine(paths.WebUiDirectory, WebUiAppStager.AppManifestFileName)));
	}

	[Fact]
	public async Task Run_SecondRun_IsIdempotentAndReusesSitePoolAndToken()
	{
		(BuildContext context, RdpAuditPaths paths, _, IisConfigureService service) =
			BuildFullContext(certificateFound: true);

		IisConfigureOutcome first = await service.RunAsync();
		Assert.True(first.Success);

		(BuildContext second, _, _, IisConfigureService secondService) =
			BuildFullContext(certificateFound: true, existingRoot: context.Root);
		second.Runner.SetResult(
			"IIS site list", BuildSuccess("SITE \"RdpAuditWebUi\" (id:1,bindings:https/127.0.0.1:443:,state:Started)\r\n"));
		second.Runner.SetResult(
			"IIS app pool list", BuildSuccess("APPPOOL \"RdpAuditWebUi\" (MgdVersion:v4.0,state:Started)\r\n"));
		second.Runner.SetResult(
			"IIS site confirm", BuildSuccess("SITE \"RdpAuditWebUi\" (id:1,bindings:https/127.0.0.1:443:,state:Started)\r\n"));

		IisConfigureOutcome secondRun = await secondService.RunAsync();

		Assert.True(secondRun.Success);
		Assert.Contains(secondRun.Steps, s => s.Contains("Updated the IIS site physical path", StringComparison.Ordinal));
		Assert.Contains(secondRun.Steps, s => s.Contains("Updated the dedicated IIS application pool.", StringComparison.Ordinal));
		Assert.Contains(secondRun.Steps, s => s.Contains("Reusing the existing shared web-UI token", StringComparison.Ordinal));
		Assert.Contains(second.Runner.DirectCalls, c => c.Label == "IIS site update");
		Assert.Contains(second.Runner.DirectCalls, c => c.Label == "IIS app pool update");
		Assert.DoesNotContain(second.Runner.DirectCalls, c => c.Label == "IIS site add");
		Assert.DoesNotContain(second.Runner.DirectCalls, c => c.Label == "IIS app pool add");

		// Both runs must land on the same final artifact set.
		Assert.True(File.Exists(Path.Combine(paths.WebUiDirectory, "wwwroot", "index.html")));
		Assert.True(File.Exists(paths.WebUiTokenPath));
	}

	[Fact]
	public async Task Scenario_InstallThenConfigure_ReportsLiveWebAccess()
	{
		string temp = CreateRoot("scenario");
		RdpAuditPaths paths = new(temp);

		// Install IIS is driven by fakes only: without an injected module probe and appcmd path the
		// worker inspects the real machine, so the asserted line would depend on whether this build
		// host happens to have the Hosting Bundle and the IIS management tools installed.
		string appCmdPath = Path.Combine(temp, "appcmd.exe");
		File.WriteAllText(appCmdPath, string.Empty);

		ConfigureFakeRunner installRunner = new();
		IisInstallService install = new(
			new StaticPlatformProbe(installed: true, w3svc: true),
			installRunner,
			new FakeElevation(elevated: true).Check,
			dismTimeout: null,
			moduleProbe: new AspNetCoreModuleProbe("C:\\rdpaudit-test-inetsrv", _ => true),
			appCmdExecutablePath: appCmdPath);

		(BuildContext context, _, _, IisConfigureService configure) = BuildFullContext(
			certificateFound: true,
			existingRoot: temp);
		ServiceLayoutInfo layout = BuildLayout(temp);
		IisWebAccessWorkflowHost host = new(install, layout, configure);

		string installLine = (await host.RunInstallIisAsync()).StatusLine;
		string configureLine = await host.RunConfigureIisAsync();

		Assert.Contains("already present", installLine, StringComparison.OrdinalIgnoreCase);
		Assert.Empty(installRunner.DirectCalls);
		Assert.Contains(
			"web access is live at " + IisWebUiDefaults.HttpsUrl,
			configureLine,
			StringComparison.OrdinalIgnoreCase);
		Assert.True(File.Exists(Path.Combine(paths.WebUiDirectory, "wwwroot", "index.html")));
		Assert.True(File.Exists(paths.AppSettingsPath));
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Helpers
	// ─────────────────────────────────────────────────────────────────────────

	private sealed class StaticPlatformProbe : IIisPlatformProbe
	{
		private readonly bool? _installed;
		private readonly bool? _w3svc;

		internal StaticPlatformProbe(bool? installed, bool? w3svc)
		{
			_installed = installed;
			_w3svc = w3svc;
		}

		public string Provider => "StaticPlatformProbe";

		public int InstalledCalls { get; private set; }

		public List<string> ServiceProbeNames { get; } = new();

		public Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken)
		{
			InstalledCalls++;
			return Task.FromResult(_installed);
		}

		public Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken)
		{
			ServiceProbeNames.Add(serviceName);
			return Task.FromResult(_w3svc);
		}
	}

	private sealed class FakeElevation
	{
		private readonly bool _elevated;

		internal FakeElevation(bool elevated)
		{
			_elevated = elevated;
		}

		public ElevationStatus Check() => _elevated
			? new ElevationStatus(true, "Process is running elevated (Administrators).")
			: new ElevationStatus(false, "Elevation required - run the Configurator as administrator.");
	}

	private sealed record DirectCall(string Label, string Executable, IReadOnlyList<string> Arguments);

	private sealed class ConfigureFakeRunner : IExternalCommandRunner
	{
		private readonly Dictionary<string, ExternalCommandResult> _results = new(StringComparer.Ordinal);

		public List<DirectCall> DirectCalls { get; } = new();

		public IEnumerable<string> Labels => DirectCalls.Select(c => c.Label);

		public void SetResult(string label, ExternalCommandResult result) => _results[label] = result;

		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout, CancellationToken ct)
			=> throw new NotSupportedException("The configure workflow must use direct execution only.");

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel, string executable, IReadOnlyList<string> arguments,
			TimeSpan timeout, CancellationToken ct)
		{
			DirectCalls.Add(new DirectCall(commandLabel, executable, arguments));
			return Task.FromResult(_results.TryGetValue(commandLabel, out ExternalCommandResult? known)
				? known
				: BuildSuccess(string.Empty));
		}
	}

	private sealed class StubCertificateSource : IWebUiCertificateSource
	{
		private readonly WebUiCertificateInfo? _default;
		private readonly Queue<WebUiCertificateInfo?> _sequence = new();

		internal StubCertificateSource(WebUiCertificateInfo? defaultValue)
		{
			_default = defaultValue;
		}

		internal void Enqueue(WebUiCertificateInfo? value) => _sequence.Enqueue(value);

		public WebUiCertificateInfo? FindUsableCertificate()
			=> _sequence.Count > 0 ? _sequence.Dequeue() : _default;
	}

	private sealed class BuildContext
	{
		public required string Root { get; init; }
		public required RdpAuditPaths Paths { get; init; }
		public required string PublishRoot { get; init; }
		public required StaticPlatformProbe Platform { get; init; }
		public required ConfigureFakeRunner Runner { get; init; }
		public required IisConfigureService Service { get; init; }

		/// <summary>Projects the context so tests can deconstruct it into the pieces they assert
		/// on: (context, paths, publish-root, service).</summary>
		public void Deconstruct(
			out BuildContext context,
			out RdpAuditPaths paths,
			out string publishRoot,
			out IisConfigureService service)
		{
			context = this;
			paths = Paths;
			publishRoot = PublishRoot;
			service = Service;
		}
	}

	/// <summary>
	/// Builds a fully wired service on a fresh temp root. <paramref name="existingRoot"/> reuses an
	/// already configured root (idempotency runs). <paramref name="certificateFound"/> seeds a
	/// pre-existing certificate; <paramref name="certificateAfterGeneration"/> simulates the
	/// generate-then-reread path of a missing certificate.
	/// </summary>
	private static BuildContext BuildFullContext(
		bool certificateFound = true,
		bool elevated = true,
		bool? iisInstalled = true,
		bool? w3svc = true,
		bool publishWithoutWebConfig = false,
		WebUiCertificateInfo? certificateAfterGeneration = null,
		string? existingRoot = null)
	{
		string root = existingRoot ?? CreateRoot("run");
		RdpAuditPaths paths = new(root);
		string publish = CreatePublishRoot(root, omitWebConfig: publishWithoutWebConfig);

		StaticPlatformProbe platform = new(iisInstalled, w3svc);
		ConfigureFakeRunner runner = BuildHappyRunner();

		StubCertificateSource certSource = new(
			certificateFound ? new WebUiCertificateInfo(KnownThumbprint, SelfSigned: false) : null);
		if (certificateAfterGeneration is not null)
		{
			certSource.Enqueue(null);
			certSource.Enqueue(certificateAfterGeneration);
		}

		InMemorySecretProtector protector = new();
		IisConfigureService service = new(
			platform,
			runner,
			certSource,
			protector,
			paths,
			paths.AppSettingsPath,
			publish,
			elevationCheck: new FakeElevation(elevated).Check,
			// No IIS pool identity in the unit-test sandbox: the vault hardens the folder for
			// SYSTEM + Administrators only, mirroring the supported no-pool setup.
			vaultFactory: p => new WebTokenVault(p, paths.WebUiTokenPath, webPoolIdentity: null),
			// Real stager without the pool ACL grant (the virtual pool account does not exist
			// off a real IIS host); hashing / manifest / stale-cleanup logic stays fully exercised.
			stagerFactory: p => new WebUiAppStager(p, webPoolIdentity: null));

		return new BuildContext
		{
			Root = root,
			Paths = paths,
			PublishRoot = publish,
			Platform = platform,
			Runner = runner,
			Service = service,
		};
	}

	private static ConfigureFakeRunner BuildHappyRunner()
	{
		ConfigureFakeRunner runner = new();
		runner.SetResult(
			"appcmd list modules (ANCM check)",
			BuildSuccess("MODULE \"AspNetCoreModuleV2\" (native,GlobalModules)\r\n"));
		runner.SetResult(
			"IIS site confirm",
			BuildSuccess("SITE \"RdpAuditWebUi\" (id:1,bindings:https/127.0.0.1:443:,state:Started)\r\n"));
		return runner;
	}

	private static ExternalCommandResult BuildSuccess(string stdout) => new(
		"stub",
		"stub.exe",
		0,
		stdout,
		string.Empty,
		TimedOut: false,
		TimeSpan.FromMilliseconds(1),
		EnglishConsoleMode: false);

	private static string CreateRoot(string tag)
	{
		string root = Path.Combine(Path.GetTempPath(), "rdpaudit-configure-" + tag + "-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(root);
		return root;
	}

	private static string CreatePublishRoot(string root, bool omitWebConfig = false)
	{
		string publish = Path.Combine(root, "publish-web");
		Directory.CreateDirectory(Path.Combine(publish, "wwwroot", "assets"));
		if (!omitWebConfig)
		{
			File.WriteAllText(Path.Combine(publish, "web.config"), "<configuration />\r\n");
		}

		File.WriteAllText(
			Path.Combine(publish, "wwwroot", "index.html"),
			"<html><head><title>RdpAudit Web Access</title></head><body></body></html>\r\n");
		File.WriteAllText(Path.Combine(publish, "wwwroot", "assets", "app.js"), "// stub\r\n");
		return publish;
	}

	private static JsonObject ReadSettingsSection(string path, params string[] sectionPath)
	{
		JsonNode? node = JsonNode.Parse(File.ReadAllText(path));
		Assert.NotNull(node);
		foreach (string segment in sectionPath)
		{
			node = node![segment];
			Assert.NotNull(node);
		}

		return node!.AsObject();
	}

	private static ServiceLayoutInfo BuildLayout(string root)
		=> new(
			ConfiguratorDirectory: root,
			DistributionDirectory: root,
			DistributionExists: true,
			ExpectedServiceExecutable: Path.Combine(root, ServiceLayout.ServiceExeName),
			ServiceExecutableExists: false,
			InstallDirectory: root,
			ProgramDataDirectory: root,
			AppSettingsPath: Path.Combine(root, "appsettings.json"),
			DefaultDatabasePath: Path.Combine(root, "rdpaudit.db"));
}
