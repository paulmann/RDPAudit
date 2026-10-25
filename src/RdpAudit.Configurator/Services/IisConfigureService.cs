// File:    src/RdpAudit.Configurator/Services/IisConfigureService.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Worker behind the Configurator "Configure IIS" button (plan Step 11, variant A).
//          Converts a machine that has IIS installed (Step 10) into a loopback-only HTTPS
//          dashboard host for the web UI:
//
//            1. Elevation and IIS/W3SVC gates, plus the ASP.NET Core Module v2 (ANCM)
//               presence check that in-process hosting hard-requires.
//            2. Resolves (or generates, self-signed with an explicit trust warning) the
//               certificate that TLS-serves https://127.0.0.1:443.
//            3. Prepares the shared web-UI bearer token in the DPAPI vault and enables the
//               service REST backend in %ProgramData%\RdpAudit\appsettings.json (the token is
//               written ONLY as a protected envelope).
//            4. Creates the RdpAuditWebUi IIS site and application pool (idempotent add-or-set),
//               stages the published RdpAudit.Web output with the pool identity read grant, and
//               writes the proxy settings (loopback backend URL, optional TLS pin) into the
//               staged web application settings.
//            5. Reserves the HTTPS certificate binding on the exact loopback literal
//               (delete-then-add, idempotent), starts the site, restarts the RdpAudit service
//               and verifies the converged result.
//
//          Never throws except for external cancellation; every operational failure is
//          reported through a curated outcome. Raw multi-line command output never reaches the
//          UI - only bounded diagnostic summaries, and the token plaintext is never logged.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of one Configure IIS workflow run: curated step lines, warnings (e.g.
/// self-signed certificate), errors and idempotency notes (e.g. benign 'already stopped').</summary>
public sealed record IisConfigureOutcome(
	bool Success,
	IReadOnlyList<string> Steps,
	IReadOnlyList<string> Warnings,
	IReadOnlyList<string> Errors,
	IReadOnlyList<string> IdempotentNotes);

/// <summary>Fail-closed, idempotent executor that turns an IIS-installed machine into the
/// loopback web-UI host of the plan.</summary>
[SupportedOSPlatform("windows")]
public sealed class IisConfigureService
{
	/// <summary>Hard timeout for appcmd / netsh / sc subprocesses.</summary>
	public static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromSeconds(30);

	/// <summary>Hard timeout for the New-SelfSignedCertificate PowerShell run (cold store reads
	/// on a busy machine can take tens of seconds).</summary>
	public static readonly TimeSpan DefaultPowerShellTimeout = TimeSpan.FromSeconds(120);

	private readonly IIisPlatformProbe _platform;
	private readonly IExternalCommandRunner _runner;
	private readonly IWebUiCertificateSource _certSource;
	private readonly ISecretProtector _protector;
	private readonly RdpAuditPaths _paths;
	private readonly string _appSettingsPath;
	private readonly string _publishWebRoot;
	private readonly Func<ElevationStatus> _elevationCheck;
	private readonly Func<ISecretProtector, WebTokenVault> _vaultFactory;
	private readonly Func<RdpAuditPaths, WebUiAppStager> _stagerFactory;
	private readonly TimeSpan _commandTimeout;
	private readonly TimeSpan _powershellTimeout;

	public IisConfigureService(
		IIisPlatformProbe platform,
		IExternalCommandRunner runner,
		IWebUiCertificateSource certSource,
		ISecretProtector protector,
		RdpAuditPaths paths,
		string appSettingsPath,
		string publishWebRoot,
		Func<ElevationStatus>? elevationCheck = null,
		Func<ISecretProtector, WebTokenVault>? vaultFactory = null,
		Func<RdpAuditPaths, WebUiAppStager>? stagerFactory = null,
		TimeSpan? commandTimeout = null,
		TimeSpan? powershellTimeout = null)
	{
		_platform = platform ?? throw new ArgumentNullException(nameof(platform));
		_runner = runner ?? throw new ArgumentNullException(nameof(runner));
		_certSource = certSource ?? throw new ArgumentNullException(nameof(certSource));
		_protector = protector ?? throw new ArgumentNullException(nameof(protector));
		_paths = paths ?? throw new ArgumentNullException(nameof(paths));
		ArgumentException.ThrowIfNullOrWhiteSpace(appSettingsPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(publishWebRoot);
		_appSettingsPath = appSettingsPath;
		_publishWebRoot = publishWebRoot;
		_elevationCheck = elevationCheck ?? ElevationGuard.Check;
		_vaultFactory = vaultFactory
			?? (p => new WebTokenVault(p, _paths.WebUiTokenPath, IisWebUiDefaults.PoolAccountName));
		_stagerFactory = stagerFactory
			?? (p => new WebUiAppStager(p, IisWebUiDefaults.PoolAccountName));
		_commandTimeout = commandTimeout ?? DefaultCommandTimeout;
		_powershellTimeout = powershellTimeout ?? DefaultPowerShellTimeout;
	}

	/// <summary>Runs the full Configure IIS workflow. Never throws except for external
	/// cancellation; every operational failure is reported through the returned outcome.</summary>
	public async Task<IisConfigureOutcome> RunAsync(CancellationToken ct = default)
	{
		List<string> steps = new();
		List<string> warnings = new();
		List<string> errors = new();
		List<string> notes = new();

		ct.ThrowIfCancellationRequested();

		ElevationStatus elevation = _elevationCheck();
		if (!elevation.IsElevated)
		{
			errors.Add(elevation.Message);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add(elevation.Message);

		bool? installed = await _platform.IsIisInstalledAsync(ct).ConfigureAwait(false);
		ct.ThrowIfCancellationRequested();
		bool? w3svc = await _platform
			.ServiceExistsAsync(WindowsIisPlatformProbe.W3SvcServiceName, ct)
			.ConfigureAwait(false);
		ct.ThrowIfCancellationRequested();

		if (installed != true || w3svc != true)
		{
			errors.Add(
				"IIS must be installed with the World Wide Web Publishing Service before the web "
				+ "access can be configured. Run Install IIS first (and reboot if it requested one), "
				+ "then retry Configure IIS.");
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("IIS role and W3SVC are present.");

		string appCmdExecutable = IisConfigureCommandSet.ResolveAppCmdExecutable();

		ExternalCommandResult? modules = await RunCommandAsync(
			"appcmd list modules (ANCM check)",
			appCmdExecutable,
			IisConfigureCommandSet.BuildListConfigModulesArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (modules is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!modules.Success || !AppCmdListOutputs.ContainsAspNetCoreModuleV2(modules.StdOut))
		{
			errors.Add(
				"The ASP.NET Core Module v2 (AspNetCoreModuleV2) is not installed, which in-process "
				+ "hosting of the web UI requires. Install the ASP.NET Core Hosting Bundle, then retry "
				+ "Configure IIS."
				+ (modules.Success ? string.Empty : " " + modules.BuildDiagnosticSummary()));
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("ASP.NET Core Module v2 is installed.");

		string siteCertHash = await ResolveWebSiteCertificateAsync(steps, warnings, errors, ct)
			.ConfigureAwait(false);
		if (siteCertHash.Length == 0)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		string tokenEnvelope = PrepareToken(steps, errors);
		if (tokenEnvelope.Length == 0)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		AppSettingsEditResult serviceEdit = WebUiAppSettingsEditor.EnsureApiSection(
			_appSettingsPath,
			tokenEnvelope);
		if (!serviceEdit.Ok)
		{
			errors.Add("The service REST settings could not be written: " + serviceEdit.Failure);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("Enabled the service REST backend and stored the protected shared token.");

		string? backendPin = NormalizeThumbprint(serviceEdit.ExistingCertificateThumbprint);
		if (backendPin is not null)
		{
			steps.Add("Pinning the web proxy TLS trust to the REST backend certificate.");
		}
		else if (!string.IsNullOrWhiteSpace(serviceEdit.ExistingCertificateSubject))
		{
			warnings.Add(
				"The REST backend certificate is selected by subject, so the proxy TLS pin is left "
				+ "unset; only the loopback URL constrains the backend (system validation applies).");
		}

		ExternalCommandResult? serviceStop = await RunCommandAsync(
			"RdpAuditService stop",
			IisConfigureCommandSet.ScExecutable,
			IisConfigureCommandSet.BuildScStopServiceArguments(InstallationService.ServiceName),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (serviceStop is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (serviceStop.Success)
		{
			steps.Add("Stopped the RdpAudit service so the new REST settings load instead of the old ones.");
		}
		else
		{
			notes.Add("The RdpAudit service was not running (or could not be stopped); continuing.");
		}

		if (!await EnsureIisSiteAndPoolAsync(appCmdExecutable, steps, errors, ct).ConfigureAwait(false))
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		// The pool account now exists, so the staging ACL grant can resolve the identity.
		WebUiAppStager stager = _stagerFactory(_paths);
		WebUiAppStageResult stage;
		try
		{
			stage = stager.Stage(_publishWebRoot);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
		{
			errors.Add("The web application could not be staged: " + ex.Message);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!stage.Succeeded)
		{
			errors.AddRange(stage.Failures);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add(string.Format(
			System.Globalization.CultureInfo.InvariantCulture,
			"Staged the web application into {0} ({1} file(s) verified).",
			stage.TargetDirectory,
			stage.FilesVerified));

		string stagedSettingsPath = Path.Combine(_paths.WebUiDirectory, RdpAuditPaths.AppSettingsFileName);
		AppSettingsEditResult proxyEdit = WebUiAppSettingsEditor.EnsureWebUiProxySection(
			stagedSettingsPath,
			"https://127.0.0.1:8443",
			backendPin);
		if (!proxyEdit.Ok)
		{
			errors.Add("The web proxy settings could not be written: " + proxyEdit.Failure);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("Wrote the web proxy settings (loopback backend, strict CSP).");

		ExternalCommandResult? reservationDelete = await RunCommandAsync(
			"HTTP.sys SSL reservation delete",
			IisConfigureCommandSet.NetshExecutable,
			IisConfigureCommandSet.BuildNetshDeleteSslCertArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (reservationDelete is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!reservationDelete.Success)
		{
			notes.Add("No existing HTTP.sys SSL reservation for the loopback site (fresh configure).");
		}

		ExternalCommandResult? reservationAdd = await RunCommandAsync(
			"HTTP.sys SSL reservation add",
			IisConfigureCommandSet.NetshExecutable,
			IisConfigureCommandSet.BuildNetshAddSslCertArguments(siteCertHash),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (reservationAdd is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!reservationAdd.Success)
		{
			errors.Add(
				"The HTTPS certificate reservation for " + IisConfigureCommandSet.LoopbackBindingInformation
				+ " could not be created. " + reservationAdd.BuildDiagnosticSummary());
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("Reserved the HTTPS certificate for the loopback site.");

		ExternalCommandResult? siteStart = await RunCommandAsync(
			"IIS site start",
			appCmdExecutable,
			IisConfigureCommandSet.BuildStartSiteArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (siteStart is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!siteStart.Success)
		{
			errors.Add("The IIS site could not be started. " + siteStart.BuildDiagnosticSummary());
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("Started the IIS site on " + IisWebUiDefaults.HttpsUrl);

		ExternalCommandResult? serviceStart = await RunCommandAsync(
			"RdpAuditService start",
			IisConfigureCommandSet.ScExecutable,
			IisConfigureCommandSet.BuildScStartServiceArguments(InstallationService.ServiceName),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (serviceStart is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (serviceStart.Success)
		{
			steps.Add("Started the RdpAudit service with the REST backend enabled.");
		}
		else
		{
			warnings.Add(
				"The RdpAudit service start command returned a non-zero code; the service may already "
				+ "be running - verify its state in the Service tab.");
		}

		ExternalCommandResult? siteConfirm = await RunCommandAsync(
			"IIS site confirm",
			appCmdExecutable,
			IisConfigureCommandSet.BuildListSitesArguments(),
			timeout: _commandTimeout,
			errors: errors,
			ct: ct).ConfigureAwait(false);
		if (siteConfirm is null)
		{
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		if (!siteConfirm.Success || !AppCmdListOutputs.ContainsSiteNamed(siteConfirm.StdOut, IisWebUiDefaults.SiteName))
		{
			errors.Add(
				"Final verification failed: the IIS site is not present in the site list. "
				+ (siteConfirm.Success ? string.Empty : siteConfirm.BuildDiagnosticSummary()));
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		bool verified = VerifyFinalState(out string verificationFailure);
		if (!verified)
		{
			errors.Add("Final verification failed: " + verificationFailure);
			return new IisConfigureOutcome(false, steps, warnings, errors, notes);
		}

		steps.Add("Final verification passed: site, staged application and shared token all present.");
		return new IisConfigureOutcome(true, steps, warnings, errors, notes);
	}

	/// <summary>Resolves an existing loopback-capable machine certificate or generates a
	/// self-signed one (with an explicit operator warning). Returns an empty string on failure.</summary>
	private async Task<string> ResolveWebSiteCertificateAsync(
		List<string> steps,
		List<string> warnings,
		List<string> errors,
		CancellationToken ct)
	{
		WebUiCertificateInfo? certificate = _certSource.FindUsableCertificate();
		if (certificate is null)
		{
			ExternalCommandResult? generation = await RunCommandAsync(
				"New-SelfSignedCertificate (web site)",
				WebUiSelfSignedCertificateCommandSet.PowerShellExecutable,
				WebUiSelfSignedCertificateCommandSet.BuildNewSelfSignedCertificateArguments(),
				timeout: _powershellTimeout,
				ct: ct,
				errors: errors).ConfigureAwait(false);
			if (generation is null)
			{
				return string.Empty;
			}

			if (!generation.Success)
			{
				errors.Add(
					"The web site certificate could not be generated. "
					+ generation.BuildDiagnosticSummary());
				return string.Empty;
			}

			warnings.Add(
				"A self-signed certificate was generated for the loopback web site; the browser will "
				+ "show a certificate warning until it is trusted or replaced with a private CA certificate.");

			certificate = _certSource.FindUsableCertificate();
			if (certificate is null)
			{
				errors.Add("The self-signed web site certificate was created but could not be read back from the machine store.");
				return string.Empty;
			}

			steps.Add("Generated a self-signed certificate for the loopback web site.");
		}
		else
		{
			if (certificate.SelfSigned)
			{
				warnings.Add(
					"The web site certificate is self-signed; the browser will show a certificate warning "
					+ "until the certificate is trusted or replaced.");
			}

			steps.Add("Reusing the existing web site certificate for the loopback binding.");
		}

		return certificate.Thumbprint;
	}

	/// <summary>Prepares the shared web-UI bearer token and returns its DPAPI protected envelope.
	/// Returns an empty string on failure (curated error recorded).</summary>
	private string PrepareToken(List<string> steps, List<string> errors)
	{
		WebTokenVault vault = _vaultFactory(_protector);
		string token;
		try
		{
			if (vault.Exists)
			{
				token = vault.LoadToken();
				steps.Add("Reusing the existing shared web-UI token from the protected vault.");
			}
			else
			{
				token = vault.GenerateAndStoreToken();
				steps.Add("Generated and stored a new shared web-UI token in the protected vault.");
			}
		}
		catch (SecretProtectionException ex)
		{
			errors.Add("The shared web-UI token vault could not be prepared: " + ex.Message);
			return string.Empty;
		}

		try
		{
			return _protector.Protect(token, SecretScope.LocalMachine);
		}
		catch (SecretProtectionException ex)
		{
			errors.Add("The shared web-UI token could not be protected for the service settings: " + ex.Message);
			return string.Empty;
		}
	}

	/// <summary>Creates the RdpAuditWebUi IIS site and application pool (idempotent add-or-set)
	/// and pins the site root application to the dedicated pool. Returns false on failure.</summary>
	private async Task<bool> EnsureIisSiteAndPoolAsync(
		string appCmdExecutable,
		List<string> steps,
		List<string> errors,
		CancellationToken ct)
	{
		try
		{
			Directory.CreateDirectory(_paths.WebUiDirectory);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			errors.Add("The web application root could not be created: " + ex.Message);
			return false;
		}

		ExternalCommandResult? stopSite = await RunCommandAsync(
			"IIS site stop (pre-configure)",
			appCmdExecutable,
			IisConfigureCommandSet.BuildStopSiteArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (stopSite is null)
		{
			return false;
		}

		if (!stopSite.Success)
		{
			steps.Add("The IIS site is not running yet (or does not exist); proceeding.");
		}

		ExternalCommandResult? sites = await RunCommandAsync(
			"IIS site list",
			appCmdExecutable,
			IisConfigureCommandSet.BuildListSitesArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (sites is null)
		{
			return false;
		}

		if (!sites.Success)
		{
			errors.Add("The IIS site list could not be read. " + sites.BuildDiagnosticSummary());
			return false;
		}

		bool siteExists = AppCmdListOutputs.ContainsSiteNamed(sites.StdOut, IisWebUiDefaults.SiteName);
		ExternalCommandResult? siteWrite = await RunCommandAsync(
			siteExists ? "IIS site update" : "IIS site add",
			appCmdExecutable,
			siteExists
				? IisConfigureCommandSet.BuildSetSiteArguments(_paths.WebUiDirectory)
				: IisConfigureCommandSet.BuildAddSiteArguments(_paths.WebUiDirectory),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (siteWrite is null)
		{
			return false;
		}

		if (!siteWrite.Success)
		{
			errors.Add(
				(siteExists ? "The IIS site could not be updated. " : "The IIS site could not be added. ")
				+ siteWrite.BuildDiagnosticSummary());
			return false;
		}

		steps.Add(siteExists
			? "Updated the IIS site physical path (existing binding preserved)."
			: "Added the IIS site with the loopback HTTPS binding.");

		ExternalCommandResult? pools = await RunCommandAsync(
			"IIS app pool list",
			appCmdExecutable,
			IisConfigureCommandSet.BuildListAppPoolsArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (pools is null)
		{
			return false;
		}

		if (!pools.Success)
		{
			errors.Add("The IIS application pool list could not be read. " + pools.BuildDiagnosticSummary());
			return false;
		}

		bool poolExists = AppCmdListOutputs.ContainsAppPoolNamed(pools.StdOut, IisWebUiDefaults.PoolName);
		ExternalCommandResult? poolWrite = await RunCommandAsync(
			poolExists ? "IIS app pool update" : "IIS app pool add",
			appCmdExecutable,
			poolExists
				? IisConfigureCommandSet.BuildSetAppPoolArguments()
				: IisConfigureCommandSet.BuildAddAppPoolArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (poolWrite is null)
		{
			return false;
		}

		if (!poolWrite.Success)
		{
			errors.Add(
				(poolExists ? "The IIS application pool could not be updated. " : "The IIS application pool could not be added. ")
				+ poolWrite.BuildDiagnosticSummary());
			return false;
		}

		steps.Add(poolExists
			? "Updated the dedicated IIS application pool."
			: "Added the dedicated IIS application pool (ApplicationPoolIdentity).");

		ExternalCommandResult? rootPool = await RunCommandAsync(
			"IIS root application pool pin",
			appCmdExecutable,
			IisConfigureCommandSet.BuildSetRootAppPoolArguments(),
			timeout: _commandTimeout,
			ct: ct,
			errors: errors).ConfigureAwait(false);
		if (rootPool is null)
		{
			return false;
		}

		if (!rootPool.Success)
		{
			errors.Add("The site root application pool could not be set. " + rootPool.BuildDiagnosticSummary());
			return false;
		}

		steps.Add("Pinned the site root application to the dedicated pool.");
		return true;
	}

	/// <summary>Reads the final on-disk state the workflow is responsible for.</summary>
	private bool VerifyFinalState(out string failure)
	{
		failure = string.Empty;
		string manifestPath = Path.Combine(_paths.WebUiDirectory, WebUiAppStager.AppManifestFileName);
		string webConfigPath = Path.Combine(_paths.WebUiDirectory, "web.config");
		string indexPath = Path.Combine(
			_paths.WebUiDirectory,
			RdpAuditPaths.WebUiWwwRootFolderName,
			"index.html");

		if (!File.Exists(manifestPath) || !File.Exists(webConfigPath) || !File.Exists(indexPath))
		{
			failure = "the staged web application is incomplete (manifest, web.config and index.html must all be present).";
			return false;
		}

		if (!File.Exists(_paths.WebUiTokenPath))
		{
			failure = "the shared token vault file is missing.";
			return false;
		}

		return true;
	}

	/// <summary>Runs one external command through the central runner; curates start failures.</summary>
	private async Task<ExternalCommandResult?> RunCommandAsync(
		string commandLabel,
		string executable,
		IReadOnlyList<string> arguments,
		TimeSpan timeout,
		List<string> errors,
		CancellationToken ct)
	{
		try
		{
			return await _runner
				.RunDirectAsync(commandLabel, executable, arguments, timeout, ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			errors.Add(commandLabel + " could not be started: " + ex.Message);
			return null;
		}
	}

	private static string? NormalizeThumbprint(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string normalized = value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
		return normalized.Length == 40 && normalized.All(static c => Uri.IsHexDigit(c))
			? normalized
			: null;
	}
}
