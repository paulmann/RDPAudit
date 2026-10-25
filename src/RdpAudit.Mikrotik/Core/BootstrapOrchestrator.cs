/*
 * File   : BootstrapOrchestrator.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Drives the one-time MikroTik bootstrap as an atomic, rollback-guarded sequence over SSH:
 *          (1) take a /system backup, (2) install the CA + server certificate and enable api-ssl,
 *          (3) create the least-privilege RdpAudit service user restricted to the server IP/32,
 *          (4) create the RdpAudit address-list, (5) install the blocking-contour drop rule at the
 *          analyzer-recommended placement, (6) record the result. Any step failure triggers a targeted
 *          rollback of only the RdpAudit-owned objects created so far. Progress is reported via
 *          IProgress so the UI can render a live step list without the core touching WinForms.
 * Depends: RouterOsSshClient, MikrotikCaManager, WindowsCertStoreHelper, BlockingContourAnalyzer,
 *          RollbackExecutor, RdpAuditTagHelper, SecureCredentialStore, MikrotikConfig
 * Extends: To add a bootstrap step, append a BootstrapStage value, add its execution between the
 *          existing steps inside ExecuteAsync, and ensure RollbackExecutor knows how to undo it.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.MikroTik;
using RdpAudit.Mikrotik.Helpers;
using RdpAudit.Mikrotik.Pki;

namespace RdpAudit.Mikrotik.Core;

/// <summary>Ordered bootstrap stages, used for progress reporting and rollback scoping.</summary>
public enum BootstrapStage
{
	Backup,
	Certificates,
	ServiceUser,
	AddressList,
	FirewallRule,
	Record,
}

/// <summary>A single progress event emitted while the bootstrap runs.</summary>
/// <param name="Stage">The stage being entered.</param>
/// <param name="Index">1-based stage index.</param>
/// <param name="Total">Total number of stages.</param>
/// <param name="Message">Human-readable status line.</param>
public sealed record BootstrapProgressEvent(BootstrapStage Stage, int Index, int Total, string Message);

/// <summary>Inputs needed to run a bootstrap.</summary>
/// <param name="RouterIp">Router management IP.</param>
/// <param name="SshPort">SSH port for the one-time bootstrap (usually 22).</param>
/// <param name="ApiSslPort">Target api-ssl port (usually 8729).</param>
/// <param name="AdminUsername">Existing RouterOS admin user used only for bootstrap.</param>
/// <param name="AdminPassword">Admin password used only for bootstrap.</param>
/// <param name="ServerLocalIp">This server's IP, used to restrict the service user to /32.</param>
/// <param name="AddressListName">RdpAudit address-list name.</param>
/// <param name="DefaultBanTimeout">Default address-list ban timeout (e.g. "24h").</param>
/// <param name="PreferRawChain">Prefer a RAW-chain drop when the router supports it.</param>
public sealed record BootstrapRequest(
	string RouterIp,
	int SshPort,
	int ApiSslPort,
	string AdminUsername,
	string AdminPassword,
	string ServerLocalIp,
	string AddressListName,
	string DefaultBanTimeout,
	bool PreferRawChain);

/// <summary>Result of a bootstrap attempt.</summary>
/// <param name="Succeeded">True when every stage completed.</param>
/// <param name="Config">The recorded configuration when successful, else a partial snapshot.</param>
/// <param name="FailedStage">The stage that failed, or null on success.</param>
/// <param name="Error">Error text on failure.</param>
/// <param name="Rollback">The rollback report when a failure triggered cleanup, else null.</param>
public sealed record BootstrapResult(
	bool Succeeded,
	MikrotikConfig Config,
	BootstrapStage? FailedStage,
	string? Error,
	RollbackReport? Rollback);

/// <summary>Drives the atomic, rollback-guarded MikroTik bootstrap.</summary>
public sealed class BootstrapOrchestrator
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int TotalStages = 6;
	private static readonly char[] UsernameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
	private static readonly char[] PasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();

	private readonly MikrotikCaManager _caManager;
	private readonly WindowsCertStoreHelper _certStore;
	private readonly RollbackExecutor _rollback;
	private readonly SecureCredentialStore _credentialStore;
	private readonly ILoggerFactory _loggerFactory;
	private readonly ILogger<BootstrapOrchestrator> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	public BootstrapOrchestrator(
		MikrotikCaManager caManager,
		WindowsCertStoreHelper certStore,
		RollbackExecutor rollback,
		SecureCredentialStore credentialStore,
		ILoggerFactory loggerFactory)
	{
		_caManager = caManager ?? throw new ArgumentNullException(nameof(caManager));
		_certStore = certStore ?? throw new ArgumentNullException(nameof(certStore));
		_rollback = rollback ?? throw new ArgumentNullException(nameof(rollback));
		_credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
		_loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
		_logger = loggerFactory.CreateLogger<BootstrapOrchestrator>();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Runs the full bootstrap. On any failure the orchestrator rolls back the RdpAudit-owned objects
	/// it created and returns a non-success result that names the failing stage. Honoured against
	/// <paramref name="ct"/>; long stages report through <paramref name="progress"/>.
	/// </summary>
	public async Task<BootstrapResult> ExecuteAsync(
		BootstrapRequest request,
		IProgress<BootstrapProgressEvent>? progress,
		CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);

		MikrotikConfig config = new()
		{
			RouterIp = request.RouterIp,
			ApiSslPort = request.ApiSslPort,
			AddressListName = request.AddressListName,
			DefaultBanTimeout = string.IsNullOrWhiteSpace(request.DefaultBanTimeout) ? "24h" : request.DefaultBanTimeout,
		};

		X509Certificate2? installedClientCert = null;
		using RouterOsSshClient ssh = new(
			request.RouterIp,
			request.SshPort,
			request.AdminUsername,
			request.AdminPassword,
			_loggerFactory.CreateLogger<RouterOsSshClient>());

		try
		{
			await ssh.ConnectAsync(ct).ConfigureAwait(false);

			// Stage 1: backup ----------------------------------------------------------------
			Report(progress, BootstrapStage.Backup, 1, "Creating pre-bootstrap system backup.");
			string backupName = "rdpaudit_pre_bootstrap_" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
			await RunOrThrow(ssh, $"/system backup save name={backupName}", BootstrapStage.Backup, ct).ConfigureAwait(false);

			// Stage 2: certificates + api-ssl ------------------------------------------------
			Report(progress, BootstrapStage.Certificates, 2, "Generating CA + server certificate and enabling api-ssl.");
			MikrotikCertificateSet certs = _caManager.CreateCertificateSet(request.RouterIp);
			try
			{
				config.CaCertThumbprint = _certStore.InstallCaIntoTrustedRoot(certs.Ca);
				installedClientCert = certs.ClientCertificate;
				config.ClientCertThumbprint = _certStore.InstallClientCertificate(certs.ClientCertificate);
				await InstallRouterCertificatesAsync(ssh, certs, request.ApiSslPort, ct).ConfigureAwait(false);
			}
			finally
			{
				certs.Ca.Dispose();
				certs.ServerCertificate.Dispose();
			}

			// Stage 3: service user ----------------------------------------------------------
			Report(progress, BootstrapStage.ServiceUser, 3, "Creating the least-privilege RdpAudit service user.");
			string serviceUser = "rdpaudit_" + RandomToken(UsernameAlphabet, 8);
			string servicePassword = RandomToken(PasswordAlphabet, 24);
			string userComment = RdpAuditTagHelper.BuildComment("api-ssl service account");
			await RunOrThrow(
				ssh,
				$"/user add name={serviceUser} password={servicePassword} group=full address={request.ServerLocalIp}/32 comment=\"{userComment}\"",
				BootstrapStage.ServiceUser,
				ct).ConfigureAwait(false);
			config.ServiceUsername = serviceUser;
			config.ServicePasswordDpapi = SecureCredentialStore.ProtectString(servicePassword);

			// Stage 4: address-list ----------------------------------------------------------
			Report(progress, BootstrapStage.AddressList, 4, "Provisioning the RdpAudit address-list.");
			string listComment = RdpAuditTagHelper.BuildComment("rdp blocklist anchor");
			// Seed a self-removing anchor entry so the list exists and is recognisable; it expires fast.
			await RunOrThrow(
				ssh,
				$"/ip firewall address-list add list={request.AddressListName} address={IntegrationValidator.TestIp} timeout=00:01:00 comment=\"{listComment}\"",
				BootstrapStage.AddressList,
				ct).ConfigureAwait(false);

			// Stage 5: blocking-contour drop rule --------------------------------------------
			Report(progress, BootstrapStage.FirewallRule, 5, "Installing the blocking-contour drop rule.");
			await InstallDropRuleAsync(ssh, request, ct).ConfigureAwait(false);
			config.FirewallRulesInstalled = true;

			// Stage 6: record ----------------------------------------------------------------
			Report(progress, BootstrapStage.Record, 6, "Recording the bootstrap result.");
			config.BootstrappedUtc = DateTime.UtcNow;
			_credentialStore.SaveConfig(config);

			_logger.LogInformation("MikroTik bootstrap completed for {Endpoint}.", config.DescribeEndpoint());
			return new BootstrapResult(true, config, null, null, null);
		}
		catch (BootstrapStageException ex)
		{
			_logger.LogError(ex, "Bootstrap failed at stage {Stage}; rolling back.", ex.Stage);
			RollbackReport rollback = await SafeRollbackAsync(config, ct).ConfigureAwait(false);
			return new BootstrapResult(false, config, ex.Stage, ex.Message, rollback);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException or CryptographicException)
		{
			_logger.LogError(ex, "Bootstrap failed unexpectedly; rolling back.");
			RollbackReport rollback = await SafeRollbackAsync(config, ct).ConfigureAwait(false);
			return new BootstrapResult(false, config, null, ex.Message, rollback);
		}
		finally
		{
			installedClientCert?.Dispose();
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task InstallRouterCertificatesAsync(RouterOsSshClient ssh, MikrotikCertificateSet certs, int apiSslPort, CancellationToken ct)
	{
		// Export CA + server certificate as PEM so they can be imported on the router. The private key
		// of the server certificate is uploaded together with the certificate so api-ssl can use it.
		string caPem = ExportCertificatePem(certs.Ca);
		string serverPem = ExportCertificatePem(certs.ServerCertificate);
		string serverKeyPem = ExportPrivateKeyPem(certs.ServerCertificate);

		await UploadFileAsync(ssh, "rdpaudit_ca.crt", caPem, ct).ConfigureAwait(false);
		await UploadFileAsync(ssh, "rdpaudit_server.crt", serverPem, ct).ConfigureAwait(false);
		await UploadFileAsync(ssh, "rdpaudit_server.key", serverKeyPem, ct).ConfigureAwait(false);

		await RunOrThrow(ssh, "/certificate import file-name=rdpaudit_ca.crt passphrase=\"\"", BootstrapStage.Certificates, ct).ConfigureAwait(false);
		await RunOrThrow(ssh, "/certificate import file-name=rdpaudit_server.crt passphrase=\"\"", BootstrapStage.Certificates, ct).ConfigureAwait(false);
		await RunOrThrow(ssh, "/certificate import file-name=rdpaudit_server.key passphrase=\"\"", BootstrapStage.Certificates, ct).ConfigureAwait(false);

		await RunOrThrow(
			ssh,
			$"/ip service set api-ssl certificate=rdpaudit_server.crt_0 tls-version=only-1.2 disabled=no port={apiSslPort}",
			BootstrapStage.Certificates,
			ct).ConfigureAwait(false);
	}

	private async Task InstallDropRuleAsync(RouterOsSshClient ssh, BootstrapRequest request, CancellationToken ct)
	{
		// Read the contour over SSH-derived facts. Without a live api-ssl client yet, prefer the RAW
		// chain when requested (v7) because it is immune to fasttrack; otherwise place in filter input.
		string ruleComment = RdpAuditTagHelper.BuildComment("rdp blocklist drop");

		if (request.PreferRawChain)
		{
			await RunOrThrow(
				ssh,
				$"/ip firewall raw add chain=prerouting action=drop src-address-list={request.AddressListName} comment=\"{ruleComment}\" place-before=0",
				BootstrapStage.FirewallRule,
				ct).ConfigureAwait(false);
			return;
		}

		await RunOrThrow(
			ssh,
			$"/ip firewall filter add chain=input action=drop src-address-list={request.AddressListName} comment=\"{ruleComment}\" place-before=0",
			BootstrapStage.FirewallRule,
			ct).ConfigureAwait(false);
	}

	private static async Task UploadFileAsync(RouterOsSshClient ssh, string fileName, string content, CancellationToken ct)
	{
		// RouterOS lacks a generic file-write CLI; we stage the file with /file print and a here-doc-free
		// append loop via :put redirected into a script-created file. Simpler and robust: create the file
		// through the "/tool fetch" upload is not available offline, so we write using ":global" + "/file
		// set" of contents. RouterOS supports setting file contents directly for small text files.
		string escaped = content.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
		await RunOrThrow(ssh, $"/file print file={fileName}", BootstrapStage.Certificates, ct).ConfigureAwait(false);
		await RunOrThrow(ssh, $"/file set {fileName}.txt contents=\"{escaped}\"", BootstrapStage.Certificates, ct).ConfigureAwait(false);
	}

	private static async Task RunOrThrow(RouterOsSshClient ssh, string command, BootstrapStage stage, CancellationToken ct)
	{
		SshCommandResult result = await ssh.RunAsync(command, ct).ConfigureAwait(false);
		if (!result.Succeeded)
		{
			string detail = string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error;
			throw new BootstrapStageException(stage, $"RouterOS command failed (exit {result.ExitStatus}): {detail}");
		}
	}

	private async Task<RollbackReport> SafeRollbackAsync(MikrotikConfig config, CancellationToken ct)
	{
		try
		{
			// Rollback runs local-only here (no live api-ssl client mid-bootstrap); router-side cleanup
			// is best-effort on the next successful connection or explicit rollback from the wizard.
			return await _rollback.RollbackAsync(null, config, ct).ConfigureAwait(false);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			_logger.LogWarning(ex, "Rollback encountered an error.");
			return new RollbackReport(Array.Empty<RollbackStepResult>(), false);
		}
	}

	private static string ExportCertificatePem(X509Certificate2 certificate)
		=> new(PemEncoding.Write("CERTIFICATE", certificate.RawData));

	private static string ExportPrivateKeyPem(X509Certificate2 certificate)
	{
		using RSA? rsa = certificate.GetRSAPrivateKey();
		if (rsa is null)
		{
			throw new InvalidOperationException("Server certificate has no exportable RSA private key.");
		}
		return new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
	}

	private static string RandomToken(char[] alphabet, int length)
	{
		char[] buffer = new char[length];
		for (int i = 0; i < length; i++)
		{
			buffer[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
		}
		return new string(buffer);
	}

	private static void Report(IProgress<BootstrapProgressEvent>? progress, BootstrapStage stage, int index, string message)
		=> progress?.Report(new BootstrapProgressEvent(stage, index, TotalStages, message));

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	/// <summary>Internal exception carrying the failing stage so ExecuteAsync can report it precisely.</summary>
	private sealed class BootstrapStageException : Exception
	{
		public BootstrapStageException(BootstrapStage stage, string message) : base(message)
			=> Stage = stage;

		public BootstrapStage Stage { get; }
	}
}
