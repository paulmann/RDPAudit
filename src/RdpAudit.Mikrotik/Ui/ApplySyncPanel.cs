/*
 * File   : ApplySyncPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Step 5 — runs the atomic bootstrap (BootstrapOrchestrator), validates the live
 *          api-ssl/mTLS channel with the RFC 5737 test IP (IntegrationValidator), persists the result
 *          (SecureCredentialStore) and pushes it to the running RdpAudit Service over IPC
 *          (ConfiguratorIpcBridge → PushMikroTikConfig), then polls GetMikroTikMtlsStatus to confirm
 *          the Service adopted the configuration. Bootstrap progress is rendered live via IProgress.
 * Depends: StepPanelBase, BootstrapOrchestrator, IntegrationValidator, RouterOsApiClient,
 *          WindowsCertStoreHelper, SecureCredentialStore, ConfiguratorIpcBridge, ILoggerFactory
 * Extends: To run a deeper post-bootstrap validation, add probes after the IntegrationValidator call;
 *          to push additional facts to the Service, extend MikrotikConfigPushMessage and the bridge.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.MikroTik;
using RdpAudit.Mikrotik.Core;
using RdpAudit.Mikrotik.Helpers;
using RdpAudit.Mikrotik.Ipc;
using RdpAudit.Mikrotik.Pki;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Step 5: run the bootstrap, validate the mTLS channel, persist and push to the Service.</summary>
public sealed class ApplySyncPanel : StepPanelBase
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly BootstrapOrchestrator _orchestrator;
	private readonly IntegrationValidator _validator;
	private readonly WindowsCertStoreHelper _certStore;
	private readonly SecureCredentialStore _credentialStore;
	private readonly ConfiguratorIpcBridge _ipcBridge;
	private readonly ILoggerFactory _loggerFactory;
	private readonly FirewallPanel _firewallPanel;

	// ── Construction ─────────────────────────────────────────────────────────────

	public ApplySyncPanel(
		WizardContext context,
		BootstrapOrchestrator orchestrator,
		IntegrationValidator validator,
		WindowsCertStoreHelper certStore,
		SecureCredentialStore credentialStore,
		ConfiguratorIpcBridge ipcBridge,
		ILoggerFactory loggerFactory,
		FirewallPanel firewallPanel) : base(context)
	{
		_orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
		_validator = validator ?? throw new ArgumentNullException(nameof(validator));
		_certStore = certStore ?? throw new ArgumentNullException(nameof(certStore));
		_credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
		_ipcBridge = ipcBridge ?? throw new ArgumentNullException(nameof(ipcBridge));
		_loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
		_firewallPanel = firewallPanel ?? throw new ArgumentNullException(nameof(firewallPanel));

		Heading = "Apply & Sync";
		Description = "Run the atomic bootstrap (with rollback on failure), validate the mutual-TLS channel, persist the configuration, and push it to the running RdpAudit Service.";
		ActionText = "Apply bootstrap & sync to service";
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	protected override async Task RunActionAsync(CancellationToken ct)
	{
		if (Context.Endpoint is null)
		{
			FailStep("No endpoint configured.");
			return;
		}

		ConnectionEndpoint ep = Context.Endpoint;
		BootstrapRequest request = new(
			RouterIp: ep.RouterIp,
			SshPort: ep.SshPort,
			ApiSslPort: ep.ApiSslPort,
			AdminUsername: ep.AdminUsername,
			AdminPassword: ep.AdminPassword,
			ServerLocalIp: string.IsNullOrWhiteSpace(Context.ServerLocalIp) ? "0.0.0.0" : Context.ServerLocalIp,
			AddressListName: _firewallPanel.AddressListName,
			DefaultBanTimeout: _firewallPanel.BanTimeout,
			PreferRawChain: _firewallPanel.PreferRawChain);

		Progress<BootstrapProgressEvent> progress = new(e => AppendLog($"[{e.Index}/{e.Total}] {e.Message}"));

		AppendLog("Starting bootstrap ...");
		BootstrapResult result = await _orchestrator.ExecuteAsync(request, progress, ct).ConfigureAwait(false);
		Context.BootstrapResult = result;

		if (!result.Succeeded)
		{
			AppendLog("Bootstrap FAILED" + (result.FailedStage is { } stage ? $" at stage {stage}" : string.Empty) + ": " + result.Error);
			if (result.Rollback is { } rb)
			{
				foreach (RollbackStepResult step in rb.Steps)
				{
					AppendLog($"  rollback · {step.Step}: removed {step.Removed} ({(step.Succeeded ? "ok" : "failed")})");
				}
			}
			FailStep(result.Error ?? "Bootstrap failed.");
			return;
		}

		Context.Config = result.Config;
		AppendLog("Bootstrap succeeded for " + result.Config.DescribeEndpoint());

		bool validated = await ValidateMtlsAsync(result.Config, ct).ConfigureAwait(false);
		if (!validated)
		{
			FailStep("Mutual-TLS validation failed after bootstrap.");
			return;
		}

		await SyncToServiceAsync(result.Config, ct).ConfigureAwait(false);
		CompleteStep();
	}

	private async Task<bool> ValidateMtlsAsync(MikrotikConfig config, CancellationToken ct)
	{
		AppendLog("Validating the mutual-TLS channel with the test IP " + IntegrationValidator.TestIp + " ...");

		X509Certificate2? clientCert = _certStore.FindByThumbprint(config.ClientCertThumbprint, StoreName.My, StoreLocation.CurrentUser);
		X509Certificate2? caCert = _certStore.FindByThumbprint(config.CaCertThumbprint, StoreName.Root, StoreLocation.LocalMachine);
		if (clientCert is null)
		{
			AppendLog("Client certificate not found in the store; cannot open the api-ssl channel.");
			return false;
		}

		string password = SecureCredentialStore.UnprotectString(config.ServicePasswordDpapi);
		await using RouterOsApiClient api = new(
			config.RouterIp,
			config.ApiSslPort,
			clientCert,
			caCert,
			validateServerCertificate: true,
			_loggerFactory.CreateLogger<RouterOsApiClient>());

		try
		{
			await api.ConnectAndLoginAsync(config.ServiceUsername, password, ct).ConfigureAwait(false);
			ValidationReport report = await _validator.ValidateAsync(api, config.AddressListName, ct).ConfigureAwait(false);
			AppendLog(report.Message);
			return report.OverallSucceeded;
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			AppendLog("api-ssl validation error: " + ex.Message);
			return false;
		}
		finally
		{
			clientCert.Dispose();
			caCert?.Dispose();
		}
	}

	private async Task SyncToServiceAsync(MikrotikConfig config, CancellationToken ct)
	{
		AppendLog("Persisting the configuration to the secure credential store ...");
		_credentialStore.SaveConfig(config);

		AppendLog("Checking whether the RdpAudit Service is running ...");
		if (!await _ipcBridge.IsServiceReachableAsync(ct).ConfigureAwait(false))
		{
			AppendLog("The RdpAudit Service is not reachable; the configuration is saved locally and will be adopted when the service next reads it.");
			return;
		}

		AppendLog("Pushing the configuration to the Service ...");
		IpcBridgeResult push = await _ipcBridge.PushConfigAsync(config, note: "Bootstrap completed via RdpAudit.Mikrotik wizard.", ct).ConfigureAwait(false);
		if (!push.Success)
		{
			AppendLog("Push failed: " + push.Error);
			return;
		}

		IpcBridgeResult<MikrotikMtlsStatusReply> status = await _ipcBridge.GetMtlsStatusAsync(ct).ConfigureAwait(false);
		if (status is { Success: true, Value: { } reply })
		{
			AppendLog($"Service status: configured={reply.Configured}, endpoint={reply.Endpoint}, rules={reply.FirewallRulesInstalled}.");
		}
		else
		{
			AppendLog("Service accepted the push; status read returned: " + (status.Error ?? "no detail"));
		}
	}
}
