/*
 * File   : PkiPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Step 3 — generates the MikroTik Local CA, the api-ssl server certificate and the Windows
 *          client certificate, previews their thumbprints, and (on confirmation) installs the CA into
 *          the machine Trusted Root and the client certificate into the user Personal store. This is
 *          the only step that writes to the Windows certificate store.
 * Depends: StepPanelBase, MikrotikCaManager, WindowsCertStoreHelper, WizardContext
 * Extends: To change key strength / validity, route through MikrotikCaManager; to add a second client
 *          certificate (e.g. for the Service account), generate and install it here.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography.X509Certificates;
using RdpAudit.Core.MikroTik;
using RdpAudit.Mikrotik.Pki;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Step 3: PKI generation and Windows certificate-store installation.</summary>
public sealed class PkiPanel : StepPanelBase
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly MikrotikCaManager _caManager;
	private readonly WindowsCertStoreHelper _certStore;

	// ── Construction ─────────────────────────────────────────────────────────────

	public PkiPanel(WizardContext context, MikrotikCaManager caManager, WindowsCertStoreHelper certStore) : base(context)
	{
		_caManager = caManager ?? throw new ArgumentNullException(nameof(caManager));
		_certStore = certStore ?? throw new ArgumentNullException(nameof(certStore));
		Heading = "PKI / Certificates";
		Description = "Generate the Local CA, server and client certificates for mutual TLS, then install the CA (Trusted Root) and client certificate (Personal).";
		ActionText = "Generate & install certificates";
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	protected override Task RunActionAsync(CancellationToken ct)
	{
		if (Context.Endpoint is null)
		{
			FailStep("No endpoint configured.");
			return Task.CompletedTask;
		}

		string routerIp = Context.Endpoint.RouterIp;
		AppendLog("Generating the MikroTik Local CA + server + client certificate set ...");

		MikrotikCertificateSet certs = _caManager.CreateCertificateSet(routerIp);
		try
		{
			AppendLog("  CA       : " + certs.Ca.Thumbprint);
			AppendLog("  Server   : " + certs.ServerCertificate.Thumbprint);
			AppendLog("  Client   : " + certs.ClientCertificate.Thumbprint);

			AppendLog("Installing the CA into LocalMachine\\Root ...");
			string caThumb = _certStore.InstallCaIntoTrustedRoot(certs.Ca);

			AppendLog("Installing the client certificate into CurrentUser\\My ...");
			string clientThumb = _certStore.InstallClientCertificate(certs.ClientCertificate);

			MikrotikConfig config = Context.Config ?? new MikrotikConfig
			{
				RouterIp = routerIp,
				ApiSslPort = Context.Endpoint.ApiSslPort,
			};
			config.CaCertThumbprint = caThumb;
			config.ClientCertThumbprint = clientThumb;
			Context.Config = config;

			AppendLog("Certificates installed. The router-side import happens during Apply & Sync (bootstrap).");
			CompleteStep();
		}
		finally
		{
			certs.Ca.Dispose();
			certs.ServerCertificate.Dispose();
			certs.ClientCertificate.Dispose();
		}

		return Task.CompletedTask;
	}
}
