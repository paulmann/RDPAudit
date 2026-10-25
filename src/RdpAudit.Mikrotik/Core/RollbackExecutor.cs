/*
 * File   : RollbackExecutor.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Undoes a partial or completed bootstrap by removing ONLY RdpAudit-owned RouterOS objects
 *          (recognised by the RdpAudit comment tag) — firewall rules, address-list entries, the
 *          service user and the api-ssl certificates — and by removing the locally installed Windows
 *          certificates. Operator-created objects are never touched. Used both for explicit rollback
 *          and for the atomic abort path inside BootstrapOrchestrator.
 * Depends: RouterOsApiClient, RdpAuditTagHelper, WindowsCertStoreHelper, MikrotikConfig
 * Extends: When the bootstrap learns to create a new RouterOS object category, add a matching
 *          targeted removal step here so rollback stays complete; never broaden a delete to match
 *          objects without the RdpAudit ownership tag.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.MikroTik;
using RdpAudit.Mikrotik.Helpers;
using RdpAudit.Mikrotik.Pki;

namespace RdpAudit.Mikrotik.Core;

/// <summary>Per-step outcome of a rollback pass.</summary>
/// <param name="Step">Human-readable rollback step name.</param>
/// <param name="Removed">How many objects were removed.</param>
/// <param name="Succeeded">True when the step completed without error.</param>
/// <param name="Detail">Optional detail / error text.</param>
public sealed record RollbackStepResult(string Step, int Removed, bool Succeeded, string? Detail);

/// <summary>Aggregate rollback report.</summary>
/// <param name="Steps">Per-step results in execution order.</param>
/// <param name="Succeeded">True when every step succeeded.</param>
public sealed record RollbackReport(IReadOnlyList<RollbackStepResult> Steps, bool Succeeded);

/// <summary>Removes RdpAudit-owned objects to undo a bootstrap.</summary>
public sealed class RollbackExecutor
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly WindowsCertStoreHelper _certStore;
	private readonly ILogger<RollbackExecutor> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	public RollbackExecutor(WindowsCertStoreHelper certStore, ILogger<RollbackExecutor> logger)
	{
		_certStore = certStore ?? throw new ArgumentNullException(nameof(certStore));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Removes RdpAudit-owned router objects over <paramref name="client"/> and the local Windows
	/// certificates referenced by <paramref name="config"/>. Each step is independent and best-effort
	/// so a single failure does not abort the remaining cleanup. The router client may be null when
	/// the bootstrap never reached a connected state (local-only cleanup).
	/// </summary>
	public async Task<RollbackReport> RollbackAsync(RouterOsApiClient? client, MikrotikConfig config, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(config);
		List<RollbackStepResult> steps = new();

		if (client is not null)
		{
			steps.Add(await RemoveTaggedRules(client, "/ip/firewall/raw", config.AddressListName, ct).ConfigureAwait(false));
			steps.Add(await RemoveTaggedRules(client, "/ip/firewall/filter", config.AddressListName, ct).ConfigureAwait(false));
			steps.Add(await RemoveTaggedAddressList(client, config.AddressListName, ct).ConfigureAwait(false));
			steps.Add(await RemoveServiceUser(client, config.ServiceUsername, ct).ConfigureAwait(false));
			steps.Add(await RemoveTaggedCertificates(client, ct).ConfigureAwait(false));
		}

		steps.Add(RemoveLocalCertificate("client certificate", config.ClientCertThumbprint, StoreName.My, StoreLocation.CurrentUser));
		steps.Add(RemoveLocalCertificate("CA trusted root", config.CaCertThumbprint, StoreName.Root, StoreLocation.LocalMachine));

		bool succeeded = steps.All(s => s.Succeeded);
		return new RollbackReport(steps, succeeded);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task<RollbackStepResult> RemoveTaggedRules(RouterOsApiClient client, string path, string addressList, CancellationToken ct)
	{
		string step = "Remove RdpAudit rules in " + path;
		try
		{
			RouterOsResult list = await client.ExecuteAsync(path + "/print", Array.Empty<string>(), ct).ConfigureAwait(false);
			int removed = 0;
			foreach (IReadOnlyDictionary<string, string> row in list.Rows)
			{
				if (!RdpAuditTagHelper.IsRdpAuditManaged(row.GetValueOrDefault("comment", string.Empty)))
				{
					continue;
				}
				if (!row.TryGetValue(".id", out string? id))
				{
					continue;
				}
				RouterOsResult remove = await client.ExecuteAsync(path + "/remove", new[] { "=.id=" + id }, ct).ConfigureAwait(false);
				if (remove.Succeeded)
				{
					removed++;
				}
			}
			return new RollbackStepResult(step, removed, true, null);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			_logger.LogWarning(ex, "Rollback step failed: {Step}.", step);
			return new RollbackStepResult(step, 0, false, ex.Message);
		}
	}

	private async Task<RollbackStepResult> RemoveTaggedAddressList(RouterOsApiClient client, string addressList, CancellationToken ct)
	{
		const string step = "Remove RdpAudit address-list entries";
		try
		{
			RouterOsResult list = await client.ExecuteAsync(
				"/ip/firewall/address-list/print",
				new[] { "?list=" + addressList },
				ct).ConfigureAwait(false);

			int removed = 0;
			foreach (IReadOnlyDictionary<string, string> row in list.Rows)
			{
				if (!row.TryGetValue(".id", out string? id))
				{
					continue;
				}
				RouterOsResult remove = await client.ExecuteAsync("/ip/firewall/address-list/remove", new[] { "=.id=" + id }, ct).ConfigureAwait(false);
				if (remove.Succeeded)
				{
					removed++;
				}
			}
			return new RollbackStepResult(step, removed, true, null);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			return new RollbackStepResult(step, 0, false, ex.Message);
		}
	}

	private async Task<RollbackStepResult> RemoveServiceUser(RouterOsApiClient client, string username, CancellationToken ct)
	{
		const string step = "Remove RdpAudit service user";
		if (string.IsNullOrWhiteSpace(username))
		{
			return new RollbackStepResult(step, 0, true, "No service user recorded.");
		}

		try
		{
			RouterOsResult users = await client.ExecuteAsync("/user/print", new[] { "?name=" + username }, ct).ConfigureAwait(false);
			int removed = 0;
			foreach (IReadOnlyDictionary<string, string> row in users.Rows)
			{
				if (!row.TryGetValue(".id", out string? id))
				{
					continue;
				}
				RouterOsResult remove = await client.ExecuteAsync("/user/remove", new[] { "=.id=" + id }, ct).ConfigureAwait(false);
				if (remove.Succeeded)
				{
					removed++;
				}
			}
			return new RollbackStepResult(step, removed, true, null);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			return new RollbackStepResult(step, 0, false, ex.Message);
		}
	}

	private async Task<RollbackStepResult> RemoveTaggedCertificates(RouterOsApiClient client, CancellationToken ct)
	{
		const string step = "Remove RdpAudit certificates on router";
		try
		{
			RouterOsResult certs = await client.ExecuteAsync("/certificate/print", Array.Empty<string>(), ct).ConfigureAwait(false);
			int removed = 0;
			foreach (IReadOnlyDictionary<string, string> row in certs.Rows)
			{
				string name = row.GetValueOrDefault("name", string.Empty);
				if (!name.StartsWith("rdpaudit_", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				if (!row.TryGetValue(".id", out string? id))
				{
					continue;
				}
				RouterOsResult remove = await client.ExecuteAsync("/certificate/remove", new[] { "=.id=" + id }, ct).ConfigureAwait(false);
				if (remove.Succeeded)
				{
					removed++;
				}
			}
			return new RollbackStepResult(step, removed, true, null);
		}
		catch (Exception ex) when (ex is IOException or InvalidOperationException)
		{
			return new RollbackStepResult(step, 0, false, ex.Message);
		}
	}

	private RollbackStepResult RemoveLocalCertificate(string label, string thumbprint, StoreName storeName, StoreLocation location)
	{
		string step = "Remove local " + label;
		if (string.IsNullOrWhiteSpace(thumbprint))
		{
			return new RollbackStepResult(step, 0, true, "No thumbprint recorded.");
		}

		try
		{
			bool removed = _certStore.RemoveByThumbprint(thumbprint, storeName, location);
			return new RollbackStepResult(step, removed ? 1 : 0, true, null);
		}
		catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
		{
			_logger.LogWarning(ex, "Failed to remove local certificate {Label}.", label);
			return new RollbackStepResult(step, 0, false, ex.Message);
		}
	}
}
