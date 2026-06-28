/*
 * File   : IntegrationValidator.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Proves end-to-end that the bootstrapped api-ssl/mTLS channel can actually enforce a block.
 *          It adds a non-routable RFC 5737 test IP (192.0.2.123) to the RdpAudit address-list, reads
 *          it back to confirm it landed with the RdpAudit ownership tag, then removes it — leaving the
 *          router exactly as it was. A green result here is the wizard's go/no-go gate for "Apply".
 * Depends: RouterOsApiClient, RdpAuditTagHelper
 * Extends: To validate an additional capability (e.g. RAW chain hit counters), add a probe method and
 *          fold its result into ValidationReport; keep the test IP non-routable and always clean up.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using Microsoft.Extensions.Logging;
using RdpAudit.Mikrotik.Helpers;

namespace RdpAudit.Mikrotik.Core;

/// <summary>Outcome of the end-to-end integration validation.</summary>
/// <param name="AddSucceeded">True when the test IP was added to the address-list.</param>
/// <param name="ReadBackSucceeded">True when the test IP was found with the RdpAudit ownership tag.</param>
/// <param name="CleanupSucceeded">True when the test IP was removed afterwards.</param>
/// <param name="OverallSucceeded">True only when add + read-back + cleanup all succeeded.</param>
/// <param name="Message">Operator-facing summary.</param>
public sealed record ValidationReport(
	bool AddSucceeded,
	bool ReadBackSucceeded,
	bool CleanupSucceeded,
	bool OverallSucceeded,
	string Message);

/// <summary>Proves the api-ssl/mTLS channel can add, observe and remove an address-list block.</summary>
public sealed class IntegrationValidator
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>RFC 5737 TEST-NET-1 address — guaranteed non-routable, safe to add/remove.</summary>
	public const string TestIp = "192.0.2.123";

	private readonly ILogger<IntegrationValidator> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	public IntegrationValidator(ILogger<IntegrationValidator> logger)
		=> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Runs add → read-back → cleanup of <see cref="TestIp"/> on <paramref name="addressListName"/>
	/// over <paramref name="client"/>. Always attempts cleanup, even when the read-back fails.
	/// </summary>
	public async Task<ValidationReport> ValidateAsync(RouterOsApiClient client, string addressListName, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(client);
		ArgumentException.ThrowIfNullOrWhiteSpace(addressListName);

		string comment = RdpAuditTagHelper.BuildComment("integration self-test");

		RouterOsResult add = await client.ExecuteAsync(
			"/ip/firewall/address-list/add",
			new[] { "=list=" + addressListName, "=address=" + TestIp, "=comment=" + comment, "=timeout=00:05:00" },
			ct).ConfigureAwait(false);
		bool addSucceeded = add.Succeeded;

		bool readBack = false;
		RouterOsResult find = await client.ExecuteAsync(
			"/ip/firewall/address-list/print",
			new[] { "?list=" + addressListName, "?address=" + TestIp },
			ct).ConfigureAwait(false);
		if (find.Succeeded)
		{
			readBack = find.Rows.Any(r => RdpAuditTagHelper.IsRdpAuditManaged(r.GetValueOrDefault("comment", string.Empty)));
		}

		bool cleanup = await CleanupAsync(client, addressListName, ct).ConfigureAwait(false);

		bool overall = addSucceeded && readBack && cleanup;
		string message = overall
			? "Integration self-test passed: the test IP was added, observed with the RdpAudit tag, and removed."
			: $"Integration self-test incomplete (add={addSucceeded}, readBack={readBack}, cleanup={cleanup}).";

		_logger.LogInformation("MikroTik integration validation: {Message}", message);
		return new ValidationReport(addSucceeded, readBack, cleanup, overall, message);
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private static async Task<bool> CleanupAsync(RouterOsApiClient client, string addressListName, CancellationToken ct)
	{
		RouterOsResult find = await client.ExecuteAsync(
			"/ip/firewall/address-list/print",
			new[] { "?list=" + addressListName, "?address=" + TestIp },
			ct).ConfigureAwait(false);

		if (!find.Succeeded)
		{
			return false;
		}

		bool allRemoved = true;
		foreach (IReadOnlyDictionary<string, string> row in find.Rows)
		{
			if (!row.TryGetValue(".id", out string? id))
			{
				continue;
			}
			RouterOsResult remove = await client.ExecuteAsync("/ip/firewall/address-list/remove", new[] { "=.id=" + id }, ct).ConfigureAwait(false);
			allRemoved &= remove.Succeeded;
		}
		return allRemoved;
	}
}
