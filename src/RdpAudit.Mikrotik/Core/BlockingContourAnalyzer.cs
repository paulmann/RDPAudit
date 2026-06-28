/*
 * File   : BlockingContourAnalyzer.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Analyses the router's existing firewall "blocking contour" to decide WHERE an
 *          address-list drop rule must be placed so it actually takes effect. FastTrack short-circuits
 *          the filter chain, so a drop rule placed after a fasttrack-connection accept can never see
 *          attacker packets; this analyzer detects that condition and recommends placing the drop rule
 *          BEFORE fasttrack in the filter chain, or in the RAW prerouting chain (RouterOS v7).
 * Depends: RouterOsApiClient, RdpAuditTagHelper (ownership recognition is delegated to callers)
 * Extends: To recognise another bypass mechanism (e.g. a custom accept jump), add a detector in
 *          Analyze and surface it through a new BlockingContourReport flag plus a recommendation line.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

namespace RdpAudit.Mikrotik.Core;

/// <summary>Where RdpAudit should install its drop rule.</summary>
public enum BlockPlacement
{
	/// <summary>No fasttrack present; appending to the filter input chain is safe.</summary>
	FilterInputAppend,

	/// <summary>FastTrack present in filter; the drop rule must be placed BEFORE the fasttrack rule.</summary>
	FilterBeforeFastTrack,

	/// <summary>RouterOS v7 RAW prerouting drop — bypasses connection tracking and fasttrack entirely.</summary>
	RawPrerouting,
}

/// <summary>Result of analysing the firewall blocking contour.</summary>
/// <param name="HasFastTrack">True when a fasttrack-connection rule was found in the filter chain.</param>
/// <param name="FastTrackRuleId">RouterOS .id of the first fasttrack rule, or null.</param>
/// <param name="ExistingAddressList">True when an address-list with the target name already exists.</param>
/// <param name="ExistingRdpAuditRules">Count of firewall rules already tagged as RdpAudit-owned.</param>
/// <param name="RecommendedPlacement">Where the drop rule should go.</param>
/// <param name="Explanation">Operator-facing rationale.</param>
public sealed record BlockingContourReport(
	bool HasFastTrack,
	string? FastTrackRuleId,
	bool ExistingAddressList,
	int ExistingRdpAuditRules,
	BlockPlacement RecommendedPlacement,
	string Explanation);

/// <summary>Analyses the firewall blocking contour to choose a correct drop-rule placement.</summary>
public sealed class BlockingContourAnalyzer
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Reads the filter chain (and, on v7, the RAW chain) over <paramref name="client"/> and returns a
	/// placement recommendation. When <paramref name="preferRawChain"/> is true and the router supports
	/// it, RAW prerouting is recommended outright because it is immune to fasttrack and conntrack.
	/// </summary>
	public async Task<BlockingContourReport> AnalyzeAsync(
		RouterOsApiClient client,
		string addressListName,
		bool supportsRawChain,
		bool preferRawChain,
		CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(client);
		ArgumentException.ThrowIfNullOrWhiteSpace(addressListName);

		RouterOsResult filter = await client.ExecuteAsync("/ip/firewall/filter/print", Array.Empty<string>(), ct).ConfigureAwait(false);

		string? fastTrackId = null;
		int rdpAuditRules = 0;

		foreach (IReadOnlyDictionary<string, string> row in filter.Rows)
		{
			string action = row.GetValueOrDefault("action", string.Empty);
			string comment = row.GetValueOrDefault("comment", string.Empty);

			if (string.Equals(action, "fasttrack-connection", StringComparison.OrdinalIgnoreCase) && fastTrackId is null)
			{
				fastTrackId = row.TryGetValue(".id", out string? idValue) ? idValue : null;
			}

			if (Helpers.RdpAuditTagHelper.IsRdpAuditManaged(comment))
			{
				rdpAuditRules++;
			}
		}

		bool hasFastTrack = fastTrackId is not null;

		RouterOsResult addressLists = await client.ExecuteAsync(
			"/ip/firewall/address-list/print",
			new[] { "?list=" + addressListName },
			ct).ConfigureAwait(false);
		bool existingList = addressLists.Succeeded && addressLists.Rows.Count > 0;

		(BlockPlacement placement, string explanation) = Decide(hasFastTrack, supportsRawChain, preferRawChain);

		return new BlockingContourReport(hasFastTrack, fastTrackId, existingList, rdpAuditRules, placement, explanation);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	internal static (BlockPlacement Placement, string Explanation) Decide(bool hasFastTrack, bool supportsRawChain, bool preferRawChain)
	{
		if (supportsRawChain && preferRawChain)
		{
			return (BlockPlacement.RawPrerouting,
				"RAW prerouting drop chosen: it runs before connection tracking and fasttrack, guaranteeing attacker packets are dropped regardless of the filter contour.");
		}

		if (hasFastTrack)
		{
			return (BlockPlacement.FilterBeforeFastTrack,
				"FastTrack detected in the filter chain. The drop rule must be inserted BEFORE the fasttrack-connection rule, otherwise fast-tracked packets bypass the filter and the block never applies.");
		}

		return (BlockPlacement.FilterInputAppend,
			"No fasttrack rule detected. Appending the address-list drop rule to the filter input chain is sufficient.");
	}
}
