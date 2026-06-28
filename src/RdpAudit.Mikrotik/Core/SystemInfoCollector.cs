/*
 * File   : SystemInfoCollector.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Gathers read-only RouterOS identity and capability facts (identity, RouterOS version,
 *          board/model, architecture, uptime) over an established channel so the wizard can show the
 *          operator what they are about to modify and so version-dependent bootstrap decisions
 *          (e.g. RAW chain availability, certificate command syntax) can be made safely.
 * Depends: RouterOsApiClient
 * Extends: To collect another fact, add a property to MikrotikSystemInfo and a corresponding
 *          ExecuteAsync read in CollectAsync; keep every command strictly read-only.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

namespace RdpAudit.Mikrotik.Core;

/// <summary>Read-only snapshot of RouterOS identity and capabilities.</summary>
public sealed class MikrotikSystemInfo
{
	/// <summary>System identity (router name).</summary>
	public string Identity { get; set; } = string.Empty;

	/// <summary>RouterOS version string (e.g. "7.15.3").</summary>
	public string Version { get; set; } = string.Empty;

	/// <summary>Board / model name (e.g. "RB5009UG+S+").</summary>
	public string BoardName { get; set; } = string.Empty;

	/// <summary>CPU architecture (e.g. "arm64").</summary>
	public string Architecture { get; set; } = string.Empty;

	/// <summary>Reported uptime string.</summary>
	public string Uptime { get; set; } = string.Empty;

	/// <summary>True when the RouterOS major version is 7 or greater (RAW chain + modern cert syntax).</summary>
	public bool SupportsRawChain { get; set; }
}

/// <summary>Gathers read-only RouterOS system information.</summary>
public sealed class SystemInfoCollector
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Collects identity, version, board, architecture and uptime over the supplied client.</summary>
	public async Task<MikrotikSystemInfo> CollectAsync(RouterOsApiClient client, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(client);
		MikrotikSystemInfo info = new();

		RouterOsResult identity = await client.ExecuteAsync("/system/identity/print", Array.Empty<string>(), ct).ConfigureAwait(false);
		if (identity.Succeeded && identity.Rows.Count > 0 && identity.Rows[0].TryGetValue("name", out string? name))
		{
			info.Identity = name;
		}

		RouterOsResult resource = await client.ExecuteAsync("/system/resource/print", Array.Empty<string>(), ct).ConfigureAwait(false);
		if (resource.Succeeded && resource.Rows.Count > 0)
		{
			IReadOnlyDictionary<string, string> row = resource.Rows[0];
			info.Version = row.GetValueOrDefault("version", string.Empty);
			info.BoardName = row.GetValueOrDefault("board-name", string.Empty);
			info.Architecture = row.GetValueOrDefault("architecture-name", string.Empty);
			info.Uptime = row.GetValueOrDefault("uptime", string.Empty);
		}

		info.SupportsRawChain = MajorVersionAtLeast(info.Version, 7);
		return info;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static bool MajorVersionAtLeast(string version, int minimumMajor)
	{
		if (string.IsNullOrWhiteSpace(version))
		{
			return false;
		}

		int dot = version.IndexOf('.', StringComparison.Ordinal);
		string majorText = dot > 0 ? version[..dot] : version;
		return int.TryParse(majorText, out int major) && major >= minimumMajor;
	}
}
