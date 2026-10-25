// File:    src/RdpAudit.Core/Config/CrossHostOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for P4-18 cross-host correlation transport and polling. The central
//          service pulls fact projections from the configured agent hosts over the existing
//          admin-only named-pipe channel. Correlation thresholds live in
//          CrossHostChainRule (data in the assembly, pinned by tests); this section only carries
//          the polling schedule, connection budget, per-poll bounds and the agent host list.
//          Host credentials, when present, must be protected envelopes (ISecretProtector) -
//          plaintext must NEVER appear on disk, in logs or in IPC payloads.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the cross-host correlation feature (pull transport + polling).</summary>
public sealed class CrossHostOptions
{
	/// <summary>Default poll interval in seconds.</summary>
	public const int DefaultPollIntervalSeconds = 60;

	/// <summary>Default named-pipe connect timeout in milliseconds.</summary>
	public const int DefaultConnectTimeoutMs = 5_000;

	/// <summary>Default maximum facts accepted from one host per poll.</summary>
	public const int DefaultMaxFactsPerPoll = 1_000;

	public const int MinPollIntervalSeconds = 10;

	public const int MaxPollIntervalSeconds = 3_600;

	public const int MinConnectTimeoutMs = 100;

	public const int MaxConnectTimeoutMs = 60_000;

	public const int MinMaxFactsPerPoll = 1;

	public const int MaxMaxFactsPerPoll = 100_000;

	/// <summary>Enables the cross-host correlation worker. Defaults to false: the feature is
	/// opt-in and never opens outbound connections until an operator configures it.</summary>
	public bool Enabled { get; set; }

	/// <summary>Agent hosts the central service pulls fact projections from.</summary>
	public List<CrossHostHostOptions> Hosts { get; set; } = new();

	/// <summary>Seconds between correlation polls. Clamped to
	/// <see cref="MinPollIntervalSeconds"/>..<see cref="MaxPollIntervalSeconds"/> at use site.</summary>
	public int PollIntervalSeconds { get; set; } = DefaultPollIntervalSeconds;

	/// <summary>Named-pipe connect timeout per host in milliseconds. Clamped to
	/// <see cref="MinConnectTimeoutMs"/>..<see cref="MaxConnectTimeoutMs"/> at use site; exceeding
	/// it marks the host Unavailable (fail-closed).</summary>
	public int ConnectTimeoutMs { get; set; } = DefaultConnectTimeoutMs;

	/// <summary>Maximum facts accepted from one host per poll. Clamped to
	/// <see cref="MinMaxFactsPerPoll"/>..<see cref="MaxMaxFactsPerPoll"/> at use site.</summary>
	public int MaxFactsPerPoll { get; set; } = DefaultMaxFactsPerPoll;

	/// <summary>Returns the configured poll interval clamped to the supported range.</summary>
	public int ResolvePollIntervalSeconds() => Math.Clamp(PollIntervalSeconds, MinPollIntervalSeconds, MaxPollIntervalSeconds);

	/// <summary>Returns the configured connect timeout clamped to the supported range.</summary>
	public int ResolveConnectTimeoutMs() => Math.Clamp(ConnectTimeoutMs, MinConnectTimeoutMs, MaxConnectTimeoutMs);

	/// <summary>Returns the configured per-poll fact cap clamped to the supported range.</summary>
	public int ResolveMaxFactsPerPoll() => Math.Clamp(MaxFactsPerPoll, MinMaxFactsPerPoll, MaxMaxFactsPerPoll);

	/// <summary>Returns the configured agent hosts with blank host names removed.</summary>
	public List<CrossHostHostOptions> ResolveHosts() =>
		Hosts.Where(h => !string.IsNullOrWhiteSpace(h.HostName))
			.Select(h => new CrossHostHostOptions { HostName = h.HostName.Trim(), Credential = h.Credential })
			.ToList();
}

/// <summary>One agent host the central service pulls cross-host fact projections from.</summary>
public sealed class CrossHostHostOptions
{
	/// <summary>Agent host name or IP literal used as the named-pipe server name.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>Optional protected envelope (ISecretProtector) holding credentials for reaching
	/// this host when domain / machine authentication is unavailable. Empty means "use the
	/// current account" (domain service account or machine account). Plaintext is never allowed.</summary>
	public string Credential { get; set; } = string.Empty;
}
