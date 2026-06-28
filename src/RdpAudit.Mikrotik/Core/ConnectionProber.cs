/*
 * File   : ConnectionProber.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Probes the candidate RouterOS management ports (SSH 22, API 8728, API-SSL 8729,
 *          WebFig/HTTPS 443) in parallel with a bounded per-port timeout, so the wizard can tell
 *          the operator which connection methods the router actually exposes and recommend the
 *          secure path (api-ssl for production, SSH only for bootstrap).
 * Depends: System.Net.Sockets.TcpClient
 * Extends: To probe an additional RouterOS service, add a MikrotikPort entry and include it in the
 *          default port set passed to ProbeAsync; the recommendation logic lives in BuildSummary.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Net.Sockets;

namespace RdpAudit.Mikrotik.Core;

/// <summary>A single RouterOS management port and its human-readable role.</summary>
/// <param name="Port">TCP port number.</param>
/// <param name="Service">Service name (e.g. "api-ssl").</param>
/// <param name="Secure">True when the port carries a TLS-protected protocol.</param>
public sealed record MikrotikPort(int Port, string Service, bool Secure)
{
	/// <summary>The default set of ports the wizard probes.</summary>
	public static IReadOnlyList<MikrotikPort> Defaults { get; } = new[]
	{
		new MikrotikPort(22, "ssh", true),
		new MikrotikPort(8728, "api", false),
		new MikrotikPort(8729, "api-ssl", true),
		new MikrotikPort(443, "https", true),
	};
}

/// <summary>Result of probing one port.</summary>
/// <param name="Port">The probed port descriptor.</param>
/// <param name="Open">True when the TCP connect succeeded within the timeout.</param>
/// <param name="ElapsedMs">How long the probe took, in milliseconds.</param>
public sealed record PortProbeResult(MikrotikPort Port, bool Open, long ElapsedMs);

/// <summary>Aggregated probe summary plus the recommended bootstrap / production methods.</summary>
/// <param name="Results">Per-port outcomes.</param>
/// <param name="ApiSslAvailable">True when port 8729 is open.</param>
/// <param name="SshAvailable">True when port 22 is open.</param>
/// <param name="Recommendation">Operator-facing recommendation text.</param>
public sealed record ConnectionProbeSummary(
	IReadOnlyList<PortProbeResult> Results,
	bool ApiSslAvailable,
	bool SshAvailable,
	string Recommendation);

/// <summary>Probes RouterOS management ports in parallel.</summary>
public sealed class ConnectionProber
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Probes <paramref name="ports"/> (defaults to <see cref="MikrotikPort.Defaults"/>) on
	/// <paramref name="host"/> in parallel with a <paramref name="timeoutMs"/> per-port deadline and
	/// returns a summary including a secure-path recommendation. Never throws.
	/// </summary>
	public async Task<ConnectionProbeSummary> ProbeAsync(
		string host,
		IReadOnlyList<MikrotikPort>? ports = null,
		int timeoutMs = 3_000,
		CancellationToken ct = default)
	{
		IReadOnlyList<MikrotikPort> targets = ports is { Count: > 0 } ? ports : MikrotikPort.Defaults;

		IEnumerable<Task<PortProbeResult>> probes = targets.Select(p => ProbeOneAsync(host, p, timeoutMs, ct));
		PortProbeResult[] results = await Task.WhenAll(probes).ConfigureAwait(false);

		return BuildSummary(results);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static async Task<PortProbeResult> ProbeOneAsync(string host, MikrotikPort port, int timeoutMs, CancellationToken ct)
	{
		long start = Environment.TickCount64;
		using TcpClient tcp = new();

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(timeoutMs);

		try
		{
			await tcp.ConnectAsync(host, port.Port, cts.Token).ConfigureAwait(false);
			return new PortProbeResult(port, tcp.Connected, Environment.TickCount64 - start);
		}
		catch (OperationCanceledException)
		{
			return new PortProbeResult(port, false, Environment.TickCount64 - start);
		}
		catch (SocketException)
		{
			return new PortProbeResult(port, false, Environment.TickCount64 - start);
		}
	}

	internal static ConnectionProbeSummary BuildSummary(IReadOnlyList<PortProbeResult> results)
	{
		bool apiSsl = results.Any(r => r.Open && r.Port.Port == 8729);
		bool ssh = results.Any(r => r.Open && r.Port.Port == 22);

		string recommendation;
		if (apiSsl && ssh)
		{
			recommendation = "SSH is available for one-time bootstrap; api-ssl (8729) is available for the secure production channel.";
		}
		else if (ssh && !apiSsl)
		{
			recommendation = "SSH is available for bootstrap. api-ssl (8729) is not yet open — the wizard will enable it during bootstrap.";
		}
		else if (apiSsl && !ssh)
		{
			recommendation = "api-ssl (8729) is open but SSH (22) is closed — bootstrap requires SSH access; enable it or use an already-bootstrapped router.";
		}
		else
		{
			recommendation = "Neither SSH (22) nor api-ssl (8729) is reachable — verify the router IP, firewall and that the services are enabled.";
		}

		return new ConnectionProbeSummary(results, apiSsl, ssh, recommendation);
	}
}
