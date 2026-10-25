/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IZabbixSender.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: Transport abstraction for the Zabbix sender protocol, so the push service can be exercised
//          without a listening socket and the socket client can be exercised without the service.
// Extends: System.Object

using RdpAudit.Core.Zabbix;

namespace RdpAudit.Service.Zabbix;

/// <summary>Result of a bare reachability probe of the trapper port.</summary>
/// <param name="Reachable">True when a TCP connection was established.</param>
/// <param name="Message">Human-readable detail, safe to show.</param>
public sealed record ZabbixProbeResult(bool Reachable, string Message);

/// <summary>Sends value batches to a Zabbix server or proxy.</summary>
public interface IZabbixSender
{
	/// <summary>Opens a connection to the trapper port and closes it, without sending a value.</summary>
	/// <param name="host">Server or proxy host name.</param>
	/// <param name="port">Trapper port.</param>
	/// <param name="timeout">Connection deadline.</param>
	/// <param name="ct">Cancellation token.</param>
	Task<ZabbixProbeResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct);

	/// <summary>Sends one batch and returns the server's accounting of it.</summary>
	/// <param name="host">Server or proxy host name.</param>
	/// <param name="port">Trapper port.</param>
	/// <param name="values">Values to send; must not be empty.</param>
	/// <param name="timeout">Round-trip deadline.</param>
	/// <param name="ct">Cancellation token.</param>
	Task<ZabbixSenderOutcome> SendAsync(
		string host,
		int port,
		IReadOnlyList<ZabbixValue> values,
		TimeSpan timeout,
		CancellationToken ct);
}
