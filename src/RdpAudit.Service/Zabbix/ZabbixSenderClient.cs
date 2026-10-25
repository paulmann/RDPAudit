/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSenderClient.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: TCP client for the Zabbix sender protocol. One connection per batch, a bounded read for
//          the answer, and an explicit distinction between "no answer", "answered but rejected
//          everything" and "accepted". The socket is never shared: a stuck round-trip must not
//          poison the next one.
// Extends: System.Object

using System.Globalization;
using System.Net.Sockets;
using RdpAudit.Core.Zabbix;

namespace RdpAudit.Service.Zabbix;

/// <summary>Default <see cref="IZabbixSender"/> over a plain TCP socket.</summary>
public sealed class ZabbixSenderClient : IZabbixSender
{
	/// <inheritdoc />
	public async Task<ZabbixProbeResult> ProbeAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(host);
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		if (timeout > TimeSpan.Zero)
		{
			cts.CancelAfter(timeout);
		}

		try
		{
			using TcpClient client = new();
			await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
			return new ZabbixProbeResult(true, string.Format(
				CultureInfo.InvariantCulture,
				"TCP {0}:{1} accepted a connection.",
				host,
				port));
		}
		catch (OperationCanceledException) when (!ct.IsCancellationRequested)
		{
			return new ZabbixProbeResult(false, string.Format(
				CultureInfo.InvariantCulture,
				"Timed out connecting to {0}:{1} after {2:0.#} s. The trapper port is usually not exposed through NAT — forward TCP {1} to the Zabbix server or point the agent at a proxy.",
				host,
				port,
				timeout.TotalSeconds));
		}
		catch (SocketException ex)
		{
			return new ZabbixProbeResult(false, string.Format(
				CultureInfo.InvariantCulture,
				"Cannot reach {0}:{1} — {2}. Forward TCP {1} from this machine to the Zabbix server, or configure a proxy.",
				host,
				port,
				ex.SocketErrorCode));
		}
	}

	/// <inheritdoc />
	public async Task<ZabbixSenderOutcome> SendAsync(
		string host,
		int port,
		IReadOnlyList<ZabbixValue> values,
		TimeSpan timeout,
		CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(host);
		ArgumentNullException.ThrowIfNull(values);
		if (values.Count == 0)
		{
			return new ZabbixSenderOutcome(false, 0, 0, 0, "Nothing to send: the batch is empty.", string.Empty);
		}

		string requestJson;
		try
		{
			requestJson = ZabbixSenderProtocol.BuildRequestJson(values, DateTime.UtcNow);
		}
		catch (ArgumentException ex)
		{
			return new ZabbixSenderOutcome(false, 0, 0, 0, "The batch could not be serialized: " + ex.Message, string.Empty);
		}

		byte[] frame = ZabbixSenderProtocol.BuildFrame(requestJson);

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		if (timeout > TimeSpan.Zero)
		{
			cts.CancelAfter(timeout);
		}

		try
		{
			using TcpClient client = new();
			await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
			await using NetworkStream stream = client.GetStream();

			await stream.WriteAsync(frame, cts.Token).ConfigureAwait(false);
			await stream.FlushAsync(cts.Token).ConfigureAwait(false);

			byte[] prefix = new byte[ZabbixSenderProtocol.HeaderLength];
			await stream.ReadExactlyAsync(prefix, cts.Token).ConfigureAwait(false);
			if (!ZabbixSenderProtocol.TryReadHeader(prefix, out int length))
			{
				return new ZabbixSenderOutcome(false, 0, 0, values.Count,
					"The server did not answer in the Zabbix sender envelope (wrong port, proxy or TLS in between).",
					string.Empty);
			}

			byte[] body = new byte[length];
			await stream.ReadExactlyAsync(body, cts.Token).ConfigureAwait(false);
			string text = System.Text.Encoding.UTF8.GetString(body);
			return ZabbixSenderProtocol.ParseResponse(text);
		}
		catch (OperationCanceledException) when (!ct.IsCancellationRequested)
		{
			return new ZabbixSenderOutcome(false, 0, 0, values.Count, string.Format(
				CultureInfo.InvariantCulture,
				"No answer from {0}:{1} within {2:0.#} s; the batch will be retried on the next cycle.",
				host,
				port,
				timeout.TotalSeconds), string.Empty);
		}
		catch (SocketException ex)
		{
			return new ZabbixSenderOutcome(false, 0, 0, values.Count,
				"Transport error: " + ex.SocketErrorCode + ". The batch will be retried on the next cycle.", string.Empty);
		}
		catch (IOException ex)
		{
			return new ZabbixSenderOutcome(false, 0, 0, values.Count,
				"Connection dropped while the server was answering: " + ex.Message, string.Empty);
		}
	}
}
