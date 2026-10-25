/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSenderClientTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Exercises the TCP client against a real loopback listener rather than a mocked socket, so
//          the frame layout, the read of the answer prefix and the accounting of a partial rejection
//          are proven end to end. The rejection case is the important one: measured on Zabbix 8.0.0,
//          the server answers {"response":"success"} with failed: N when it stored nothing.
// Extends: System.Object

using System.Net;
using System.Net.Sockets;
using System.Text;
using RdpAudit.Core.Zabbix;
using RdpAudit.Service.Zabbix;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Socket-level tests of <see cref="ZabbixSenderClient"/>.</summary>
public sealed class ZabbixSenderClientTests
{
	private static readonly ZabbixValue[] Batch =
	{
		new("win-a", "rdpaudit.agent.status", "1"),
		new("win-a", "rdpaudit.incidents.max_severity", "4"),
	};

	[Fact]
	public async Task SendAsync_ProviderAcceptsEveryValue_ReportsDelivered()
	{
		string seen = string.Empty;
		using TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;

		Task server = Task.Run(async () =>
		{
			using TcpClient client = await listener.AcceptTcpClientAsync();
			seen = await ReadRequestAsync(client);
			await AnswerAsync(client, "{\"response\":\"success\",\"info\":\"processed: 2; failed: 0; total: 2; seconds spent: 0.0001\"}")
				;
		});

		ZabbixSenderOutcome outcome = await new ZabbixSenderClient()
			.SendAsync("127.0.0.1", port, Batch, TimeSpan.FromSeconds(5), CancellationToken.None)
			;
		await server;

		Assert.True(outcome.Delivered);
		Assert.Equal(2, outcome.Processed);
		Assert.Equal(0, outcome.Failed);
		Assert.Contains("\"key\":\"rdpaudit.incidents.max_severity\"", seen, StringComparison.Ordinal);
		Assert.Contains("\"host\":\"win-a\"", seen, StringComparison.Ordinal);
		Assert.Contains("\"request\":\"sender data\"", seen, StringComparison.Ordinal);
	}

	[Fact]
	public async Task SendAsync_ServerRejectsTheBatch_IsNotDelivered()
	{
		using TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;

		Task server = Task.Run(async () =>
		{
			using TcpClient client = await listener.AcceptTcpClientAsync();
			_ = await ReadRequestAsync(client);
			await AnswerAsync(client, "{\"response\":\"success\",\"info\":\"processed: 0; failed: 2; total: 2; seconds spent: 0.0001\"}")
				;
		});

		ZabbixSenderOutcome outcome = await new ZabbixSenderClient()
			.SendAsync("127.0.0.1", port, Batch, TimeSpan.FromSeconds(5), CancellationToken.None)
			;
		await server;

		Assert.False(outcome.Delivered);
		Assert.Equal(2, outcome.Failed);
		Assert.Contains("rejected", outcome.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task SendAsync_ForeignAnswer_IsReportedAsProtocolFailure()
	{
		using TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;

		Task server = Task.Run(async () =>
		{
			using TcpClient client = await listener.AcceptTcpClientAsync();
			_ = await ReadRequestAsync(client);
			// An HTTP server on the wrong port answers like this.
			byte[] banner = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\n\r\n");
			await client.GetStream().WriteAsync(banner);
		});

		ZabbixSenderOutcome outcome = await new ZabbixSenderClient()
			.SendAsync("127.0.0.1", port, Batch, TimeSpan.FromSeconds(5), CancellationToken.None)
			;
		await server;

		Assert.False(outcome.ProtocolAccepted);
		Assert.False(outcome.Delivered);
	}

	[Fact]
	public async Task SendAsync_ClosedPort_IsNotDeliveredAndSaysSo()
	{
		// Nothing listens on this port: the client must report a transport failure, never a success.
		ZabbixSenderOutcome outcome = await new ZabbixSenderClient()
			.SendAsync("127.0.0.1", 1, Batch, TimeSpan.FromSeconds(2), CancellationToken.None)
			;

		Assert.False(outcome.Delivered);
		Assert.False(string.IsNullOrWhiteSpace(outcome.Message));
	}

	[Fact]
	public async Task SendAsync_EmptyBatch_IsRefusedWithoutTouchingTheNetwork()
	{
		ZabbixSenderOutcome outcome = await new ZabbixSenderClient()
			.SendAsync("127.0.0.1", 1, Array.Empty<ZabbixValue>(), TimeSpan.FromSeconds(2), CancellationToken.None)
			;

		Assert.False(outcome.Delivered);
		Assert.Contains("empty", outcome.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task ProbeAsync_ReachablePort_ReportsReachable()
	{
		using TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;
		Task server = Task.Run(async () =>
		{
			using TcpClient client = await listener.AcceptTcpClientAsync();
			await Task.Delay(50);
		});

		ZabbixProbeResult probe = await new ZabbixSenderClient()
			.ProbeAsync("127.0.0.1", port, TimeSpan.FromSeconds(5), CancellationToken.None)
			;
		await server;

		Assert.True(probe.Reachable);
	}

	[Fact]
	public async Task ProbeAsync_ClosedPort_NamesThePortInTheMessage()
	{
		ZabbixProbeResult probe = await new ZabbixSenderClient()
			.ProbeAsync("127.0.0.1", 1, TimeSpan.FromSeconds(2), CancellationToken.None)
			;

		Assert.False(probe.Reachable);
		Assert.Contains(":1", probe.Message, StringComparison.Ordinal);
	}

	private static async Task<string> ReadRequestAsync(TcpClient client)
	{
		NetworkStream stream = client.GetStream();
		byte[] prefix = new byte[ZabbixSenderProtocol.HeaderLength];
		await stream.ReadExactlyAsync(prefix);
		Assert.True(ZabbixSenderProtocol.TryReadHeader(prefix, out int length));
		byte[] body = new byte[length];
		await stream.ReadExactlyAsync(body);
		return Encoding.UTF8.GetString(body);
	}

	private static async Task AnswerAsync(TcpClient client, string body)
	{
		byte[] payload = Encoding.UTF8.GetBytes(body);
		byte[] prefix = new byte[ZabbixSenderProtocol.HeaderLength];
		"ZBXD\x01"u8.CopyTo(prefix);
		BitConverter.GetBytes((long)payload.Length).CopyTo(prefix, 5);
		NetworkStream stream = client.GetStream();
		await stream.WriteAsync(prefix);
		await stream.WriteAsync(payload);
		await stream.FlushAsync();
	}
}
