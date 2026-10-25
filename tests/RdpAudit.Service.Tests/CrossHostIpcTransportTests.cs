/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostIpcTransportTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Transport-level tests for the cross-host named-pipe transport: ExchangeAsync
//          round-trips an IpcRequest/IpcResponse frame against an in-process echo pipe with the
//          same 4-byte LE framing the Configurator client and the IpcServerWorker use. The
//          envelope is MessagePack; the payload inside it is a JSON string (the same convention
//          the existing Configurator->Service channel uses).
// Depends: ICrossHostIpcTransport, NamedPipeCrossHostIpcTransport, IpcRequest, IpcResponse, xUnit
// Extends: Add a test whenever the transport begins to mutate or cache DTOs.

using System.IO.Pipes;
using MessagePack;
using RdpAudit.Core.Ipc;
using RdpAudit.Service.CrossHost;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Transport-level tests for the cross-host named-pipe transport.</summary>
public sealed class CrossHostIpcTransportTests
{
	private const string PipePrefix = "RdpAuditTest-";
	private const string RequestJson = "{\"sinceUtc\":null,\"maxFacts\":10}";

	[Fact]
	public async Task ExchangeAsync_ReturnsEchoedPayload()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeAsync(server, serverCts.Token);

			try
			{
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport { PipeName = pipeName };
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
				IpcResponse response = await transport.ExchangeAsync(BuildRequest(), clientCts.Token);

				Assert.True(response.Success);
				Assert.Equal("{\"status\":0,\"latestFactUtc\":null,\"facts\":[]}", response.Payload);
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	[Fact]
	public async Task ExchangeAsync_WhenServerReportsError_ReturnsErrorResponse()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeErrorAsync(server, "host unreachable", serverCts.Token);

			try
			{
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport { PipeName = pipeName };
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
				IpcResponse response = await transport.ExchangeAsync(BuildRequest(), clientCts.Token);

				Assert.False(response.Success);
				Assert.Equal("host unreachable", response.Error);
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	[Fact]
	public async Task ExchangeAsync_HostNameRoutesToRemoteServer()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeAsync(server, serverCts.Token);

			try
			{
				// Same-pipe connection with an explicit server name ("." is this machine). The
				// transport must address the remote agent by host name, not hardcode the local box.
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport
				{
					PipeName = pipeName,
					HostName = ".",
				};
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
				IpcResponse response = await transport.ExchangeAsync(BuildRequest(), clientCts.Token);

				Assert.True(response.Success);
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	[Fact]
	public async Task ExchangeAsync_WhenCancelled_ThrowsOperationCanceledException()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeSlowAsync(server, serverCts.Token);

			try
			{
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport { PipeName = pipeName };
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
				await Assert.ThrowsAsync<OperationCanceledException>(
					async () => await transport.ExchangeAsync(BuildRequest(), clientCts.Token));
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	[Fact]
	public async Task ExchangeAsync_DisconnectedPipe_ThrowsIOException()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeDisconnectAsync(server, serverCts.Token);

			try
			{
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport { PipeName = pipeName };
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
				await Assert.ThrowsAsync<IOException>(
					async () => await transport.ExchangeAsync(BuildRequest(), clientCts.Token));
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	[Fact]
	public async Task ExchangeAsync_ServerRejectsOversizedFrame_ThrowsIOException()
	{
		(NamedPipeServerStream server, string pipeName) = CreateServer();
		using (server)
		{
			using CancellationTokenSource serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
			Task serveTask = ServeBadLengthAsync(server, serverCts.Token);

			try
			{
				ICrossHostIpcTransport transport = new NamedPipeCrossHostIpcTransport { PipeName = pipeName };
				using CancellationTokenSource clientCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
				await Assert.ThrowsAsync<IOException>(
					async () => await transport.ExchangeAsync(BuildRequest(), clientCts.Token));
			}
			finally
			{
				serverCts.Cancel();
				await SwallowAsync(serveTask);
			}
		}
	}

	// ── helpers ───────────────────────────────────────────────────────────────

	private static IpcRequest BuildRequest()
		=> new IpcRequest { Command = IpcCommand.GetCrossHostFacts, Payload = RequestJson };

	private static (NamedPipeServerStream Server, string PipeName) CreateServer()
	{
		string pipeName = PipePrefix + Guid.NewGuid().ToString("N");
		NamedPipeServerStream server = new(
			pipeName,
			PipeDirection.InOut,
			1,
			PipeTransmissionMode.Byte,
			PipeOptions.Asynchronous);
		return (server, pipeName);
	}

	private static async Task SwallowAsync(Task task)
	{
		try
		{
			await task;
		}
		catch (OperationCanceledException)
		{
			// expected
		}
		catch (IOException)
		{
			// expected when the client tears the pipe down
		}
	}

	private static async Task ServeAsync(NamedPipeServerStream server, CancellationToken ct)
	{
		await server.WaitForConnectionAsync(ct);
		while (!ct.IsCancellationRequested)
		{
			IpcRequest? request = await ReadRequestAsync(server, ct);
			if (request is null)
			{
				return;
			}

			await WriteResponseAsync(server, new IpcResponse
			{
				Success = true,
				Error = null,
				Payload = "{\"status\":0,\"latestFactUtc\":null,\"facts\":[]}",
			}, ct);
		}
	}

	private static async Task ServeErrorAsync(NamedPipeServerStream server, string error, CancellationToken ct)
	{
		await server.WaitForConnectionAsync(ct);
		while (!ct.IsCancellationRequested)
		{
			IpcRequest? request = await ReadRequestAsync(server, ct);
			if (request is null)
			{
				return;
			}

			await WriteResponseAsync(server, new IpcResponse
			{
				Success = false,
				Error = error,
				Payload = null,
			}, ct);
		}
	}

	private static async Task ServeSlowAsync(NamedPipeServerStream server, CancellationToken ct)
	{
		await server.WaitForConnectionAsync(ct);
		await Task.Delay(TimeSpan.FromSeconds(10), ct);
	}

	private static async Task ServeDisconnectAsync(NamedPipeServerStream server, CancellationToken ct)
	{
		await server.WaitForConnectionAsync(ct);
		await Task.Delay(TimeSpan.FromMilliseconds(100), ct);
		await server.DisposeAsync();
	}

	private static async Task ServeBadLengthAsync(NamedPipeServerStream server, CancellationToken ct)
	{
		await server.WaitForConnectionAsync(ct);
		await ReadRequestAsync(server, ct);
		await server.WriteAsync(BitConverter.GetBytes(IpcConstants.MaxFrameBytes + 1024), ct);
		await server.FlushAsync(ct);
		await Task.Delay(TimeSpan.FromMilliseconds(200), ct);
		await server.DisposeAsync();
	}

	private static async Task<IpcRequest?> ReadRequestAsync(NamedPipeServerStream server, CancellationToken ct)
	{
		byte[] lenBuf = new byte[4];
		int read = await server.ReadAsync(lenBuf.AsMemory(0, 4), ct);
		if (read == 0)
		{
			ct.ThrowIfCancellationRequested();
			return null;
		}

		while (read < 4)
		{
			int extra = await server.ReadAsync(lenBuf.AsMemory(read, 4 - read), ct);
			if (extra == 0)
			{
				return null;
			}

			read += extra;
		}

		int len = BitConverter.ToInt32(lenBuf);
		if (len <= 0 || len > IpcConstants.MaxFrameBytes)
		{
			throw new InvalidDataException("Bad frame length");
		}

		byte[] payload = new byte[len];
		await server.ReadExactlyAsync(payload, ct);
		return MessagePackSerializer.Deserialize<IpcRequest>(payload, cancellationToken: ct);
	}

	private static async Task WriteResponseAsync(NamedPipeServerStream server, IpcResponse response, CancellationToken ct)
	{
		byte[] bytes = MessagePackSerializer.Serialize(response, cancellationToken: ct);
		await server.WriteAsync(BitConverter.GetBytes(bytes.Length), ct);
		await server.WriteAsync(bytes, ct);
		await server.FlushAsync(ct);
	}
}
