/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : NamedPipeIpcTransport.cs
// Project: RdpAudit.Service (RdpAudit.Service.CrossHost)
// Purpose: Raw named-pipe request/response seam for the P4-18 pull transport. The central
//          service sends an IpcRequest frame to the agent host admin-only pipe and returns the
//          raw IpcResponse. Wire format matches the Configurator client: 4-byte LE frame length
//          followed by a MessagePack envelope whose Payload is a JSON string. The transport
//          carries no correlation logic: callers own DTO parsing and fail-closed handling.
// Depends: IpcCommand, IpcConstants, IpcRequest, IpcResponse, MessagePack
// Extends: Add a new transport only when a different IPC medium is introduced.

using System.IO.Pipes;
using MessagePack;
using RdpAudit.Core.Ipc;

namespace RdpAudit.Service.CrossHost;

/// <summary>Raw request/response seam for the agent-host named pipe.</summary>
public interface ICrossHostIpcTransport
{
	/// <summary>Agent host this transport targets (server name for the pipe).</summary>
	string HostName { get; }

	/// <summary>Sends one request frame and returns the raw response envelope. I/O failures
	/// (timeout, broken pipe, malformed frame) propagate as exceptions.</summary>
	Task<IpcResponse> ExchangeAsync(IpcRequest request, CancellationToken ct);
}

/// <summary>Named-pipe implementation of <see cref="ICrossHostIpcTransport"/>. Per-command
/// deadlines come from <see cref="IpcConstants.TimeoutMsFor"/> so a vanished agent never blocks
/// the correlation worker beyond budget.</summary>
public sealed class NamedPipeCrossHostIpcTransport : ICrossHostIpcTransport
{
	/// <summary>Pipe name to connect to; tests override with a unique test pipe.</summary>
	public string PipeName { get; init; } = IpcConstants.PipeName;

	/// <summary>Connect timeout override; null uses <see cref="IpcConstants.ConnectTimeoutMs"/>.</summary>
	public int? ConnectTimeoutMs { get; init; }

	/// <inheritdoc/>
	public string HostName { get; init; } = string.Empty;

	/// <inheritdoc/>
	public async Task<IpcResponse> ExchangeAsync(IpcRequest request, CancellationToken ct)
	{
		int connectTimeout = ConnectTimeoutMs ?? IpcConstants.ConnectTimeoutMs;
		using (CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
		{
			timeoutCts.CancelAfter(IpcConstants.TimeoutMsFor(request.Command));

			try
			{
				string serverName = string.IsNullOrWhiteSpace(HostName) ? "." : HostName;
				await using NamedPipeClientStream pipe = new(serverName, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
				await pipe.ConnectAsync(connectTimeout, timeoutCts.Token).ConfigureAwait(false);
				return await ExchangeFrameAsync(pipe, request, timeoutCts.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (!ct.IsCancellationRequested)
			{
				throw new TimeoutException("Timed out talking to the agent host named pipe.");
			}
		}
	}

	private static async Task<IpcResponse> ExchangeFrameAsync(NamedPipeClientStream pipe, IpcRequest request, CancellationToken token)
	{
		byte[] reqBytes = MessagePackSerializer.Serialize(request, global::RdpAudit.Core.Ipc.IpcConstants.SerializerOptions, cancellationToken: token);
		await pipe.WriteAsync(BitConverter.GetBytes(reqBytes.Length), token).ConfigureAwait(false);
		await pipe.WriteAsync(reqBytes, token).ConfigureAwait(false);
		await pipe.FlushAsync(token).ConfigureAwait(false);

		byte[] lenBuf = new byte[4];
		await pipe.ReadExactlyAsync(lenBuf, token).ConfigureAwait(false);
		int len = BitConverter.ToInt32(lenBuf);
		if (len <= 0 || len > IpcConstants.MaxFrameBytes)
		{
			throw new IOException("Agent host returned an empty or oversized response frame.");
		}

		byte[] respBytes = new byte[len];
		await pipe.ReadExactlyAsync(respBytes, token).ConfigureAwait(false);
		return MessagePackSerializer.Deserialize<IpcResponse>(respBytes, global::RdpAudit.Core.Ipc.IpcConstants.SerializerOptions, cancellationToken: token);
	}
}
