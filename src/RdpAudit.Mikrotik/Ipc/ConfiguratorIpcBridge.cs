/*
 * File   : ConfiguratorIpcBridge.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ipc)
 * Purpose: Self-contained named-pipe IPC client that lets the MikroTik wizard hand its completed
 *          bootstrap to the running RdpAudit Service (PushMikroTikConfig) and read back the Service's
 *          mutual-TLS channel health (GetMikroTikMtlsStatus). It mirrors the Configurator's wire
 *          contract exactly — a 4-byte little-endian length prefix followed by a MessagePack
 *          IpcRequest/IpcResponse envelope whose Payload is a JSON string serialized with
 *          JsonOptions.Default — but depends only on RdpAudit.Core so the module stays independent of
 *          the Configurator assembly.
 * Depends: System.IO.Pipes.NamedPipeClientStream, MessagePack, RdpAudit.Core.Ipc.*,
 *          RdpAudit.Core.MikroTik.*, RdpAudit.Core.Util.JsonOptions
 * Extends: To call a new Service command, add a typed method that serializes the request payload and
 *          deserializes the reply; reuse ExchangeAsync for the framing so the wire stays canonical.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.IO.Pipes;
using System.Text.Json;
using MessagePack;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Util;

namespace RdpAudit.Mikrotik.Ipc;

/// <summary>Outcome of an IPC round-trip to the Service.</summary>
/// <param name="Success">True when the Service reported success.</param>
/// <param name="Error">Curated error text on failure, else null.</param>
public readonly record struct IpcBridgeResult(bool Success, string? Error);

/// <summary>Typed result carrying a deserialized payload.</summary>
/// <typeparam name="T">Payload type.</typeparam>
/// <param name="Success">True when the Service reported success and a payload was returned.</param>
/// <param name="Value">Deserialized payload, or default on failure / empty payload.</param>
/// <param name="Error">Curated error text on failure, else null.</param>
public readonly record struct IpcBridgeResult<T>(bool Success, T? Value, string? Error);

/// <summary>Thin named-pipe client bridging the MikroTik wizard to the RdpAudit Service.</summary>
public sealed class ConfiguratorIpcBridge
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Pushes the completed bootstrap configuration to the Service for adoption.</summary>
	public async Task<IpcBridgeResult> PushConfigAsync(MikrotikConfig config, string? note = null, CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(config);
		MikrotikConfigPushMessage message = new() { Config = config, Note = note };
		return await SendAsync(IpcCommand.PushMikroTikConfig, message, ct).ConfigureAwait(false);
	}

	/// <summary>Reads the Service's current mutual-TLS channel status.</summary>
	public async Task<IpcBridgeResult<MikrotikMtlsStatusReply>> GetMtlsStatusAsync(CancellationToken ct = default)
		=> await SendAsync<MikrotikMtlsStatusReply>(IpcCommand.GetMikroTikMtlsStatus, null, ct).ConfigureAwait(false);

	/// <summary>True when the Service named pipe accepts a connection (service running).</summary>
	public async Task<bool> IsServiceReachableAsync(CancellationToken ct = default)
	{
		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, ct).ConfigureAwait(false);
			return pipe.IsConnected;
		}
		catch (Exception ex) when (ex is TimeoutException or IOException or OperationCanceledException)
		{
			return false;
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static async Task<IpcBridgeResult> SendAsync(IpcCommand command, object? payload, CancellationToken ct)
	{
		IpcBridgeResult<string> raw = await SendAsync<string>(command, payload, ct).ConfigureAwait(false);
		return new IpcBridgeResult(raw.Success, raw.Error);
	}

	private static async Task<IpcBridgeResult<T>> SendAsync<T>(IpcCommand command, object? payload, CancellationToken ct)
	{
		int timeoutMs = IpcConstants.TimeoutMsFor(command);
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));

		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token).ConfigureAwait(false);

			IpcResponse response = await ExchangeAsync(pipe, command, payload, cts.Token).ConfigureAwait(false);
			if (!response.Success)
			{
				return new IpcBridgeResult<T>(false, default, response.Error ?? "The service reported an error with no detail.");
			}

			if (response.Payload is null)
			{
				return new IpcBridgeResult<T>(true, default, null);
			}

			T? value = JsonSerializer.Deserialize<T>(response.Payload, JsonOptions.Default);
			return new IpcBridgeResult<T>(true, value, null);
		}
		catch (OperationCanceledException)
		{
			return new IpcBridgeResult<T>(false, default, "The request timed out before the service responded.");
		}
		catch (TimeoutException)
		{
			return new IpcBridgeResult<T>(false, default, "Timed out connecting to the service named pipe (service stopped or not installed).");
		}
		catch (IOException ex)
		{
			return new IpcBridgeResult<T>(false, default, "IPC transport error: " + ex.Message);
		}
		catch (MessagePackSerializationException ex)
		{
			return new IpcBridgeResult<T>(false, default, "Failed to deserialize the service response: " + ex.Message);
		}
		catch (JsonException ex)
		{
			return new IpcBridgeResult<T>(false, default, "Failed to parse the service payload: " + ex.Message);
		}
	}

	private static async Task<IpcResponse> ExchangeAsync(NamedPipeClientStream pipe, IpcCommand command, object? payload, CancellationToken token)
	{
		IpcRequest request = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		byte[] reqBytes = MessagePackSerializer.Serialize(request, cancellationToken: token);
		await pipe.WriteAsync(BitConverter.GetBytes(reqBytes.Length), token).ConfigureAwait(false);
		await pipe.WriteAsync(reqBytes, token).ConfigureAwait(false);
		await pipe.FlushAsync(token).ConfigureAwait(false);

		byte[] lenBuf = new byte[4];
		await pipe.ReadExactlyAsync(lenBuf, token).ConfigureAwait(false);
		int len = BitConverter.ToInt32(lenBuf);
		if (len <= 0 || len > IpcConstants.MaxFrameBytes)
		{
			return new IpcResponse { Success = false, Error = "Service returned an empty or oversized response frame." };
		}

		byte[] respBytes = new byte[len];
		await pipe.ReadExactlyAsync(respBytes, token).ConfigureAwait(false);
		return MessagePackSerializer.Deserialize<IpcResponse>(respBytes, cancellationToken: token);
	}
}
