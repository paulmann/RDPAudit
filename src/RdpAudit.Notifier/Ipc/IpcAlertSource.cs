// File:    src/RdpAudit.Notifier/Ipc/IpcAlertSource.cs
// Module:  RdpAudit.Notifier.Ipc
// Purpose: Read-only named-pipe client used by the tray notifier. Pulls effective notification
//          settings (IPC 78) and recent alerts (IPC 3) from the running service. Every failure
//          maps to null so the polling loop degrades silently instead of throwing.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO.Pipes;
using System.Text.Json;
using MessagePack;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Notifier.Ipc;

/// <summary>Read-only named-pipe client used by the tray notifier.</summary>
public sealed class IpcAlertSource : IAlertSource
{
	private static readonly JsonSerializerOptions Json = JsonOptions.Default;

	public async Task<NotificationSettingsDto?> FetchSettingsAsync(CancellationToken ct)
	{
		IpcResponse response = await ExchangeAsync(IpcCommand.GetNotificationSettings, null, ct).ConfigureAwait(false);
		if (!response.Success || response.Payload is null)
		{
			return null;
		}

		return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload, Json);
	}

	public async Task<List<Alert>?> FetchRecentAlertsAsync(CancellationToken ct)
	{
		IpcResponse response = await ExchangeAsync(IpcCommand.GetRecentAlerts, null, ct).ConfigureAwait(false);
		if (!response.Success || response.Payload is null)
		{
			return null;
		}

		return JsonSerializer.Deserialize<List<Alert>>(response.Payload, Json);
	}

	private static async Task<IpcResponse> ExchangeAsync(IpcCommand command, object? payload, CancellationToken ct)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.OperationTimeoutMs));

		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token).ConfigureAwait(false);

			IpcRequest request = new()
			{
				Command = command,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, Json),
			};

			byte[] reqBytes = MessagePackSerializer.Serialize(request, global::RdpAudit.Core.Ipc.IpcConstants.SerializerOptions, cancellationToken: cts.Token);
			await pipe.WriteAsync(BitConverter.GetBytes(reqBytes.Length), cts.Token).ConfigureAwait(false);
			await pipe.WriteAsync(reqBytes, cts.Token).ConfigureAwait(false);
			await pipe.FlushAsync(cts.Token).ConfigureAwait(false);

			byte[] lenBuf = new byte[4];
			await pipe.ReadExactlyAsync(lenBuf, cts.Token).ConfigureAwait(false);
			int len = BitConverter.ToInt32(lenBuf);
			if (len <= 0 || len > IpcConstants.MaxFrameBytes)
			{
				return new IpcResponse { Success = false, Error = "Service returned an empty or oversized response frame." };
			}

			byte[] respBytes = new byte[len];
			await pipe.ReadExactlyAsync(respBytes, cts.Token).ConfigureAwait(false);
			return MessagePackSerializer.Deserialize<IpcResponse>(respBytes, global::RdpAudit.Core.Ipc.IpcConstants.SerializerOptions, cancellationToken: cts.Token);
		}
		catch (OperationCanceledException) when (!ct.IsCancellationRequested)
		{
			return new IpcResponse { Success = false, Error = "IPC request timed out." };
		}
		catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException or MessagePackSerializationException or JsonException)
		{
			return new IpcResponse { Success = false, Error = "IPC transport error: " + ex.Message };
		}
	}
}
