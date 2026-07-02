// File:    src/RdpAudit.Configurator/Ipc/IpcClient.cs
// Module:  RdpAudit.Configurator.Ipc
// Purpose: Async named-pipe IPC client with per-command hard timeouts. Exposes three call shapes:
//          SendAsync<T> (legacy, collapses any failure to default for callers that only need a
//          value), SendRawAsync (success flag + curated error + raw payload), and SendDetailedAsync<T>
//          (the structured IpcCallResult<T> that distinguishes connect-failed / timeout / service-error
//          / transport-error / null-payload from a real success, with command-level tracing). The
//          per-command deadline comes from IpcConstants.TimeoutMsFor so long firewall / Tools Diag
//          operations are not abandoned mid-flight and misreported as a dead service.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.2

using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using MessagePack;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Ipc;

/// <summary>
/// Outcome of a raw IPC round-trip. Unlike <see cref="IpcClient.SendAsync{T}"/> (which collapses
/// every failure to <c>default</c>), this preserves the service-supplied <see cref="Error"/> so the
/// caller can surface a precise status message instead of a bare "FAILED".
/// </summary>
/// <param name="Success">True when the service reported success.</param>
/// <param name="Error">Curated error text from the service, or a transport-failure description.</param>
/// <param name="Payload">Raw JSON payload when present.</param>
public readonly record struct IpcRawResult(bool Success, string? Error, string? Payload);

/// <summary>Async named-pipe IPC client with per-command hard timeouts.</summary>
public sealed class IpcClient
{
	public async Task<T?> SendAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
	{
		IpcCallResult<T> result = await SendDetailedAsync<T>(command, payload, ct).ConfigureAwait(false);
		return result.IsSuccess ? result.Value : default;
	}

	/// <summary>
	/// Sends <paramref name="command"/> and returns the full service result (success flag, curated
	/// error text, raw payload). Transport failures are mapped to a non-success result with a
	/// descriptive error rather than being swallowed, so callers can show why a mutation failed.
	/// </summary>
	public async Task<IpcRawResult> SendRawAsync(IpcCommand command, object? payload = null, CancellationToken ct = default)
	{
		int timeoutMs = IpcConstants.TimeoutMsFor(command);
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));

		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token).ConfigureAwait(false);

			IpcResponse response = await ExchangeAsync(pipe, command, payload, cts.Token).ConfigureAwait(false);
			return new IpcRawResult(response.Success, response.Error, response.Payload);
		}
		catch (OperationCanceledException)
		{
			return new IpcRawResult(false, "Request timed out before the service responded.", null);
		}
		catch (TimeoutException)
		{
			return new IpcRawResult(false, "Timed out connecting to the service named pipe.", null);
		}
		catch (IOException ex)
		{
			return new IpcRawResult(false, "IPC transport error: " + ex.Message, null);
		}
	}

	/// <summary>Sends <paramref name="command"/> and returns a structured <see cref="IpcCallResult{T}"/>
	/// that distinguishes every failure mode (connect-failed / timeout / service-error / transport-error /
	/// null-payload) from a real success, with command-level tracing. The per-command deadline is taken
	/// from <see cref="IpcConstants.TimeoutMsFor"/>. Never throws.</summary>
	public async Task<IpcCallResult<T>> SendDetailedAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
	{
		int timeoutMs = IpcConstants.TimeoutMsFor(command);
		DateTime startUtc = DateTime.UtcNow;
		Stopwatch sw = Stopwatch.StartNew();
		bool connected = false;

		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));

		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			try
			{
				await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token).ConfigureAwait(false);
				connected = true;
			}
			catch (TimeoutException)
			{
				return Fail<T>(command, IpcCallOutcome.ConnectFailed, "The service named pipe is not accepting connections (service stopped or not installed).", nameof(TimeoutException), startUtc, sw, timeoutMs, connected, false);
			}
			catch (OperationCanceledException) when (!ct.IsCancellationRequested)
			{
				return Fail<T>(command, IpcCallOutcome.ConnectFailed, "Timed out connecting to the service named pipe (service stopped or not installed).", nameof(TimeoutException), startUtc, sw, timeoutMs, connected, false);
			}
			catch (UnauthorizedAccessException ex)
			{
				// Pipe exists but ACL blocks this client, or an AV/EDR product (Kaspersky KLIF)
				// is intercepting the named pipe. Run the Configurator as Administrator.
				return Fail<T>(command, IpcCallOutcome.ConnectFailed,
					"Access denied connecting to named pipe — run the Configurator as Administrator, " +
					"or check if an AV/EDR product is intercepting named pipes. Detail: " + ex.Message,
					nameof(UnauthorizedAccessException), startUtc, sw, timeoutMs, connected, false);
			}
			catch (IOException ex) when (!connected)
			{
				// Named pipe exists but connect failed (access-denied variant, Kaspersky interception,
				// or broken pipe before connected=true). Surfaces the exact OS message instead of
				// the generic "IPC transport error" the outer IOException catch would produce.
				return Fail<T>(command, IpcCallOutcome.ConnectFailed,
					"I/O error connecting to named pipe — possible AV/EDR interception. Detail: " + ex.Message,
					nameof(IOException), startUtc, sw, timeoutMs, connected, false);
			}

			IpcResponse response = await ExchangeAsync(pipe, command, payload, cts.Token).ConfigureAwait(false);

			if (!response.Success)
			{
				return Fail<T>(command, IpcCallOutcome.ServiceError, response.Error ?? "The service reported an error with no detail.", "ServiceError", startUtc, sw, timeoutMs, connected, true);
			}

			if (response.Payload is null)
			{
				return new IpcCallResult<T>(command, IpcCallOutcome.SuccessNoPayload, default, null, null, startUtc, sw.ElapsedMilliseconds, timeoutMs, connected, true);
			}

			T? value = JsonSerializer.Deserialize<T>(response.Payload, JsonOptions.Default);
			IpcCallResult<T> ok = new(command, IpcCallOutcome.Success, value, null, null, startUtc, sw.ElapsedMilliseconds, timeoutMs, connected, true);
			TraceRoundTrip(ok);
			return ok;
		}
		catch (OperationCanceledException)
		{
			// Connected==false here means connect itself was cancelled by the caller's token; otherwise the
			// pipe connected and the post-connect exchange ran past the deadline (operation in progress).
			IpcCallOutcome outcome = connected ? IpcCallOutcome.Timeout : IpcCallOutcome.ConnectFailed;
			string message = connected
				? "The service is reachable but did not finish within the timeout (an operation may still be in progress)."
				: "Connection to the service was cancelled before it completed.";
			return Fail<T>(command, outcome, message, nameof(OperationCanceledException), startUtc, sw, timeoutMs, connected, false);
		}
		catch (TimeoutException)
		{
			return Fail<T>(command, IpcCallOutcome.ConnectFailed, "Timed out connecting to the service named pipe (service stopped or not installed).", nameof(TimeoutException), startUtc, sw, timeoutMs, connected, false);
		}
		catch (IOException ex)
		{
			return Fail<T>(command, IpcCallOutcome.TransportError, "IPC transport error: " + ex.Message, nameof(IOException), startUtc, sw, timeoutMs, connected, false);
		}
		catch (MessagePackSerializationException ex)
		{
			return Fail<T>(command, IpcCallOutcome.TransportError, "Failed to deserialize the service response: " + ex.Message, nameof(MessagePackSerializationException), startUtc, sw, timeoutMs, connected, false);
		}
		catch (JsonException ex)
		{
			return Fail<T>(command, IpcCallOutcome.TransportError, "Failed to parse the service payload: " + ex.Message, nameof(JsonException), startUtc, sw, timeoutMs, connected, false);
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

	private static IpcCallResult<T> Fail<T>(
		IpcCommand command, IpcCallOutcome outcome, string message, string errorType, DateTime startUtc,
		Stopwatch sw, int timeoutMs, bool connected, bool responseReceived)
	{
		IpcCallResult<T> result = new(command, outcome, default, message, errorType, startUtc, sw.ElapsedMilliseconds, timeoutMs, connected, responseReceived);
		TraceRoundTrip(result);
		return result;
	}

	// v1.4.1: Emit a per-command round-trip trace to the debugger output for an attached-debugger
	// session (see SKILL "Debug Conventions"). This is in addition to the server-side OperationLog
	// DEBUG entries written by IpcDispatcher when Diagnostics.DebugMode is enabled; the client side
	// has no access to that runtime flag, so [Conditional("DEBUG")] keeps this free in Release builds.
	[Conditional("DEBUG")]
	private static void TraceRoundTrip<T>(IpcCallResult<T> result)
		=> Debug.WriteLine("[IpcClient] " + result.TraceLine);

	public async Task<bool> PingAsync(CancellationToken ct = default)
	{
		IpcCallResult<string> result = await SendDetailedAsync<string>(IpcCommand.Ping, null, ct).ConfigureAwait(false);
		return result.IsSuccess;
	}
}
