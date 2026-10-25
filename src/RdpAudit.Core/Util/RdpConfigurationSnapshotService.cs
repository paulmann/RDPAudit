// File:    src/RdpAudit.Core/Util/RdpConfigurationSnapshotService.cs
// Module:  RdpAudit.Core.Util
// Purpose: Orchestrates the two-tier read strategy for the "RDP Configuration" tab — first try
//          the RdpAudit service over IPC, then fall back to an in-process direct read when IPC
//          returns null, times out, or reports a non-success status. The orchestrator accepts
//          plain delegates so it lives in Core (no Windows.Forms / pipe-client dependency) and
//          can be unit-tested without a live named pipe or registry under test.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Two-tier snapshot orchestrator: prefers IPC, falls back to in-process registry read.</summary>
public sealed class RdpConfigurationSnapshotService
{
	private readonly Func<CancellationToken, Task<RdpConfigurationDto?>> _ipcFetch;
	private readonly Func<RdpConfigurationDto> _localFetch;

	/// <summary>Construct with explicit fetch delegates. The Configurator wires this with the live
	/// <c>IpcClient</c> and <c>LocalRdpConfigurationProvider</c> at the call site; tests wire it
	/// with in-memory delegates that return canned values.</summary>
	public RdpConfigurationSnapshotService(
		Func<CancellationToken, Task<RdpConfigurationDto?>> ipcFetch,
		Func<RdpConfigurationDto> localFetch)
	{
		_ipcFetch = ipcFetch ?? throw new ArgumentNullException(nameof(ipcFetch));
		_localFetch = localFetch ?? throw new ArgumentNullException(nameof(localFetch));
	}

	/// <summary>Capture a snapshot. Always returns a non-null result; <see cref="RdpConfigurationSnapshotResult.HasSnapshot"/>
	/// is false only when both IPC and the local fallback fail.</summary>
	public async Task<RdpConfigurationSnapshotResult> CaptureAsync(CancellationToken ct = default)
	{
		RdpConfigurationDto? viaIpc = null;
		try
		{
			viaIpc = await _ipcFetch(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			// Treat cancellation/timeout like an absent service: try the local fallback below.
		}
		catch (IOException)
		{
			// IpcClient already swallows IOException internally; this guards alternate fetchers in tests.
		}

		if (viaIpc is not null && viaIpc.Status == IpcResultStatus.Success)
		{
			return new RdpConfigurationSnapshotResult(viaIpc, RdpConfigurationSnapshotSource.ServiceIpc, Error: null);
		}

		try
		{
			RdpConfigurationDto local = _localFetch();
			return new RdpConfigurationSnapshotResult(local, RdpConfigurationSnapshotSource.LocalFallback, Error: null);
		}
		catch (Exception ex)
		{
			return new RdpConfigurationSnapshotResult(
				Snapshot: null,
				Source: RdpConfigurationSnapshotSource.None,
				Error: ex.GetType().Name + ": " + ex.Message);
		}
	}
}
