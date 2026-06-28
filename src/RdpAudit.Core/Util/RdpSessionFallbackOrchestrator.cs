// File:    src/RdpAudit.Core/Util/RdpSessionFallbackOrchestrator.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure two-tier session-list orchestrator for the Remote RDP Clients tab — prefer the
//          RdpAudit service over IPC, fall back to an in-process local enumerator when the
//          service is unreachable or returns no rows. Accepts plain delegates so it lives in
//          Core (no Windows.Forms / pipe-client dependency) and can be unit-tested without a
//          live named pipe or qwinsta invocation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Origin of an <see cref="RdpSessionListSnapshot"/>.</summary>
public enum RdpSessionListSource
{
	/// <summary>Neither IPC nor local fallback produced sessions.</summary>
	None = 0,

	/// <summary>The RdpAudit service returned a Success result.</summary>
	ServiceIpc = 1,

	/// <summary>The Configurator built the list locally; historical enrichment is unavailable.</summary>
	LocalFallback = 2,
}

/// <summary>Snapshot result returned by <see cref="RdpSessionFallbackOrchestrator"/>.</summary>
public sealed record RdpSessionListSnapshot(
	IReadOnlyList<RdpSessionDto> Sessions,
	RdpSessionListSource Source,
	string? IpcDetail,
	string? LocalDetail)
{
	/// <summary>True when at least one source produced a sessions array (possibly empty).</summary>
	public bool HasSessions => Source != RdpSessionListSource.None;
}

/// <summary>Pure two-tier session-list orchestrator.</summary>
public sealed class RdpSessionFallbackOrchestrator
{
	private readonly Func<CancellationToken, Task<RdpSessionListDto?>> _ipcFetch;
	private readonly Func<CancellationToken, Task<LocalSessionFallbackResult>> _localFetch;

	/// <summary>Construct with explicit fetch delegates.</summary>
	public RdpSessionFallbackOrchestrator(
		Func<CancellationToken, Task<RdpSessionListDto?>> ipcFetch,
		Func<CancellationToken, Task<LocalSessionFallbackResult>> localFetch)
	{
		_ipcFetch = ipcFetch ?? throw new ArgumentNullException(nameof(ipcFetch));
		_localFetch = localFetch ?? throw new ArgumentNullException(nameof(localFetch));
	}

	/// <summary>Capture sessions. Prefers IPC; falls back to the local enumerator when IPC returns
	/// null, throws, or reports a non-success status.</summary>
	public async Task<RdpSessionListSnapshot> CaptureAsync(CancellationToken ct = default)
	{
		RdpSessionListDto? viaIpc = null;
		string? ipcDetail = null;
		try
		{
			viaIpc = await _ipcFetch(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			ipcDetail = "operation cancelled / timed out";
		}
		catch (IOException ex)
		{
			ipcDetail = "IO error: " + ex.Message;
		}

		if (viaIpc is not null && viaIpc.Status == IpcResultStatus.Success)
		{
			return new RdpSessionListSnapshot(
				Sessions: viaIpc.Sessions,
				Source: RdpSessionListSource.ServiceIpc,
				IpcDetail: viaIpc.Message,
				LocalDetail: null);
		}

		ipcDetail ??= viaIpc is null
			? "service unreachable"
			: string.Format(System.Globalization.CultureInfo.InvariantCulture,
				"status {0}: {1}", viaIpc.Status, viaIpc.Message ?? "no message");

		LocalSessionFallbackResult local;
		try
		{
			local = await _localFetch(ct).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			return new RdpSessionListSnapshot(
				Sessions: Array.Empty<RdpSessionDto>(),
				Source: RdpSessionListSource.None,
				IpcDetail: ipcDetail,
				LocalDetail: ex.GetType().Name + " — " + ex.Message);
		}

		if (!local.Success)
		{
			return new RdpSessionListSnapshot(
				Sessions: Array.Empty<RdpSessionDto>(),
				Source: RdpSessionListSource.None,
				IpcDetail: ipcDetail,
				LocalDetail: local.Error);
		}

		return new RdpSessionListSnapshot(
			Sessions: local.Sessions,
			Source: RdpSessionListSource.LocalFallback,
			IpcDetail: ipcDetail,
			LocalDetail: local.Detail);
	}
}

/// <summary>Outcome of a local fallback session enumeration, surfaced through
/// <see cref="RdpSessionFallbackOrchestrator"/>. <see cref="Detail"/> is an optional
/// human-readable note about how the listing was sourced (e.g. "stable English qwinsta
/// output" vs "localized qwinsta output (Cyrillic-tolerant parse)"), shown by the UI in
/// the status line so the operator can tell which path served the rows.</summary>
public sealed record LocalSessionFallbackResult(
	bool Success,
	IReadOnlyList<RdpSessionDto> Sessions,
	string? Error,
	string? Detail)
{
	/// <summary>Convenience factory for a successful local listing without a sub-source label.</summary>
	public static LocalSessionFallbackResult Ok(IReadOnlyList<RdpSessionDto> sessions) =>
		new(true, sessions, null, null);

	/// <summary>Convenience factory for a successful local listing with a sub-source label.</summary>
	public static LocalSessionFallbackResult Ok(IReadOnlyList<RdpSessionDto> sessions, string detail) =>
		new(true, sessions, null, detail);

	/// <summary>Convenience factory for a failed local listing.</summary>
	public static LocalSessionFallbackResult Failed(string error) =>
		new(false, Array.Empty<RdpSessionDto>(), error, null);
}
