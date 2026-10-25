// File:    src/RdpAudit.Core/CrossHost/IHostFactSource.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Abstraction over a source of cross-host fact projections. The central correlation
//          worker consumes sources through this interface only: transport details (named-pipe
//          IPC, future REST, test fakes) are never visible to the engine. Fail-closed contract:
//          an implementation that cannot service a pull reports Unavailable status and an
//          operator-facing message instead of inventing facts.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.CrossHost;

/// <summary>
/// Source of fact projections contributed by one agent host. Implementations must be
/// thread-safe (the worker may poll sequentially, but tests and future callers may parallelize).
/// </summary>
public interface IHostFactSource
{
	/// <summary>Human-readable name of the host this source pulls from. Used for logs and for
	/// availability accounting; never empty.</summary>
	string HostName { get; }

	/// <summary>
	/// Pulls a bounded batch of fact projections from the host. <paramref name="sinceUtc"/>
	/// is an exclusive lower bound on observation time (null asks for the most recent facts
	/// only). The host clamps <paramref name="maxFacts"/> to its own configured cap. Never
	/// throws for transport-level failures: the returned DTO carries
	/// <see cref="IpcResultStatus.Unavailable"/> and a message instead.
	/// </summary>
	Task<CrossHostFactsDto> PullFactsAsync(DateTime? sinceUtc, int maxFacts, string? requestId, CancellationToken ct);
}
