// File:    src/RdpAudit.Core/Util/RdpConfigurationSnapshotResult.cs
// Module:  RdpAudit.Core.Util
// Purpose: Read-only result returned by <see cref="RdpConfigurationSnapshotService"/> — pairs
//          the captured <see cref="RdpAudit.Core.Ipc.Contracts.RdpConfigurationDto"/> with its
//          origin (service IPC vs local fallback) and an optional human-readable error when
//          neither source produced a value.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Outcome of a snapshot capture attempt by <see cref="RdpConfigurationSnapshotService"/>.</summary>
public sealed record RdpConfigurationSnapshotResult(
	RdpConfigurationDto? Snapshot,
	RdpConfigurationSnapshotSource Source,
	string? Error)
{
	/// <summary>True when a usable snapshot is attached (either from IPC or local fallback).</summary>
	public bool HasSnapshot => Snapshot is not null && Source != RdpConfigurationSnapshotSource.None;
}
