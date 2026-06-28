// File:    src/RdpAudit.Core/Util/RdpConfigurationSnapshotSource.cs
// Module:  RdpAudit.Core.Util
// Purpose: Defines the origin of an RDP configuration snapshot rendered by the Configurator UI —
//          either the RdpAudit Windows service over IPC, or the Configurator's own in-process
//          registry / service inspector when IPC is unreachable. Lives in Core so the two-tier
//          read strategy is unit-testable from RdpAudit.Core.Tests without dragging in the
//          WinForms / WindowsDesktop runtime dependency of the Configurator project.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Origin of a <see cref="RdpAudit.Core.Ipc.Contracts.RdpConfigurationDto"/> rendered by
/// the "RDP Configuration" tab.</summary>
public enum RdpConfigurationSnapshotSource
{
	/// <summary>No snapshot — neither IPC nor local fallback produced a result.</summary>
	None = 0,

	/// <summary>Snapshot was returned by the RdpAudit service over its named-pipe IPC channel.</summary>
	ServiceIpc = 1,

	/// <summary>Snapshot was built locally by the Configurator (RdpAudit service was unreachable
	/// or returned no data); read directly from the registry and service surface in this process.</summary>
	LocalFallback = 2,
}
