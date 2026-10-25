// File:    src/RdpAudit.Notifier/Ipc/IAlertSource.cs
// Module:  RdpAudit.Notifier.Ipc
// Purpose: Abstraction over the service IPC used by the polling loop so tests can inject fakes.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Ipc;

/// <summary>Source of notification settings and recent alerts over service IPC.</summary>
public interface IAlertSource
{
	/// <summary>Fetches effective notification settings; null when the service is unreachable.</summary>
	Task<NotificationSettingsDto?> FetchSettingsAsync(CancellationToken ct);

	/// <summary>Fetches the newest alerts; null when the service is unreachable.</summary>
	Task<List<Alert>?> FetchRecentAlertsAsync(CancellationToken ct);
}
