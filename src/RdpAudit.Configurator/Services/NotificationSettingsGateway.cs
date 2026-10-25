// File:    src/RdpAudit.Configurator/Services/NotificationSettingsGateway.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: IPC gateway for notification settings. The page depends on the interface so unit
//          tests can substitute a fake; the production adapter maps to commands 78/79.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Services;

/// <summary>Abstraction over the notification-settings IPC boundary (commands 78/79).</summary>
public interface INotificationSettingsGateway
{
	Task<IpcCallResult<NotificationSettingsDto>> GetAsync(CancellationToken ct = default);
	Task<IpcCallResult<NotificationSettingsDto>> SaveAsync(NotificationSettingsDto dto, CancellationToken ct = default);
}

/// <summary>Production gateway backed by <see cref="IpcClient"/>.</summary>
public sealed class NotificationSettingsGateway : INotificationSettingsGateway
{
	private readonly IpcClient _ipc;

	public NotificationSettingsGateway(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
	}

	public Task<IpcCallResult<NotificationSettingsDto>> GetAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<NotificationSettingsDto>(IpcCommand.GetNotificationSettings, null, ct);

	public Task<IpcCallResult<NotificationSettingsDto>> SaveAsync(NotificationSettingsDto dto, CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<NotificationSettingsDto>(IpcCommand.SaveNotificationSettings, dto, ct);
}
