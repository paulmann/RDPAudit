/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixGateway.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: IPC boundary of the Zabbix tab (commands 96-101). The page depends on the interface so a
//          test can substitute a fake and never touch a live named pipe.
// Extends: System.Object

using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Services;

/// <summary>Abstraction over the Zabbix IPC commands.</summary>
public interface IZabbixGateway
{
	/// <summary>Reads the settings with both credentials masked.</summary>
	Task<IpcCallResult<ZabbixSettingsDto>> GetSettingsAsync(CancellationToken ct = default);

	/// <summary>Persists the edited settings and returns the effective values.</summary>
	Task<IpcCallResult<ZabbixSettingsDto>> SaveSettingsAsync(ZabbixSettingsDto dto, CancellationToken ct = default);

	/// <summary>Reads the push pipeline status.</summary>
	Task<IpcCallResult<ZabbixStatusDto>> GetStatusAsync(CancellationToken ct = default);

	/// <summary>Probes the sender port and the API endpoint.</summary>
	Task<IpcCallResult<ZabbixTestResultDto>> TestAsync(CancellationToken ct = default);

	/// <summary>Sends the pending incidents immediately.</summary>
	Task<IpcCallResult<ZabbixPushResultDto>> PushNowAsync(CancellationToken ct = default);

	/// <summary>Creates the host, items, triggers and dashboard in Zabbix.</summary>
	Task<IpcCallResult<ZabbixProvisionResultDto>> ProvisionAsync(CancellationToken ct = default);
}

/// <summary>Production gateway backed by <see cref="IpcClient"/>.</summary>
public sealed class ZabbixGateway : IZabbixGateway
{
	private readonly IpcClient _ipc;

	/// <summary>Creates the gateway.</summary>
	/// <param name="ipc">Named-pipe client shared with the rest of the Configurator.</param>
	public ZabbixGateway(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
	}

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixSettingsDto>> GetSettingsAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixSettingsDto>(IpcCommand.GetZabbixSettings, null, ct);

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixSettingsDto>> SaveSettingsAsync(ZabbixSettingsDto dto, CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixSettingsDto>(IpcCommand.SaveZabbixSettings, dto, ct);

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixStatusDto>> GetStatusAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixStatusDto>(IpcCommand.GetZabbixStatus, null, ct);

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixTestResultDto>> TestAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixTestResultDto>(IpcCommand.TestZabbixConnection, null, ct);

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixPushResultDto>> PushNowAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixPushResultDto>(IpcCommand.PushZabbixNow, null, ct);

	/// <inheritdoc />
	public Task<IpcCallResult<ZabbixProvisionResultDto>> ProvisionAsync(CancellationToken ct = default)
		=> _ipc.SendDetailedAsync<ZabbixProvisionResultDto>(IpcCommand.ProvisionZabbix, null, ct);
}
