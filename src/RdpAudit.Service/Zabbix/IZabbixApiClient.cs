/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IZabbixApiClient.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: The two API operations the product needs: prove the endpoint and the credential, and make
//          sure the host, its items and its triggers exist. Nothing here deletes anything.
// Extends: System.Object

namespace RdpAudit.Service.Zabbix;

/// <summary>Result of probing the Zabbix JSON-RPC endpoint.</summary>
/// <param name="Reachable">True when the endpoint answered a version request.</param>
/// <param name="Version">Version string reported by the server.</param>
/// <param name="Authenticated">True when the configured credential was accepted.</param>
/// <param name="Message">Operator-facing detail; never contains a credential.</param>
public sealed record ZabbixApiProbe(bool Reachable, string Version, bool Authenticated, string Message);

/// <summary>What provisioning created and what was already there.</summary>
/// <param name="GroupCreated">Host group created by this call.</param>
/// <param name="GroupExisted">Host group already present.</param>
/// <param name="HostCreated">Host created by this call.</param>
/// <param name="HostExisted">Host already present.</param>
/// <param name="ItemsCreated">Items created by this call.</param>
/// <param name="ItemsExisted">Items already present.</param>
/// <param name="ItemsUpdated">Items whose allowed-hosts list had to be widened.</param>
/// <param name="TrapperHosts">Allowed-hosts list the items now carry, for the operator.</param>
/// <param name="TriggersCreated">Triggers created by this call.</param>
/// <param name="TriggersExisted">Triggers already present.</param>
/// <param name="DashboardCreated">Dashboard created by this call.</param>
/// <param name="DashboardExisted">Dashboard already present.</param>
/// <param name="Message">Operator-facing summary.</param>
public sealed record ZabbixProvisionReport(
	bool GroupCreated,
	bool GroupExisted,
	bool HostCreated,
	bool HostExisted,
	int ItemsCreated,
	int ItemsExisted,
	int ItemsUpdated,
	string TrapperHosts,
	int TriggersCreated,
	int TriggersExisted,
	bool DashboardCreated,
	bool DashboardExisted,
	string Message);

/// <summary>Provisioning calls against a Zabbix instance.</summary>
public interface IZabbixApiClient
{
	/// <summary>Reads the server version and verifies the configured credential.</summary>
	/// <param name="ct">Cancellation token.</param>
	Task<ZabbixApiProbe> ProbeAsync(CancellationToken ct);

	/// <summary>Ensures the host group, the host, its items and its triggers exist. Idempotent: every
	/// object is looked up before it is created, and nothing is ever deleted or overwritten.</summary>
	/// <param name="provisionTriggers">Create the trigger set when it is missing.</param>
	/// <param name="createDashboard">Create the shared "one window" dashboard when it is missing.</param>
	/// <param name="ct">Cancellation token.</param>
	Task<ZabbixProvisionReport> ProvisionAsync(bool provisionTriggers, bool createDashboard, CancellationToken ct);
}

/// <summary>An error reported by the Zabbix API. Carries the server's own message, never a secret.</summary>
public sealed class ZabbixApiException : Exception
{
	/// <summary>Creates the exception from the server's error object.</summary>
	/// <param name="message">Server-supplied message.</param>
	public ZabbixApiException(string message)
		: base(message)
	{
	}

	/// <summary>Creates the exception with an inner cause.</summary>
	/// <param name="message">Server-supplied message.</param>
	/// <param name="innerException">Underlying failure.</param>
	public ZabbixApiException(string message, Exception innerException)
		: base(message, innerException)
	{
	}
}
