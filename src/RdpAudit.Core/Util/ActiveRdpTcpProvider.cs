// File:    src/RdpAudit.Core/Util/ActiveRdpTcpProvider.cs
// Module:  RdpAudit.Core.Util
// Purpose: Queries currently-established TCP connections terminating at a specific local port
//          (the dynamically-resolved RDP listener port). Uses the managed
//          IPGlobalProperties.GetActiveTcpConnections() API so no P/Invoke is required — the
//          managed call already wraps GetExtendedTcpTable under the hood and returns a fully
//          typed list including state. Filters down to Established connections whose local
//          port matches the RDP listener and projects every match into ActiveRdpTcpEndpoint.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace RdpAudit.Core.Util;

/// <summary>Source of TCP connection rows used by <see cref="ActiveRdpTcpProvider"/>. Decoupled
/// so tests can inject a deterministic table without spinning up real connections.</summary>
public interface IActiveTcpConnectionSource
{
	/// <summary>Returns the currently-established TCP connection table.</summary>
	IReadOnlyList<TcpConnectionInformation> GetActiveTcpConnections();
}

/// <summary>Production source backed by <see cref="IPGlobalProperties.GetIPGlobalProperties"/>.</summary>
[SupportedOSPlatform("windows")]
public sealed class SystemActiveTcpConnectionSource : IActiveTcpConnectionSource
{
	/// <inheritdoc/>
	public IReadOnlyList<TcpConnectionInformation> GetActiveTcpConnections()
	{
		try
		{
			return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
		}
		catch (NetworkInformationException)
		{
			return Array.Empty<TcpConnectionInformation>();
		}
	}
}

/// <summary>Reads established RDP listener TCP endpoints from the local TCP table.</summary>
public sealed class ActiveRdpTcpProvider
{
	private readonly IActiveTcpConnectionSource _source;

	/// <summary>Test-friendly constructor.</summary>
	public ActiveRdpTcpProvider(IActiveTcpConnectionSource source)
	{
		_source = source ?? throw new ArgumentNullException(nameof(source));
	}

	/// <summary>Returns the list of currently-established remote endpoints whose local port
	/// equals <paramref name="rdpListenerPort"/>. Never returns null; an empty list means no
	/// remote peer is currently connected on the RDP listener port.</summary>
	public IReadOnlyList<ActiveRdpTcpEndpoint> GetEstablishedEndpoints(int rdpListenerPort)
	{
		IReadOnlyList<TcpConnectionInformation> table = _source.GetActiveTcpConnections();
		List<ActiveRdpTcpEndpoint> result = new();

		foreach (TcpConnectionInformation row in table)
		{
			if (row.State != TcpState.Established)
			{
				continue;
			}

			if (row.LocalEndPoint.Port != rdpListenerPort)
			{
				continue;
			}

			string remoteIp = row.RemoteEndPoint.Address.ToString();
			int remotePort = row.RemoteEndPoint.Port;
			result.Add(new ActiveRdpTcpEndpoint(remoteIp, remotePort));
		}

		return result;
	}
}
