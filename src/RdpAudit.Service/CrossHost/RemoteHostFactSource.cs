/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RemoteHostFactSource.cs
// Project: RdpAudit.Service (RdpAudit.Service.CrossHost)
// Purpose: Service-side implementation of the Core IHostFactSource abstraction. Adapter over the
//          raw named-pipe transport for one configured agent host: builds a GetCrossHostFacts
//          request (JSON payload string per the Configurator wire convention), sends it through
//          the transport and deserializes the JSON payload back into CrossHostFactsDto. Fail-
//          closed: every transport, framing, envelope or deserialization failure collapses to an
//          Unavailable DTO with an operator-facing message - facts are never invented and raw
//          exceptions never leak into the correlation engine.
// Depends: ICrossHostIpcTransport, IHostFactSource, CrossHostFactsRequest/Dto
// Extends: Add decoration (auth, metrics) without touching the engine-facing contract.

using System.Text.Json;
using MessagePack;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.CrossHost;

/// <summary>Remote named-pipe source of fact projections for one agent host.</summary>
public sealed class RemoteHostFactSource : IHostFactSource
{
	private readonly ICrossHostIpcTransport _transport;

	public RemoteHostFactSource(ICrossHostIpcTransport transport)
	{
		_transport = transport ?? throw new ArgumentNullException(nameof(transport));
	}

	public string HostName => _transport.HostName;

	/// <summary>Pulls a bounded batch of facts from the remote agent. Never throws for transport
	/// failures: an Unavailable result is returned instead (fail-closed pull transport).</summary>
	public async Task<CrossHostFactsDto> PullFactsAsync(DateTime? sinceUtc, int maxFacts, string? requestId, CancellationToken ct)
	{
		try
		{
			string payload = JsonSerializer.Serialize(
				new CrossHostFactsRequest
				{
					SinceUtc = sinceUtc,
					MaxFacts = maxFacts,
					RequestId = requestId,
				},
				JsonOptions.Default);

			IpcResponse response = await _transport.ExchangeAsync(
				new IpcRequest { Command = IpcCommand.GetCrossHostFacts, Payload = payload },
				ct).ConfigureAwait(false);

			if (!response.Success)
			{
				return new CrossHostFactsDto
				{
					Status = IpcResultStatus.Unavailable,
					QueriedUtc = DateTime.UtcNow,
					RequestId = requestId,
					LatestFactUtc = null,
					Message = response.Error ?? "Agent host reported an error with no detail.",
				};
			}

			if (string.IsNullOrWhiteSpace(response.Payload))
			{
				return new CrossHostFactsDto
				{
					Status = IpcResultStatus.Unavailable,
					QueriedUtc = DateTime.UtcNow,
					RequestId = requestId,
					LatestFactUtc = null,
					Message = "Agent host returned an empty response payload.",
				};
			}

			CrossHostFactsDto? dto = JsonSerializer.Deserialize<CrossHostFactsDto>(response.Payload, JsonOptions.Default);
			if (dto is null)
			{
				return new CrossHostFactsDto
				{
					Status = IpcResultStatus.Unavailable,
					QueriedUtc = DateTime.UtcNow,
					RequestId = requestId,
					LatestFactUtc = null,
					Message = "Agent host payload could not be deserialized.",
				};
			}

			return dto;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is TimeoutException or IOException or MessagePackSerializationException or JsonException or InvalidOperationException)
		{
			return new CrossHostFactsDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = DateTime.UtcNow,
				RequestId = requestId,
				LatestFactUtc = null,
				Message = "Agent host pull failed: " + ex.Message,
			};
		}
	}
}
