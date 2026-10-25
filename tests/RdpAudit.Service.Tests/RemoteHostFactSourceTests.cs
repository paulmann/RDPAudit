/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RemoteHostFactSourceTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Tests for the service-side RemoteHostFactSource adapter: it must serialize the pull
//          request into the Configurator wire convention (JSON string payload), deserialize the
//          response payload back into CrossHostFactsDto, and collapse every failure mode into an
//          Unavailable DTO (fail-closed) without leaking raw exceptions into the engine.
// Depends: RemoteHostFactSource, ICrossHostIpcTransport, CrossHostFactsRequest/Dto, xUnit
// Extends: Add a test whenever a new cancellation or failure branch is introduced.

using System.Text.Json;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Service.CrossHost;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Unit tests for RemoteHostFactSource.</summary>
public sealed class RemoteHostFactSourceTests
{
	private const string HostName = "SRV-AGENT-1";

	[Fact]
	public async Task PullFactsAsync_Success_DeserializesDtoAndPreservesFacts()
	{
		CrossHostFactsDto facts = BuildDto("SRV-AGENT-1", 2);
		FakeTransport transport = new(HostName, new IpcResponse
		{
			Success = true,
			Payload = JsonSerializer.Serialize(facts),
		});
		RemoteHostFactSource source = new(transport);

		CrossHostFactsDto result = await source.PullFactsAsync(DateTime.UtcNow.AddMinutes(-5), 100, "r1", default);

		Assert.Equal(IpcResultStatus.Success, result.Status);
		Assert.Equal(2, result.Facts.Count);
		Assert.Equal("SRV-AGENT-1", result.Facts[0].HostName);
	}

	[Fact]
	public async Task PullFactsAsync_EnvelopeFailure_ReturnsUnavailable()
	{
		FakeTransport transport = new(HostName, new IpcResponse
		{
			Success = false,
			Error = "host refused",
		});
		RemoteHostFactSource source = new(transport);

		CrossHostFactsDto result = await source.PullFactsAsync(null, 100, "r1", default);

		Assert.Equal(IpcResultStatus.Unavailable, result.Status);
		Assert.Empty(result.Facts);
		Assert.Equal("host refused", result.Message);
		Assert.Equal("r1", result.RequestId);
	}

	[Fact]
	public async Task PullFactsAsync_TransientException_ReturnsUnavailable()
	{
		FakeTransport transport = new(HostName, new IOException("pipe broken"));
		RemoteHostFactSource source = new(transport);

		CrossHostFactsDto result = await source.PullFactsAsync(null, 100, null, default);

		Assert.Equal(IpcResultStatus.Unavailable, result.Status);
		Assert.Empty(result.Facts);
		Assert.Contains("pipe broken", result.Message);
	}

	[Fact]
	public async Task PullFactsAsync_BlankPayload_ReturnsUnavailable()
	{
		FakeTransport transport = new(HostName, new IpcResponse
		{
			Success = true,
			Payload = "  ",
		});
		RemoteHostFactSource source = new(transport);

		CrossHostFactsDto result = await source.PullFactsAsync(null, 100, null, default);

		Assert.Equal(IpcResultStatus.Unavailable, result.Status);
	}

	[Fact]
	public async Task PullFactsAsync_CallerCancellation_Propagates()
	{
		FakeTransport transport = new(HostName, new IOException("never thrown"));
		RemoteHostFactSource source = new(transport);
		using CancellationTokenSource cts = new();
		cts.Cancel();

		await Assert.ThrowsAnyAsync<OperationCanceledException>(
			async () => await source.PullFactsAsync(null, 100, null, cts.Token));
	}

	[Fact]
	public void HostName_DelegatesToTransport()
	{
		FakeTransport transport = new(HostName, new IpcResponse { Success = false });
		RemoteHostFactSource source = new(transport);
		Assert.Equal(HostName, source.HostName);
	}

	// ── helpers ───────────────────────────────────────────────────────────────

	private static CrossHostFactsDto BuildDto(string host, int count)
	{
		CrossHostFactsDto dto = new CrossHostFactsDto
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			RequestId = "r1",
			LatestFactUtc = DateTime.UtcNow,
			Message = "ok",
		};
		for (int i = 0; i < count; i++)
		{
			dto.Facts.Add(new CrossHostFactDto
			{
				HostName = host,
				TimeUtc = DateTime.UtcNow,
				UserName = "alice",
				NormalizedUserName = "alice",
				SourceIp = "198.51.100." + (i + 1),
				LogonType = 10,
				Kind = CrossHostFactKind.SuccessfulLogon,
				EventId = 4624,
				DedupKey = "dedup" + i,
			});
		}

		return dto;
	}

	/// <summary>Capturing fake transport: records the request and returns a canned outcome.</summary>
	private sealed class FakeTransport : ICrossHostIpcTransport
	{
		private readonly IpcResponse _response;
		private readonly Exception? _exception;

		public FakeTransport(string hostName, IpcResponse response)
		{
			HostName = hostName;
			_response = response;
		}

		public FakeTransport(string hostName, Exception exception)
		{
			HostName = hostName;
			_exception = exception;
			_response = new IpcResponse { Success = false, Error = "unreachable" };
		}

		public string HostName { get; }

		public IpcRequest? LastRequest { get; private set; }

		public Task<IpcResponse> ExchangeAsync(IpcRequest request, CancellationToken ct)
		{
			LastRequest = request;
			ct.ThrowIfCancellationRequested();
			if (_exception is not null)
			{
				throw _exception;
			}

			return Task.FromResult(_response);
		}
	}
}
