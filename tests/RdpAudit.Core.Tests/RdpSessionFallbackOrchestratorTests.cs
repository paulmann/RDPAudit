// File:    tests/RdpAudit.Core.Tests/RdpSessionFallbackOrchestratorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the two-tier session-list strategy used by the Remote RDP Clients tab — IPC
//          first, local fallback when IPC returns null / throws / reports a non-success status.
//          Mirrors the read-side orchestrator used by the RDP Configuration tab; ensures the
//          page never just reports "service unreachable" — it always falls back to local rows
//          whenever the fallback succeeds.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpSessionFallbackOrchestratorTests
{
	[Fact]
	public async Task CaptureAsync_PrefersServiceIpc_WhenSuccess()
	{
		RdpSessionListDto fromIpc = new()
		{
			Status = IpcResultStatus.Success,
			Sessions = { new RdpSessionDto { SessionId = 1, UserName = "alice" } },
		};
		bool localCalled = false;

		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(fromIpc),
			localFetch: _ =>
			{
				localCalled = true;
				return Task.FromResult(LocalSessionFallbackResult.Ok(Array.Empty<RdpSessionDto>()));
			});

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.ServiceIpc, snapshot.Source);
		Assert.Single(snapshot.Sessions);
		Assert.False(localCalled);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcReturnsNull()
	{
		RdpSessionDto local = new() { SessionId = 7, UserName = "bob", State = "Active" };
		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(null),
			localFetch: _ => Task.FromResult(LocalSessionFallbackResult.Ok(new[] { local })));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.LocalFallback, snapshot.Source);
		Assert.Single(snapshot.Sessions);
		Assert.Equal(7, snapshot.Sessions[0].SessionId);
		Assert.Equal("service unreachable", snapshot.IpcDetail);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcReportsNonSuccess()
	{
		RdpSessionListDto failed = new()
		{
			Status = IpcResultStatus.Unavailable,
			Message = "qwinsta enumeration failed",
		};
		RdpSessionDto local = new() { SessionId = 1, UserName = "carol" };

		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(failed),
			localFetch: _ => Task.FromResult(LocalSessionFallbackResult.Ok(new[] { local })));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.LocalFallback, snapshot.Source);
		Assert.Single(snapshot.Sessions);
		Assert.Contains("Unavailable", snapshot.IpcDetail!, System.StringComparison.Ordinal);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcThrowsOperationCanceled()
	{
		RdpSessionDto local = new() { SessionId = 2 };
		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => throw new OperationCanceledException(),
			localFetch: _ => Task.FromResult(LocalSessionFallbackResult.Ok(new[] { local })));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.LocalFallback, snapshot.Source);
		Assert.Single(snapshot.Sessions);
		Assert.Contains("cancelled", snapshot.IpcDetail!, System.StringComparison.Ordinal);
	}

	[Fact]
	public async Task CaptureAsync_ReturnsNone_WhenBothPathsFail()
	{
		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(null),
			localFetch: _ => Task.FromResult(LocalSessionFallbackResult.Failed("qwinsta exit 1: not allowed")));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.False(snapshot.HasSessions);
		Assert.Equal(RdpSessionListSource.None, snapshot.Source);
		Assert.NotNull(snapshot.IpcDetail);
		Assert.NotNull(snapshot.LocalDetail);
	}

	[Fact]
	public async Task CaptureAsync_PropagatesLocalDetail_WhenLocalFallbackUsed()
	{
		// The Configurator-side LocalRdpSessionProvider tags its result with a Detail string
		// (e.g. "stable English qwinsta output" vs the Cyrillic-tolerant variant). The
		// orchestrator must surface that tag through Snapshot.LocalDetail so the UI status
		// line can tell which path served the rows.
		RdpSessionDto local = new() { SessionId = 11, UserName = "af", State = "Active", IsActive = true };
		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(null),
			localFetch: _ => Task.FromResult(LocalSessionFallbackResult.Ok(
				new[] { local }, "stable English qwinsta output")));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.LocalFallback, snapshot.Source);
		Assert.Equal("stable English qwinsta output", snapshot.LocalDetail);
	}

	[Fact]
	public async Task CaptureAsync_LocalFallback_AccessibleEvenWhenIpcReturnsEmptySuccess()
	{
		// Stage IP-D edge: ListRdpSessions can return Success with an empty Sessions list when
		// the service is reachable but cannot enumerate locally — the page must still surface
		// that as the service result (not silently swap to fallback) so the source line is honest.
		RdpSessionListDto fromIpc = new() { Status = IpcResultStatus.Success };
		RdpSessionFallbackOrchestrator sut = new(
			ipcFetch: _ => Task.FromResult<RdpSessionListDto?>(fromIpc),
			localFetch: _ => throw new InvalidOperationException("should not be called"));

		RdpSessionListSnapshot snapshot = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpSessionListSource.ServiceIpc, snapshot.Source);
		Assert.Empty(snapshot.Sessions);
	}
}
