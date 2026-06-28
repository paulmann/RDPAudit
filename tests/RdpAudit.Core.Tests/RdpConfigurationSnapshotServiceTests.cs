// File:    tests/RdpAudit.Core.Tests/RdpConfigurationSnapshotServiceTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the two-tier read strategy used by the "RDP Configuration" tab — IPC first,
//          local fallback when IPC returns null / throws / reports a non-success status. The
//          orchestrator lives in RdpAudit.Core.Util, accepts plain delegates, and is tested
//          here without a live named pipe and without any dependency on the Windows registry.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpConfigurationSnapshotServiceTests
{
	[Fact]
	public async Task CaptureAsync_PrefersServiceIpc_WhenIpcReturnsSuccess()
	{
		RdpConfigurationDto fromIpc = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredPort = 40000,
			TermServiceInstalled = true,
			TermServiceRunning = true,
		};
		bool localCalled = false;

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(fromIpc),
			localFetch: () => { localCalled = true; return new RdpConfigurationDto(); });

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.True(result.HasSnapshot);
		Assert.Equal(RdpConfigurationSnapshotSource.ServiceIpc, result.Source);
		Assert.Same(fromIpc, result.Snapshot);
		Assert.False(localCalled);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcReturnsNull()
	{
		RdpConfigurationDto fromLocal = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredPort = 3390,
		};

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(null),
			localFetch: () => fromLocal);

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.True(result.HasSnapshot);
		Assert.Equal(RdpConfigurationSnapshotSource.LocalFallback, result.Source);
		Assert.Same(fromLocal, result.Snapshot);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcThrowsOperationCanceled()
	{
		RdpConfigurationDto fromLocal = new() { Status = IpcResultStatus.Success };

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => throw new OperationCanceledException(),
			localFetch: () => fromLocal);

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpConfigurationSnapshotSource.LocalFallback, result.Source);
		Assert.Same(fromLocal, result.Snapshot);
	}

	[Fact]
	public async Task CaptureAsync_FallsBackToLocal_WhenIpcReportsNonSuccess()
	{
		RdpConfigurationDto failed = new() { Status = IpcResultStatus.NotImplemented };
		RdpConfigurationDto fromLocal = new() { Status = IpcResultStatus.Success };

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(failed),
			localFetch: () => fromLocal);

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.Equal(RdpConfigurationSnapshotSource.LocalFallback, result.Source);
		Assert.Same(fromLocal, result.Snapshot);
	}

	[Fact]
	public async Task CaptureAsync_ReturnsErrorResult_WhenBothPathsFail()
	{
		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(null),
			localFetch: () => throw new InvalidOperationException("registry locked"));

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.False(result.HasSnapshot);
		Assert.Equal(RdpConfigurationSnapshotSource.None, result.Source);
		Assert.Null(result.Snapshot);
		Assert.NotNull(result.Error);
		Assert.Contains("registry locked", result.Error!, StringComparison.Ordinal);
	}

	[Fact]
	public async Task CaptureAsync_LocalFallbackSnapshot_SurfacesCustomConfiguredPort()
	{
		RdpConfigurationDto fromLocal = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredPort = 40000,
		};

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(null),
			localFetch: () => fromLocal);

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.NotNull(result.Snapshot);
		Assert.Equal(40000, result.Snapshot!.ConfiguredPort);
	}

	[Fact]
	public async Task CaptureAsync_LocalFallbackSnapshot_NullPortMeansFallbackToDefault()
	{
		// When ConfiguredPort is null the UI is responsible for rendering RdpConfigurationModel.DefaultRdpPort
		// alongside a "not configured" hint. Verify the orchestrator preserves the null so the UI
		// can branch on it instead of silently replacing it with 3389 here.
		RdpConfigurationDto fromLocal = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredPort = null,
		};

		RdpConfigurationSnapshotService sut = new(
			ipcFetch: _ => Task.FromResult<RdpConfigurationDto?>(null),
			localFetch: () => fromLocal);

		RdpConfigurationSnapshotResult result = await sut.CaptureAsync().ConfigureAwait(true);

		Assert.NotNull(result.Snapshot);
		Assert.Null(result.Snapshot!.ConfiguredPort);
		Assert.Equal(3389, RdpConfigurationModel.DefaultRdpPort);
	}
}
