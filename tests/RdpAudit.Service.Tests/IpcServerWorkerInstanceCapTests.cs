/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.4
// File   : IpcServerWorkerInstanceCapTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Stage 2 regression for the named-pipe instance leak and off-by-one cap. Runs the real
//          IpcServerWorker against REAL Windows named-pipe clients (\\.\pipe\RdpAuditService) and
//          verifies the acceptance criteria: 12 sequential and 12 parallel Ping clients all succeed
//          with zero ERROR_PIPE_BUSY (231), a connected-but-silent client is reclaimed by the
//          per-connection deadline, the live-instance gauge returns to 1 (listener only) after the
//          traffic drains, and the failure classifier keeps 231 in the "instance cap reached"
//          bucket instead of the AV/EDR hint bucket.
// Depends: IpcServerWorker, IpcDispatcher, IpcConstants, AuditDbContext, SqliteConnection,
//          MessagePack, xunit, Microsoft.Extensions.DependencyInjection
// Extends: Add a case here when the accept loop gains a new failure classification that must not
//          masquerade as AV/EDR interception.

using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using MessagePack;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Real-client integration tests for <see cref="IpcServerWorker"/> instance management. These
/// tests bind the production pipe name, so they must run on a host where no RdpAuditService real
/// instance is already serving the pipe.
/// </summary>
public sealed class IpcServerWorkerInstanceCapTests
{
	// ── Tests ────────────────────────────────────────────────────────────────────

	[Fact]
	public async Task SequentialTwelveClients_AllSucceed_NoPipeBusy_AndInstancesSettleToOne()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			IpcServerWorker worker = CreateWorker(services);
			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token);
			try
			{
				Assert.True(await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
					"The listener pipe never came up.");

				List<PingResult> results = new(12);
				for (int index = 0; index < 12; index++)
				{
					results.Add(await PingWithClassifiedResultAsync(cts.Token));
				}

				Assert.All(results, result => Assert.False(result.Busy, "Sequential client hit ERROR_PIPE_BUSY: " + result.Detail));
				Assert.All(results, result => Assert.True(result.Success, "Sequential client failed: " + result.Detail));
				Assert.True(await WaitUntilAsync(() => worker.ActiveHandlers == 0, TimeSpan.FromSeconds(5)));
				Assert.Equal(1, worker.LivePipeInstances);
				Assert.Equal(0, worker.PipeBusyEvents);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}
		}
	}

	[Fact]
	public async Task ParallelTwelveClients_AllSucceed_NoPipeBusy_AndInstancesSettleToOne()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			IpcServerWorker worker = CreateWorker(services);
			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token);
			try
			{
				Assert.True(await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
					"The listener pipe never came up.");

				Task<PingResult>[] attempts = new Task<PingResult>[12];
				for (int index = 0; index < attempts.Length; index++)
				{
					attempts[index] = PingWithClassifiedResultAsync(cts.Token);
				}

				PingResult[] results = await Task.WhenAll(attempts);

				Assert.All(results, result => Assert.False(result.Busy, "Parallel client hit ERROR_PIPE_BUSY: " + result.Detail));
				Assert.All(results, result => Assert.True(result.Success, "Parallel client failed: " + result.Detail));
				Assert.True(await WaitUntilAsync(() => worker.ActiveHandlers == 0, TimeSpan.FromSeconds(5)));
				Assert.Equal(1, worker.LivePipeInstances);
				Assert.Equal(0, worker.PipeBusyEvents);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}
		}
	}

	[Fact]
	public async Task SilentClient_IsReclaimedByDeadline_AndInstancesSettleToOne()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			IpcServerWorker worker = CreateWorker(services);
			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token);
			try
			{
				Assert.True(await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
					"The listener pipe never came up.");

				await using NamedPipeClientStream client = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
				await client.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token);

				// The client sends nothing. The handler's linked OperationTimeoutMs deadline must
				// reclaim the instance within that window plus scheduling slack.
				Assert.True(await WaitUntilAsync(() => worker.ActiveHandlers >= 1, TimeSpan.FromSeconds(5)),
					"The silent client never reached a connection handler.");
				Assert.True(await WaitUntilAsync(() => worker.ActiveHandlers == 0, TimeSpan.FromSeconds(12)),
					"The silent client was not reclaimed by the deadline.");
				Assert.Equal(1, worker.LivePipeInstances);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}
		}
	}

	[Fact]
	public void PipelineConstants_PinInstanceHeadroom()
	{
		Assert.Equal(10, IpcServerWorker.MaxConcurrent);
		Assert.Equal(IpcServerWorker.MaxConcurrent + 1, IpcServerWorker.PipeInstances);
		Assert.Equal(11, IpcServerWorker.PipeInstances);
		Assert.Equal(231, IpcServerWorker.Win32ErrorPipeBusy);
	}

	[Theory]
	[InlineData(231, true)]
	[InlineData(232, false)]
	[InlineData(5, false)]
	[InlineData(183, false)]
	public void IsPipeBusyException_ClassifiesOnlyWin32Error231(int nativeErrorCode, bool expected)
	{
		Win32Exception busyLike = new(nativeErrorCode);
		Assert.Equal(expected, IpcServerWorker.IsPipeBusyException(busyLike));
	}

	[Fact]
	public void IsPipeBusyException_GenericIOException_IsNotBusy()
	{
		Assert.False(IpcServerWorker.IsPipeBusyException(new IOException("pipe is broken")));
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	private sealed class TestDbContextFactory(DbContextOptions<AuditDbContext> options) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => new(options);
	}

	private sealed class StaticOptionsMonitorLocal<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;

		public T Get(string? name) => value;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class NullOperationLogWriter : IOperationLogWriter
	{
		public bool IsDebugEnabled => false;

		public Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default) => Task.CompletedTask;

		public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default) => Task.CompletedTask;

		public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default) => Task.CompletedTask;

		public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default) => Task.CompletedTask;

		public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default) => Task.CompletedTask;
	}

	private readonly record struct PingResult(bool Success, bool Busy, string Detail);

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static async Task<(IServiceProvider Services, SqliteConnection Connection)> CreateServicesAsync()
	{
		SqliteConnection connection = new("DataSource=:memory:");
		await connection.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;
		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		TestDbContextFactory factory = new(options);
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> monitor = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);

		ServiceCollection collection = new();
		collection.AddSingleton<IDbContextFactory<AuditDbContext>>(factory);
		collection.AddSingleton(metrics);
		collection.AddSingleton<IOptionsMonitor<RdpAuditOptions>>(monitor);
		collection.AddSingleton(settings);
		collection.AddSingleton(firewall);
		collection.AddSingleton<IOperationLogWriter, NullOperationLogWriter>();
		collection.AddScoped<IpcDispatcher>(sp => new IpcDispatcher(
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<SettingsManager>(),
			sp.GetRequiredService<FirewallManager>(),
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance));

		return (collection.BuildServiceProvider(), connection);
	}

	private static IpcServerWorker CreateWorker(IServiceProvider services)
		=> new(services, NullLogger<IpcServerWorker>.Instance);

	private static async Task StopWorkerAsync(IpcServerWorker worker)
	{
		try
		{
			await worker.StopAsync(CancellationToken.None);
			if (worker.ExecuteTask is { } executeTask)
			{
				await executeTask.WaitAsync(TimeSpan.FromSeconds(5));
			}
		}
		catch (OperationCanceledException)
		{
			// Accept-loop shutdown cancellation is the expected outcome.
		}
	}

	private static async Task<PingResult> PingWithClassifiedResultAsync(CancellationToken ct)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromSeconds(20));
		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token);

			IpcRequest request = new() { Command = IpcCommand.Ping };
			byte[] requestBytes = MessagePackSerializer.Serialize(request, cancellationToken: cts.Token);
			await pipe.WriteAsync(BitConverter.GetBytes(requestBytes.Length), cts.Token);
			await pipe.WriteAsync(requestBytes, cts.Token);
			await pipe.FlushAsync(cts.Token);

			byte[] lengthBuffer = new byte[4];
			await pipe.ReadExactlyAsync(lengthBuffer, cts.Token);
			int length = BitConverter.ToInt32(lengthBuffer);
			if (length <= 0 || length > IpcConstants.MaxFrameBytes)
			{
				return new PingResult(false, false, "Service returned an invalid response frame.");
			}

			byte[] responseBytes = new byte[length];
			await pipe.ReadExactlyAsync(responseBytes, cts.Token);
			IpcResponse response = MessagePackSerializer.Deserialize<IpcResponse>(responseBytes, cancellationToken: cts.Token);
			return new PingResult(response.Success, false, response.Error ?? "ok");
		}
		catch (Exception ex) when (IpcServerWorker.IsPipeBusyException(ex))
		{
			return new PingResult(false, true, ex.GetType().Name + ": " + ex.Message);
		}
		catch (Exception ex)
		{
			return new PingResult(false, false, ex.GetType().Name + ": " + ex.Message);
		}
	}

	private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		while (stopwatch.Elapsed < timeout)
		{
			if (condition())
			{
				return true;
			}

			await Task.Delay(50);
		}

		return condition();
	}
}
