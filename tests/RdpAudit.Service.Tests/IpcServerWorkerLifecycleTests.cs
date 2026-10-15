/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.5
// File   : IpcServerWorkerLifecycleTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Regression tests for IpcServerWorker instance lifecycle and composition-root
//          registration. Pins that ExecuteAsync is invoked once per worker instance during a
//          normal BackgroundService start/stop, that stopping-token cancellation produces exactly
//          one observable exit with a non-empty reason, that the composition root registers exactly
//          one TimedHostedService wrapping IpcServerWorker, and that the real named-pipe accept loop
//          keeps 12 sequential / 12 parallel clients free of ERROR_PIPE_BUSY while a silent client
//          is reclaimed by the per-connection deadline.
// Depends: IpcServerWorker, IpcDispatcher, IpcConstants, Program.TimedHostedService, MessagePack,
//          xunit, Microsoft.Extensions.DependencyInjection, Microsoft.Extensions.Options
// Extends: Add a lifecycle assertion here when the accept loop gains a new exit-mode or when a new
//          hosted-service wrapper is introduced in Program.RegisterServices.

using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.ExceptionServices;
using MessagePack;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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

public sealed class IpcServerWorkerLifecycleTests
{
	// ── Tests ────────────────────────────────────────────────────────────────────

	[Fact]
	public async Task ExecuteAsync_StartsOncePerInstance_AndStopsOnceWithReason()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			IpcServerWorker worker = CreateWorker(services);
			Guid instanceId = worker.InstanceId;
			Assert.NotEqual(Guid.Empty, instanceId);

			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token);
			try
			{
				Assert.True(
					await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
					"The listener pipe never came up.");
				Assert.Equal(1, worker.ExecuteEntryCount);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}

			Assert.Equal(1, worker.ExecuteExitCount);
			Assert.Equal(instanceId, worker.InstanceId);
			Assert.False(string.IsNullOrWhiteSpace(worker.LastExitReason), "Exit reason must not be empty.");
		}
	}

	[Fact]
	public async Task StoppingTokenCancellation_ProducesOneExit_WithReasonAndCancellationFact()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			IpcServerWorker worker = CreateWorker(services);
			Guid instanceId = worker.InstanceId;

			using CancellationTokenSource cts = new();
			await worker.StartAsync(cts.Token);
			Assert.True(
				await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
				"The listener pipe never came up.");

			cts.Cancel();
			if (worker.ExecuteTask is { } executeTask)
			{
				await executeTask.WaitAsync(TimeSpan.FromSeconds(5));
			}

			Assert.Equal(1, worker.ExecuteEntryCount);
			Assert.Equal(1, worker.ExecuteExitCount);
			Assert.Equal(instanceId, worker.InstanceId);
			Assert.True(worker.LastExitStoppingTokenCancelled, "Stopping token cancellation must be recorded as an observable fact.");
			Assert.Equal("WorkerStopAsync", worker.LastExitReason);

			await Task.Delay(300);
			Assert.Equal(1, worker.ExecuteEntryCount);
			Assert.Equal(1, worker.ExecuteExitCount);
		}
	}

	[Fact]
	public void CompositionRoot_RegistersExactlyOneTimedHostedServiceForIpcServerWorker()
	{
		ServiceCollection services = new();
		services.AddLogging();

		RdpAuditOptions options = new()
		{
			Storage = new StorageOptions
			{
				DatabasePath = Path.Combine(
					Path.GetTempPath(),
					"RdpAudit.Service.Tests",
					Guid.NewGuid().ToString("N"),
					"rdpaudit.db"),
			},
		};

		services.AddSingleton<IOptions<RdpAuditOptions>>(Options.Create(options));
		services.AddSingleton<IOptionsMonitor<RdpAuditOptions>>(new StaticOptionsMonitorLocal<RdpAuditOptions>(options));
		InvokeRegisterServices(services);

		IpcServerWorker worker = new(NullServiceProvider.Instance, NullLogger<IpcServerWorker>.Instance);
		SingleWorkerServiceProvider workerProvider = new(worker);
		List<Program.TimedHostedService> matches = new();

		foreach (ServiceDescriptor descriptor in services)
		{
			if (descriptor.ServiceType != typeof(IHostedService) || descriptor.ImplementationFactory is null)
			{
				continue;
			}

			try
			{
				object? service = descriptor.ImplementationFactory(workerProvider);
				if (service is Program.TimedHostedService { Inner: IpcServerWorker } timed)
				{
					matches.Add(timed);
				}
			}
			catch (InvalidOperationException)
			{
				// This factory expected a different hosted-service type; the proxy intentionally
				// supplies only IpcServerWorker so all unrelated wrappers can be skipped safely.
			}
		}

		Assert.Single(matches);
		Assert.Equal(nameof(IpcServerWorker), matches[0].Name);
		Assert.IsType<IpcServerWorker>(matches[0].Inner);
	}

	[Fact]
	public async Task SequentialTwelveClients_AllSucceed_NoPipeBusy_AndLifecycleStaysSingleEntry()
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
				Assert.True(
					await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
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
				Assert.Equal(1, worker.ExecuteEntryCount);
				Assert.Equal(0, worker.ExecuteExitCount);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}
		}
	}

	[Fact]
	public async Task ParallelTwelveClients_AllSucceed_NoPipeBusy()
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
				Assert.True(
					await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
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
				Assert.Equal(1, worker.ExecuteEntryCount);
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
				Assert.True(
					await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
					"The listener pipe never came up.");

				await using NamedPipeClientStream client = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
				await client.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token);

				Assert.True(
					await WaitUntilAsync(() => worker.ActiveHandlers >= 1, TimeSpan.FromSeconds(5)),
					"The silent client never reached a connection handler.");
				Assert.True(
					await WaitUntilAsync(() => worker.ActiveHandlers == 0, TimeSpan.FromSeconds(12)),
					"The silent client was not reclaimed by the deadline.");

				Assert.Equal(1, worker.LivePipeInstances);
				Assert.Equal(1, worker.ExecuteEntryCount);
			}
			finally
			{
				await StopWorkerAsync(worker);
			}
		}
	}

	// ── P1 acceptance: exit classification, duplicate construction, anti-spin ──

	[Fact]
	public async Task HostShutdown_CancelsApplicationStopping_ProducesHostShutdownReason()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		(IServiceProvider services, SqliteConnection connection) = await CreateServicesAsync();
		await using (connection)
		{
			using FakeHostLifetime lifetime = new();
			IpcServerWorker worker = new(services, NullLogger<IpcServerWorker>.Instance, lifetime);
			using CancellationTokenSource cts = new();

			// Mirror the real host link: the hosted-service stopping token is the application-stopping
			// token, so cancelling the lifetime must cancel the worker's token too.
			using CancellationTokenRegistration registration =
				lifetime.ApplicationStopping.Register(static state => ((CancellationTokenSource)state!).Cancel(), cts);

			await worker.StartAsync(cts.Token);
			Assert.True(
				await WaitUntilAsync(() => worker.LivePipeInstances >= 1, TimeSpan.FromSeconds(5)),
				"The listener pipe never came up.");

			lifetime.StopApplication();
			if (worker.ExecuteTask is { } executeTask)
			{
				await executeTask.WaitAsync(TimeSpan.FromSeconds(5));
			}

			Assert.Equal(1, worker.ExecuteEntryCount);
			Assert.Equal(1, worker.ExecuteExitCount);
			Assert.True(worker.LastExitStoppingTokenCancelled);
			Assert.True(worker.LastExitHostApplicationStoppingCancelled);
			Assert.Equal("HostShutdown", worker.LastExitReason);
		}
	}

	[Fact]
	public void SecondConstruction_LogsCritical_AndIncrementsInstanceCounter()
	{
		// The process-wide counter is shared by every worker construction in the test process, so
		// parallel tests race with exact (+1/+2) equality. Only monotonic growth is asserted: each
		// construction must observably move the counter forward.
		int before = IpcServerWorker.ConstructedInstances;

		RecordingLogger<IpcServerWorker> firstLogger = new();
		_ = new IpcServerWorker(NullServiceProvider.Instance, firstLogger);
		int afterFirst = IpcServerWorker.ConstructedInstances;
		Assert.True(afterFirst > before, "Construction must increase the process-wide instance counter.");

		RecordingLogger<IpcServerWorker> secondLogger = new();
		IpcServerWorker second = new(NullServiceProvider.Instance, secondLogger);
		Assert.True(
			IpcServerWorker.ConstructedInstances > afterFirst,
			"The second construction must increase the process-wide instance counter beyond the first.");

		LogEntry critical = Assert.Single(secondLogger.Entries, entry => entry.Level == LogLevel.Critical);
		Assert.Contains("CRITICAL composition error", critical.Message);
		Assert.Contains(second.InstanceId.ToString(), critical.Message);
	}

	[Fact]
	public void AntiSpin_BelowThreshold_NoPause_AtThreshold_PauseAndReset()
	{
		int counter = 0;

		for (int i = 1; i < IpcConstants.AntiSpinInstantIterationThreshold; i++)
		{
			int pause = IpcServerWorker.ComputeAntiSpinPauseMilliseconds(true, ref counter);
			Assert.Equal(0, pause);
			Assert.Equal(i, counter);
		}

		int thresholdPause = IpcServerWorker.ComputeAntiSpinPauseMilliseconds(true, ref counter);
		Assert.Equal(IpcConstants.AntiSpinPauseMilliseconds, thresholdPause);
		Assert.Equal(0, counter);
	}

	[Fact]
	public void AntiSpin_NonInstantIteration_ResetsCounter()
	{
		int counter = 7;

		int pause = IpcServerWorker.ComputeAntiSpinPauseMilliseconds(false, ref counter);

		Assert.Equal(0, pause);
		Assert.Equal(0, counter);
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

	private sealed class NullServiceProvider : IServiceProvider
	{
		public static readonly NullServiceProvider Instance = new();

		public object? GetService(Type serviceType) => null;
	}

	private sealed class SingleWorkerServiceProvider(IpcServerWorker worker) : IServiceProvider
	{
		public object? GetService(Type serviceType) => serviceType == typeof(IpcServerWorker) ? worker : null;
	}

	private sealed class FakeHostLifetime : IHostApplicationLifetime, IDisposable
	{
		private readonly CancellationTokenSource _started = new();
		private readonly CancellationTokenSource _stopping = new();
		private readonly CancellationTokenSource _stopped = new();

		public CancellationToken ApplicationStarted => _started.Token;

		public CancellationToken ApplicationStopping => _stopping.Token;

		public CancellationToken ApplicationStopped => _stopped.Token;

		public void StopApplication()
		{
			_stopping.Cancel();
			_stopped.Cancel();
		}

		public void NotifyStarted() => _started.Cancel();

		public void NotifyStopped() => _stopped.Cancel();

		public void Dispose()
		{
			_started.Dispose();
			_stopping.Dispose();
			_stopped.Dispose();
		}
	}

	private sealed class RecordingLogger<T> : ILogger<T>
	{
		public List<LogEntry> Entries { get; } = new();

		public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

		public bool IsEnabled(LogLevel logLevel) => true;

		public void Log<TState>(
			LogLevel logLevel,
			EventId eventId,
			TState state,
			Exception? exception,
			Func<TState, Exception?, string> formatter)
		{
			Entries.Add(new LogEntry(logLevel, formatter(state, exception)));
		}
	}

	private readonly record struct LogEntry(LogLevel Level, string Message);

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

	private static void InvokeRegisterServices(IServiceCollection services)
	{
		MethodInfo registerServices = typeof(Program).GetMethod(
			"RegisterServices",
			BindingFlags.NonPublic | BindingFlags.Static)
			?? throw new InvalidOperationException("Program.RegisterServices was not found.");

		try
		{
			registerServices.Invoke(null, new object[] { services });
		}
		catch (TargetInvocationException ex) when (ex.InnerException is not null)
		{
			ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
			throw;
		}
	}
}
