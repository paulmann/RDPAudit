/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.5
// File   : src/RdpAudit.Service/Workers/IpcServerWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Hosts the named-pipe IPC server with admin-only ACL.
//          v2.3.4: fixed the named-pipe instance leak and off-by-one cap. The OS instance limit
//          previously equalled MaxConcurrent (10), so the 11th instance was refused by the OS
//          (ERROR_PIPE_BUSY, 231) before the worker's own connectionTasks.Count check could ever
//          fire - the application-level "connection cap exceeded" warning was physically
//          unreachable and the failure degraded monotonically as stalled clients held their
//          instances forever. The OS limit is now PipeInstances = MaxConcurrent + 1: one slot is
//          always the listening standby pipe that the accept loop owns WITHOUT consuming a
//          connection slot, and up to MaxConcurrent connected pipes are handed to handlers.
//          Backpressure is enforced through SemaphoreSlim(MaxConcurrent) BETWEEN the successful
//          WaitForConnectionAsync and the handler handoff (released in the handler's finally), so
//          a saturated handler pool can never stop the accept loop from standing up its next
//          listener - the previously observed "service unreachable" mode. 231 is classified as
//          "instance cap reached" (no AV/EDR hint), the AV/EDR hint is kept only for
//          access-denied failures, and a live-instance / PID gauge is emitted on accept, release
//          and saturation. Every handler runs under a linked CancellationTokenSource whose
//          deadline comes from IpcConstants so a connected-but-silent client cannot hold an
//          instance forever.
//          v2.3.6(exit classification): exitReason now reports the REAL cause instead of a
//          constant: HostShutdown (hostApplicationStopping fired), WorkerStopAsync (only the
//          worker's stoppingToken cancelled), LoopExited (accept loop exited without cancellation),
//          Faulted:<type>. Added anti-spin protection for the expected-disconnect
//          branch: after IpcConstants.AntiSpinInstantIterationThreshold instant iterations a
//          minimum pause of IpcConstants.AntiSpinPauseMilliseconds is enforced, and a second
//          constructor call inside one process logs a Critical configuration error (static
//          Interlocked instance counter) instead of silently producing a dormant worker.
//          v2.3.5: added per-instance lifecycle observability (Guid instance id, construction
//          breadcrumb, iteration counter, and an exit line carrying exit reason plus both
//          cancellation facts) so a reported "three ExecuteAsync entries in one PID" symptom can
//          be attributed to one or multiple worker/host instances from ipc-startup.log alone.
// Depends: BackgroundService, NamedPipeServerStreamAcl, MessagePack, IServiceProvider,
//          IpcDispatcher, IpcConstants, ILogger, IHostApplicationLifetime
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using MessagePack;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;

namespace RdpAudit.Service.Workers;

/// <summary>Hosts the named-pipe IPC server with admin-only ACL.</summary>
public sealed class IpcServerWorker : BackgroundService
{
	internal const int MaxConcurrent = 10;

	/// <summary>
	/// Number of named-pipe server instances requested from the OS. This MUST exceed
	/// <see cref="MaxConcurrent"/> by one: the extra slot is the always-listening standby pipe the
	/// accept loop owns while up to <see cref="MaxConcurrent"/> connected-handler instances are
	/// alive. When this limit equalled <see cref="MaxConcurrent"/> the OS refused the next instance
	/// itself (Win32 <c>ERROR_PIPE_BUSY</c>, 231) before the application backpressure could, so the
	/// operator saw a monotonic OK→FAILED degradation with no "cap reached" diagnostic.
	/// </summary>
	internal const int PipeInstances = MaxConcurrent + 1;

	internal const int Win32ErrorPipeBusy = 231;

	/// <summary>Process-wide construction counter. The composition root MUST create exactly one
	/// IpcServerWorker; a second construction is a configuration error (double registration,
	/// accidental DI activation, or a diagnostic resolving the type) that removes the pipe owner
	/// without any observable bus activity. The counter lets the constructor log Critical on the
	/// second call with both instance ids and the full call stack as durable proof.</summary>
	private static int _constructedInstances;

	/// <summary>Total IpcServerWorker instances constructed during this process, including the
	/// first. Exposed so composition-root lifecycle tests can assert the count did not grow.</summary>
	internal static int ConstructedInstances => Volatile.Read(ref _constructedInstances);

	/// <summary>Minimum gap between durable Critical operation-log records for an identical accept-loop
	/// fault signature. A genuinely broken accept loop (e.g. ACL failure) re-faults every iteration; without
	/// this gate it would flood the OperationLog table with thousands of identical Critical rows per minute.
	/// The structured logger still records every occurrence at the classified level.</summary>
	private static readonly TimeSpan FaultLogDedupeWindow = TimeSpan.FromMinutes(1);

	private readonly IServiceProvider _services;
	private readonly ILogger<IpcServerWorker> _logger;

	/// <summary>Optional host-lifetime handle used to record the observable fact that the Generic Host
	/// application-stopping token fired. Kept optional so existing tests that construct the worker with two
	/// arguments keep compiling; production DI injects the host lifetime automatically.</summary>
	private readonly IHostApplicationLifetime? _hostLifetime;

	/// <summary>Absolute IPC breadcrumb log path resolved from the injected
	/// <see cref="IRdpAuditPathsProvider"/> at construction, or null when no provider is in scope
	/// (unit tests / non-DI constructions), in which case the breadcrumb sink stays silent instead
	/// of guessing a machine-wide ProgramData path (D2 guard).</summary>
	private readonly string? _ipcStartupLogPath;

	/// <summary>Stable per-instance identity proving how many worker instances were constructed. Created in
	/// the constructor so entered/exiting lines can be unambiguously paired with one instance.</summary>
	private readonly Guid _instanceId = Guid.NewGuid();

	/// <summary>Instance-lifetime clock started at construction. The final exit line reports its elapsed
	/// milliseconds so a short-lived instance is visible even without a debugger.</summary>
	private readonly Stopwatch _lifetime = Stopwatch.StartNew();

	// In-process concurrency limit. The semaphore gates ONLY the handoff of a connected pipe to
	// HandleConnectionAsync; the listening standby pipe is created without consuming a slot, so a
	// fully saturated handler pool can never starve the accept loop's next listener (the historic
	// "service unreachable" failure mode). Release lives in the handler's finally, so a slot can
	// never leak on any exit path.
	private readonly SemaphoreSlim _connectionSlots = new(MaxConcurrent, MaxConcurrent);

	// Live gauge exposed for diagnostics and tests. _livePipeInstances counts every pipe currently
	// held by the worker (listener standby + pipes waiting for a handler slot + in-flight handlers);
	// _activeHandlers counts handlers only; _pipeBusyEvents counts Win32 ERROR_PIPE_BUSY observations
	// since startup.
	private int _livePipeInstances;
	private int _activeHandlers;
	private int _pipeBusyEvents;

	// Accept-loop / instance-lifecycle counters. They are updated with Interlocked and read with
	// Volatile so tests can observe them while ExecuteAsync is running on another thread.
	private long _iteration;
	private int _executeEntryCount;
	private int _executeExitCount;
	private string? _lastExitReason;
	private bool _lastExitStoppingTokenCancelled;
	private bool _lastExitHostApplicationStoppingCancelled;

	private readonly List<Task> _connectionTasks = new();

	// Dedupe state for repeated accept-loop faults (single accept loop -> no cross-thread contention).
	private string? _lastFaultSignature;
	private DateTime _lastFaultDurableLogUtc = DateTime.MinValue;

	/// <summary>Reset to false on CreatePipe failure so the "pipe accepting" banner re-emits after recovery.</summary>
	private bool _pipeBannerLogged;

	/// <summary>Counts consecutive IsExpectedAcceptDisconnect IOExceptions from WaitForConnectionAsync.
	/// When this exceeds the threshold it suggests an AV/EDR product is killing the pipe immediately after
	/// creation (CreatePipe succeeds, but the pipe is destroyed before a client can connect).
	/// Escalate to Warning after threshold so the issue is visible without IPC.</summary>
	private int _consecutiveWaitFailures;
	private const int WaitFailureWarnThreshold = 5;

	/// <summary>Consecutive accept-loop iterations that completed at or below
	/// IpcConstants.AntiSpinInstantIterationMaxElapsedMs. When they reach
	/// IpcConstants.AntiSpinInstantIterationThreshold the loop enforces the
	/// IpcConstants.AntiSpinPauseMilliseconds pause so an expected-disconnect storm can never turn
	/// into a 100% CPU busy-loop. Reset on any iteration that took longer than the instant bound.</summary>
	private int _instantIterations;

	internal int LivePipeInstances => Volatile.Read(ref _livePipeInstances);

	internal int ActiveHandlers => Volatile.Read(ref _activeHandlers);

	internal int PipeBusyEvents => Volatile.Read(ref _pipeBusyEvents);

	internal Guid InstanceId => _instanceId;

	internal long Iteration => Volatile.Read(ref _iteration);

	internal int ExecuteEntryCount => Volatile.Read(ref _executeEntryCount);

	internal int ExecuteExitCount => Volatile.Read(ref _executeExitCount);

	internal string LastExitReason => Volatile.Read(ref _lastExitReason) ?? string.Empty;

	internal bool LastExitStoppingTokenCancelled => Volatile.Read(ref _lastExitStoppingTokenCancelled);

	internal bool LastExitHostApplicationStoppingCancelled => Volatile.Read(ref _lastExitHostApplicationStoppingCancelled);

	public IpcServerWorker(
		IServiceProvider services,
		ILogger<IpcServerWorker> logger,
		IHostApplicationLifetime? hostLifetime = null,
		IRdpAuditPathsProvider? pathsProvider = null)
	{
		_services = services;
		_logger = logger;
		_hostLifetime = hostLifetime;
		// D2: resolve the IPC breadcrumb log path ONLY from an available provider. Production DI
		// registers DefaultRdpAuditPathsProvider, so the service logs to %ProgramData%\RdpAudit\logs.
		// Unit tests that construct the worker against a stub service provider (no provider
		// registered) get null -> a silent sink, so merely constructing the worker can never write
		// into the real %ProgramData% tree.
		_ipcStartupLogPath = (pathsProvider
			?? (IRdpAuditPathsProvider?)services.GetService(typeof(IRdpAuditPathsProvider)))
			?.Paths.IpcStartupLogPath;

		int instanceOrdinal = Interlocked.Increment(ref _constructedInstances);

		// Log construction with the same InstanceId that the entered/exiting lines carry, so a
		// production log can prove whether more than one IpcServerWorker was created per process.
		WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} instance constructed (pid={Environment.ProcessId}, instanceId={_instanceId}, ordinal={instanceOrdinal})");

		if (instanceOrdinal > 1)
		{
			// A second construction inside one process is a composition error, not a runtime
			// state: the first instance owns the pipe and the second one can never serve. Log
			// Critical with both instance ids and the construction stack so the operator sees
			// exactly which registration path produced the duplicate.
			string stack = Environment.StackTrace;
			WriteIpcDebugLine(
				$"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} DUPLICATE CONSTRUCTION (pid={Environment.ProcessId}, ordinal={instanceOrdinal}, " +
				$"newInstanceId={_instanceId}) CRITICAL configuration error: exactly one IpcServerWorker must be constructed per process." +
				Environment.NewLine + stack);
			_logger.LogCritical(
				"{Worker} constructed {Ordinal} times in one process (newInstanceId={NewInstanceId}, pid={Pid}) - CRITICAL composition error: exactly one IpcServerWorker must be registered as IHostedService and resolved once. Construction stack:{NewLine}{Stack}",
				nameof(IpcServerWorker), instanceOrdinal, _instanceId, Environment.ProcessId,
				Environment.NewLine, stack);
			return;
		}

		_logger.LogInformation(
			"{Worker} instance constructed (pid={Pid}, instanceId={InstanceId}, ordinal={Ordinal})",
			nameof(IpcServerWorker), Environment.ProcessId, _instanceId, instanceOrdinal);
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		// Written unconditionally and before any pipe/AV interaction so ipc-startup.log always shows a
		// worker-start breadcrumb even if the process is killed or faults before CreatePipe ever runs.
		int entryCount = Interlocked.Increment(ref _executeEntryCount);
		WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} ExecuteAsync entered (pid={Environment.ProcessId}, instanceId={_instanceId}, entry={entryCount})");
		_logger.LogInformation(
			"{Worker} starting (pid={Pid}, instanceId={InstanceId}, entry={Entry})",
			nameof(IpcServerWorker), Environment.ProcessId, _instanceId, entryCount);
		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("Named pipe ACL APIs require Windows; IPC disabled on this host.");
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
			return;
		}

		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				long iteration = Interlocked.Increment(ref _iteration);
				long iterationStartTimestamp = Stopwatch.GetTimestamp();
				_logger.LogDebug(
					"{Worker} accept loop iteration {Iteration} begins (pid={Pid}, instanceId={InstanceId})",
					nameof(IpcServerWorker), iteration, Environment.ProcessId, _instanceId);

				// Create the listening standby pipe WITHOUT consuming a connection slot. The slot is
				// acquired only after a client connects, right before the handler handoff, so a
				// saturated handler pool can never stop the accept loop from standing up its next
				// listener.
				NamedPipeServerStream? pipe = null;
				bool slotAcquired = false;
				bool handlerStarted = false;

				try
				{
					try
					{
						pipe = CreateTrackedPipe();
						if (!_pipeBannerLogged)
						{
							_pipeBannerLogged = true;
							_consecutiveWaitFailures = 0;
							_logger.LogInformation(
								"{Worker} named pipe \\\\.\\pipe\\{PipeName} created -- accepting connections " +
								"(ACL: Administrators + LocalSystem, instances: {Instances}, pid={Pid})",
								nameof(IpcServerWorker), IpcConstants.PipeName, PipeInstances, Environment.ProcessId);
							WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe OK -- \\\\.\\pipe\\{IpcConstants.PipeName} accepting connections");
						}
					}
					catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
					{
						return;
					}
					catch (IOException ex) when (IsPipeBusyException(ex))
					{
						// The OS refused the instance (ERROR_PIPE_BUSY) - legitimate backpressure, NOT an
						// AV/EDR interception. Do not run the AV hint and do not treat this as a durable
						// accept-loop fault: the standby slot makes this impossible during normal
						// operation, so when it does happen the log must say exactly that.
						Interlocked.Increment(ref _pipeBusyEvents);
						_pipeBannerLogged = false;
						LogInstanceCapWarning(ex, "CreatePipe");
						WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe FAILED busy [{ex.GetType().Name}]: {ex.Message}");
						await TryLogInstanceCapAsync(ex, "CreatePipe", stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromMilliseconds(50), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}
					catch (UnauthorizedAccessException ex)
					{
						// Access-denied on CreatePipe is the AV/EDR interception signature: an EDR filter
						// (e.g. Kaspersky KLIF) denies NamedPipeServerStreamAcl.Create. Keep the AV hint
						// here and keep it OUT of the ERROR_PIPE_BUSY branch.
						_pipeBannerLogged = false;
						_logger.LogWarning(ex,
							"{Worker} CreatePipe FAILED [{ExType}]: {ExMsg} -- possible AV/EDR pipe interception " +
							"(Kaspersky?). Add RdpAudit.Service.exe to your AV trusted list. Retrying in 5 s.",
							nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
						WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe FAILED [{ex.GetType().Name}]: {ex.Message}");
						await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}
					catch (IOException ex)
					{
						_pipeBannerLogged = false;
						_logger.LogWarning(ex,
							"{Worker} CreatePipe FAILED [{ExType}]: {ExMsg} -- possible AV/EDR pipe interception. " +
							"Add RdpAudit.Service.exe to your AV trusted list. Retrying in 5 s.",
							nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
						WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe FAILED [{ex.GetType().Name}]: {ex.Message}");
						await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}
					catch (Exception ex)
					{
						_pipeBannerLogged = false;
						_logger.LogError(ex,
							"{Worker} CreatePipe unexpected fault [{ExType}]: {ExMsg} -- continuing",
							nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
						await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}

					try
					{
						await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
					{
						await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						return;
					}
					catch (IOException ex) when (IsPipeBusyException(ex))
					{
						await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						Interlocked.Increment(ref _pipeBusyEvents);
						LogInstanceCapWarning(ex, "WaitForConnection");
						WriteIpcDebugLine($"[{DateTime.UtcNow:O}] WaitForConnection busy [{ex.GetType().Name}]: {ex.Message}");
						await TryLogInstanceCapAsync(ex, "WaitForConnection", stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromMilliseconds(50), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}
					catch (Exception ex) when (IsExpectedAcceptDisconnect(ex))
					{
						await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						_consecutiveWaitFailures++;
						if (_consecutiveWaitFailures >= WaitFailureWarnThreshold)
						{
							// Rapid consecutive failures suggest AV/EDR destroys the pipe immediately after
							// creation. CreatePipe succeeds, but no client can ever connect (Kaspersky KLIF).
							_logger.LogWarning(ex,
								"{Worker} pipe destroyed {Count}x before any client connected [{ExType}]: {ExMsg} "
								+ "-- AV/EDR (Kaspersky?) may be intercepting the pipe. Add RdpAudit.Service.exe to AV trusted list.",
								nameof(IpcServerWorker), _consecutiveWaitFailures, ex.GetType().Name, ex.Message);
							WriteIpcDebugLine($"[{DateTime.UtcNow:O}] WaitForConnection fail #{_consecutiveWaitFailures} [{ex.GetType().Name}]: {ex.Message}");
							await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
							_consecutiveWaitFailures = 0;
						}
						else
					{
						_logger.LogDebug(ex, "{Worker} expected accept/disconnect transient -- continuing", nameof(IpcServerWorker));
					}

					// Anti-spin protection for the expected-disconnect continuation. When the loop
					// completes iteratively faster than the configured instant bound, something is
					// destroying the standby pipe in a tight loop; count consecutive instant
					// iterations and force the configured minimum pause at the threshold so the
					// loop can never sustain more than one turn per 10 ms on average.
					long iterationElapsedMs =
						(Stopwatch.GetTimestamp() - iterationStartTimestamp) * 1000 / Stopwatch.Frequency;
					bool instantIteration = iterationElapsedMs <= IpcConstants.AntiSpinInstantIterationMaxElapsedMs;
					int pauseMs = ComputeAntiSpinPauseMilliseconds(instantIteration, ref _instantIterations);
					if (pauseMs > 0)
					{
						_logger.LogWarning(
							"{Worker} anti-spin guard engaged after {Count} instant accept-loop iterations [{ExType}]: {ExMsg} -- pausing {PauseMs} ms",
							nameof(IpcServerWorker), IpcConstants.AntiSpinInstantIterationThreshold,
							ex.GetType().Name, ex.Message, pauseMs);
						WriteIpcDebugLine(
							$"[{DateTime.UtcNow:O}] anti-spin guard engaged after {IpcConstants.AntiSpinInstantIterationThreshold} instant iterations; pausing {pauseMs} ms");
						if (!await DelayWithCancellationAsync(
								TimeSpan.FromMilliseconds(pauseMs),
								stoppingToken).ConfigureAwait(false))
						{
							return;
						}
					}

					// Back-off to prevent tight-loop CPU spin when AV/EDR repeatedly destroys the pipe.
					if (_consecutiveWaitFailures > 0)
					{
						if (!await DelayWithCancellationAsync(TimeSpan.FromMilliseconds(500), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
					}
					continue;
				}
				catch (Exception ex)
					{
						await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						_logger.LogError(ex,
							"{Worker} WaitForConnection fault [{ExType}]: {ExMsg} -- continuing",
							nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
						await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
						if (!await DelayWithCancellationAsync(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false))
						{
							return;
						}
						continue;
					}

					// A client connected. Reserve a handler slot BEFORE the handoff. While the pool is
					// saturated the connected client waits (its pipe stays alive inside the standby
					// slot); if the service stops during that wait the pipe is disposed and the loop
					// exits cleanly.
					try
					{
						await _connectionSlots.WaitAsync(stoppingToken).ConfigureAwait(false);
						slotAcquired = true;
					}
					catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
					{
						await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						return;
					}

					_consecutiveWaitFailures = 0;
					int activeHandlers = Interlocked.Increment(ref _activeHandlers);
					_logger.LogDebug(
						"{Worker} client connected -- dispatching (activeHandlers={ActiveHandlers}, livePipes={LivePipes}, pid={Pid})",
						nameof(IpcServerWorker), activeHandlers, LivePipeInstances, Environment.ProcessId);
					LogInstanceGauge("accepted");

					// Ownership of the pipe and the slot transfers to HandleConnectionAsync: the
					// handler disposes the pipe and releases the slot in its finally.
					Task handler = HandleConnectionAsync(pipe, stoppingToken);
					handlerStarted = true;
					_connectionTasks.Add(handler);
					_connectionTasks.RemoveAll(static task => task.IsCompleted);
				}
				catch (Exception ex)
				{
					// Any unhandled fault inside one accept iteration must never leak the pipe or the
					// slot. Once the handler task has started it owns both (its finally releases the
					// slot and disposes the pipe); before that point this catch cleans up directly.
					_logger.LogError(ex,
						"{Worker} accept iteration fault [{ExType}]: {ExMsg} -- continuing",
						nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
					if (!handlerStarted)
					{
						if (pipe is not null)
						{
							await DisposeAndUntrackAsync(pipe).ConfigureAwait(false);
						}

						if (slotAcquired)
						{
							_connectionSlots.Release();
						}
					}
					continue;
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			// A fault escaping this outer try means the accept loop is dead and the BackgroundService is
			// about to stop silently from the host's perspective - the historic cause of "IPC Connected:
			// no" with no trace anywhere. Always leave a breadcrumb on disk before rethrowing.
			Volatile.Write(ref _lastExitReason, "Faulted:" + ex.GetType().Name);
			WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} FATAL accept-loop exit [{ex.GetType().Name}]: {ex.Message}");
			_logger.LogCritical(ex, "{Worker} accept loop terminated unexpectedly [{ExType}]: {ExMsg}", nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
			await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
			throw;
		}
		finally
		{
			int exitCount = Interlocked.Increment(ref _executeExitCount);
			bool stoppingCancelled = stoppingToken.IsCancellationRequested;
			bool hostStoppingCancelled = _hostLifetime?.ApplicationStopping.IsCancellationRequested ?? false;
			string exitReason = Volatile.Read(ref _lastExitReason) ?? string.Empty;
			if (string.IsNullOrEmpty(exitReason))
			{
				exitReason = hostStoppingCancelled
					? "HostShutdown"
					: stoppingCancelled
						? "WorkerStopAsync"
						: "LoopExited";
			}

			Volatile.Write(ref _lastExitReason, exitReason);
			Volatile.Write(ref _lastExitStoppingTokenCancelled, stoppingCancelled);
			Volatile.Write(ref _lastExitHostApplicationStoppingCancelled, hostStoppingCancelled);

			WriteIpcDebugLine(
				$"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} ExecuteAsync exiting " +
				$"(pid={Environment.ProcessId}, instanceId={_instanceId}, entryCount={Volatile.Read(ref _executeEntryCount)}, " +
				$"exitCount={exitCount}, iteration={Volatile.Read(ref _iteration)}, activeHandlers={ActiveHandlers}, " +
				$"livePipes={LivePipeInstances}, stoppingTokenCancelled={stoppingCancelled}, " +
				$"hostApplicationStoppingCancelled={hostStoppingCancelled}, exitReason={exitReason}, lifetimeMs={_lifetime.ElapsedMilliseconds})");

			_logger.LogInformation(
				"{Worker} stopped (pid={Pid}, instanceId={InstanceId}, entryCount={EntryCount}, exitCount={ExitCount}, " +
				"iteration={Iteration}, activeHandlers={ActiveHandlers}, livePipes={LivePipes}, " +
				"stoppingTokenCancelled={StoppingTokenCancelled}, hostApplicationStoppingCancelled={HostApplicationStoppingCancelled}, " +
				"exitReason={ExitReason}, lifetimeMs={LifetimeMs})",
				nameof(IpcServerWorker),
				Environment.ProcessId,
				_instanceId,
				Volatile.Read(ref _executeEntryCount),
				exitCount,
				Volatile.Read(ref _iteration),
				ActiveHandlers,
				LivePipeInstances,
				stoppingCancelled,
				hostStoppingCancelled,
				exitReason,
				_lifetime.ElapsedMilliseconds);
		}
	}

	/// <summary>
	/// Anti-spin accounting for one accept-loop iteration. Returns the pause in milliseconds the
	/// accept loop must apply before its next iteration, or zero when no pause is required. When
	/// <paramref name="instantIteration"/> is true the consecutive-instant counter is incremented
	/// and, once it reaches <see cref="IpcConstants.AntiSpinInstantIterationThreshold"/>, the counter
	/// is reset and the configured <see cref="IpcConstants.AntiSpinPauseMilliseconds"/> pause is
	/// returned. A non-instant iteration resets the counter and returns zero. Extracted as a static
	/// helper so the threshold/reset semantics are unit-testable without a live named pipe loop.
	/// </summary>
	internal static int ComputeAntiSpinPauseMilliseconds(bool instantIteration, ref int instantIterationCount)
	{
		if (instantIteration)
		{
			int count = Interlocked.Increment(ref instantIterationCount);
			if (count >= IpcConstants.AntiSpinInstantIterationThreshold)
			{
				Interlocked.Exchange(ref instantIterationCount, 0);
				return IpcConstants.AntiSpinPauseMilliseconds;
			}

			return 0;
		}

		Interlocked.Exchange(ref instantIterationCount, 0);
		return 0;
	}

	/// <summary>True when an accept-loop exception represents the routine end of a client session rather
	/// than a service fault: a client that closed the pipe, a cancellation, or a disposed/broken pipe.
	/// These are logged at Debug and never written durably, so they do not masquerade as Critical faults
	/// in the OperationLog. Anything else is treated as a genuine fault worth surfacing.</summary>
	internal static bool IsExpectedAcceptDisconnect(Exception ex) => ex switch
	{
		OperationCanceledException => true,
		ObjectDisposedException => true,
		// Broken-pipe / connection-reset surfaces as IOException; on Windows a client closing the handle
		// also surfaces as a Win32-backed IOException. Both are the expected close of a client session.
		IOException => true,
		_ => false,
	};

	/// <summary>True when the exception carries Win32 <c>ERROR_PIPE_BUSY</c> (231): the OS refused a
	/// pipe instance because the configured instance limit was reached. With PipeInstances =
	/// MaxConcurrent + 1 this is backpressure evidence, not an AV/EDR interception, so it is logged in
	/// its own branch and never fed into the AV hint.</summary>
	internal static bool IsPipeBusyException(Exception ex)
	{
		if ((ex.HResult & 0xFFFF) == Win32ErrorPipeBusy)
		{
			return true;
		}

		if (ex is Win32Exception win32 && win32.NativeErrorCode == Win32ErrorPipeBusy)
		{
			return true;
		}

		return ex.InnerException is { } inner && (inner.HResult & 0xFFFF) == Win32ErrorPipeBusy;
	}

	/// <summary>Best-effort durable record for a genuine accept-loop fault. Rate-limits identical fault
	/// signatures (type + message) to one durable Critical row per <see cref="FaultLogDedupeWindow"/> so a
	/// loop that re-faults every iteration cannot flood the OperationLog. Resolves the writer from the root
	/// provider and never throws (the IPC loop must stay alive).</summary>
	private async Task TryLogOperationFaultAsync(Exception ex, CancellationToken ct)
	{
		string signature = ex.GetType().FullName + "|" + ex.Message;
		DateTime now = DateTime.UtcNow;
		bool sameAsLast = string.Equals(signature, _lastFaultSignature, StringComparison.Ordinal);
		if (sameAsLast && (now - _lastFaultDurableLogUtc) < FaultLogDedupeWindow)
		{
			return;
		}

		_lastFaultSignature = signature;
		_lastFaultDurableLogUtc = now;

		try
		{
			RdpAudit.Core.Data.IOperationLogWriter opLog =
				_services.GetRequiredService<RdpAudit.Core.Data.IOperationLogWriter>();
			await opLog.ErrorAsync("Ipc", "AcceptLoopFault",
				"IPC accept-loop fault; server continuing.", ex,
				RdpAudit.Core.Models.OperationLogSeverity.Critical, ct).ConfigureAwait(false);
		}
		catch
		{
			// ignored -- logger already captured it; the operation log is best-effort
		}
	}

	/// <summary>Durable Warning record for an instance-cap observation. Deliberately separate from
	/// accept-loop faults: saturation is expected backpressure, not a service fault, and the row must
	/// tell the operator "instance cap reached", never the AV/EDR hint.</summary>
	private async Task TryLogInstanceCapAsync(Exception ex, string phase, CancellationToken ct)
	{
		try
		{
			RdpAudit.Core.Data.IOperationLogWriter opLog =
				_services.GetRequiredService<RdpAudit.Core.Data.IOperationLogWriter>();
			await opLog.WarnAsync(
				"Ipc",
				"InstanceCapReached",
				"Named pipe instance cap reached during " + phase + "; connection will retry after active handlers drain.",
				"error=" + ex.GetType().Name + ";activeHandlers=" + ActiveHandlers
					+ ";livePipes=" + LivePipeInstances + ";pid=" + Environment.ProcessId,
				ct).ConfigureAwait(false);
		}
		catch
		{
			// ignored -- the structured logger already recorded the saturation event
		}
	}

	/// <summary>Logs the live-instance / handler / busy-event gauge with the process id so saturation
	/// events can be correlated across restarts even when only the structured file log survives.</summary>
	private void LogInstanceGauge(string phase)
	{
		_logger.LogDebug(
			"{Worker} instance gauge ({Phase}): activeHandlers={ActiveHandlers} livePipes={LivePipes} pipeBusyEvents={PipeBusyEvents} pid={Pid}",
			nameof(IpcServerWorker), phase, ActiveHandlers, LivePipeInstances, PipeBusyEvents, Environment.ProcessId);
	}

	private void LogInstanceCapWarning(Exception ex, string phase)
	{
		_logger.LogWarning(
			ex,
			"{Worker} named pipe instance cap reached during {Phase}: {ExMsg} -- " +
			"activeHandlers={ActiveHandlers} livePipes={LivePipes} pipeBusyEvents={PipeBusyEvents} pid={Pid}",
			nameof(IpcServerWorker), phase, ex.Message, ActiveHandlers, LivePipeInstances, PipeBusyEvents, Environment.ProcessId);
	}

	[SupportedOSPlatform("windows")]
	/// <summary>Appends one line to the IPC startup breadcrumb log resolved at construction
	/// through <see cref="IRdpAuditPathsProvider"/> (logs\ipc-startup.log) with the shared
	/// size-capped rotation from <see cref="DiagnosticLogRotation"/>. Provides IPC-startup
	/// diagnostics readable WITHOUT a working IPC channel. When no paths provider was in scope
	/// at construction (unit tests), the sink stays silent - it never reaches for the real
	/// %ProgramData% tree. Silently swallows all I/O errors so a full disk never kills the
	/// accept loop.</summary>
	private void WriteIpcDebugLine(string line)
	{
		string? path = _ipcStartupLogPath;
		if (path is null)
		{
			return;
		}

		try
		{
			DiagnosticLogRotation.AppendLine(path, line);
		}
		catch
		{
			// Never let a debug write kill the accept loop.
		}
	}

	/// <summary>Creates one pipe instance and accounts for it in the live-pipe gauge. The gauge is
	/// decremented exactly once - when the pipe is disposed on a non-connected path or by the handler
	/// after its response completes.</summary>
	private NamedPipeServerStream CreateTrackedPipe()
	{
		NamedPipeServerStream pipe = CreatePipe();
		Interlocked.Increment(ref _livePipeInstances);
		return pipe;
	}

	/// <summary>Disposes one pipe instance and decrements the live pipe gauge. Swallows a dispose
	/// failure so a filter driver never kills the accept loop.</summary>
	private async Task DisposeAndUntrackAsync(NamedPipeServerStream pipe)
	{
		try
		{
			await pipe.DisposeAsync().ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Failed to dispose a named pipe instance cleanly");
		}
		finally
		{
			TrackPipeDisposed();
		}
	}

	private void TrackPipeDisposed()
	{
		int remaining = Interlocked.Decrement(ref _livePipeInstances);
		if (remaining < 0)
		{
			// Defensive floor for an impossible double-dispose; the gauge is informational only.
			Interlocked.Exchange(ref _livePipeInstances, 0);
		}
	}

	/// <summary>Waits <paramref name="delay"/> while the service is running. Returns false when the
	/// stopping token fired, so callers can exit the accept loop cleanly without a nested try/catch.
	/// The accept loop is driven ONLY by the service stopping token; there is no local cancellation.
	/// Therefore an <see cref="OperationCanceledException"/> here necessarily means host/worker stop,
	/// and converting it to <c>false</c> is the correct exit signal rather than a swallowed fault.</summary>
	private static async Task<bool> DelayWithCancellationAsync(TimeSpan delay, CancellationToken ct)
	{
		try
		{
			await Task.Delay(delay, ct).ConfigureAwait(false);
			return true;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			return false;
		}
	}

	private static NamedPipeServerStream CreatePipe()
	{
		PipeSecurity security = new();
		security.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
			PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
			AccessControlType.Allow));
		security.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		return NamedPipeServerStreamAcl.Create(
			IpcConstants.PipeName,
			PipeDirection.InOut,
			PipeInstances,
			PipeTransmissionMode.Message,
			PipeOptions.Asynchronous | PipeOptions.WriteThrough,
			inBufferSize: 65_536,
			outBufferSize: 65_536,
			pipeSecurity: security);
	}

	private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
	{
		_logger.LogDebug("{Worker} client connected -- dispatching", nameof(IpcServerWorker));

		// Total connection deadline. The linked source is cancelled by the service stop token or after
		// the current command budget elapses; either way the pipe is disposed and the instance/slot are
		// released in the finally below, so a connected-but-silent or hung client can never hold its
		// instance forever (the historic monotonic OK→FAILED degradation).
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.OperationTimeoutMs));
		CancellationToken token = cts.Token;

		try
		{
			await using (pipe)
			{
				try
				{
					byte[] lenBuf = new byte[4];
					await pipe.ReadExactlyAsync(lenBuf, token).ConfigureAwait(false);
					int len = BitConverter.ToInt32(lenBuf);
					if (len <= 0 || len > IpcConstants.MaxFrameBytes)
					{
						_logger.LogWarning("IPC frame size {Len} rejected", len);
						return;
					}

					byte[] body = new byte[len];
					await pipe.ReadExactlyAsync(body, token).ConfigureAwait(false);

					IpcRequest request = MessagePackSerializer.Deserialize<IpcRequest>(body, cancellationToken: token);

					// Extend the deadline to the per-command budget now that the command is known. The
					// initial OperationTimeoutMs window covers the frame read; a silent client is
					// therefore reclaimed after that window without waiting for a command.
					int budgetMs = IpcConstants.TimeoutMsFor(request.Command);
					if (budgetMs > IpcConstants.OperationTimeoutMs)
					{
						cts.CancelAfter(TimeSpan.FromMilliseconds(budgetMs));
					}

					using IServiceScope scope = _services.CreateScope();
					IpcDispatcher dispatcher = scope.ServiceProvider.GetRequiredService<IpcDispatcher>();
					IpcResponse response = await dispatcher.DispatchAsync(request, token).ConfigureAwait(false);

					byte[] respBytes = MessagePackSerializer.Serialize(response, cancellationToken: token);
					await pipe.WriteAsync(BitConverter.GetBytes(respBytes.Length), token).ConfigureAwait(false);
					await pipe.WriteAsync(respBytes, token).ConfigureAwait(false);
					await pipe.FlushAsync(token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (ct.IsCancellationRequested)
				{
				}
				catch (OperationCanceledException)
				{
					_logger.LogWarning("IPC connection deadline exceeded");
				}
				catch (IOException ex)
				{
					_logger.LogDebug(ex, "IPC client disconnected mid-stream");
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "IPC handler failed");
				}
			}
		}
		finally
		{
			// Pipe disposal above has already run; now return the instance to the gauge and the
			// connection slot to the accept loop on every exit path (success, deadline, client
			// disconnect, fault, service stop).
			Interlocked.Decrement(ref _activeHandlers);
			_connectionSlots.Release();
			TrackPipeDisposed();
		}
	}
}
