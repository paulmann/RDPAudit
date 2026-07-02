// File:    src/RdpAudit.Service/Workers/IpcServerWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Hosts the named-pipe IPC server with admin-only ACL.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.6.4

using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using MessagePack;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc;
using RdpAudit.Service.Ipc;

namespace RdpAudit.Service.Workers;

/// <summary>Hosts the named-pipe IPC server with admin-only ACL.</summary>
public sealed class IpcServerWorker : BackgroundService
{
	private const int MaxConcurrent = 10;

	/// <summary>Minimum gap between durable Critical operation-log records for an identical accept-loop
	/// fault signature. A genuinely broken accept loop (e.g. ACL failure) re-faults every iteration; without
	/// this gate it would flood the OperationLog table with thousands of identical Critical rows per minute.
	/// The structured logger still records every occurrence at the classified level.</summary>
	private static readonly TimeSpan FaultLogDedupeWindow = TimeSpan.FromMinutes(1);

	private readonly IServiceProvider _services;
	private readonly ILogger<IpcServerWorker> _logger;

	// Dedupe state for repeated accept-loop faults (single accept loop -> no cross-thread contention).
	private string? _lastFaultSignature;
	private DateTime _lastFaultDurableLogUtc = DateTime.MinValue;

	/// <summary>Reset to false on CreatePipe failure so the "pipe accepting" banner re-emits after recovery.</summary>
	private bool _pipeBannerLogged;

	/// <summary>Counts consecutive IsExpectedAcceptDisconnect IOExceptions from WaitForConnectionAsync.
	/// When this exceeds the threshold it suggests Kaspersky is killing the pipe immediately after creation
	/// (CreatePipe succeeds, but the pipe is destroyed before a client can connect).
	/// Escalate to Warning after threshold so the issue is visible without IPC.</summary>
	private int _consecutiveWaitFailures;
	private const int WaitFailureWarnThreshold = 5;

	public IpcServerWorker(IServiceProvider services, ILogger<IpcServerWorker> logger)
	{
		_services = services;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		// Written unconditionally and before any pipe/AV interaction so ipc-startup.log always shows a
		// worker-start breadcrumb even if the process is killed or faults before CreatePipe ever runs.
		WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} ExecuteAsync entered (pid={Environment.ProcessId})");
		_logger.LogInformation("{Worker} starting", nameof(IpcServerWorker));
		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("Named pipe ACL APIs require Windows; IPC disabled on this host.");
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
			return;
		}

		try
		{
			List<Task> connectionTasks = new();
			while (!stoppingToken.IsCancellationRequested)
			{
				// -- CreatePipe is intentionally OUTSIDE the accept-try so that failures from the
				//    OS or AV/EDR interceptors (UnauthorizedAccessException, IOException from
				//    Kaspersky KLIF etc.) are caught and logged at Warning level, NOT silently
				//    swallowed as IsExpectedAcceptDisconnect (which treats all IOException as a
				//    normal client close). This is the primary diagnostic for "IPC Connected: no".
				NamedPipeServerStream? pipe = null;
				try
				{
					pipe = CreatePipe();
					if (!_pipeBannerLogged)
					{
						_pipeBannerLogged = true;
						_consecutiveWaitFailures = 0;
						_logger.LogInformation(
							"{Worker} named pipe \\\\.\\pipe\\{PipeName} created -- accepting connections (ACL: Administrators + LocalSystem)",
							nameof(IpcServerWorker), IpcConstants.PipeName);
						WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe OK -- \\\\.\\pipe\\{IpcConstants.PipeName} accepting connections");
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
				{
					// Most-likely cause: Kaspersky / another EDR intercepts NamedPipeServerStreamAcl.Create()
					// and returns access-denied or a broken-pipe error before any client connects.
					// Mark pipe banner as unlogged so next success re-emits it.
					_pipeBannerLogged = false;
					_logger.LogWarning(ex,
						"{Worker} CreatePipe FAILED [{ExType}]: {ExMsg} -- possible AV/EDR pipe interception " +
						"(Kaspersky?). Add RdpAudit.Service.exe to your AV trusted list. Retrying in 5 s.",
						nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
					WriteIpcDebugLine($"[{DateTime.UtcNow:O}] CreatePipe FAILED [{ex.GetType().Name}]: {ex.Message}");
					await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
					try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false); }
					catch (OperationCanceledException) { break; }
					continue;
				}
				catch (Exception ex)
				{
					_pipeBannerLogged = false;
					_logger.LogError(ex,
						"{Worker} CreatePipe unexpected fault [{ExType}]: {ExMsg} -- continuing",
						nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
					await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
					try { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false); }
					catch (OperationCanceledException) { break; }
					continue;
				}

				try
				{
					await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					await pipe.DisposeAsync().ConfigureAwait(false);
					break;
				}
				catch (Exception ex) when (IsExpectedAcceptDisconnect(ex))
				{
					await pipe.DisposeAsync().ConfigureAwait(false);
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

					// Back-off to prevent tight-loop CPU spin when AV/EDR repeatedly destroys the pipe.
					if (_consecutiveWaitFailures > 0)
					{
						try { await Task.Delay(TimeSpan.FromMilliseconds(500), stoppingToken).ConfigureAwait(false); }
						catch (OperationCanceledException) { break; }
					}
					continue;
				}
				catch (Exception ex)
				{
					await pipe.DisposeAsync().ConfigureAwait(false);
					_logger.LogError(ex,
						"{Worker} WaitForConnection fault [{ExType}]: {ExMsg} -- continuing",
						nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
					await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
					try { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false); }
					catch (OperationCanceledException) { break; }
					continue;
				}

				_consecutiveWaitFailures = 0;
				Task task = HandleConnectionAsync(pipe, stoppingToken);
				connectionTasks.Add(task);
				connectionTasks.RemoveAll(t => t.IsCompleted);
				if (connectionTasks.Count > MaxConcurrent)
				{
					_logger.LogWarning("IPC concurrent connection cap exceeded ({Count}); rejecting new ones briefly", connectionTasks.Count);
					await Task.Delay(50, stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			// A fault escaping this outer try means the accept loop is dead and the BackgroundService is
			// about to stop silently from the host's perspective — the historic cause of "IPC Connected:
			// no" with no trace anywhere. Always leave a breadcrumb on disk before rethrowing.
			WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} FATAL accept-loop exit [{ex.GetType().Name}]: {ex.Message}");
			_logger.LogCritical(ex, "{Worker} accept loop terminated unexpectedly [{ExType}]: {ExMsg}", nameof(IpcServerWorker), ex.GetType().Name, ex.Message);
			await TryLogOperationFaultAsync(ex, stoppingToken).ConfigureAwait(false);
			throw;
		}
		finally
		{
			WriteIpcDebugLine($"[{DateTime.UtcNow:O}] {nameof(IpcServerWorker)} ExecuteAsync exiting");
			_logger.LogInformation("{Worker} stopped", nameof(IpcServerWorker));
		}
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
		// also surfaces as an Win32-backed IOException. Both are the expected close of a client session.
		IOException => true,
		_ => false,
	};

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
			// Suppress the durable write for a repeated identical fault inside the dedupe window; the
			// structured logger already recorded this occurrence at Error level above.
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

	[SupportedOSPlatform("windows")]
	/// <summary>Appends one line to <c>%ProgramData%\RdpAudit\ipc-startup.log</c>.
	/// Provides IPC-startup diagnostics that are readable WITHOUT a working IPC channel.
	/// Silently swallows all I/O errors so a full disk never kills the accept loop.</summary>
	private static void WriteIpcDebugLine(string line)
	{
		try
		{
			// Co-located with the structured Serilog output (Program.ConfigureSerilog writes to the
			// same "logs" subfolder) so operators only need to look in one place for every service log
			// artifact instead of hunting for a stray file directly under %ProgramData%\RdpAudit.
			string dir = Path.Combine(
				Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
				"RdpAudit",
				"logs");
			Directory.CreateDirectory(dir);
			string logPath = Path.Combine(dir, "ipc-startup.log");
			FileInfo fi = new(logPath);
			if (fi.Exists && fi.Length > 512 * 1024)
				File.Delete(logPath);
			File.AppendAllText(logPath, line + Environment.NewLine);
		}
		catch
		{
			// Never let a debug write kill the accept loop.
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
			MaxConcurrent,
			PipeTransmissionMode.Message,
			PipeOptions.Asynchronous | PipeOptions.WriteThrough,
			inBufferSize: 65_536,
			outBufferSize: 65_536,
			pipeSecurity: security);
	}

	private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
	{
		_logger.LogDebug("{Worker} client connected -- dispatching", nameof(IpcServerWorker));
		await using (pipe)
		{
			// Read the request frame first under the short default deadline (a connected client must send
			// promptly), then widen the deadline to the per-command budget before dispatching. This keeps
			// the server and client agreeing on how long a long-running command (firewall repair / verify /
			// Tools Diag) is allowed to take, so the service is not cancelled mid-operation while the client
			// still waits -- the historic cause of "service unreachable" right after a Repair.
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.OperationTimeoutMs));
			CancellationToken token = cts.Token;
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

				// Extend the deadline to the per-command budget now that the command is known. The Stopwatch
				// already elapsed during the read is negligible against multi-second command budgets.
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
}
