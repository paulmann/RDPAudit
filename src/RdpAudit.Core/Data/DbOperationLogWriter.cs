// File:    src/RdpAudit.Core/Data/DbOperationLogWriter.cs
// Module:  RdpAudit.Core.Data
// Purpose: SQLite-backed IOperationLogWriter. Persists each entry on its own short-lived DbContext
//          (via the context factory) so it is safe to call from any worker / handler scope, and
//          gates detail fields (stack trace, details JSON) on the global DEBUG-mode setting. Every
//          write is wrapped so a logging failure self-logs to ILogger and is otherwise swallowed —
//          the operation-log facility must never be the reason a real action fails or the service
//          stops.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.1

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data;

/// <summary>SQLite-backed, best-effort <see cref="IOperationLogWriter"/>.</summary>
public sealed class DbOperationLogWriter : IOperationLogWriter
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<DbOperationLogWriter> _logger;

	public DbOperationLogWriter(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<DbOperationLogWriter> logger)
	{
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	private bool DebugEnabled => _options.CurrentValue.Diagnostics.DebugMode;

	public bool IsDebugEnabled => DebugEnabled;

	public async Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(entry);
		bool debug = DebugEnabled;

		try
		{
			OperationLog row = new()
			{
				TimeUtc = DateTime.UtcNow,
				Severity = entry.Severity,
				Source = Truncate(entry.Source, 64)!,
				Operation = Truncate(entry.Operation, 128)!,
				Message = Truncate(entry.Message, 2048)!,
				// Structured details are only meaningful when an operator is troubleshooting; storing
				// them unconditionally would bloat the table on every routine action.
				DetailsJson = debug ? Truncate(entry.DetailsJson, 65536) : null,
				ExceptionType = entry.Exception?.GetType().FullName is { } t ? Truncate(t, 256) : null,
				ExceptionMessage = entry.Exception?.Message is { } m ? Truncate(m, 2048) : null,
				// Stack traces are large and only useful in DEBUG investigations.
				StackTrace = debug ? Truncate(entry.Exception?.StackTrace, 65536) : null,
				CorrelationId = Truncate(entry.CorrelationId, 64),
				DurationMs = entry.DurationMs,
				IsDebug = debug,
				Actor = Truncate(entry.Actor, 256),
			};

			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			db.OperationLogs.Add(row);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// Shutdown / caller cancellation — drop the entry silently.
		}
		catch (Exception ex)
		{
			// The operation-log facility must never disrupt the calling action. Self-log to the
			// structured logger (file / Event Log) so the failure is still observable.
			_logger.LogWarning(ex, "OperationLog write failed for {Source}/{Operation}", entry.Source, entry.Operation);
		}
	}

	public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default)
		=> WriteAsync(new OperationLogEntry
		{
			Severity = OperationLogSeverity.Information,
			Source = source,
			Operation = operation,
			Message = message,
		}, ct);

	public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default)
		=> WriteAsync(new OperationLogEntry
		{
			Severity = OperationLogSeverity.Warning,
			Source = source,
			Operation = operation,
			Message = message,
			DetailsJson = detailsJson,
		}, ct);

	public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default)
		=> WriteAsync(new OperationLogEntry
		{
			Severity = severity,
			Source = source,
			Operation = operation,
			Message = message,
			Exception = exception,
		}, ct);

	public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default)
	{
		// No-op (and zero allocation) when DEBUG mode is off: verbose traces must not cost anything in
		// normal operation. The details payload is built lazily, so an expensive diagnostic string is
		// only materialised when an operator is actually troubleshooting.
		if (!DebugEnabled)
		{
			return Task.CompletedTask;
		}

		return WriteAsync(new OperationLogEntry
		{
			Severity = OperationLogSeverity.Information,
			Source = source,
			Operation = operation,
			Message = message,
			DetailsJson = detailsBuilder?.Invoke(),
			CorrelationId = correlationId,
		}, ct);
	}

	private static string? Truncate(string? value, int max)
		=> value is null ? null : (value.Length <= max ? value : value[..max]);
}
