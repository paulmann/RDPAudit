/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrashGuardBoundedCompletionTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: P2-2 regression tests for CrashGuard's bounded OperationLog write on the crash path.
//          Pins that a hanging OperationLog writer cannot stall RecordCrash anywhere near the old
//          3-second wait: the fault handler must return well under 2 seconds (the production bound
//          is 250 ms), and that the durable writer is actually invoked exactly once with a
//          Critical entry so the crash is still recorded when the database responds in time.
// Depends: CrashGuard, IOperationLogWriter, OperationLogEntry, OperationLogSeverity, xunit,
//          Microsoft.Extensions.Logging.Abstractions
// Extends: Add assertions here when the fault-handler wait bound changes or when a new durable
//          sink is added to the RecordCrash path.

using System.Diagnostics;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class CrashGuardBoundedCompletionTests
{
	[Fact]
	public void RecordCrash_WhenOperationLogWriterHangs_ReturnsWithinBoundedWindow()
	{
		HangingOperationLogWriter writer = new();
		CrashGuard guard = new(writer, NullLogger<CrashGuard>.Instance);

		MethodInfo recordCrash = typeof(CrashGuard).GetMethod(
			"RecordCrash", BindingFlags.NonPublic | BindingFlags.Instance)!;

		Stopwatch stopwatch = Stopwatch.StartNew();
		recordCrash.Invoke(guard, new object?[] { "unit-test", new InvalidOperationException("boom"), false });
		stopwatch.Stop();

		// The hanging writer forces the 250 ms bound to be consumed; assert its presence and
		// its upper bound (the old 3 s wait must never return).
		Assert.True(
			stopwatch.Elapsed >= TimeSpan.FromMilliseconds(200),
			$"RecordCrash took {stopwatch.Elapsed.TotalMilliseconds:F0} ms; the bounded wait was not engaged.");
		Assert.True(
			stopwatch.Elapsed < TimeSpan.FromSeconds(2),
			$"RecordCrash took {stopwatch.Elapsed.TotalMilliseconds:F0} ms; expected a bounded fault-handler wait.");
		Assert.Equal(1, writer.WriteCount);
		Assert.Equal(OperationLogSeverity.Critical, writer.LastSeverity);
	}

	private sealed class HangingOperationLogWriter : IOperationLogWriter
	{
		private readonly TaskCompletionSource<int> _neverCompletes = new(TaskCreationOptions.RunContinuationsAsynchronously);

		public int WriteCount { get; private set; }

		public OperationLogSeverity? LastSeverity { get; private set; }

		public bool IsDebugEnabled => false;

		public Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default)
		{
			WriteCount++;
			LastSeverity = entry.Severity;
			return _neverCompletes.Task;
		}

		public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default)
			=> Task.CompletedTask;

		public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default)
			=> Task.CompletedTask;

		public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default)
			=> Task.CompletedTask;

		public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default)
			=> Task.CompletedTask;
	}
}
