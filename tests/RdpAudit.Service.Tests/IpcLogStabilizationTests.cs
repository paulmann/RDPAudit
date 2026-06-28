// File:    tests/RdpAudit.Service.Tests/IpcLogStabilizationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Covers the v1.3.4 IPC log-stabilization behaviour: the accept-loop classifier that
//          distinguishes an expected client disconnect (logged Debug, never durable) from a genuine
//          fault (Error + durable Critical), and the operation-log duplicate-collapsing used by the
//          Logs tab default view so a repeated identical row does not flood the operator's view.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Unit tests for the v1.3.4 IPC accept-loop fault classification and operation-log
/// duplicate collapsing.</summary>
public class IpcLogStabilizationTests
{
	[Theory]
	[InlineData(typeof(OperationCanceledException))]
	[InlineData(typeof(ObjectDisposedException))]
	[InlineData(typeof(IOException))]
	public void IsExpectedAcceptDisconnect_ClassifiesRoutineCloses_AsExpected(Type exceptionType)
	{
		Exception ex = exceptionType == typeof(ObjectDisposedException)
			? new ObjectDisposedException("pipe")
			: (Exception)Activator.CreateInstance(exceptionType)!;

		Assert.True(IpcServerWorker.IsExpectedAcceptDisconnect(ex));
	}

	[Theory]
	[InlineData(typeof(InvalidOperationException))]
	[InlineData(typeof(UnauthorizedAccessException))]
	[InlineData(typeof(System.Security.SecurityException))]
	public void IsExpectedAcceptDisconnect_ClassifiesGenuineFaults_AsUnexpected(Type exceptionType)
	{
		Exception ex = (Exception)Activator.CreateInstance(exceptionType)!;
		Assert.False(IpcServerWorker.IsExpectedAcceptDisconnect(ex));
	}

	[Fact]
	public void CollapseConsecutiveDuplicates_CollapsesRun_IntoSingleRowWithCount()
	{
		List<OperationLogDto> rows = new()
		{
			Row(1, "Ipc", "AcceptLoopFault", "boom"),
			Row(2, "Ipc", "AcceptLoopFault", "boom"),
			Row(3, "Ipc", "AcceptLoopFault", "boom"),
		};

		List<OperationLogDto> collapsed = IpcDispatcher.CollapseConsecutiveDuplicates(rows);

		Assert.Single(collapsed);
		Assert.Equal(3, collapsed[0].OccurrenceCount);
		Assert.Equal(1, collapsed[0].Id); // representative is the first (newest) row of the run
	}

	[Fact]
	public void CollapseConsecutiveDuplicates_KeepsDistinctRows_Separate()
	{
		List<OperationLogDto> rows = new()
		{
			Row(1, "Ipc", "AcceptLoopFault", "boom"),
			Row(2, "Firewall", "Repair", "ok"),
			Row(3, "Ipc", "AcceptLoopFault", "boom"),
		};

		List<OperationLogDto> collapsed = IpcDispatcher.CollapseConsecutiveDuplicates(rows);

		// Non-consecutive duplicates stay distinct so the timeline is preserved.
		Assert.Equal(3, collapsed.Count);
		Assert.All(collapsed, r => Assert.Equal(1, r.OccurrenceCount));
	}

	[Fact]
	public void CollapseConsecutiveDuplicates_DoesNotCollapse_AcrossSeverity()
	{
		List<OperationLogDto> rows = new()
		{
			Row(1, "Ipc", "AcceptLoopFault", "boom", OperationLogSeverity.Error),
			Row(2, "Ipc", "AcceptLoopFault", "boom", OperationLogSeverity.Critical),
		};

		List<OperationLogDto> collapsed = IpcDispatcher.CollapseConsecutiveDuplicates(rows);

		Assert.Equal(2, collapsed.Count);
	}

	[Fact]
	public void OperationLogQueryRequest_DefaultsToQuietView()
	{
		OperationLogQueryRequest req = new();
		Assert.True(req.ExcludeDebugNoise);
		Assert.True(req.GroupDuplicates);
	}

	private static OperationLogDto Row(
		long id,
		string source,
		string operation,
		string message,
		OperationLogSeverity severity = OperationLogSeverity.Error) => new()
	{
		Id = id,
		TimeUtc = DateTime.UtcNow,
		Severity = severity,
		Source = source,
		Operation = operation,
		Message = message,
		OccurrenceCount = 1,
	};
}
