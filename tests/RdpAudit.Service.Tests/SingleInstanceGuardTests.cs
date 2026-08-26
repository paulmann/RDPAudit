/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Tests | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : SingleInstanceGuardTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verifies the pre-host single-instance guard. Deterministic and handle-clean: every
//          guard is disposed before the test returns, mutex names are unique per test run, and
//          in-process duplicate ownership is asserted through the guard's process-level registry.
//          The AbandonedMutexException path is exercised through the internal factory test seam
//          because true in-proc abandonment requires the owning THREAD to terminate, which an
//          xUnit test process cannot simulate for itself; the fake reproduces the exact
//          exception the kernel raises. Windows-only: on non-Windows hosts every test is skipped.
// Depends: SingleInstanceGuard, SingleInstanceExitCodePolicy, xUnit, FakeWindowsNamedMutex.
// Extends: Test-file pattern of the suite - direct structured asserts, deterministic names,
//          skip-on-non-Windows via the SingleInstanceWindowsFact attribute.

using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SingleInstanceGuardTests
{
	// ── Guard Acquisition Tests ────────────────────────────────────────────────

	[SingleInstanceWindowsFact]
	public void TryAcquire_TwoSequentialAcquiresInSameProcess_SecondReturnsFalse()
	{
		string name = CreateUniqueMutexName();
		using SingleInstanceGuard first = CreateGuard(name);
		using SingleInstanceGuard second = CreateGuard(name);

		SingleInstanceAcquireResult firstResult = first.TryAcquire();
		SingleInstanceAcquireResult secondResult = second.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.Acquired, firstResult.Status);
		// In a non-elevated test runner the explicit LocalSystem/Administrators DACL can legitimately
		// fall back to the process-default ACL; the acquisition contract is the only thing asserted.
		Assert.Equal(SingleInstanceAcquireStatus.AlreadyRunning, secondResult.Status);
	}

	[SingleInstanceWindowsFact]
	public void TryAcquire_AfterFirstGuardDisposed_SecondAcquiresTheSameMutex()
	{
		string name = CreateUniqueMutexName();

		using SingleInstanceGuard first = CreateGuard(name);
		SingleInstanceAcquireResult firstResult = first.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.Acquired, firstResult.Status);

		first.Dispose();

		using SingleInstanceGuard second = CreateGuard(name);
		SingleInstanceAcquireResult secondResult = second.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.Acquired, secondResult.Status);
	}

	[SingleInstanceWindowsFact]
	public void TryAcquire_WithDaclFallback_KeepsOwnershipAndReportsFallback()
	{
		bool factoryInvoked = false;
		using SingleInstanceGuard guard = new(CreateUniqueMutexName(), (string name, out bool createdNew) =>
		{
			createdNew = true;
			factoryInvoked = true;
			return new FakeWindowsNamedMutex(acquirable: true, fallbackUsed: true);
		});

		SingleInstanceAcquireResult result = guard.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.Acquired, result.Status);
		Assert.True(result.FallbackToDefaultAcl);
		Assert.True(factoryInvoked);
	}

	// ── Abandoned Mutex Recovery Tests ─────────────────────────────────────────

	[SingleInstanceWindowsFact]
	public void TryAcquire_WhenWaitOneThrowsAbandonedMutexException_DoesNotThrowAndRecoversOwnership()
	{
		// The fake raises the same AbandonedMutexException the kernel raises when the previous
		// owner thread terminated without ReleaseMutex. The guard must treat ownership as
		// transferred and report RecoveredAbandoned instead of failing startup.
		using SingleInstanceGuard survivor = CreateGuardWithAbandoningMutex(CreateUniqueMutexName());

		SingleInstanceAcquireResult survivorResult = survivor.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.RecoveredAbandoned, survivorResult.Status);
		Assert.False(survivorResult.FallbackToDefaultAcl);
	}

	[SingleInstanceWindowsFact]
	public void TryAcquire_AfterAbandonedRecovery_GuardRetainsOwnership()
	{
		// After the survivor recovers the abandoned mutex it must keep the process-level owner
		// slot, so a second guard for the SAME name is refused. This proves the recovery path did
		// not yield ownership.
		string name = CreateUniqueMutexName();
		using SingleInstanceGuard survivor = CreateGuardWithAbandoningMutex(name);
		SingleInstanceAcquireResult survivorResult = survivor.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.RecoveredAbandoned, survivorResult.Status);

		using SingleInstanceGuard second = CreateGuard(name);
		SingleInstanceAcquireResult secondResult = second.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.AlreadyRunning, secondResult.Status);
	}

	// ── Exit Code Policy Tests ─────────────────────────────────────────────────

	[SingleInstanceWindowsFact]
	public void GetExitCode_ForAlreadyRunning_ReturnsDocumentedExitCode()
	{
		int exitCode = SingleInstanceExitCodePolicy.GetExitCode(SingleInstanceAcquireStatus.AlreadyRunning);

		Assert.Equal(SingleInstanceExitCodePolicy.AlreadyRunningExitCode, exitCode);
		Assert.Equal(0x1000, exitCode);
	}

	[SingleInstanceWindowsFact]
	public void GetExitCode_ForAlreadyRunning_IsDistinctFromWin32AndHostFaultCodes()
	{
		int exitCode = SingleInstanceExitCodePolicy.GetExitCode(SingleInstanceAcquireStatus.AlreadyRunning);

		// ERROR_FILE_NOT_FOUND (0x2) is the error the legacy pipe race could surface; 1 is the
		// generic host-lifecycle fault code. The documented project code must never collide
		// with either.
		Assert.NotEqual(2, exitCode);
		Assert.NotEqual(1, exitCode);
		Assert.Equal(0x1000, exitCode);
	}

	[SingleInstanceWindowsFact]
	public void GetExitCode_ForAcquiredOrRecovered_ReturnsZero()
	{
		Assert.Equal(0, SingleInstanceExitCodePolicy.GetExitCode(SingleInstanceAcquireStatus.Acquired));
		Assert.Equal(0, SingleInstanceExitCodePolicy.GetExitCode(SingleInstanceAcquireStatus.RecoveredAbandoned));
	}

	[SingleInstanceWindowsFact]
	public void TryAcquire_OnSameGuard_IsIdempotentAndReturnsSameResult()
	{
		using SingleInstanceGuard guard = CreateGuard(CreateUniqueMutexName());

		SingleInstanceAcquireResult first = guard.TryAcquire();
		SingleInstanceAcquireResult second = guard.TryAcquire();

		Assert.Equal(SingleInstanceAcquireStatus.Acquired, first.Status);
		Assert.Equal(first, second);
	}

	// ── Helpers ────────────────────────────────────────────────────────────────

	private static SingleInstanceGuard CreateGuard(string? name = null)
	{
		return new SingleInstanceGuard(name ?? CreateUniqueMutexName());
	}

	private static SingleInstanceGuard CreateGuardWithAbandoningMutex(string name)
	{
		return new SingleInstanceGuard(name, (string name, out bool createdNew) =>
		{
			createdNew = true;
			return new FakeWindowsNamedMutex(
				acquirable: true,
				fallbackUsed: false,
				throwAbandonedOnFirstWait: true);
		});
	}

	private static string CreateUniqueMutexName()
	{
		return @"Global\RdpAuditService.Tests." + Guid.NewGuid().ToString("N");
	}

	// ── Fakes ──────────────────────────────────────────────────────────────────

	private sealed class FakeWindowsNamedMutex : IWindowsNamedMutex
	{
		private readonly bool _acquirable;
		private readonly bool _throwAbandonedOnFirstWait;
		private bool _waitCalled;
		private bool _released;

		public FakeWindowsNamedMutex(
			bool acquirable,
			bool fallbackUsed,
			bool throwAbandonedOnFirstWait = false)
		{
			_acquirable = acquirable;
			FallbackUsed = fallbackUsed;
			_throwAbandonedOnFirstWait = throwAbandonedOnFirstWait;
		}

		public bool FallbackUsed { get; }

		public bool WaitOne(int millisecondsTimeout)
		{
			if (_throwAbandonedOnFirstWait && !_waitCalled)
			{
				_waitCalled = true;
				throw new AbandonedMutexException(
					"The named mutex was abandoned by its previous owner.");
			}

			return _acquirable;
		}

		public void Release()
		{
			_released = true;
		}

		public void Dispose()
		{
			if (!_released)
			{
				Release();
			}
		}
	}
}

/// <summary>Fact attribute that skips with a descriptive reason on non-Windows hosts.</summary>
internal sealed class SingleInstanceWindowsFactAttribute : FactAttribute
{
	public SingleInstanceWindowsFactAttribute()
	{
		if (!OperatingSystem.IsWindows())
		{
			Skip = "SingleInstanceGuard uses Windows kernel named mutexes and the test requires Windows.";
		}
	}
}
