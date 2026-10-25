/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Infrastructure | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : SingleInstanceGuard.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Process-wide single-instance enforcement for RdpAuditService. Wraps the kernel
//          named mutex Global\RdpAuditService in an IDisposable guard. The guard is acquired
//          synchronously BEFORE the host / DI services are built, so a second process can never
//          reach the IPC named pipe, apply EF migrations, or start a duplicate event collector.
//          The mutex is created through CreateMutexEx with an explicit DACL granting LocalSystem
//          and Administrators. If the OS refuses that explicit DACL (elevated-only TrustedInstaller
//          scenario, locked-down security descriptor configuration), the guard transparently
//          retries with the process-default security descriptor and reports
//          FallbackToDefaultAcl. Abandoned mutexes are recovered: WaitOne raises
//          AbandonedMutexException when the previous owner died without ReleaseMutex, and this type
//          treats that state as ownership acquisition, not startup failure.
// Depends: SingleInstanceNativeMethods (LibraryImport P/Invokes), SafeWaitHandle,
//          CommonSecurityDescriptor / DiscretionaryAcl, Win32Exception, Mutex.
// Extends: New process-wide startup checks should be added to Program.Main after the guard block
//          if they must run before any hosted service. Platform-specific exit-code rules belong
//          in SingleInstanceExitCodePolicy.

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace RdpAudit.Service.Infrastructure;

/// <summary>Result of a synchronous single-instance acquisition attempt.</summary>
public enum SingleInstanceAcquireStatus
{
	/// <summary>The process owns the mutex and startup may continue.</summary>
	Acquired,

	/// <summary>The previous owner died without releasing the mutex; ownership was recovered.</summary>
	RecoveredAbandoned,

	/// <summary>Another live process owns the mutex; startup must stop.</summary>
	AlreadyRunning,
}

/// <summary>Immutable outcome of <see cref="SingleInstanceGuard.TryAcquire"/>.</summary>
/// <param name="Status">Whether ownership was obtained, recovered, or refused.</param>
/// <param name="FallbackToDefaultAcl">True when the explicit LocalSystem/Administrators DACL could
/// not be applied and CreateMutexEx retried with the process default security descriptor.</param>
public readonly record struct SingleInstanceAcquireResult(
	SingleInstanceAcquireStatus Status,
	bool FallbackToDefaultAcl);

/// <summary>Pure exit-code policy for the single-instance guard.</summary>
public static class SingleInstanceExitCodePolicy
{
	/// <summary>
	/// Project-level exit code returned when startup is refused because the RdpAuditService
	/// mutex is already owned by another process. Selected to live outside both the 0..255
	/// conventional process-error range and Windows system error codes such as
	/// ERROR_FILE_NOT_FOUND (0x2); this value is intentionally NOT raised for ordinary
	/// host-lifecycle faults, which continue to use 1.
	/// </summary>
	public const int AlreadyRunningExitCode = 0x1000;

	private const int SuccessExitCode = 0;

	/// <summary>Maps a guard outcome to the process exit code.</summary>
	public static int GetExitCode(SingleInstanceAcquireStatus status)
	{
		return status == SingleInstanceAcquireStatus.AlreadyRunning
			? AlreadyRunningExitCode
			: SuccessExitCode;
	}
}

/// <summary>
/// Owns the named Windows mutex for the lifetime of the service process. Acquire once;
/// <see cref="TryAcquire"/> is synchronous and uses a zero-millisecond wait, so it never blocks
/// the service startup thread. No async/Task/CancellationToken surface is used because this guard
/// is consumed directly by Program.Main before the host and does not need cooperative cancellation.
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
	// ── Constants ──────────────────────────────────────────────────────────────

	public const string DefaultMutexName = @"Global\RdpAuditService";

	// MUTEX_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE
	//                     | MUTANT_MODIFY_STATE. Matches what Mutex requests for a
	//                     created-or-opened named mutex, and equals the numeric value of
	//                     System.Security.AccessControl.MutexRights.FullControl.
	private const int MutexAllAccess = 0x001F0001;

	private const int ErrorAccessDenied = 5;                     // ERROR_ACCESS_DENIED
	private const int ErrorInvalidOwner = 1307;                  // ERROR_INVALID_OWNER
	private const int ErrorPrivilegeNotHeld = 1314;              // ERROR_PRIVILEGE_NOT_HELD
	private const int ErrorInvalidSecurityDescriptor = 1338;     // ERROR_INVALID_SECURITY_DESCR
	private const int ErrorAlreadyExists = 183;                  // ERROR_ALREADY_EXISTS

	// ── State ──────────────────────────────────────────────────────────────────

	// Windows mutex waits are recursive per owner thread, so two handles opened by the same
	// process for the same kernel object both pass WaitOne. This process-wide registry adds the
	// missing single-holder guarantee inside one process; the kernel mutex still enforces the
	// cross-process exclusion. Keyed by mutex name, guarded by a dedicated lock.
	private static readonly object ProcessRegistryLock = new();
	private static readonly HashSet<string> ProcessOwnedMutexNames = new(StringComparer.Ordinal);

	private readonly string _mutexName;
	private readonly SingleInstanceMutexFactory? _mutexFactory;
	private IWindowsNamedMutex? _ownedMutex;
	private SingleInstanceAcquireResult? _acquireResult;
	private bool _ownsProcessRegistrySlot;
	private bool _disposed;

	// ── Construction ───────────────────────────────────────────────────────────

	public SingleInstanceGuard(string mutexName)
	{
		if (string.IsNullOrWhiteSpace(mutexName))
		{
			throw new ArgumentException("The mutex name must not be empty.", nameof(mutexName));
		}

		_mutexName = mutexName;
		_mutexFactory = null;
	}

	/// <summary>Test seam: allows a deterministic fake mutex in unit tests without exposing the
	/// Windows creation path.</summary>
	internal SingleInstanceGuard(string mutexName, SingleInstanceMutexFactory mutexFactory)
		: this(mutexName)
	{
		_mutexFactory = mutexFactory ?? throw new ArgumentNullException(nameof(mutexFactory));
	}

	// ── Acquisition ────────────────────────────────────────────────────────────

	/// <summary>
	/// Attempts to acquire the named mutex exactly once. This is a fast synchronous operation
	/// (WaitOne with zero timeout); it is executed before the host is built and therefore cannot
	/// block any service event loop or hosted worker. The result is cached, so repeated calls
	/// return the same outcome without touching the kernel.
	/// </summary>
	public SingleInstanceAcquireResult TryAcquire()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_acquireResult is not null)
		{
			return _acquireResult.Value;
		}

		// Process-level dedupe must happen before opening a kernel handle (see the registry
		// comment above). If another guard of THIS process already owns the name, refuse without
		// creating a second handle.
		if (!TryRegisterProcessOwnership(_mutexName))
		{
			SingleInstanceAcquireResult refusedByRegistry = new(
				SingleInstanceAcquireStatus.AlreadyRunning,
				FallbackToDefaultAcl: false);
			_acquireResult = refusedByRegistry;
			return refusedByRegistry;
		}

		_ownsProcessRegistrySlot = true;

		IWindowsNamedMutex mutex;
		try
		{
			mutex = CreateMutex();
		}
		catch
		{
			UnregisterProcessOwnership(_mutexName);
			_ownsProcessRegistrySlot = false;
			throw;
		}

		try
		{
			bool acquired;
			bool recoveredAbandoned = false;

			try
			{
				acquired = mutex.WaitOne(millisecondsTimeout: 0);
			}
			catch (AbandonedMutexException)
			{
				// Windows has transferred ownership to the caller: the previous owner terminated
				// without ReleaseMutex, so the mutex is abandoned but usable. Startup must continue
				// with ownership recovered; refusing to start would turn a recoverable state into a
				// service outage.
				acquired = true;
				recoveredAbandoned = true;
			}

			if (!acquired)
			{
				// Another LIVE process holds the mutex and we do not own anything: drop the handle,
				// release the process registry slot (this guard never became the owner), and report
				// the refusal.
				bool fallbackUsed = mutex.FallbackUsed;
				mutex.Dispose();
				UnregisterProcessOwnership(_mutexName);
				_ownsProcessRegistrySlot = false;

				SingleInstanceAcquireResult refused = new(
					SingleInstanceAcquireStatus.AlreadyRunning,
					fallbackUsed);
				_acquireResult = refused;
				return refused;
			}

			_ownedMutex = mutex;
			SingleInstanceAcquireResult owned = new(
				recoveredAbandoned
					? SingleInstanceAcquireStatus.RecoveredAbandoned
					: SingleInstanceAcquireStatus.Acquired,
				mutex.FallbackUsed);
			_acquireResult = owned;
			return owned;
		}
		catch
		{
			mutex.Dispose();
			UnregisterProcessOwnership(_mutexName);
			_ownsProcessRegistrySlot = false;
			throw;
		}
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		if (_ownedMutex is not null)
		{
			try
			{
				_ownedMutex.Release();
			}
			catch (Exception)
			{
				// Dispose must remain best-effort. ReleaseMutex failures are extremely rare at this
				// point (process shutdown), and throwing from a using declaration would mask the
				// real host result.
			}

			_ownedMutex.Dispose();
			_ownedMutex = null;
		}

		if (_ownsProcessRegistrySlot)
		{
			UnregisterProcessOwnership(_mutexName);
			_ownsProcessRegistrySlot = false;
		}

		_disposed = true;
		GC.SuppressFinalize(this);
	}

	// ── Process Registry Helpers ───────────────────────────────────────────────

	private static bool TryRegisterProcessOwnership(string mutexName)
	{
		lock (ProcessRegistryLock)
		{
			return ProcessOwnedMutexNames.Add(mutexName);
		}
	}

	private static void UnregisterProcessOwnership(string mutexName)
	{
		lock (ProcessRegistryLock)
		{
			ProcessOwnedMutexNames.Remove(mutexName);
		}
	}

	// ── Mutex Creation ─────────────────────────────────────────────────────────

	private IWindowsNamedMutex CreateMutex()
	{
		if (_mutexFactory is not null)
		{
			return _mutexFactory(_mutexName, out _);
		}

		return WindowsNamedMutex.Create(_mutexName, out _);
	}

	/// <summary>
	/// Production mutex wrapper. Uses CreateMutexEx so the mutex can be created without initial
	/// ownership and, when possible, with an explicit LocalSystem/Administrators DACL. The
	/// unmanaged handle is adopted into a managed <see cref="Mutex"/> whose SafeWaitHandle is
	/// the only stored native handle; no bare IntPtr is retained.
	/// </summary>
	private sealed class WindowsNamedMutex : IWindowsNamedMutex
	{
		private readonly Mutex _mutex;
		private bool _released;

		public bool FallbackUsed { get; }

		private WindowsNamedMutex(Mutex mutex, bool fallbackUsed)
		{
			_mutex = mutex;
			FallbackUsed = fallbackUsed;
		}

		public static WindowsNamedMutex Create(string name, out bool createdNew)
		{
			(SafeWaitHandle handle, bool created, bool fallbackUsed) = CreateMutexHandle(name);
			createdNew = created;

			// ADOPT the unmanaged handle into a managed Mutex. Mutex exposes no public constructor
			// taking a SafeWaitHandle, so the runtime pattern is: create an unnamed managed
			// instance, then swap its handle. The setter releases the previous (placeholder) handle
			// and the mutex becomes the sole owner of the kernel handle returned by CreateMutexEx.
			Mutex mutex = new(initiallyOwned: false);
			try
			{
				mutex.SafeWaitHandle = handle;
				return new WindowsNamedMutex(mutex, fallbackUsed);
			}
			catch
			{
				mutex.Dispose();
				handle.Dispose();
				throw;
			}
		}

		public bool WaitOne(int millisecondsTimeout) => _mutex.WaitOne(millisecondsTimeout);

		public void Release()
		{
			if (_released)
			{
				return;
			}

			// Release through the raw kernel entry point because the managed Mutex never performed
			// its own stateful WaitOne on this handle (the wait happened on the adopted handle
			// BEFORE adoption), so managed Mutex.ReleaseMutex ownership bookkeeping does not apply.
			int result = SingleInstanceNativeMethods.ReleaseMutex(_mutex.SafeWaitHandle);
			if (result == 0)
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError());
			}

			_released = true;
		}

		public void Dispose()
		{
			_mutex.Dispose();
		}
	}

	// ── Native Handle Creation ─────────────────────────────────────────────────

	private static (SafeWaitHandle Handle, bool CreatedNew, bool FallbackUsed) CreateMutexHandle(
		string name)
	{
		try
		{
			(SafeWaitHandle handle, bool createdNew) = CreateMutexHandleWithExplicitDacl(name);
			return (handle, createdNew, FallbackUsed: false);
		}
		catch (Win32Exception ex) when (IsFallbackEligible(ex.NativeErrorCode))
		{
			// FALLBACK RATIONALE: an explicit security descriptor can be refused in elevated /
			// restricted security configurations (e.g. ERROR_PRIVILEGE_NOT_HELD when the caller
			// cannot write the owner, or ERROR_INVALID_OWNER / ERROR_INVALID_SECURITY_DESCR under
			// locked-down policy). The service still needs a functional mutex; re-creating with a
			// null security descriptor applies the process default DACL and preserves
			// single-instance behavior. This produces a weaker ACL than the LocalSystem /
			// Administrators-only design, so the caller reports FallbackToDefaultAcl and
			// Program.Main logs a warning. The decision to keep this fallback (rather than
			// requiring TrustedInstaller-level elevation for a startup mutex) is deliberate:
			// service startup must not hard-fail on hosts where policy forbids custom DACLs.
			(SafeWaitHandle handle, bool createdNew) = CreateMutexHandleWithDefaultSecurity(name);
			return (handle, createdNew, FallbackUsed: true);
		}
	}

	private static (SafeWaitHandle Handle, bool CreatedNew) CreateMutexHandleWithExplicitDacl(
		string name)
	{
		byte[] securityDescriptor = BuildExplicitMutexSecurityDescriptor();

		using SafeHGlobalBuffer securityDescriptorBuffer = new(securityDescriptor.Length);
		Marshal.Copy(
			securityDescriptor,
			0,
			securityDescriptorBuffer.DangerousGetHandle(),
			securityDescriptor.Length);

		SingleInstanceNativeMethods.SECURITY_ATTRIBUTES attributes = new()
		{
			nLength = Marshal.SizeOf<SingleInstanceNativeMethods.SECURITY_ATTRIBUTES>(),
			lpSecurityDescriptor = securityDescriptorBuffer.DangerousGetHandle(),
			bInheritHandle = 0,
		};

		using SafeHGlobalBuffer securityAttributesBuffer = new(
			Marshal.SizeOf<SingleInstanceNativeMethods.SECURITY_ATTRIBUTES>());
		Marshal.StructureToPtr(
			attributes,
			securityAttributesBuffer.DangerousGetHandle(),
			fDeleteOld: false);

		// The pointer passed here is a transient view INSIDE a SafeHandle-owned buffer; it is not
		// retained by the guard. The only native handle kept is the SafeWaitHandle returned below.
		return CreateMutexHandle(name, securityAttributesBuffer.DangerousGetHandle());
	}

	private static (SafeWaitHandle Handle, bool CreatedNew) CreateMutexHandleWithDefaultSecurity(
		string name)
	{
		return CreateMutexHandle(name, securityAttributesPointer: 0);
	}

	private static (SafeWaitHandle Handle, bool CreatedNew) CreateMutexHandle(
		string name,
		nint securityAttributesPointer)
	{
		nint rawHandle = SingleInstanceNativeMethods.CreateMutexEx(
			securityAttributesPointer,
			name,
			dwFlags: 0,
			(uint)MutexAllAccess);
		int lastError = Marshal.GetLastPInvokeError();

		if (rawHandle == 0)
		{
			throw new Win32Exception(lastError);
		}

		// For a newly created mutex the last error is ERROR_SUCCESS; for an existing one the
		// function returns the handle and sets ERROR_ALREADY_EXISTS (documented CreateMutexEx
		// contract).
		SafeWaitHandle safeHandle = new((IntPtr)rawHandle, ownsHandle: true);
		return (safeHandle, lastError != ErrorAlreadyExists);
	}

	private static bool IsFallbackEligible(int error)
	{
		return error == ErrorAccessDenied
			|| error == ErrorPrivilegeNotHeld
			|| error == ErrorInvalidSecurityDescriptor
			|| error == ErrorInvalidOwner;
	}

	private static byte[] BuildExplicitMutexSecurityDescriptor()
	{
		SecurityIdentifier localSystem = new(WellKnownSidType.LocalSystemSid, null);
		SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

		DiscretionaryAcl discretionaryAcl = new(isContainer: false, isDS: false, capacity: 2);

		// MutexAllAccess is numerically equal to MutexRights.FullControl: both require
		// STANDARD_RIGHTS_ALL, SYNCHRONIZE and MUTANT_QUERY_STATE/MODIFY_STATE bits.
		discretionaryAcl.AddAccess(
			AccessControlType.Allow,
			localSystem,
			MutexAllAccess,
			InheritanceFlags.None,
			PropagationFlags.None);
		discretionaryAcl.AddAccess(
			AccessControlType.Allow,
			administrators,
			MutexAllAccess,
			InheritanceFlags.None,
			PropagationFlags.None);

		// Self-relative absolute SD: owner + primary group are LocalSystem, DACL grants only the
		// two required SIDs FullControl. CreateMutexEx serializes it into an absolute
		// SECURITY_DESCRIPTOR and applies it to the new kernel object.
		CommonSecurityDescriptor descriptor = new(
			isContainer: false,
			isDS: false,
			flags: ControlFlags.DiscretionaryAclPresent,
			owner: localSystem,
			group: localSystem,
			systemAcl: null,
			discretionaryAcl: discretionaryAcl);

		byte[] binaryForm = new byte[descriptor.BinaryLength];
		descriptor.GetBinaryForm(binaryForm, 0);
		return binaryForm;
	}
}

/// <summary>Testable mutex shape; production implementation wraps <see cref="Mutex"/>.</summary>
internal interface IWindowsNamedMutex : IDisposable
{
	bool FallbackUsed { get; }

	bool WaitOne(int millisecondsTimeout);

	void Release();
}

/// <summary>Factory signature used by the <see cref="SingleInstanceGuard"/> test seam.</summary>
internal delegate IWindowsNamedMutex SingleInstanceMutexFactory(
	string mutexName,
	out bool createdNew);

/// <summary>
/// LibraryImport-only native surface. SetLastError is enabled on every call, and every caller
/// reads <see cref="Marshal.GetLastPInvokeError"/> immediately, wrapping failures in
/// <see cref="Win32Exception"/>. All handles are SafeHandle-compatible types; no bare IntPtr
/// crosses the interop boundary.
/// </summary>
internal static partial class SingleInstanceNativeMethods
{
	internal struct SECURITY_ATTRIBUTES
	{
		internal int nLength;
		internal IntPtr lpSecurityDescriptor;
		internal int bInheritHandle;
	}

	[LibraryImport(
		"kernel32.dll",
		EntryPoint = "CreateMutexExW",
		SetLastError = true,
		StringMarshalling = StringMarshalling.Utf16)]
	internal static partial nint CreateMutexEx(
		nint lpMutexAttributes,
		string lpName,
		uint dwFlags,
		uint dwDesiredAccess);

	[LibraryImport("kernel32.dll", EntryPoint = "ReleaseMutex", SetLastError = true)]
	internal static partial int ReleaseMutex(SafeWaitHandle hMutex);
}

/// <summary>Owns an unmanaged HGlobal buffer via SafeHandle semantics.</summary>
internal sealed class SafeHGlobalBuffer : SafeHandleZeroOrMinusOneIsInvalid
{
	internal SafeHGlobalBuffer()
		: base(ownsHandle: true)
	{
	}

	public SafeHGlobalBuffer(int size)
		: this()
	{
		ArgumentOutOfRangeException.ThrowIfNegative(size);

		SetHandle(Marshal.AllocHGlobal(size));
		if (IsInvalid)
		{
			throw new OutOfMemoryException(
				"Unable to allocate unmanaged memory for native security attributes.");
		}
	}

	protected override bool ReleaseHandle()
	{
		Marshal.FreeHGlobal(handle);
		return true;
	}
}
