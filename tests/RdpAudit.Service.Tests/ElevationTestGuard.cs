/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ElevationTestGuard.cs
// Project: RdpAudit.Service.Tests
// Purpose: B21/P1-1 regression guard. A handful of tests in this project bind a REAL Windows named pipe
//          through IpcServerWorker, whose security descriptor is the PRODUCTION one: owner SYSTEM /
//          BUILTIN\Administrators, access granted to Administrators only (the ACL is a security control and
//          must never be relaxed for a test). Creating that pipe - and, on some hosts, connecting to it -
//          therefore requires an elevated process token. On a non-elevated host those tests used to fail
//          with System.UnauthorizedAccessException from NamedPipeClientStream.ConnectAsync, which reads as
//          "the accept loop is broken" when the truth is "this host cannot run this test at all". Six to
//          nine false failures on every non-elevated developer machine or CI agent is exactly the trust
//          erosion B4/B21 record.
//          The fix is test-side only: state the precondition and SKIP with a recorded reason. Nothing here
//          touches the production pipe ACL.
//          Two properties are required and both are implemented deliberately:
//            1. FAIL-CLOSED. Any failure of the elevation probe (no token, denied registry/SID lookup, an
//               unexpected platform exception) is reported as NOT elevated, so the tests skip rather than
//               run and fail. "We could not prove we are elevated" must never read as "we are elevated".
//            2. INJECTABLE. `SkipReason` is decided by the pure function `ResolveSkipReason(bool)`, and the
//               boolean comes from `IsElevated`, whose probe is replaceable through `OverrideProbe` (an
//               internal seam visible only to this test assembly, since this type lives in it). That is not
//               a nicety: the automation host for this engagement is ELEVATED (IsInRole(Administrator) =
//               True) and a non-elevated run is not available on it, so without the seam only the "run"
//               branch could ever be exercised. The skip branch is covered by driving the attribute through
//               the seam - deterministically, not by hope.
//          What this guard is NOT: it is not a production elevation check. The Configurator has its own
//          (src/RdpAudit.Configurator/Services/ElevationGuard.cs) and the service refuses to start paths
//          that need a privilege at the point of use.
// Depends: xunit (FactAttribute / TheoryAttribute), System.Security.Principal
// Extends: Mark every test that starts or connects to a real named pipe with [ElevationFact] /
//          [ElevationTheory]. ElevationPreconditionMetaTests fails the suite when one is missed, so the
//          precondition cannot silently disappear again (the B21 regression).

using System.Runtime.Versioning;
using System.Security.Principal;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Decides whether the current test host is allowed to run the real-named-pipe tests, and states
/// why they are skipped when it is not.</summary>
[SupportedOSPlatform("windows")]
internal static class ElevationTestGuard
{
	/// <summary>Reason recorded on every skipped real-pipe test. It names the precondition, the observed
	/// fact and the remedy, because a skip line is often the only thing a CI reader sees.</summary>
	internal const string NonElevatedSkipReason =
		"Requires an elevated (Administrator) process: this test binds or connects to a real Windows named "
		+ "pipe protected by the production ACL, which grants access to Administrators only. The production "
		+ "ACL is a security control and is intentionally NOT relaxed for tests. Run the suite from an "
		+ "elevated shell (or an elevated CI agent) to execute this test.";

	private static readonly object Gate = new();

	/// <summary>Test-only replacement for the elevation probe. Null means "use the real probe".</summary>
	private static Func<bool>? _probeOverride;

	/// <summary>Cached result of the real probe. Caching matters because the probe opens a token and
	/// resolves the Administrators SID; doing that per test method is measurable and pointless - the
	/// elevation of a process cannot change while it runs.</summary>
	private static bool? _cachedRealProbe;

	/// <summary>True when the current process token is in BUILTIN\Administrators. Fail-closed: every
	/// failure of the probe is reported as <see langword="false"/>.</summary>
	internal static bool IsElevated
	{
		get
		{
			lock (Gate)
			{
				if (_probeOverride is { } probe)
				{
					// Deliberately NOT cached: an injected probe is a seam, and a seam that remembers its
					// first answer cannot express "not elevated" and "elevated" in the same test run.
					return InvokeSafely(probe);
				}

				_cachedRealProbe ??= InvokeSafely(ProbeCurrentProcess);
				return _cachedRealProbe.Value;
			}
		}
	}

	/// <summary>The reason a real-pipe test must be skipped, or null when it may run.</summary>
	internal static string? SkipReason => ResolveSkipReason(IsElevated);

	/// <summary>Pure decision function: the whole precondition in one place, so both branches are testable
	/// without a token and without changing how the suite is launched.</summary>
	internal static string? ResolveSkipReason(bool elevated) => elevated ? null : NonElevatedSkipReason;

	/// <summary>Raw, uncached probe of the current process token. Public to the test assembly so a test can
	/// record the observed host state in its output; failures are reported as not elevated.</summary>
	internal static bool ProbeCurrentProcess()
	{
		if (!OperatingSystem.IsWindows())
		{
			// The named-pipe tests are Windows-only anyway; on another platform the elevation precondition
			// cannot be satisfied, and skipping is the honest report.
			return false;
		}

		using WindowsIdentity identity = WindowsIdentity.GetCurrent();
		WindowsPrincipal principal = new(identity);
		return principal.IsInRole(WindowsBuiltInRole.Administrator);
	}

	/// <summary>Replaces the elevation probe for the lifetime of the returned scope and clears the cached
	/// real answer while it is active. Used only by the tests that cover both branches of the guard.</summary>
	internal static IDisposable OverrideProbe(Func<bool> probe)
	{
		ArgumentNullException.ThrowIfNull(probe);
		lock (Gate)
		{
			Func<bool>? previous = _probeOverride;
			_probeOverride = probe;
			return new ProbeOverride(previous);
		}
	}

	/// <summary>Drops the cached probe answer so the next read performs a real token check.</summary>
	internal static void ResetCache()
	{
		lock (Gate)
		{
			_cachedRealProbe = null;
		}
	}

	private static bool InvokeSafely(Func<bool> probe)
	{
		try
		{
			return probe();
		}
		catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
		{
			// Fail-closed: "we could not establish that we are elevated" is reported as not elevated, which
			// skips the tests. The alternative - assuming elevation - turns an environment problem into a
			// red suite and is exactly the failure mode this guard exists to remove.
			return false;
		}
	}

	private sealed class ProbeOverride(Func<bool>? previous) : IDisposable
	{
		private bool _disposed;

		public void Dispose()
		{
			lock (Gate)
			{
				if (_disposed)
				{
					return;
				}

				_disposed = true;
				_probeOverride = previous;
				_cachedRealProbe = null;
			}
		}
	}
}

/// <summary>A <see cref="FactAttribute"/> that skips on a host where the process is not elevated, with the
/// reason recorded in the test report. Use it for every test that binds or connects to a real named pipe;
/// <c>ElevationPreconditionMetaTests</c> fails the suite when such a test does not carry it.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ElevationFactAttribute : FactAttribute
{
	public ElevationFactAttribute() => Skip = ElevationTestGuard.SkipReason;
}

/// <summary>A <see cref="TheoryAttribute"/> with the same elevation precondition as
/// <see cref="ElevationFactAttribute"/>.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ElevationTheoryAttribute : TheoryAttribute
{
	public ElevationTheoryAttribute() => Skip = ElevationTestGuard.SkipReason;
}
