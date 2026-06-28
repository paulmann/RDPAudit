// File:    src/RdpAudit.Configurator/Services/ElevationGuard.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Single source of truth for "is the running Configurator process running with
//          administrator privileges?". The Configurator's app.manifest already requests
//          requireAdministrator so launches go through UAC, but this helper exists for
//          install/update flows that must hard-fail with an actionable English error
//          when something has bypassed the manifest (e.g. the binary was launched from
//          a service or scheduled task without elevation, or the manifest was stripped
//          during an unsigned rebuild). Never assumes the manifest will catch every
//          path — verifies the actual token at runtime.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Security.Principal;

namespace RdpAudit.Configurator.Services;

/// <summary>Result of <see cref="ElevationGuard.Check"/> — boolean elevation flag plus an
/// English message suitable for direct display to the operator.</summary>
public sealed record ElevationStatus(bool IsElevated, string Message);

/// <summary>Verifies the running Configurator has administrator privileges.</summary>
[SupportedOSPlatform("windows")]
public static class ElevationGuard
{
	/// <summary>Returns <see langword="true"/> when the current process token is in the
	/// BUILTIN\Administrators role, otherwise <see langword="false"/> with an actionable
	/// English message.</summary>
	public static ElevationStatus Check()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			WindowsPrincipal principal = new(identity);
			bool elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
			string message = elevated
				? "Process is running elevated (Administrators)."
				: "Elevation required — the Configurator must run as Administrator to install, "
				  + "update, or write under C:\\Program Files\\RdpAudit. Right-click the Configurator "
				  + "and choose 'Run as administrator', then retry the action.";
			return new ElevationStatus(elevated, message);
		}
		catch (Exception ex)
		{
			return new ElevationStatus(false,
				"Elevation check failed: " + ex.Message
				+ ". Treating the process as non-elevated and refusing the install/update.");
		}
	}

	/// <summary>Throws <see cref="UnauthorizedAccessException"/> when the current process is
	/// not elevated. The exception message is the English diagnostic from <see cref="Check"/>.
	/// Use at the top of any code path that writes under <c>C:\Program Files</c> or talks to
	/// the Service Control Manager so failures surface as clear "Elevation required" errors
	/// rather than later as raw <see cref="UnauthorizedAccessException"/> from File.Copy.</summary>
	public static void Require()
	{
		ElevationStatus status = Check();
		if (!status.IsElevated)
		{
			throw new UnauthorizedAccessException(status.Message);
		}
	}
}
