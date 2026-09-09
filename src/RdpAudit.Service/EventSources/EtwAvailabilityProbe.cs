/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EtwAvailabilityProbe.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Pure static probe consulted by EventSourceFactorySelector at service startup to decide
//          whether the ETW transport can be armed on this host. Returns Ok=true only when both
//          (a) the OS is Windows and (b) the current process has the privilege required to open
//          a real-time TraceEventSession (SeSystemProfilePrivilege or equivalent, exposed by
//          TraceEventSession.IsElevated). All other outcomes carry a human-readable Reason that
//          the selector logs verbatim so operators immediately understand the fallback.
// Depends: TraceEventSession.IsElevated, RuntimeInformation.IsOSPlatform
// Extends: When adding a new pre-flight condition (e.g. a specific Windows build minimum), add
//          it here in the order failures should be surfaced. Keep the probe cheap and stateless
//          so it is safe to call from the DI factory lambda.

using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Session;

namespace RdpAudit.Service.EventSources;

/// <summary>Pure availability probe for the ETW ingestion transport.</summary>
public static class EtwAvailabilityProbe
{
	/// <summary>
	/// Return <c>(true, null)</c> when the current process can open a real-time
	/// <see cref="TraceEventSession"/>. Otherwise return <c>(false, reason)</c> so
	/// <see cref="EventSourceFactorySelector"/> can log the fallback reason.
	/// </summary>
	public static (bool Ok, string? Reason) Probe()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return (false, "ETW is only available on Windows.");
		}

		try
		{
			// TraceEventSession.IsElevated returns null when the privilege state is unknown
			// (e.g. down-level runtime), true when the process holds enough rights to open a
			// real-time session, false otherwise.
			bool? elevated = TraceEventSession.IsElevated();
			if (elevated == true)
			{
				return (true, null);
			}
			if (elevated == false)
			{
				return (false, "The service must run as Administrator or a Performance Log Users member to open a real-time ETW session.");
			}
			return (false, "TraceEventSession.IsElevated returned null; cannot determine ETW privilege state.");
		}
		catch (Exception ex)
		{
			return (false, "ETW probe threw: " + ex.Message);
		}
	}
}
