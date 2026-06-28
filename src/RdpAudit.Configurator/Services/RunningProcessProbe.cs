// File:    src/RdpAudit.Configurator/Services/RunningProcessProbe.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Best-effort snapshot of a running service process for the Copy diagnostics report.
//          Returns the main module path, file fingerprint (SHA-256/length/version) and start
//          time when accessible. Process.MainModule routinely throws Win32 access-denied for
//          a service running as LocalSystem when the Configurator queries it from a normal
//          interactive admin token; the helper swallows those errors so the diagnostics
//          report still renders the rest of the inputs.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Best-effort running-process inspector for the Copy diagnostics report.</summary>
[SupportedOSPlatform("windows")]
public static class RunningProcessProbe
{
	/// <summary>Returns a snapshot of the process identified by <paramref name="processId"/>.
	/// When the PID is null the snapshot reports a no-process placeholder.</summary>
	public static RunningProcessFingerprint Probe(int? processId)
	{
		if (processId is not int pid || pid <= 0)
		{
			return new RunningProcessFingerprint(
				ProcessId: null,
				MainModulePath: null,
				MainModuleFingerprint: null,
				StartTimeUtc: null);
		}

		string? modulePath = null;
		DateTime? startUtc = null;
		try
		{
			using Process proc = Process.GetProcessById(pid);
			try
			{
				modulePath = proc.MainModule?.FileName;
			}
			catch (Win32Exception)
			{
				// Access denied for a higher-integrity service is expected; continue without it.
			}
			catch (InvalidOperationException)
			{
				// Process exited between GetProcessById and MainModule access.
			}

			try
			{
				startUtc = proc.StartTime.ToUniversalTime();
			}
			catch (Win32Exception)
			{
			}
			catch (InvalidOperationException)
			{
			}
		}
		catch (ArgumentException)
		{
			return new RunningProcessFingerprint(
				ProcessId: pid,
				MainModulePath: null,
				MainModuleFingerprint: null,
				StartTimeUtc: null);
		}
		catch (Exception)
		{
			return new RunningProcessFingerprint(
				ProcessId: pid,
				MainModulePath: null,
				MainModuleFingerprint: null,
				StartTimeUtc: null);
		}

		BinaryFingerprint? fingerprint = string.IsNullOrEmpty(modulePath)
			? null
			: BinaryFingerprintReader.Read(modulePath);

		return new RunningProcessFingerprint(
			ProcessId: pid,
			MainModulePath: modulePath,
			MainModuleFingerprint: fingerprint,
			StartTimeUtc: startUtc);
	}
}
