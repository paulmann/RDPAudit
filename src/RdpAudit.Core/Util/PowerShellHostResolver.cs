// File:    src/RdpAudit.Core/Util/PowerShellHostResolver.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for which PowerShell host RdpAudit spawns. The product standard is
//          PowerShell 7 (`pwsh`): Windows PowerShell 5.1 is not the supported execution environment
//          and must never be selected silently. Every firewall-policy and certificate command used to
//          hardcode one host, so a machine that had only one of the two behaved differently from the
//          machine that had the other - and on a host without pwsh the product quietly ran policy
//          commands inside 5.1.
//
//          Resolution order (deterministic, never consults PATH first):
//            1. %ProgramW6432%\PowerShell\7\pwsh.exe   (the documented install location);
//            2. %ProgramFiles%\PowerShell\7\pwsh.exe   (32-bit process view);
//            3. the newest pwsh.exe under %ProgramFiles%\PowerShell\7* — covers preview-style
//               side-by-side folders without guessing a version;
//            4. the full path of Windows PowerShell 5.1, reported as a DEGRADED host so the caller
//               and the operator can see that the fallback happened.
//
//          The result is cached (the machine does not gain pwsh mid-run) and the probe is injectable
//          so unit tests stay deterministic. Pure code: no process is started and nothing is executed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace RdpAudit.Core.Util;

/// <summary>Which PowerShell host was resolved and why, for logging and diagnostics.</summary>
/// <param name="Path">Executable path or bare file name to hand to the command runner.</param>
/// <param name="IsPowerShellSeven">True when the resolved host is pwsh, which is the supported one.</param>
/// <param name="Detail">Human-readable explanation of the resolution outcome.</param>
public sealed record PowerShellHostInfo(string Path, bool IsPowerShellSeven, string Detail);

/// <summary>Resolves the PowerShell host used for firewall policy and certificate commands.</summary>
public static class PowerShellHostResolver
{
	/// <summary>The supported host (PowerShell 7+).</summary>
	public const string PowerShellSevenExecutable = "pwsh.exe";

	/// <summary>The legacy host. Only ever selected as an explicitly reported degraded fallback.</summary>
	public const string WindowsPowerShellExecutable = "powershell.exe";

	/// <summary>Relative path of the supported host inside a Program Files root.</summary>
	public const string PowerShellSevenRelativePath = @"PowerShell\7\pwsh.exe";

	private static readonly object Gate = new();
	private static PowerShellHostInfo? s_cached;
	private static Func<PowerShellHostInfo>? s_probeOverride;

	/// <summary>Executable path or file name of the resolved host.</summary>
	public static string Executable => Resolve().Path;

	/// <summary>True when the resolved host is the supported PowerShell 7.</summary>
	public static bool IsPowerShellSeven => Resolve().IsPowerShellSeven;

	/// <summary>Resolves (and caches) the host. Never throws: an unreadable location is skipped.</summary>
	public static PowerShellHostInfo Resolve()
	{
		Func<PowerShellHostInfo>? overridden;
		lock (Gate)
		{
			if (s_cached is { } cached)
			{
				return cached;
			}

			overridden = s_probeOverride;
		}

		PowerShellHostInfo resolved = overridden is not null ? overridden() : Probe();
		lock (Gate)
		{
			s_cached ??= resolved;
			return s_cached;
		}
	}

	/// <summary>Drops the cache and optionally installs a probe. Test-only seam: production code must
	/// never call this, because the resolved host must not change under a running service.</summary>
	internal static void ResetForTests(Func<PowerShellHostInfo>? probe = null)
	{
		lock (Gate)
		{
			s_cached = null;
			s_probeOverride = probe;
		}
	}

	private static PowerShellHostInfo Probe()
	{
		foreach (string candidate in EnumerateCandidates())
		{
			if (Exists(candidate))
			{
				// Every candidate enumerated above is a pwsh.exe location, so reaching this branch means
				// the supported host was found. The static IsPowerShellSeven must NOT be read here:
				// Resolve() would re-enter Probe() and the flag would be derived from a second, nested
				// resolution instead of from the fact that this candidate is pwsh.
				return new PowerShellHostInfo(
					candidate,
					IsPowerShellSeven: true,
					"Resolved PowerShell 7 at " + candidate + ".");
			}
		}

		return new PowerShellHostInfo(
			WindowsPowerShellExecutable,
			IsPowerShellSeven: false,
			"PowerShell 7 was not found at any of " + string.Join(", ", EnumerateCandidates())
			+ "; falling back to Windows PowerShell 5.1, which is NOT the supported host.");
	}

	private static IEnumerable<string> EnumerateCandidates()
	{
		string? programW6432 = Environment.GetEnvironmentVariable("ProgramW6432");
		string? programFiles = Environment.GetEnvironmentVariable("ProgramFiles");

		if (!string.IsNullOrWhiteSpace(programW6432))
		{
			yield return Path.Combine(programW6432, PowerShellSevenRelativePath);
		}

		if (!string.IsNullOrWhiteSpace(programFiles))
		{
			string primary = Path.Combine(programFiles, PowerShellSevenRelativePath);
			yield return primary;

			// Versioned side-by-side folders (PowerShell\7.6\...) are accepted without guessing a
			// specific version: the newest one present wins.
			foreach (string discovered in EnumerateVersionedHosts(programFiles))
			{
				if (!string.Equals(discovered, primary, StringComparison.OrdinalIgnoreCase))
				{
					yield return discovered;
				}
			}
		}

		yield return Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.System),
			@"WindowsPowerShell\v1.0\powershell.exe");
	}

	private static List<string> EnumerateVersionedHosts(string programFiles)
	{
		List<string> hosts;
		try
		{
			string root = Path.Combine(programFiles, "PowerShell");
			hosts = Directory.Exists(root)
				? Directory.EnumerateDirectories(root)
					.OrderByDescending(static dir => Path.GetFileName(dir), StringComparer.OrdinalIgnoreCase)
					.Select(dir => Path.Combine(dir, "pwsh.exe"))
					.ToList()
				: new List<string>();
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
			or ArgumentException or NotSupportedException)
		{
			hosts = new List<string>();
		}

		return hosts;
	}

	private static bool Exists(string path)
	{
		try
		{
			return File.Exists(path);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
			or ArgumentException or NotSupportedException)
		{
			return false;
		}
	}
}
