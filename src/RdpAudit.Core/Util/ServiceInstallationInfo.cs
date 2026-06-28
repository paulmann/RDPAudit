// File:    src/RdpAudit.Core/Util/ServiceInstallationInfo.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure value model describing the authoritative SCM state of a Windows
//          service: Name, DisplayName, State, ProcessId, StartMode, PathName (ImagePath),
//          Win32ExitCode, ServiceSpecificExitCode. Reads happen in the Configurator layer
//          via System.Management (WMI Win32_Service); this file deliberately stays free of
//          Windows-specific dependencies so it can be unit-tested cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Authoritative SCM snapshot of a Windows service. Mirrors the fields of
/// <c>Win32_Service</c> that drive the Service tab UI.</summary>
public sealed record ServiceInstallationInfo(
	string ServiceName,
	bool Installed,
	string? DisplayName,
	int? StateCode,
	string? StateName,
	int? ProcessId,
	string? ImagePath,
	string? StartMode,
	string? Status,
	int? Win32ExitCode,
	int? ServiceSpecificExitCode,
	string? Diagnostic)
{
	/// <summary>True when SCM reports the service in the Running state (code 4).</summary>
	public bool IsRunning => StateCode == 4
		|| string.Equals(StateName, "Running", StringComparison.OrdinalIgnoreCase);

	/// <summary>True when SCM reports a transient state (start-pending / stop-pending /
	/// continue-pending / pause-pending). Used by the button model to keep Start and
	/// Stop disabled while a transition is in flight.</summary>
	public bool IsTransitioning => StateCode is 2 or 3 or 5 or 6;

	/// <summary>True when SCM reports the service is paused (code 7).</summary>
	public bool IsPaused => StateCode == 7
		|| string.Equals(StateName, "Paused", StringComparison.OrdinalIgnoreCase);

	/// <summary>True when SCM reports the service is stopped (code 1).</summary>
	public bool IsStopped => StateCode == 1
		|| string.Equals(StateName, "Stopped", StringComparison.OrdinalIgnoreCase);

	/// <summary>Known Windows executable extensions, in priority order. <c>.exe</c> is by far
	/// the common case but the SCM accepts any of these as a service binary path. Lookup is
	/// case-insensitive on Windows so we keep the literal lowercase form and compare with
	/// <see cref="StringComparison.OrdinalIgnoreCase"/>.</summary>
	private static readonly string[] ExecutableExtensions = { ".exe", ".cmd", ".bat", ".com", ".scr" };

	/// <summary>Returns the absolute path to the service executable parsed from
	/// <see cref="ImagePath"/>. <c>Win32_Service.PathName</c> follows the same conventions as
	/// <c>sc.exe</c>: the executable token may be quoted, and arguments may follow. When the
	/// path is unquoted (Windows stores most ImagePath entries verbatim, including those that
	/// contain spaces like <c>C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe</c>), we
	/// greedily search for a known executable extension followed by end-of-string or a space —
	/// the bare first-space heuristic used previously truncated <c>C:\Program Files\...</c> at
	/// the first space and reported the executable as <c>C:\Program</c>. Returns null when no
	/// parseable path is present.</summary>
	public string? ResolveExecutablePath()
	{
		if (string.IsNullOrWhiteSpace(ImagePath))
		{
			return null;
		}

		string raw = ImagePath.Trim();
		if (raw.Length == 0)
		{
			return null;
		}

		if (raw[0] == '"')
		{
			int closing = raw.IndexOf('"', 1);
			if (closing > 1)
			{
				return raw.Substring(1, closing - 1);
			}

			return raw[1..];
		}

		// Unquoted path: search for a known executable extension whose boundary is end-of-string,
		// a space, or a tab. Without this Program Files paths get truncated at the first space.
		string? viaExtension = TryFindExecutableExtensionBoundary(raw);
		if (viaExtension is not null)
		{
			return viaExtension;
		}

		// Last-resort fallback: original behaviour for ImagePath entries that contain no extension
		// hint at all (unusual; covers DLL-hosted service stubs or legacy registrations).
		int firstSpace = raw.IndexOf(' ', StringComparison.Ordinal);
		return firstSpace > 0 ? raw[..firstSpace] : raw;
	}

	private static string? TryFindExecutableExtensionBoundary(string raw)
	{
		foreach (string ext in ExecutableExtensions)
		{
			int searchFrom = 0;
			while (searchFrom < raw.Length)
			{
				int hit = raw.IndexOf(ext, searchFrom, StringComparison.OrdinalIgnoreCase);
				if (hit < 0)
				{
					break;
				}

				int afterExt = hit + ext.Length;
				if (afterExt == raw.Length || raw[afterExt] == ' ' || raw[afterExt] == '\t')
				{
					return raw[..afterExt];
				}

				searchFrom = hit + 1;
			}
		}

		return null;
	}
}
