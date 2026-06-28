// File:    src/RdpAudit.Configurator/Services/InstallDirectoryGuard.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Hardened "ensure C:\Program Files\RdpAudit\Service exists and is writable" helper.
//          The previous code path used Directory.CreateDirectory in a single try/catch and
//          treated UnauthorizedAccess / DirectoryNotFound as identical generic failures with
//          a non-actionable message. This helper distinguishes those root causes (missing
//          parent, ACL deny, IO error from a stale handle, path-too-long) and emits an
//          English diagnostic the operator can read straight from the dialog. Pure logic —
//          all I/O lives at the call site so the helper is unit-testable in isolation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of <see cref="InstallDirectoryGuard.EnsureWritable"/>.</summary>
public sealed record DirectoryEnsureResult(bool Success, string Message, string? Detail);

/// <summary>Hardened directory ensure for the install destination under Program Files.</summary>
[SupportedOSPlatform("windows")]
public static class InstallDirectoryGuard
{
	private const string ProbeFileName = ".rdpaudit-write-probe";

	/// <summary>Ensures the install directory and every parent exists and is writable by the
	/// current process. The probe file is created with <see cref="FileMode.Create"/> and
	/// removed on success; if the probe write fails the helper returns a clear English
	/// diagnostic distinguishing UnauthorizedAccess from DirectoryNotFound and IOException.
	/// Never swallows the underlying exception — its text is included in <c>Detail</c>.</summary>
	public static DirectoryEnsureResult EnsureWritable(string path)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(path);

		string fullPath;
		try
		{
			fullPath = Path.GetFullPath(path);
		}
		catch (Exception ex)
		{
			return new DirectoryEnsureResult(false,
				"Cannot resolve install directory path: " + path, ex.Message);
		}

		try
		{
			Directory.CreateDirectory(fullPath);
		}
		catch (UnauthorizedAccessException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Access denied creating {0}. The process is not allowed to write here — "
					+ "verify the Configurator is running as Administrator and that the parent "
					+ "directory ACL grants Administrators / SYSTEM full control.", fullPath),
				ex.Message);
		}
		catch (DirectoryNotFoundException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Cannot create {0} — a parent directory is missing or inaccessible.", fullPath),
				ex.Message);
		}
		catch (PathTooLongException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Install path is too long: {0}.", fullPath),
				ex.Message);
		}
		catch (IOException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"I/O failure creating {0}.", fullPath),
				ex.Message);
		}
		catch (Exception ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Unexpected failure creating {0}.", fullPath),
				ex.Message);
		}

		if (!Directory.Exists(fullPath))
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"CreateDirectory returned without throwing but {0} does not exist on disk.",
					fullPath),
				null);
		}

		string probe = Path.Combine(fullPath, ProbeFileName);
		try
		{
			using (FileStream fs = new(probe, FileMode.Create, FileAccess.Write, FileShare.None))
			{
				fs.WriteByte(0x52); // 'R'
			}

			File.Delete(probe);
		}
		catch (UnauthorizedAccessException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Access denied writing to {0}. The directory exists but the current process "
					+ "cannot write here — re-run the Configurator as Administrator.", fullPath),
				ex.Message);
		}
		catch (IOException ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"I/O failure writing to {0} — the directory may be in use.", fullPath),
				ex.Message);
		}
		catch (Exception ex)
		{
			return new DirectoryEnsureResult(false,
				string.Format(CultureInfo.InvariantCulture,
					"Unexpected failure writing to {0}.", fullPath),
				ex.Message);
		}

		return new DirectoryEnsureResult(true,
			string.Format(CultureInfo.InvariantCulture,
				"Install directory is writable: {0}", fullPath),
			null);
	}
}
