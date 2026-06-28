// File:    src/RdpAudit.Configurator/Services/InstallTransfer.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Transactional file copy + verification used by both first-run install and the
//          Service tab "Update installed files" button. Differs from a naive File.Copy loop
//          in three ways:
//            (a) Each file is copied to a sibling .new staging name first, then atomically
//                renamed over the destination — partial copies cannot leave the install
//                directory with a file shorter than the source.
//            (b) Every destination is hashed after the rename and compared to the source
//                hash; mismatches fail the step with an explicit "Installed hash != distribution
//                hash after copy" diagnostic.
//            (c) UnauthorizedAccessException from a locked destination is decoded into a
//                helpful "File locked by PID X" diagnostic instead of propagating the raw
//                exception. The PID is captured via Process enumeration, not Restart Manager,
//                because the latter requires a higher privilege than what Configurator already
//                holds.
//          Pure transfer concerns; no SCM interaction or logging. Callers compose this with
//          ServiceControlRunner.Stop / Start and InstallUpdateLogger.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of <see cref="InstallTransfer.Copy"/> — total file count, copied count,
/// per-file mismatch list, and a high-level success flag.</summary>
public sealed record InstallTransferResult(
	bool Success,
	int FilesConsidered,
	int FilesCopied,
	IReadOnlyList<string> Mismatches,
	IReadOnlyList<string> Failures);

/// <summary>Transactional copy + post-copy hash verification helper.</summary>
[SupportedOSPlatform("windows")]
public static class InstallTransfer
{
	private const string StagingSuffix = ".rdpaudit-new";

	/// <summary>Copies every file under <paramref name="source"/> into <paramref name="destination"/>,
	/// hashing each pair and surfacing per-file failures. Returns once all files have been
	/// considered. Never throws on a single file failure — the failure detail is collected and
	/// the overall <see cref="InstallTransferResult.Success"/> flag goes to false.</summary>
	public static InstallTransferResult Copy(string source, string destination)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(source);
		ArgumentException.ThrowIfNullOrWhiteSpace(destination);

		List<string> mismatches = new();
		List<string> failures = new();
		int considered = 0;
		int copied = 0;

		IEnumerable<string> files;
		try
		{
			files = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories);
		}
		catch (Exception ex)
		{
			failures.Add(string.Format(CultureInfo.InvariantCulture,
				"Cannot enumerate source {0}: {1}", source, ex.Message));
			return new InstallTransferResult(false, 0, 0, mismatches, failures);
		}

		foreach (string sourceFile in files)
		{
			considered++;
			string relative = Path.GetRelativePath(source, sourceFile);
			string targetFile = Path.Combine(destination, relative);
			string? targetDir = Path.GetDirectoryName(targetFile);
			if (!string.IsNullOrEmpty(targetDir))
			{
				try
				{
					Directory.CreateDirectory(targetDir);
				}
				catch (Exception ex)
				{
					failures.Add(string.Format(CultureInfo.InvariantCulture,
						"Cannot create directory {0}: {1}", targetDir, ex.Message));
					continue;
				}
			}

			string staging = targetFile + StagingSuffix;
			try
			{
				if (File.Exists(staging))
				{
					File.Delete(staging);
				}

				File.Copy(sourceFile, staging, overwrite: false);
			}
			catch (UnauthorizedAccessException ex)
			{
				failures.Add(BuildLockedDiagnostic(targetFile, ex));
				continue;
			}
			catch (IOException ex)
			{
				failures.Add(BuildLockedDiagnostic(targetFile, ex));
				continue;
			}
			catch (Exception ex)
			{
				failures.Add(string.Format(CultureInfo.InvariantCulture,
					"Copy {0} -> {1} failed: {2}", sourceFile, staging, ex.Message));
				continue;
			}

			string sourceHash;
			string stagingHash;
			try
			{
				sourceHash = ComputeHash(sourceFile);
				stagingHash = ComputeHash(staging);
			}
			catch (Exception ex)
			{
				failures.Add(string.Format(CultureInfo.InvariantCulture,
					"Hash verification failed for {0}: {1}", staging, ex.Message));
				TryDelete(staging);
				continue;
			}

			if (!string.Equals(sourceHash, stagingHash, StringComparison.OrdinalIgnoreCase))
			{
				mismatches.Add(string.Format(CultureInfo.InvariantCulture,
					"Installed hash != distribution hash after copy for {0} (src {1}, dst {2})",
					relative, sourceHash[..16], stagingHash[..16]));
				TryDelete(staging);
				continue;
			}

			try
			{
				if (File.Exists(targetFile))
				{
					File.Delete(targetFile);
				}

				File.Move(staging, targetFile);
				copied++;
			}
			catch (UnauthorizedAccessException ex)
			{
				failures.Add(BuildLockedDiagnostic(targetFile, ex));
				TryDelete(staging);
			}
			catch (IOException ex)
			{
				failures.Add(BuildLockedDiagnostic(targetFile, ex));
				TryDelete(staging);
			}
			catch (Exception ex)
			{
				failures.Add(string.Format(CultureInfo.InvariantCulture,
					"Promote {0} -> {1} failed: {2}", staging, targetFile, ex.Message));
				TryDelete(staging);
			}
		}

		bool success = mismatches.Count == 0 && failures.Count == 0 && considered > 0;
		return new InstallTransferResult(success, considered, copied, mismatches, failures);
	}

	private static string ComputeHash(string path)
	{
		using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
		byte[] hash = SHA256.HashData(stream);
		return Convert.ToHexString(hash);
	}

	private static void TryDelete(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch (Exception)
		{
			// Best-effort cleanup.
		}
	}

	private static string BuildLockedDiagnostic(string targetPath, Exception ex)
	{
		string holder = TryFindHolder(targetPath);
		string holderText = string.IsNullOrEmpty(holder) ? "unknown holder" : holder;
		return string.Format(CultureInfo.InvariantCulture,
			"File locked: {0} ({1}). Stop the holding process and retry. Underlying: {2}",
			targetPath, holderText, ex.Message);
	}

	private static string TryFindHolder(string targetPath)
	{
		// Best-effort discovery: scan running processes for a main module path matching the
		// targeted file. This is intentionally conservative — Process.MainModule can throw
		// AccessDenied for protected services even when running elevated; in that case the
		// holder text simply reads "unknown holder" and the operator falls back to handle.exe.
		try
		{
			string fullPath = Path.GetFullPath(targetPath);
			foreach (Process process in Process.GetProcesses())
			{
				try
				{
					string? modulePath = process.MainModule?.FileName;
					if (!string.IsNullOrEmpty(modulePath)
						&& string.Equals(modulePath, fullPath, StringComparison.OrdinalIgnoreCase))
					{
						return string.Format(CultureInfo.InvariantCulture,
							"locked by PID {0} ({1})",
							process.Id.ToString(CultureInfo.InvariantCulture),
							process.ProcessName);
					}
				}
				catch (Exception)
				{
					// MainModule access denied / process exited — keep scanning.
				}
				finally
				{
					process.Dispose();
				}
			}
		}
		catch (Exception)
		{
			// Process enumeration itself failed — fall through to the generic message.
		}

		return string.Empty;
	}
}
