// File:    src/RdpAudit.Core/WebUi/WebUiPublisher.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Publishes the WebUI static dashboard (the RdpAudit.Web wwwroot) into the IIS physical
//          path CommonApplicationData/RdpAudit/WebUI. Every file is written atomically (temp file in the
//          same directory + overwrite move) and its SHA-256 is verified BOTH on the temp file before
//          the move and on the destination after it; a mismatch removes the file and records a failure
//          instead of leaving corrupt bytes behind. Content lives in a manifest (.webui-manifest.json)
//          so the next publish can skip unchanged files, detect tampered ones (hash differs -> rewrite)
//          and remove files that disappeared from the source. The publisher NEVER enumerates or touches
//          the wwwroot 'secrets' subfolder (the vault's private area lives there), and refuses a source
//          tree that itself contains a first-level secrets folder. On Windows an optional application-pool
//          identity receives ReadAndExecute (container+object inherit) on the target BEFORE any file lands,
//          so every published file inherits it and IIS can serve the dashboard; the grant is read back and
//          verified, and a missing grant is a publish failure, never a silent success. Publish is
//          idempotent and side-effect ordered so an interrupted run only ever leaves the previous complete
//          state plus manifestless temp files.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.WebUi;

/// <summary>
/// Publishes the WebUI static content under <see cref="RdpAuditPaths.WebUiDirectory"/> with
/// per-file SHA-256 verification, idempotent updates and optional read access for the IIS pool.
/// </summary>
public sealed class WebUiPublisher
{
	/// <summary>Name of the manifest stored in the target root: relative path -> lower-case SHA-256 hex.</summary>
	public const string ManifestFileName = ".webui-manifest.json";

	private readonly string _targetDirectory;
	private readonly string? _webPoolIdentity;

	/// <summary>Creates the publisher for the canonical web-UI static-content target.</summary>
	/// <param name="paths">Path layout providing <see cref="RdpAuditPaths.WebUiWwwRootDirectory"/>.</param>
	/// <param name="webPoolIdentity">
	/// Optional IIS application-pool identity (e.g. <c>IIS APPPOOL\RdpAuditWebUi</c>) that receives
	/// ReadAndExecute on the target before publishing. Null/blank means no pool grant is applied.
	/// </param>
	public WebUiPublisher(RdpAuditPaths paths, string? webPoolIdentity = null)
	{
		_targetDirectory = paths?.WebUiWwwRootDirectory ?? throw new ArgumentNullException(nameof(paths));
		_webPoolIdentity = webPoolIdentity;
	}

	/// <summary>
	/// Publishes every file under <paramref name="sourceRoot"/> into the target directory and
	/// verifies the result. Failures are collected on the result; no exception is thrown for
	/// content problems.
	/// </summary>
	public WebUiPublishResult Publish(string sourceRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sourceRoot);
		WebUiPublishResult result = new() { TargetDirectory = _targetDirectory };

		string sourceFull = Path.GetFullPath(sourceRoot);
		if (!Directory.Exists(sourceFull))
		{
			result.Failures.Add("The web-UI source folder does not exist: " + sourceFull);
			return result;
		}

		try
		{
			Directory.CreateDirectory(_targetDirectory);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			result.Failures.Add("The web-UI target folder could not be created: " + ex.Message);
			return result;
		}

		if (OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(_webPoolIdentity))
		{
			if (!TryGrantPoolReadAccess(out string aclFailure))
			{
				result.Failures.Add(aclFailure);
				return result;
			}
		}

		Dictionary<string, string> priorManifest = ReadManifest();
		Dictionary<string, string> nextManifest = new(StringComparer.OrdinalIgnoreCase);
		HashSet<string> currentFiles = new(StringComparer.OrdinalIgnoreCase);

		foreach (string sourcePath in Directory.EnumerateFiles(sourceFull, "*", SearchOption.AllDirectories))
		{
			string relative = Path.GetRelativePath(sourceFull, sourcePath).Replace(Path.DirectorySeparatorChar, '/');
			if (relative.StartsWith(RdpAuditPaths.WebUiSecretsFolderName + "/", StringComparison.OrdinalIgnoreCase))
			{
				result.Failures.Add(
					"The web-UI source contains a secrets folder (" + relative
					+ "); the vault's private area is never published.");
				continue;
			}

			string destination = Path.Combine(_targetDirectory, relative);
			if (!IsInsideTarget(destination))
			{
				result.Failures.Add("The web-UI source file escapes the target folder: " + relative);
				continue;
			}

			string sourceHash;
			try
			{
				sourceHash = ComputeSha256(sourcePath);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				result.Failures.Add("The web-UI source file could not be read: " + relative + " (" + ex.Message + ")");
				continue;
			}

			nextManifest[relative] = sourceHash;
			currentFiles.Add(relative);

			string? existingHash = TryComputeSha256(destination);
			if (existingHash is not null && string.Equals(existingHash, sourceHash, StringComparison.OrdinalIgnoreCase))
			{
				result.FilesVerified++;
				continue;
			}

			if (CopyVerified(sourcePath, destination, sourceHash, relative, result))
			{
				result.FilesVerified++;
			}
		}

		RemoveStaleFiles(priorManifest, currentFiles, result);

		if (result.Succeeded)
		{
			WriteManifest(nextManifest, result);
		}

		return result;
	}

	/// <summary>Copies one file atomically and verifies its SHA-256 on both sides of the move.</summary>
	private bool CopyVerified(
		string sourcePath,
		string destination,
		string expectedHash,
		string relative,
		WebUiPublishResult result)
	{
		try
		{
			Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			result.Failures.Add("The web-UI destination folder could not be created for " + relative + ": " + ex.Message);
			return false;
		}

		string temporary = Path.Combine(
			Path.GetDirectoryName(destination)!,
			".rdpaudit-webui-" + Path.GetFileName(destination) + ".tmp");

		try
		{
			File.Copy(sourcePath, temporary, overwrite: true);
			string temporaryHash = ComputeSha256(temporary);
			if (!string.Equals(temporaryHash, expectedHash, StringComparison.OrdinalIgnoreCase))
			{
				TryDelete(temporary);
				result.Failures.Add("The web-UI copy failed SHA-256 verification before install for " + relative + ".");
				return false;
			}

			File.Move(temporary, destination, overwrite: true);
			string destinationHash = ComputeSha256(destination);
			if (!string.Equals(destinationHash, expectedHash, StringComparison.OrdinalIgnoreCase))
			{
				TryDelete(destination);
				result.Failures.Add("The web-UI file failed SHA-256 verification after install and was removed: " + relative + ".");
				return false;
			}

			result.FilesCopied++;
			return true;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			TryDelete(temporary);
			result.Failures.Add("The web-UI file could not be installed: " + relative + " (" + ex.Message + ")");
			return false;
		}
	}

	/// <summary>Deletes manifest-tracked files that no longer exist in the source tree.</summary>
	private void RemoveStaleFiles(
		Dictionary<string, string> priorManifest,
		HashSet<string> currentFiles,
		WebUiPublishResult result)
	{
		foreach (string relative in priorManifest.Keys)
		{
			if (currentFiles.Contains(relative))
			{
				continue;
			}

			string stalePath = Path.Combine(_targetDirectory, relative);
			if (!IsInsideTarget(stalePath))
			{
				continue;
			}

			try
			{
				if (File.Exists(stalePath))
				{
					File.Delete(stalePath);
					result.StaleFilesRemoved++;
				}
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				result.Failures.Add("A stale web-UI file could not be removed: " + relative + " (" + ex.Message + ")");
			}
		}
	}

	/// <summary>Grants (on Windows) ReadAndExecute to the configured pool identity and verifies the grant.</summary>
	[SupportedOSPlatform("windows")]
	private bool TryGrantPoolReadAccess(out string failure)
		=> WebUiPoolAcl.TryGrantReadAndExecute(_targetDirectory, _webPoolIdentity, out failure);

	private Dictionary<string, string> ReadManifest()
	{
		string manifestPath = Path.Combine(_targetDirectory, ManifestFileName);
		try
		{
			if (!File.Exists(manifestPath))
			{
				return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			}

			string json = File.ReadAllText(manifestPath, System.Text.Encoding.UTF8);
			Dictionary<string, string>? manifest =
				JsonSerializer.Deserialize<Dictionary<string, string>>(json);
			return manifest ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
		{
			// An unreadable manifest must not block the next publish: it only disables stale cleanup
			// and makes every file a candidate for rewrite. The publish itself still verifies hashes.
			return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		}
	}

	private void WriteManifest(Dictionary<string, string> manifest, WebUiPublishResult result)
	{
		string manifestPath = Path.Combine(_targetDirectory, ManifestFileName);
		string temporary = manifestPath + ".tmp";
		try
		{
			string json = JsonSerializer.Serialize(
				manifest,
				new JsonSerializerOptions { WriteIndented = true });
			File.WriteAllText(temporary, json, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			File.Move(temporary, manifestPath, overwrite: true);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			TryDelete(temporary);
			result.Failures.Add("The web-UI manifest could not be written: " + ex.Message);
		}
	}

	private static string ComputeSha256(string filePath)
	{
		byte[] bytes = File.ReadAllBytes(filePath);
		return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
	}

	private static string? TryComputeSha256(string filePath)
	{
		try
		{
			return File.Exists(filePath) ? ComputeSha256(filePath) : null;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return null;
		}
	}

	private bool IsInsideTarget(string candidate)
	{
		string target = Path.GetFullPath(_targetDirectory);
		string full = Path.GetFullPath(candidate);
		return string.Equals(full, target, StringComparison.OrdinalIgnoreCase)
			|| full.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
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
		catch
		{
			// Best-effort cleanup; the failure has already been recorded.
		}
	}
}

/// <summary>Outcome of one <see cref="WebUiPublisher.Publish"/> run.</summary>
public sealed class WebUiPublishResult
{
	/// <summary>Absolute target directory the publish was performed into.</summary>
	public string TargetDirectory { get; internal set; } = string.Empty;

	/// <summary>Files actually written during this run.</summary>
	public int FilesCopied { get; internal set; }

	/// <summary>Files whose on-disk SHA-256 matches the source after the run (written or already current).</summary>
	public int FilesVerified { get; internal set; }

	/// <summary>Manifest-tracked files removed because they disappeared from the source.</summary>
	public int StaleFilesRemoved { get; internal set; }

	/// <summary>Curated failure lines; empty means the publish succeeded.</summary>
	public List<string> Failures { get; } = new();

	/// <summary>True when no failure was recorded.</summary>
	public bool Succeeded => Failures.Count == 0;
}