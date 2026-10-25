// File:    src/RdpAudit.Core/WebUi/WebUiAppStager.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Stages the published RdpAudit.Web application output (web.config, RdpAudit.Web.exe,
//          runtime dlls and the wwwroot static dashboard) into the IIS physical path
//          CommonApplicationData/RdpAudit/WebUI. Variant A of plan Step 11: IIS hosts the web UI
//          as a full in-process application, so the staged tree is the complete dotnet-publish
//          output and web.config (the AspNetCoreModuleV2 in-process artifact) is the entry-point
//          contract - its absence is a stage refusal, never a silent partial deployment. Every
//          file copy is verified against its source SHA-256 on both sides of an atomic temp+move;
//          a mismatch removes the destination and records a failure. A manifest
//          (.webui-app-manifest.json) makes staging idempotent: unchanged files are skipped,
//          tampered files are rewritten, and files that disappeared from the publish output become
//          stale and are removed. The stager NEVER enumerates or removes the WebUI 'secrets'
//          subfolder (the shared token vault lives there and is managed only by WebTokenVault), and
//          it refuses a source tree that carries a first-level secrets folder. On Windows the
//          optional application-pool identity receives ReadAndExecute on the app root (inherit) so
//          IIS can serve the staged application; the grant is verified after applying, and an
//          unresolvable identity or failed grant is a stage failure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.WebUi;

/// <summary>
/// Stages the complete published web application output under
/// <see cref="RdpAuditPaths.WebUiDirectory"/> with per-file SHA-256 verification, idempotent
/// updates and optional read access for the IIS application pool.
/// </summary>
public sealed class WebUiAppStager
{
	/// <summary>Name of the manifest stored in the app root: relative path -> lower-case SHA-256 hex.</summary>
	public const string AppManifestFileName = ".webui-app-manifest.json";

	private readonly string _targetDirectory;
	private readonly string? _webPoolIdentity;

	/// <summary>Creates the stager for the canonical IIS physical path.</summary>
	/// <param name="paths">Path layout providing <see cref="RdpAuditPaths.WebUiDirectory"/>.</param>
	/// <param name="webPoolIdentity">
	/// Optional IIS application-pool identity (e.g. <c>IIS APPPOOL\RdpAuditWebUi</c>) that receives
	/// ReadAndExecute on the app root before staging. Null/blank means no pool grant is applied.
	/// </param>
	public WebUiAppStager(RdpAuditPaths paths, string? webPoolIdentity = null)
	{
		ArgumentNullException.ThrowIfNull(paths);
		_targetDirectory = paths.WebUiDirectory;
		_webPoolIdentity = webPoolIdentity;
	}

	/// <summary>
	/// Stages every file under <paramref name="sourceRoot"/> (the published web application output)
	/// into the app root and verifies the result. web.config is mandatory in the source. Failures
	/// are collected on the result; no exception is thrown for content problems.
	/// </summary>
	public WebUiAppStageResult Stage(string sourceRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sourceRoot);
		WebUiAppStageResult result = new() { TargetDirectory = _targetDirectory };

		string sourceFull = Path.GetFullPath(sourceRoot);
		if (!Directory.Exists(sourceFull))
		{
			result.Failures.Add("The web application output folder does not exist: " + sourceFull);
			return result;
		}

		string webConfigPath = Path.Combine(sourceFull, "web.config");
		if (!File.Exists(webConfigPath))
		{
			result.Failures.Add(
				"The web application output must contain web.config (the ASP.NET Core in-process "
				+ "hosting entry point). Publish RdpAudit.Web, then run Configure IIS again.");
			return result;
		}

		string sourceSecrets = Path.Combine(
			sourceFull,
			RdpAuditPaths.WebUiSecretsFolderName);
		if (Directory.Exists(sourceSecrets))
		{
			result.Failures.Add(
				"The web application output contains a secrets folder; the shared token vault is "
				+ "managed by the product and is never staged from a publish folder.");
			return result;
		}

		try
		{
			Directory.CreateDirectory(_targetDirectory);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			result.Failures.Add("The web application root could not be created: " + ex.Message);
			return result;
		}

		if (OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(_webPoolIdentity))
		{
			if (!WebUiPoolAcl.TryGrantReadAndExecute(_targetDirectory, _webPoolIdentity, out string aclFailure))
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
					"The web application output contains a secrets entry (" + relative
					+ "); the shared token vault is never staged.");
				continue;
			}

			string destination = Path.Combine(_targetDirectory, relative);
			if (!IsInsideTarget(destination))
			{
				result.Failures.Add("A web application file escapes the app root: " + relative);
				continue;
			}

			string sourceHash;
			try
			{
				sourceHash = ComputeSha256(sourcePath);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				result.Failures.Add("A web application file could not be read: " + relative + " (" + ex.Message + ")");
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
		WebUiAppStageResult result)
	{
		try
		{
			Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			result.Failures.Add("A web application destination folder could not be created for " + relative + ": " + ex.Message);
			return false;
		}

		string temporary = Path.Combine(
			Path.GetDirectoryName(destination)!,
			".rdpaudit-app-" + Path.GetFileName(destination) + ".tmp");

		try
		{
			File.Copy(sourcePath, temporary, overwrite: true);
			string temporaryHash = ComputeSha256(temporary);
			if (!string.Equals(temporaryHash, expectedHash, StringComparison.OrdinalIgnoreCase))
			{
				TryDelete(temporary);
				result.Failures.Add("A web application file failed SHA-256 verification before install: " + relative + ".");
				return false;
			}

			File.Move(temporary, destination, overwrite: true);
			string destinationHash = ComputeSha256(destination);
			if (!string.Equals(destinationHash, expectedHash, StringComparison.OrdinalIgnoreCase))
			{
				TryDelete(destination);
				result.Failures.Add("A web application file failed SHA-256 verification after install and was removed: " + relative + ".");
				return false;
			}

			result.FilesCopied++;
			return true;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			TryDelete(temporary);
			result.Failures.Add("A web application file could not be installed: " + relative + " (" + ex.Message + ")");
			return false;
		}
	}

	/// <summary>Deletes manifest-tracked files that no longer exist in the publish output.</summary>
	private void RemoveStaleFiles(
		Dictionary<string, string> priorManifest,
		HashSet<string> currentFiles,
		WebUiAppStageResult result)
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
				result.Failures.Add("A stale web application file could not be removed: " + relative + " (" + ex.Message + ")");
			}
		}
	}

	private Dictionary<string, string> ReadManifest()
	{
		string manifestPath = Path.Combine(_targetDirectory, AppManifestFileName);
		return WebUiManifestFile.Read(manifestPath);
	}

	private void WriteManifest(Dictionary<string, string> manifest, WebUiAppStageResult result)
	{
		string manifestPath = Path.Combine(_targetDirectory, AppManifestFileName);
		if (!WebUiManifestFile.Write(manifestPath, manifest, out string? manifestFailure))
		{
			result.Failures.Add(manifestFailure!);
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

/// <summary>
/// Shared atomic manifest I/O used by the app stager and (historically) the wwwroot publisher.
/// The file maps relative paths to lower-case SHA-256 hex. An unreadable manifest must never
/// block the next stage: it only disables stale cleanup and makes every file a rewrite candidate.
/// </summary>
internal static class WebUiManifestFile
{
	public static Dictionary<string, string> Read(string manifestPath)
	{
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
			return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		}
	}

	public static bool Write(string manifestPath, Dictionary<string, string> manifest, out string? failure)
	{
		failure = null;
		string temporary = manifestPath + ".tmp";
		try
		{
			string json = JsonSerializer.Serialize(
				manifest,
				new JsonSerializerOptions { WriteIndented = true });
			File.WriteAllText(temporary, json, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			File.Move(temporary, manifestPath, overwrite: true);
			return true;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			try
			{
				if (File.Exists(temporary))
				{
					File.Delete(temporary);
				}
			}
			catch
			{
				// Best effort.
			}

			failure = "The web application manifest could not be written: " + ex.Message;
			return false;
		}
	}
}

/// <summary>Outcome of one <see cref="WebUiAppStager.Stage"/> run.</summary>
public sealed class WebUiAppStageResult
{
	/// <summary>Absolute target directory the stage was performed into.</summary>
	public string TargetDirectory { get; internal set; } = string.Empty;

	/// <summary>Files actually written during this run.</summary>
	public int FilesCopied { get; internal set; }

	/// <summary>Files whose on-disk SHA-256 matches the source after the run (written or already current).</summary>
	public int FilesVerified { get; internal set; }

	/// <summary>Manifest-tracked files removed because they disappeared from the publish output.</summary>
	public int StaleFilesRemoved { get; internal set; }

	/// <summary>Curated failure lines; empty means the stage succeeded.</summary>
	public List<string> Failures { get; } = new();

	/// <summary>True when no failure was recorded.</summary>
	public bool Succeeded => Failures.Count == 0;
}
