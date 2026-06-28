// File:    src/RdpAudit.Core/Util/BinaryFingerprintReader.cs
// Module:  RdpAudit.Core.Util
// Purpose: Reads a BinaryFingerprint from disk by hashing the file (SHA-256),
//          reading length and last-write time, and probing FileVersionInfo for
//          FileVersion and ProductVersion. All errors are swallowed and surfaced
//          as a fingerprint with Exists=false plus null version fields so the UI
//          can render diagnostics rather than crash.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;

namespace RdpAudit.Core.Util;

/// <summary>Reads a <see cref="BinaryFingerprint"/> from disk.</summary>
public static class BinaryFingerprintReader
{
	/// <summary>Reads the fingerprint at <paramref name="path"/>. Returns a fingerprint
	/// with <c>Exists=false</c> when the path is null/empty/missing. All exceptions are
	/// captured and reflected as best-effort: an unreadable file yields a fingerprint
	/// whose fields are populated where possible and null elsewhere.</summary>
	public static BinaryFingerprint Read(string? path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return new BinaryFingerprint(
				Path: path ?? string.Empty,
				Exists: false,
				FileVersion: null,
				ProductVersion: null,
				Length: 0,
				LastWriteTimeUtc: null,
				Sha256: null);
		}

		string normalized;
		try
		{
			normalized = System.IO.Path.GetFullPath(path);
		}
		catch (Exception)
		{
			normalized = path;
		}

		if (!File.Exists(normalized))
		{
			return new BinaryFingerprint(
				Path: normalized,
				Exists: false,
				FileVersion: null,
				ProductVersion: null,
				Length: 0,
				LastWriteTimeUtc: null,
				Sha256: null);
		}

		long length = 0;
		DateTime? lastWrite = null;
		try
		{
			FileInfo info = new(normalized);
			length = info.Length;
			lastWrite = info.LastWriteTimeUtc;
		}
		catch (Exception)
		{
			// ignored — emit what we can
		}

		string? fileVersion = null;
		string? productVersion = null;
		try
		{
			FileVersionInfo info = FileVersionInfo.GetVersionInfo(normalized);
			fileVersion = NormalizeVersion(info.FileVersion);
			productVersion = NormalizeVersion(info.ProductVersion);
		}
		catch (Exception)
		{
			// ignored — version may be missing on small/empty files
		}

		string? sha = null;
		try
		{
			using FileStream stream = new(normalized, FileMode.Open, FileAccess.Read, FileShare.Read);
			byte[] hash = SHA256.HashData(stream);
			sha = Convert.ToHexString(hash);
		}
		catch (Exception)
		{
			// ignored — locked file still gets a fingerprint without hash
		}

		return new BinaryFingerprint(
			Path: normalized,
			Exists: true,
			FileVersion: fileVersion,
			ProductVersion: productVersion,
			Length: length,
			LastWriteTimeUtc: lastWrite,
			Sha256: sha);
	}

	private static string? NormalizeVersion(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string trimmed = value.Trim();
		// Some metadata generators emit trailing CR/LF or "+commit" suffix; preserve
		// the core "M.m.b.r" / SemVer surface for stable equality checks.
		int plus = trimmed.IndexOf('+', StringComparison.Ordinal);
		if (plus >= 0)
		{
			trimmed = trimmed[..plus];
		}

		return trimmed.Length == 0 ? null : trimmed.ToString(CultureInfo.InvariantCulture);
	}
}
