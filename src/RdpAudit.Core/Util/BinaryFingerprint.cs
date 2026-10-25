// File:    src/RdpAudit.Core/Util/BinaryFingerprint.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure value object describing a service binary on disk: file version,
//          product version, length, last-write time UTC, and SHA-256 hash. Used by
//          the Service tab to compare installed vs distribution binaries and to
//          decide whether an update is available.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Immutable description of a service binary on disk.</summary>
public sealed record BinaryFingerprint(
	string Path,
	bool Exists,
	string? FileVersion,
	string? ProductVersion,
	long Length,
	DateTime? LastWriteTimeUtc,
	string? Sha256)
{
	/// <summary>Returns true when both fingerprints describe an existing file and every
	/// content-defining field matches: length, SHA-256, file version, and product version.
	/// Last-write time alone is informational and never causes inequality on its own.</summary>
	public bool IsContentIdentical(BinaryFingerprint? other)
	{
		if (other is null)
		{
			return false;
		}

		if (!Exists || !other.Exists)
		{
			return false;
		}

		if (Length != other.Length)
		{
			return false;
		}

		if (!string.Equals(Sha256, other.Sha256, StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		if (!string.Equals(FileVersion, other.FileVersion, StringComparison.Ordinal))
		{
			return false;
		}

		if (!string.Equals(ProductVersion, other.ProductVersion, StringComparison.Ordinal))
		{
			return false;
		}

		return true;
	}
}
