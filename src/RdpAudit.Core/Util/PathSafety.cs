// File:    src/RdpAudit.Core/Util/PathSafety.cs
// Module:  RdpAudit.Core.Util
// Purpose: Path traversal-safe combination helpers.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Path traversal-safe combination helpers.</summary>
public static class PathSafety
{
	/// <summary>
	/// Combines a base directory and child file name, throwing on path traversal.
	/// </summary>
	public static string SafeChildPath(string baseDir, string fileName)
	{
		ArgumentNullException.ThrowIfNull(baseDir);
		ArgumentNullException.ThrowIfNull(fileName);

		string normalisedBase = Path.GetFullPath(baseDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
		string full = Path.GetFullPath(Path.Combine(normalisedBase, fileName));
		if (!full.StartsWith(normalisedBase, StringComparison.OrdinalIgnoreCase))
		{
			throw new ArgumentException($"Path traversal detected: {fileName}", nameof(fileName));
		}

		return full;
	}
}
