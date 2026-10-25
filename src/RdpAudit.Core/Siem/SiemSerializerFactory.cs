// File:    src/RdpAudit.Core/Siem/SiemSerializerFactory.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Single entry point that resolves a SIEM format into a serializer or a file-name
//          feature. The file-helpers mirror the IpEventsExportFormatter convention: a canonical
//          extension (lower-case, leading dot), a SaveFileDialog filter line and a stable default
//          file name carrying a UTC stamp.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Siem;

/// <summary>Resolves SIEM formats to serializers and file-name features.</summary>
public static class SiemSerializerFactory
{
	private static readonly CefSerializer Cef = new();

	private static readonly LeefSerializer Leef = new();

	private static readonly SiemJsonSerializer Json = new();

	/// <summary>Returns the serializer for a format.</summary>
	public static ISiemEventSerializer GetSerializer(SiemFormat format) => format switch
	{
		SiemFormat.Cef => Cef,
		SiemFormat.Leef => Leef,
		SiemFormat.JsonNdjson => Json,
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported SIEM export format."),
	};

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(SiemFormat format) => format switch
	{
		SiemFormat.Cef => ".cef",
		SiemFormat.Leef => ".leef",
		SiemFormat.JsonNdjson => ".json",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported SIEM export format."),
	};

	/// <summary>Returns a SaveFileDialog filter line for a format, e.g. "CEF (*.cef)|*.cef".</summary>
	public static string GetSaveFileFilter(SiemFormat format) => format switch
	{
		SiemFormat.Cef => "CEF (*.cef)|*.cef",
		SiemFormat.Leef => "LEEF (*.leef)|*.leef",
		SiemFormat.JsonNdjson => "JSON Lines (*.json)|*.json",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported SIEM export format."),
	};

	/// <summary>Builds a sensible default file name for the SaveFileDialog: <c>rdpaudit-siem-{safeIp}-{utc}.{ext}</c>.</summary>
	public static string GetDefaultFileName(string ip, SiemFormat format, DateTime nowUtc)
	{
		string safeIp = SanitiseFileNameSegment(ip);
		string stamp = nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
		return string.Format(CultureInfo.InvariantCulture,
			"rdpaudit-siem-{0}-{1}{2}", safeIp, stamp, GetFileExtension(format));
	}

	private static string SanitiseFileNameSegment(string raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return "ip";
		}

		char[] chars = raw.Trim().ToCharArray();
		for (int i = 0; i < chars.Length; i++)
		{
			char c = chars[i];
			chars[i] = char.IsLetterOrDigit(c) || c == '.' || c == '-' ? c : '_';
		}

		return new string(chars);
	}
}
