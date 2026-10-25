// File:    src/RdpAudit.Core/Siem/SiemEscape.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Single home of the strict per-format escaping rules for the SIEM renderers. Every
//          method first neutralises CR / LF / TAB to a single space so an external value can
//          never inject a record boundary, then applies the format-specific escape set.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;

namespace RdpAudit.Core.Siem;

/// <summary>Strict escaping helpers for CEF and LEEF. No culture-dependent behaviour.</summary>
public static class SiemEscape
{
	/// <summary>Escapes a CEF header field: backslash and pipe are escaped, CR / LF / TAB become a space.</summary>
	public static string CefHeader(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			switch (c)
			{
				case '\\':
					sb.Append("\\\\");
					break;
				case '|':
					sb.Append("\\|");
					break;
				case '\r':
				case '\n':
				case '\t':
					sb.Append(' ');
					break;
				default:
					sb.Append(c);
					break;
			}
		}

		return sb.ToString();
	}

	/// <summary>Escapes a CEF extension value: backslash, equals and pipe are escaped, CR / LF /
	/// TAB become a space.</summary>
	public static string CefExtensionValue(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			switch (c)
			{
				case '\\':
					sb.Append("\\\\");
					break;
				case '=':
					sb.Append("\\=");
					break;
				case '|':
					sb.Append("\\|");
					break;
				case '\r':
				case '\n':
				case '\t':
					sb.Append(' ');
					break;
				default:
					sb.Append(c);
					break;
			}
		}

		return sb.ToString();
	}

	/// <summary>Escapes a LEEF header field: backslash and pipe are escaped, CR / LF / TAB become a space.</summary>
	public static string LeefHeader(string? value) => CefHeader(value);

	/// <summary>Escapes a LEEF attribute value: backslash, caret and pipe are escaped, CR / LF /
	/// TAB become a space.</summary>
	public static string LeefValue(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			switch (c)
			{
				case '\\':
					sb.Append("\\\\");
					break;
				case '^':
					sb.Append("\\^");
					break;
				case '|':
					sb.Append("\\|");
					break;
				case '\r':
				case '\n':
				case '\t':
					sb.Append(' ');
					break;
				default:
					sb.Append(c);
					break;
			}
		}

		return sb.ToString();
	}
}
