// File:    src/RdpAudit.Core/Util/ScDeleteOutputFormatter.cs
// Module:  RdpAudit.Core.Util
// Purpose: Stage 4 — pure formatter for the "sc delete" outcome detail string shown
//          in the Service tab uninstall dialog. Combines a clean English fallback
//          ("[SC] DeleteService SUCCESS" / "[SC] DeleteService FAILED exit=<code>")
//          with the native sc.exe output when it decoded readably, so operators on
//          non-English Windows never see an empty or mojibake-only message.
//          Lifted out of ServiceControlRunner so it can be exercised by unit tests.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Pure formatter for the sc.exe delete outcome string surfaced to the operator.</summary>
public static class ScDeleteOutputFormatter
{
	/// <summary>English success banner used when sc.exe exits 0 — always included even when
	/// the captured native message decoded readably, so the dialog is unambiguous on every
	/// supported Windows locale.</summary>
	public const string EnglishSuccess = "[SC] DeleteService SUCCESS";

	/// <summary>Composes a guaranteed-readable English detail string for a successful
	/// <c>sc delete</c> invocation. When the captured native sc.exe output is non-empty and
	/// decoded readably it is appended to the English banner; otherwise the banner alone is
	/// returned so the dialog never shows mojibake.</summary>
	public static string ComposeSuccess(string? capturedOutput)
	{
		if (string.IsNullOrWhiteSpace(capturedOutput))
		{
			return EnglishSuccess;
		}

		string trimmed = capturedOutput.Trim();
		if (!IsReadable(trimmed))
		{
			return EnglishSuccess;
		}

		return EnglishSuccess + " — " + trimmed;
	}

	/// <summary>Composes a clean English failure detail string for a non-zero exit. The
	/// English banner ("[SC] DeleteService FAILED exit=&lt;code&gt;") is always present;
	/// the captured native message is appended only when it decoded readably.</summary>
	public static string ComposeFailure(int exitCode, string? capturedOutput)
	{
		string banner = "[SC] DeleteService FAILED exit=" + exitCode.ToString(CultureInfo.InvariantCulture);
		if (string.IsNullOrWhiteSpace(capturedOutput))
		{
			return banner;
		}

		string trimmed = capturedOutput.Trim();
		if (!IsReadable(trimmed))
		{
			return banner;
		}

		return banner + " — " + trimmed;
	}

	/// <summary>Returns true when the captured sc.exe output looks like decoded text rather
	/// than a string of replacement / control characters. Used to decide whether the native
	/// message should be shown alongside the English banner or replaced by it entirely.</summary>
	public static bool IsReadable(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		int printable = 0;
		int total = 0;
		foreach (char c in value)
		{
			if (char.IsWhiteSpace(c))
			{
				continue;
			}

			total++;
			if (c == '�')
			{
				continue;
			}

			if (char.IsControl(c))
			{
				continue;
			}

			printable++;
		}

		if (total == 0)
		{
			return false;
		}

		// At least 80% of the non-whitespace characters must be printable. Empirically a
		// mis-decoded OEM string contains a dense cluster of U+FFFD replacement characters
		// and control bytes, so this threshold drops them while keeping legitimate localized
		// text (e.g. Cyrillic, Chinese, CJK, accented Latin) intact.
		return printable * 5 >= total * 4;
	}
}
