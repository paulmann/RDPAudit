// File:    src/RdpAudit.Core/Util/QwinstaConsoleEncoding.cs
// Module:  RdpAudit.Core.Util
// Purpose: Resolves the correct text encoding for reading qwinsta.exe stdout. qwinsta
//          writes through the standard Windows console pipe using the active OEM code
//          page (cp866 on Russian-locale Windows builds, cp437 on English builds) — not
//          UTF-8. .NET 5+ defaults Console.OutputEncoding to UTF-8 on Windows, which
//          produces mojibake (e.g. "ЂЄб...") when the underlying console is OEM. This
//          helper registers the legacy code-page provider and selects the OEM code page
//          deterministically so the Cyrillic state tokens emitted by Russian Windows
//          are decoded correctly. Pure code — no Windows API calls, fully unit-testable
//          off-Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Util;

/// <summary>Resolves the correct text encoding for reading qwinsta.exe stdout.</summary>
public static class QwinstaConsoleEncoding
{
	private static int s_providerRegistered;

	/// <summary>Returns the encoding that should be passed to
	/// <c>ProcessStartInfo.StandardOutputEncoding</c> when spawning qwinsta. The chosen
	/// encoding matches the active console's OEM code page so the Russian state tokens
	/// ("Активно" / "Диск" / etc.) decode correctly. UTF-8 is used as a last resort when
	/// the OEM code page cannot be resolved (non-Windows / unusual sandbox setups).</summary>
	/// <param name="oemCodePage">Optional override for the OEM code page — defaults to
	/// <see cref="TextInfo.OEMCodePage"/> for the current culture. Lets tests pass cp866
	/// or cp437 without changing host culture.</param>
	public static Encoding Resolve(int? oemCodePage = null)
	{
		EnsureProviderRegistered();

		int target = oemCodePage ?? CultureInfo.CurrentCulture.TextInfo.OEMCodePage;
		if (target <= 0)
		{
			return Encoding.UTF8;
		}

		try
		{
			return Encoding.GetEncoding(target);
		}
		catch (ArgumentException)
		{
			return Encoding.UTF8;
		}
		catch (NotSupportedException)
		{
			return Encoding.UTF8;
		}
	}

	/// <summary>Registers <see cref="CodePagesEncodingProvider.Instance"/> exactly once so
	/// <see cref="Encoding.GetEncoding(int)"/> can resolve legacy code pages such as cp866
	/// under .NET 8 (where the default encoding registry only contains UTF-8 / ASCII).</summary>
	public static void EnsureProviderRegistered()
	{
		if (System.Threading.Interlocked.Exchange(ref s_providerRegistered, 1) == 0)
		{
			Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
		}
	}
}
