// File:    src/RdpAudit.Core/Util/OemConsoleEncoding.cs
// Module:  RdpAudit.Core.Util
// Purpose: Central helper for resolving the Windows OEM (console) code page used by
//          legacy console-mode tools — sc.exe, qwinsta.exe, quser.exe, netsh, ... —
//          when their stdout / stderr is captured with redirection. .NET defaults
//          Console.OutputEncoding to UTF-8 on Windows, but redirected console output
//          from these classic tools is still written in the active OEM code page
//          (cp866 on Russian-locale Windows, cp437 on English builds, cp850 on many
//          Western-European builds). Decoding that stream as UTF-8 produces mojibake
//          and breaks operator-facing messages such as the "[SC] DeleteService SUCCESS"
//          confirmation. This helper resolves the correct Encoding so callers can
//          pass it to ProcessStartInfo.StandardOutputEncoding / StandardErrorEncoding.
//          Pure code — no Windows API calls — so it is fully unit-testable off-Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace RdpAudit.Core.Util;

/// <summary>Central helper for resolving the Windows OEM (console) code page used by
/// legacy console-mode tools (sc.exe, qwinsta.exe, netsh, ...) for their redirected
/// stdout / stderr streams.</summary>
public static class OemConsoleEncoding
{
	/// <summary>US-OEM (English) console code page — the historical sc.exe fallback when
	/// the active OEM code page cannot be resolved.</summary>
	public const int Cp437 = 437;

	private static int s_providerRegistered;

	/// <summary>Returns the encoding that should be passed to
	/// <c>ProcessStartInfo.StandardOutputEncoding</c> / <c>StandardErrorEncoding</c>
	/// when capturing the stdout of a classic console tool on Windows. The chosen
	/// encoding matches the active console's OEM code page so locale-specific status
	/// lines decode correctly (e.g. the Russian Windows "[SC] DeleteService: успех" form).
	/// On non-Windows hosts UTF-8 is returned so tests do not depend on a specific
	/// machine code page.</summary>
	/// <param name="oemCodePageOverride">Optional override for the OEM code page —
	/// used by unit tests to pin a specific value (cp437 / cp850 / cp866) regardless of
	/// the test host's current culture. When null the value of
	/// <see cref="TextInfo.OEMCodePage"/> on the current culture is consulted on Windows,
	/// and UTF-8 is used on non-Windows.</param>
	public static Encoding Resolve(int? oemCodePageOverride = null)
	{
		EnsureProviderRegistered();

		int? target = oemCodePageOverride ?? ResolveDefault();
		if (target is null || target.Value <= 0)
		{
			return TryGetEncoding(Cp437) ?? Encoding.UTF8;
		}

		return TryGetEncoding(target.Value) ?? TryGetEncoding(Cp437) ?? Encoding.UTF8;
	}

	/// <summary>Registers <see cref="CodePagesEncodingProvider.Instance"/> exactly once so
	/// <see cref="Encoding.GetEncoding(int)"/> can resolve legacy OEM code pages such as
	/// cp866 or cp437 under .NET 8 (where the default encoding registry only contains
	/// UTF-8 / ASCII / a handful of others).</summary>
	public static void EnsureProviderRegistered()
	{
		if (System.Threading.Interlocked.Exchange(ref s_providerRegistered, 1) == 0)
		{
			Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
		}
	}

	private static int? ResolveDefault()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return null;
		}

		int code = CultureInfo.CurrentCulture.TextInfo.OEMCodePage;
		return code > 0 ? code : null;
	}

	private static Encoding? TryGetEncoding(int codePage)
	{
		try
		{
			return Encoding.GetEncoding(codePage);
		}
		catch (ArgumentException)
		{
			return null;
		}
		catch (NotSupportedException)
		{
			return null;
		}
	}
}
