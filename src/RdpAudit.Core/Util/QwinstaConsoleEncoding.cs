// File:    src/RdpAudit.Core/Util/QwinstaConsoleEncoding.cs
// Module:  RdpAudit.Core.Util
// Purpose: Historical name for the console-encoding resolver. There used to be TWO independent
//          resolvers for the same job (this one and OemConsoleEncoding) that had DRIFTED apart: this
//          one fell back to UTF-8, the other to cp437, so identical redirected console output was
//          decoded differently depending on which helper a call site happened to use - and a fix to
//          one policy never reached the other. This type is now a thin delegate over
//          OemConsoleEncoding, which owns the single policy, and exists only so the call sites and
//          their tests keep their published names.
//
//          New code should call OemConsoleEncoding.Resolve directly.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;

namespace RdpAudit.Core.Util;

/// <summary>Console-encoding resolver kept for compatibility; all policy lives in
/// <see cref="OemConsoleEncoding"/>.</summary>
public static class QwinstaConsoleEncoding
{
	/// <summary>Resolves the encoding for a console tool's redirected stdout. Defers to
	/// <see cref="OemConsoleEncoding.Resolve(int?)"/>, including its fallback policy: an unresolvable
	/// code page yields cp437 (a real OEM page), never UTF-8.</summary>
	/// <param name="oemCodePage">Optional OEM code-page override; null consults the host's active OEM
	/// code page on Windows, and the shared fallback elsewhere. Lets tests pin cp866 or cp437 without
	/// changing host culture.</param>
	public static Encoding Resolve(int? oemCodePage = null) => OemConsoleEncoding.Resolve(oemCodePage);

	/// <summary>Registers the legacy code-page provider exactly once. Same single registration as
	/// <see cref="OemConsoleEncoding.EnsureProviderRegistered"/>; kept because tests assert the
	/// idempotency of this entry point.</summary>
	public static void EnsureProviderRegistered() => OemConsoleEncoding.EnsureProviderRegistered();
}
