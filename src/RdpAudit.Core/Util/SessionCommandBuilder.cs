// File:    src/RdpAudit.Core/Util/SessionCommandBuilder.cs
// Module:  RdpAudit.Core.Util
// Purpose: Composes argument lists for the external command-line tools used to query and
//          control RDP sessions (query session / qwinsta, tsdiscon, logoff, mstsc /shadow).
//          Pure list builders — they never spawn processes themselves, never concatenate
//          user input into a single shell string, and are exercised by Core unit tests so
//          syntax bugs are caught off-Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Session id validation result.</summary>
public sealed record SessionIdValidation(bool Ok, string? Error)
{
	public static SessionIdValidation Valid { get; } = new(true, null);
}

/// <summary>Argument-list builders for the external session-control tools.</summary>
public static class SessionCommandBuilder
{
	/// <summary>Validates a session identifier: must be a non-negative 32-bit integer in
	/// the range Windows actually exposes (0..65535).</summary>
	public static SessionIdValidation ValidateSessionId(int sessionId)
	{
		if (sessionId < 0)
		{
			return new SessionIdValidation(false, "Session id must be non-negative.");
		}

		if (sessionId > 65535)
		{
			return new SessionIdValidation(false, "Session id is out of range (0..65535).");
		}

		return SessionIdValidation.Valid;
	}

	/// <summary>Builds arguments for <c>query session</c> / <c>qwinsta</c>. The /COUNTER switch is
	/// intentionally omitted — only the session list is required.</summary>
	public static IReadOnlyList<string> BuildListSessions()
	{
		// qwinsta lists sessions on the local host by default. No arguments needed.
		return Array.Empty<string>();
	}

	/// <summary>Builds arguments for <c>tsdiscon &lt;sessionId&gt;</c>.</summary>
	public static IReadOnlyList<string> BuildDisconnect(int sessionId)
	{
		SessionIdValidation v = ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			throw new ArgumentOutOfRangeException(nameof(sessionId), v.Error);
		}

		return new[] { sessionId.ToString(CultureInfo.InvariantCulture) };
	}

	/// <summary>Builds arguments for <c>logoff &lt;sessionId&gt;</c>.</summary>
	public static IReadOnlyList<string> BuildLogoff(int sessionId)
	{
		SessionIdValidation v = ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			throw new ArgumentOutOfRangeException(nameof(sessionId), v.Error);
		}

		return new[] { sessionId.ToString(CultureInfo.InvariantCulture) };
	}

	/// <summary>Shadow modes supported by the Remote RDP Clients tab.</summary>
	public enum ShadowMode
	{
		/// <summary>View only — prompts the user.</summary>
		ViewOnly,

		/// <summary>View + control — prompts the user.</summary>
		Control,

		/// <summary>View + control — no consent prompt (requires policy).</summary>
		ControlNoConsent,
	}

	/// <summary>Builds the argument list for <c>mstsc.exe /shadow:&lt;id&gt; [/control] [/noConsentPrompt] [/admin]</c>.
	/// Always non-blocking: mstsc launches its own window. The session id is interpolated only
	/// into the <c>/shadow:</c> switch and is validated as a non-negative integer first.
	/// Control modes append <c>/admin</c> so the shadow connects to the administrative listener
	/// on hardened Windows hosts where the regular RDP listener is restricted — mirrors the
	/// operator's known-good manual command line
	/// (<c>mstsc /noConsentPrompt /control /admin /shadow:&lt;id&gt;</c>).</summary>
	public static IReadOnlyList<string> BuildShadow(int sessionId, ShadowMode mode)
	{
		SessionIdValidation v = ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			throw new ArgumentOutOfRangeException(nameof(sessionId), v.Error);
		}

		List<string> args = new()
		{
			"/shadow:" + sessionId.ToString(CultureInfo.InvariantCulture),
		};

		if (mode == ShadowMode.Control || mode == ShadowMode.ControlNoConsent)
		{
			args.Add("/control");
		}

		if (mode == ShadowMode.ControlNoConsent)
		{
			args.Add("/noConsentPrompt");
		}

		if (mode == ShadowMode.Control || mode == ShadowMode.ControlNoConsent)
		{
			args.Add("/admin");
		}

		return args;
	}
}
