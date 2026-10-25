// File:    src/RdpAudit.Core/Util/SessionConsoleCommandFactory.cs
// Module:  RdpAudit.Core.Util
// Purpose: Builds the exact ProcessStartInfo arguments for spawning qwinsta / quser through
//          a parse-stable English console — cmd.exe /d /c "chcp 437 >nul & <tool>". Pinning
//          the active code page to 437 (US OEM) is the documented technique for forcing
//          Windows console tools to emit Latin-script state tokens regardless of the
//          operator's UI culture, so the English STATE column tokens (Active / Disc / Conn /
//          Listen) are produced even on Russian-language Windows builds.
//
//          Shell-injection safety: the spawned command line is built from a FIXED whitelist
//          (TrustedTool enum) — no operator input ever flows into the command string. The
//          arguments list is fixed too. ProcessStartInfo is configured with FileName="cmd.exe"
//          and a single Arguments string composed entirely from constants, so the user can
//          never inject additional tokens.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Whitelisted external tools that may be spawned through the English console.</summary>
public enum TrustedSessionTool
{
	/// <summary>Sentinel value — never passed to <see cref="SessionConsoleCommandFactory.Build"/>.</summary>
	None = 0,

	/// <summary>qwinsta.exe — query session list.</summary>
	Qwinsta = 1,

	/// <summary>quser.exe — query logged-on users.</summary>
	Quser = 2,
}

/// <summary>The composed cmd.exe spawn parameters for a trusted tool.</summary>
public sealed record SessionConsoleSpawn(string Executable, string Arguments, int CodePage);

/// <summary>Builds the ProcessStartInfo inputs for a parse-stable English-console invocation.</summary>
public static class SessionConsoleCommandFactory
{
	/// <summary>The code page pinned by <c>chcp 437</c>. The US-OEM page guarantees the
	/// English state tokens emitted by qwinsta / quser without requiring the operator to
	/// change Region settings.</summary>
	public const int EnglishConsoleCodePage = 437;

	/// <summary>Returns the cmd.exe + arguments-string pair required to spawn the specified
	/// trusted tool through a chcp 437 console. The arguments string is single-quoted by
	/// cmd.exe's /c switch which means everything between the first and last double quote is
	/// treated as the command — exactly what we need to keep the chcp + tool invocation
	/// atomic.</summary>
	public static SessionConsoleSpawn Build(TrustedSessionTool tool)
	{
		string innerCommand = tool switch
		{
			TrustedSessionTool.Qwinsta => "qwinsta.exe",
			TrustedSessionTool.Quser => "quser.exe",
			_ => throw new ArgumentOutOfRangeException(nameof(tool), tool, "Unknown trusted session tool."),
		};

		// /d  — skip AutoRun keys (no third-party hooks)
		// /c  — run the command then exit
		// chcp 437 >nul  — pin US-OEM (English) code page for this console
		// &   — sequence into the trusted tool invocation
		string arguments = "/d /c \"chcp "
			+ EnglishConsoleCodePage.ToString(System.Globalization.CultureInfo.InvariantCulture)
			+ " >nul & "
			+ innerCommand
			+ "\"";

		return new SessionConsoleSpawn(
			Executable: ResolveCmdExe(),
			Arguments: arguments,
			CodePage: EnglishConsoleCodePage);
	}

	/// <summary>Resolves the absolute path to <c>cmd.exe</c>. Always returns a non-empty
	/// string — when the System32 directory cannot be resolved the unqualified name is used
	/// so Process.Start surfaces a deterministic Win32 error instead of a NullReferenceException.</summary>
	public static string ResolveCmdExe()
	{
		string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
		if (!string.IsNullOrEmpty(sys32))
		{
			string candidate = System.IO.Path.Combine(sys32, "cmd.exe");
			if (System.IO.File.Exists(candidate))
			{
				return candidate;
			}
		}

		return "cmd.exe";
	}
}
