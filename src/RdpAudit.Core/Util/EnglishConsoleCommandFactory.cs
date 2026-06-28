// File:    src/RdpAudit.Core/Util/EnglishConsoleCommandFactory.cs
// Module:  RdpAudit.Core.Util
// Purpose: Generalized parse-stable English console factory. Produces the cmd.exe spawn
//          parameters required to run a whitelisted Windows command-line tool through
//          cmd.exe /d /c "chcp 437 >nul & <command>" so the stdout stream contains the
//          stable English / Latin-script tokens — regardless of the operator's UI culture.
//
//          Why this exists alongside SessionConsoleCommandFactory:
//          * SessionConsoleCommandFactory is the Stage-1 specialized helper for qwinsta /
//            quser. Its contract / tests are frozen and this factory preserves it.
//          * Stage 3 needs the same chcp-437 wrapping for additional parsed-stdout commands
//            (netsh "show rule name=all verbose", auditpol /get /r, gpresult /scope computer
//            /r). Those commands carry either no operator input (auditpol /get, gpresult)
//            or a small typed argument set (netsh rule name / port). To stay injection-safe
//            this factory only accepts a whitelisted command spec — the caller never passes
//            raw operator input.
//
//          Shell-injection safety:
//          * The factory exposes a small enum of trusted commands (TrustedEnglishConsoleTool).
//            The composed cmd.exe /c command string is built from constants for the tool
//            invocation plus typed, validated arguments. Every dynamic value (port,
//            session id) is validated to be a strictly numeric / well-formed token before
//            being interpolated.
//          * cmd.exe quoting: arguments that need to reach the inner tool are first quoted
//            with QuoteForCmd which escapes embedded double quotes by doubling them — the
//            same convention cmd.exe uses when parsing /c "..." commands. Tokens are always
//            taken from a whitelist or validated by a typed builder, so the quoting step is
//            a defense-in-depth guarantee, not the only line of defense.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Whitelisted external tools that may be spawned through the English console by
/// <see cref="EnglishConsoleCommandFactory"/>. Each entry maps to a single tool invocation
/// shape — callers never pass raw command strings.</summary>
public enum TrustedEnglishConsoleTool
{
	/// <summary>Sentinel — never passed to the factory.</summary>
	None = 0,

	/// <summary>qwinsta.exe — query session list (no arguments).</summary>
	Qwinsta = 1,

	/// <summary>quser.exe — query logged-on users (no arguments).</summary>
	Quser = 2,

	/// <summary>netsh advfirewall firewall show rule name=all verbose — verbose firewall
	/// rule dump used by the prerequisite scanner and the firewall page.</summary>
	NetshShowAllRulesVerbose = 3,

	/// <summary>netsh advfirewall show allprofiles state — profile-state probe used by the
	/// Windows firewall provider.</summary>
	NetshShowAllProfilesState = 4,

	/// <summary>auditpol /get /subcategory:{guid} /r — locale-tolerant CSV read for one
	/// subcategory GUID.</summary>
	AuditpolGetSubcategoryCsv = 5,

	/// <summary>gpresult /scope computer /r — computer-scope group policy summary. Output
	/// is locale-stable when chcp 437 is in effect; only used for parsed checks.</summary>
	GpresultScopeComputer = 6,

	/// <summary>netsh advfirewall firewall show rule name={ruleName} verbose — verbose dump for a
	/// SINGLE named rule used by the Windows firewall provider's post-block verification. Routing it
	/// through the English console keeps the parsed keys ("Rule Name:", "Enabled:", "Direction:",
	/// "Action:") in Latin script on a localised host, where Direct mode would emit translated /
	/// mojibake field labels that the netsh text scanner cannot match. The rule name is a typed,
	/// validated token (conservative ASCII set), not raw operator input.</summary>
	NetshShowNamedRuleVerbose = 7,
}

/// <summary>Typed arguments accepted by tools that take dynamic but strictly-validated input.</summary>
public sealed record EnglishConsoleArgs
{
	/// <summary>Subcategory GUID for <see cref="TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv"/>.
	/// Must be a parseable Guid; the factory validates this and refuses anything else.</summary>
	public string? SubcategoryGuid { get; init; }

	/// <summary>Firewall rule name for <see cref="TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose"/>.
	/// Must match the conservative ASCII rule-name set; the factory validates this and refuses anything
	/// else so no token can break out of the cmd <c>/c</c> command string.</summary>
	public string? RuleName { get; init; }
}

/// <summary>Composed cmd.exe spawn parameters for a trusted English-console command.</summary>
public sealed record EnglishConsoleSpawn(
	string Executable,
	string Arguments,
	int CodePage,
	string CommandLabel);

/// <summary>Builds the ProcessStartInfo inputs for a parse-stable English-console invocation
/// of a whitelisted command. Single-purpose: composes the cmd.exe argument string from
/// constants and validated tokens. Pure code — no Windows API calls.</summary>
public static class EnglishConsoleCommandFactory
{
	/// <summary>The code page pinned by <c>chcp 437</c>. The US-OEM page guarantees the
	/// English state tokens emitted by qwinsta / quser / netsh / auditpol / gpresult.</summary>
	public const int EnglishConsoleCodePage = SessionConsoleCommandFactory.EnglishConsoleCodePage;

	/// <summary>Builds the spawn for a tool that requires no dynamic arguments.</summary>
	public static EnglishConsoleSpawn Build(TrustedEnglishConsoleTool tool)
		=> Build(tool, args: null);

	/// <summary>Builds the spawn for a tool that may require typed, validated arguments.</summary>
	public static EnglishConsoleSpawn Build(TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args)
	{
		(string inner, string label) = ComposeInner(tool, args);

		// /d  — skip AutoRun keys (no third-party hooks)
		// /c  — run the command then exit
		// chcp 437 >nul  — pin US-OEM (English) code page for this console
		// &   — sequence into the trusted tool invocation
		string arguments = "/d /c \"chcp "
			+ EnglishConsoleCodePage.ToString(CultureInfo.InvariantCulture)
			+ " >nul & "
			+ inner
			+ "\"";

		return new EnglishConsoleSpawn(
			Executable: SessionConsoleCommandFactory.ResolveCmdExe(),
			Arguments: arguments,
			CodePage: EnglishConsoleCodePage,
			CommandLabel: label);
	}

	/// <summary>Returns the inner command string and a stable label for the chosen tool.</summary>
	private static (string Inner, string Label) ComposeInner(
		TrustedEnglishConsoleTool tool,
		EnglishConsoleArgs? args)
	{
		switch (tool)
		{
			case TrustedEnglishConsoleTool.Qwinsta:
				return ("qwinsta.exe", "qwinsta");

			case TrustedEnglishConsoleTool.Quser:
				return ("quser.exe", "quser");

			case TrustedEnglishConsoleTool.NetshShowAllRulesVerbose:
				return (
					"netsh.exe advfirewall firewall show rule name=all verbose",
					"netsh advfirewall firewall show rule name=all verbose");

			case TrustedEnglishConsoleTool.NetshShowAllProfilesState:
				return (
					"netsh.exe advfirewall show allprofiles state",
					"netsh advfirewall show allprofiles state");

			case TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv:
				{
					string guid = ValidateGuid(args?.SubcategoryGuid);
					return (
						"auditpol.exe /get /subcategory:" + guid + " /r",
						"auditpol /get /subcategory:" + guid + " /r");
				}

			case TrustedEnglishConsoleTool.GpresultScopeComputer:
				return ("gpresult.exe /scope computer /r", "gpresult /scope computer /r");

			case TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose:
				{
					string ruleName = ValidateRuleName(args?.RuleName);
					return (
						"netsh.exe advfirewall firewall show rule name=" + QuoteForCmd(ruleName) + " verbose",
						"netsh advfirewall firewall show rule name=" + ruleName + " verbose");
				}

			default:
				throw new ArgumentOutOfRangeException(nameof(tool), tool, "Unknown trusted English-console tool.");
		}
	}

	/// <summary>Validates and normalizes a subcategory GUID for interpolation into the
	/// auditpol command string. Refuses any value that does not round-trip through Guid.Parse —
	/// blocks injection of arbitrary tokens into the cmd /c command string.</summary>
	internal static string ValidateGuid(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			throw new ArgumentException("Subcategory GUID is required for AuditpolGetSubcategoryCsv.", nameof(value));
		}

		if (!Guid.TryParse(value, out Guid parsed))
		{
			throw new ArgumentException("Subcategory GUID must be a valid GUID literal.", nameof(value));
		}

		// Use the {B}-form ("{0CCE9215-69AE-11D9-BED3-505054503030}") — the on-disk auditpol
		// reference shape. Upper-cased so the interpolated token is deterministic.
		return parsed.ToString("B", CultureInfo.InvariantCulture).ToUpperInvariant();
	}

	/// <summary>Validates a firewall rule name for interpolation into the netsh show-rule command
	/// string. Accepts only the conservative ASCII set the rule-name builder produces (letters,
	/// digits, '-', '_', '.', ':') so no shell-significant character can reach the cmd /c command —
	/// a defense-in-depth match to the producer-side validation. Refuses null / empty / over-long
	/// input.</summary>
	internal static string ValidateRuleName(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			throw new ArgumentException("Rule name is required for NetshShowNamedRuleVerbose.", nameof(value));
		}

		if (value.Length > 200)
		{
			throw new ArgumentException("Rule name exceeds 200 characters.", nameof(value));
		}

		foreach (char c in value)
		{
			if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ':'))
			{
				throw new ArgumentException("Rule name contains characters not permitted in a firewall rule name.", nameof(value));
			}
		}

		return value;
	}

	/// <summary>Wraps a token in double quotes for the inner cmd <c>/c</c> command, doubling any
	/// embedded double quote (cmd's own escaping convention). Defense-in-depth: the only callers pass
	/// values already restricted to a shell-inert ASCII set, so this never has to neutralise a real
	/// metacharacter — it simply guarantees the token is treated as a single argument.</summary>
	internal static string QuoteForCmd(string value)
	{
		value ??= string.Empty;
		return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
	}
}
