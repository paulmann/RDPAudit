// File:    src/RdpAudit.Core/Util/ScCommandBuilder.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure builder for sc.exe argument lists. sc.exe uses a "key= value" syntax
//          where the equals sign MUST be glued to the option name and the value MUST
//          arrive as a SEPARATE argv token. When the option and value are passed as
//          a single argv element (e.g. "binPath= C:\Path"), sc.exe reports exit 1639
//          (ERROR_INVALID_COMMAND_LINE). This builder encodes the correct shape so
//          ProcessStartInfo.ArgumentList yields a command-line sc.exe accepts.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Pure builder for sc.exe argument lists. Each method returns the argv tokens
/// to feed to <c>ProcessStartInfo.ArgumentList</c> verbatim. No quoting is applied here —
/// .NET's <c>PasteArguments</c> will quote tokens that contain spaces.</summary>
public static class ScCommandBuilder
{
	/// <summary>Builds the argv for <c>sc.exe create</c>. Both the option name (ending
	/// with <c>=</c>) and its value are emitted as separate argv tokens, which is the
	/// shape sc.exe parses correctly even when the value contains spaces.</summary>
	public static IReadOnlyList<string> BuildCreate(string serviceName, string binaryPath, string displayName, string startType = "auto", string objAccount = "LocalSystem")
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		ArgumentException.ThrowIfNullOrEmpty(binaryPath);
		ArgumentException.ThrowIfNullOrEmpty(displayName);
		ArgumentException.ThrowIfNullOrEmpty(startType);
		ArgumentException.ThrowIfNullOrEmpty(objAccount);

		return new[]
		{
			"create",
			serviceName,
			"binPath=", binaryPath,
			"start=", startType,
			"obj=", objAccount,
			"DisplayName=", displayName,
		};
	}

	/// <summary>Builds the argv for <c>sc.exe config</c> used to repoint an existing
	/// service at a (possibly new) binary path and reassert the start type.</summary>
	public static IReadOnlyList<string> BuildConfig(string serviceName, string binaryPath, string startType = "auto")
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		ArgumentException.ThrowIfNullOrEmpty(binaryPath);
		ArgumentException.ThrowIfNullOrEmpty(startType);

		return new[]
		{
			"config",
			serviceName,
			"binPath=", binaryPath,
			"start=", startType,
		};
	}

	/// <summary>Builds the argv for <c>sc.exe create</c> with the binary path wrapped in literal
	/// double quotes so the registry <c>ImagePath</c> is stored quoted. This is the recommended
	/// shape when the executable path contains spaces (e.g. <c>C:\Program Files\...</c>): without
	/// the literal quotes some tools that read the raw <c>ImagePath</c> token split it at the
	/// first space and report the executable as <c>C:\Program</c>. .NET's argument escaper turns
	/// the leading/trailing quotes into <c>\"</c> when it serialises argv, so sc.exe receives the
	/// quoted token verbatim and writes it that way to the registry.</summary>
	public static IReadOnlyList<string> BuildCreateQuoted(string serviceName, string binaryPath, string displayName, string startType = "auto", string objAccount = "LocalSystem")
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		ArgumentException.ThrowIfNullOrEmpty(binaryPath);
		ArgumentException.ThrowIfNullOrEmpty(displayName);
		ArgumentException.ThrowIfNullOrEmpty(startType);
		ArgumentException.ThrowIfNullOrEmpty(objAccount);

		return new[]
		{
			"create",
			serviceName,
			"binPath=", WrapInLiteralQuotes(binaryPath),
			"start=", startType,
			"obj=", objAccount,
			"DisplayName=", displayName,
		};
	}

	/// <summary>Builds the argv for <c>sc.exe config</c> with the binary path wrapped in literal
	/// double quotes. See <see cref="BuildCreateQuoted"/> for the rationale.</summary>
	public static IReadOnlyList<string> BuildConfigQuoted(string serviceName, string binaryPath, string startType = "auto")
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		ArgumentException.ThrowIfNullOrEmpty(binaryPath);
		ArgumentException.ThrowIfNullOrEmpty(startType);

		return new[]
		{
			"config",
			serviceName,
			"binPath=", WrapInLiteralQuotes(binaryPath),
			"start=", startType,
		};
	}

	/// <summary>Wrap <paramref name="value"/> in literal ASCII double-quote characters. If the
	/// value already begins with a quote it is returned unchanged so callers cannot accidentally
	/// double-quote a path that was already quoted at the call site.</summary>
	internal static string WrapInLiteralQuotes(string value)
	{
		ArgumentException.ThrowIfNullOrEmpty(value);
		if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
		{
			return value;
		}

		return "\"" + value + "\"";
	}

	/// <summary>Builds the argv for <c>sc.exe failure</c>. <paramref name="resetSeconds"/>
	/// is how long the failure counter is preserved; <paramref name="actions"/> follows
	/// the documented <c>action/delay</c> syntax (e.g. <c>restart/60000/restart/60000/restart/60000</c>).</summary>
	public static IReadOnlyList<string> BuildFailure(string serviceName, int resetSeconds, string actions)
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		ArgumentException.ThrowIfNullOrEmpty(actions);
		ArgumentOutOfRangeException.ThrowIfNegative(resetSeconds);

		return new[]
		{
			"failure",
			serviceName,
			"reset=", resetSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
			"actions=", actions,
		};
	}

	/// <summary>Builds the argv for <c>sc.exe delete</c>.</summary>
	public static IReadOnlyList<string> BuildDelete(string serviceName)
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		return new[] { "delete", serviceName };
	}

	/// <summary>Builds the argv for <c>sc.exe query</c>. Useful for diagnostics.</summary>
	public static IReadOnlyList<string> BuildQuery(string serviceName)
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		return new[] { "query", serviceName };
	}

	/// <summary>Builds the argv for <c>sc.exe queryex</c>, which additionally exposes the
	/// hosting process PID for running services. Required by the Service tab to display
	/// the running service's process id alongside lifecycle controls.</summary>
	public static IReadOnlyList<string> BuildQueryExtended(string serviceName)
	{
		ArgumentException.ThrowIfNullOrEmpty(serviceName);
		return new[] { "queryex", serviceName };
	}
}
