// File:    src/RdpAudit.Core/MikroTik/MikroTikUrlBuilder.cs
// Module:  RdpAudit.Core.MikroTik
// Purpose: Pure helper that composes the base REST URL for a MikroTik RouterOS v7 endpoint from a
//          MikroTikOptions instance. Validates host syntax and rejects schemes / hosts that could
//          turn the outbound HTTP call into a request to an unexpected target. Tested without any
//          HTTP dependency in RdpAudit.Core.Tests.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.MikroTik;

/// <summary>Pure helper that composes the base REST URL for a MikroTik RouterOS v7 endpoint.</summary>
public static class MikroTikUrlBuilder
{
	/// <summary>Outcome of a URL composition attempt.</summary>
	public sealed class Result
	{
		public bool Ok { get; init; }
		public string Url { get; init; } = string.Empty;
		public string? Error { get; init; }

		public static Result Success(string url) => new() { Ok = true, Url = url };

		public static Result Fail(string message) => new() { Ok = false, Error = message };
	}

	/// <summary>Composes the base REST URL from the supplied options.</summary>
	/// <remarks>
	/// Resolution order:
	/// 1. If <see cref="MikroTikOptions.BaseUrl"/> is non-empty, validate and use it.
	/// 2. Otherwise compose from Scheme/Host/Port.
	/// 3. Reject empty / invalid input with a structured error so the caller can surface it to UI.
	/// </remarks>
	public static Result Build(MikroTikOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);

		if (!string.IsNullOrWhiteSpace(options.BaseUrl))
		{
			return ValidateBaseUrl(options.BaseUrl.Trim());
		}

		if (string.IsNullOrWhiteSpace(options.Host))
		{
			return Result.Fail("Host is empty.");
		}

		string scheme = options.UseHttps ? "https" : "http";
		string host = options.Host.Trim();
		if (!IsValidHost(host))
		{
			return Result.Fail("Host contains characters that are not allowed.");
		}

		int port = options.Port;
		if (port < 0 || port > 65535)
		{
			return Result.Fail("Port is out of range.");
		}

		// Wrap IPv6 hosts in brackets so the resulting URL is parseable.
		string hostForUrl = WrapIpv6IfNeeded(host);

		string url = port > 0
			? string.Format(CultureInfo.InvariantCulture, "{0}://{1}:{2}", scheme, hostForUrl, port)
			: string.Format(CultureInfo.InvariantCulture, "{0}://{1}", scheme, hostForUrl);

		return ValidateBaseUrl(url);
	}

	/// <summary>Joins the base URL with a REST path under /rest, defensive against double slashes.</summary>
	public static string CombineRestPath(string baseUrl, string restRelativePath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
		ArgumentException.ThrowIfNullOrWhiteSpace(restRelativePath);

		string trimmedBase = baseUrl.TrimEnd('/');
		string trimmedPath = restRelativePath.TrimStart('/');
		if (!trimmedPath.StartsWith("rest/", StringComparison.OrdinalIgnoreCase) && !string.Equals(trimmedPath, "rest", StringComparison.OrdinalIgnoreCase))
		{
			trimmedPath = "rest/" + trimmedPath;
		}
		return string.Concat(trimmedBase, "/", trimmedPath);
	}

	private static Result ValidateBaseUrl(string url)
	{
		if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed))
		{
			return Result.Fail("BaseUrl is not a valid absolute URI.");
		}

		if (!string.Equals(parsed.Scheme, "http", StringComparison.OrdinalIgnoreCase)
			&& !string.Equals(parsed.Scheme, "https", StringComparison.OrdinalIgnoreCase))
		{
			return Result.Fail("Only http and https schemes are allowed.");
		}

		if (string.IsNullOrWhiteSpace(parsed.Host))
		{
			return Result.Fail("BaseUrl has an empty host.");
		}

		// Re-emit a canonical form without trailing slash so CombineRestPath works deterministically.
		string canonical = parsed.IsDefaultPort
			? string.Format(CultureInfo.InvariantCulture, "{0}://{1}", parsed.Scheme, parsed.Host)
			: string.Format(CultureInfo.InvariantCulture, "{0}://{1}:{2}", parsed.Scheme, parsed.Host, parsed.Port);

		return Result.Success(canonical);
	}

	private static bool IsValidHost(string host)
	{
		if (host.Length == 0 || host.Length > 253)
		{
			return false;
		}

		// Allow IPv4 / IPv6 literals.
		if (IPAddress.TryParse(host, out _))
		{
			return true;
		}

		foreach (char c in host)
		{
			if (char.IsAsciiLetterOrDigit(c))
			{
				continue;
			}
			if (c == '-' || c == '.' || c == '_')
			{
				continue;
			}
			return false;
		}
		return true;
	}

	private static string WrapIpv6IfNeeded(string host)
	{
		if (host.Length == 0 || host[0] == '[')
		{
			return host;
		}

		if (IPAddress.TryParse(host, out IPAddress? parsed)
			&& parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
		{
			return string.Concat("[", host, "]");
		}
		return host;
	}
}
