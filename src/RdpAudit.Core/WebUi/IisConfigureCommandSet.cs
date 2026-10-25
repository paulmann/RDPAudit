// File:    src/RdpAudit.Core/WebUi/IisConfigureCommandSet.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Deterministic command catalog and configuration model for the Configure IIS workflow
//          (plan Step 11, variant A). IIS hosts the web UI as a full in-process application:
//          site "RdpAuditWebUi" bound to the loopback literal https://127.0.0.1:443, served by
//          the application pool "RdpAuditWebUi" (ApplicationPoolIdentity, no managed-runtime
//          coupling). The builders live here in Core so every command shape is unit-testable
//          without a Windows host; nothing in this file EVER executes a command or changes
//          system state. Idempotency is explicit: the workflow lists an object first, adds it
//          when absent and sets its properties when present; the HTTPS certificate binding is
//          delete-then-add so a repeat run converges instead of failing on a duplicate reservation.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;

namespace RdpAudit.Core.WebUi;

/// <summary>Canonical deployment identities of the IIS-hosted web UI.</summary>
public static class IisWebUiDefaults
{
	/// <summary>IIS application pool name serving the web UI.</summary>
	public const string PoolName = "RdpAuditWebUi";

	/// <summary>IIS site name of the web UI.</summary>
	public const string SiteName = "RdpAuditWebUi";

	/// <summary>Virtual account of the application pool (identityType=ApplicationPoolIdentity).</summary>
	public const string PoolAccountName = @"IIS APPPOOL\RdpAuditWebUi";

	/// <summary>Loopback HTTPS port of the site. Deliberately NOT 8443: that port belongs to
	/// the Kestrel REST backend the proxy forwards to.</summary>
	public const int HttpsPort = 443;

	/// <summary>Operator-visible home URL after a successful configure.</summary>
	public const string HttpsUrl = "https://127.0.0.1:443/";
}

/// <summary>
/// Raw, executable command catalog for the Configure IIS workflow. The binding uses the exact
/// loopback literal, never a wildcard; site and pool names are fixed by
/// <see cref="IisWebUiDefaults"/>. All argument vectors are plain string lists for
/// ProcessStartInfo.ArgumentList - no shell, no concatenation of dynamic input.
/// </summary>
public static class IisConfigureCommandSet
{
	/// <summary>Fixed appid used for the HTTP.sys certificate reservation (an arbitrary stable GUID).</summary>
	public const string SslCertAppId = "{9f4a4c3e-7ae2-4b26-9cf0-0d2a12dc2e57}";

	/// <summary>Literal binding information of the site: ip:port:host with an empty host header.</summary>
	public static readonly string LoopbackBindingInformation = "127.0.0.1:" + IisWebUiDefaults.HttpsPort.ToString(CultureInfo.InvariantCulture) + ":";

	/// <summary>Executable of the HTTP.sys certificate reservation tool (lives in System32, always on PATH).</summary>
	public const string NetshExecutable = "netsh.exe";

	/// <summary>Resolves the full path of appcmd.exe on this host (%windir%\system32\inetsrv\appcmd.exe).
	/// inetsrv is deliberately NOT on PATH, so the path is resolved instead of relying on PATH lookup.</summary>
	[SupportedOSPlatform("windows")]
	public static string ResolveAppCmdExecutable()
		=> Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "inetsrv", "appcmd.exe");

	/// <summary>File name of the IIS management tool the Configure IIS workflow resolves through
	/// <see cref="ResolveAppCmdExecutable"/>. The Install IIS workflow checks its presence to decide
	/// whether the management-tools feature still has to be enabled.</summary>
	public const string AppCmdFileName = "appcmd.exe";

	/// <summary>Argument vector: list every site (idempotency pre-check; the output parser looks for
	/// a 'SITE "name"' line).</summary>
	public static IReadOnlyList<string> BuildListSitesArguments() => ["list", "site"];

	/// <summary>Argument vector: list every application pool (idempotency pre-check).</summary>
	public static IReadOnlyList<string> BuildListAppPoolsArguments() => ["list", "apppool"];

	/// <summary>Argument vector: stop the site before restaging the app binaries. callers treat a
	/// non-zero exit as benign - a stopped/missing site still leaves the workflow converged.</summary>
	public static IReadOnlyList<string> BuildStopSiteArguments() => ["stop", "site", IisWebUiDefaults.SiteName];

	/// <summary>Argument vector: start the site (final operation state).</summary>
	public static IReadOnlyList<string> BuildStartSiteArguments() => ["start", "site", IisWebUiDefaults.SiteName];

	/// <summary>Argument vector: read the installed IIS modules (ANCM presence pre-check; the output parser
	/// looks for an 'AspNetCoreModuleV2' entry - the module is in-process hosting's hard prerequisite).</summary>
	public static IReadOnlyList<string> BuildListConfigModulesArguments()
		=> ["list", "config", "-section:system.webServer/modules"];

	/// <summary>Argument vector: enable Windows Authentication for the site (committed to apphost as a site
	/// location). Used only when the operator opens the binding beyond the loopback; the loopback-only
	/// binding deliberately skips it so the browser never prompts on the local dashboard.</summary>
	public static IReadOnlyList<string> BuildSetWindowsAuthenticationArguments()
		=> ["set", "config", IisWebUiDefaults.SiteName + "/",
			"-section:system.webServer/security/authentication/windowsAuthentication",
			"/enabled:true",
			"/commit:apphost"];

	/// <summary>Argument vector: add the site with the loopback HTTPS binding. The add-form binding
	/// literal is 'protocol/bindingInformation' (a slash, not a scheme colon): https/127.0.0.1:443:.</summary>
	public static IReadOnlyList<string> BuildAddSiteArguments(string physicalPath)
		=> ["add", "site",
			"/name:" + IisWebUiDefaults.SiteName,
			"/physicalPath:" + physicalPath,
			"/bindings:" + BuildAddBindingLiteral()];

	/// <summary>Argument vector: refresh the physical path of an already existing site. The binding is
	/// untouched so a pre-existing operator-managed binding is never overwritten.</summary>
	public static IReadOnlyList<string> BuildSetSiteArguments(string physicalPath)
		=> ["set", "site",
			"/site.name:" + IisWebUiDefaults.SiteName,
			"/physicalPath:" + physicalPath];

	/// <summary>Argument vector: add the application pool with no managed-runtime coupling.</summary>
	public static IReadOnlyList<string> BuildAddAppPoolArguments()
		=> ["add", "apppool", "/name:" + IisWebUiDefaults.PoolName, "/managedRuntimeVersion:"];

	/// <summary>Argument vector: reset the pool's runtime coupling to the canonical shape (no CLR).</summary>
	public static IReadOnlyList<string> BuildSetAppPoolArguments()
		=> ["set", "apppool", IisWebUiDefaults.PoolName, "/managedRuntimeVersion:"];

	/// <summary>Argument vector: pin the site's root application to the dedicated pool, so the
	/// in-process proxy runs under the identity that may read the shared token vault.</summary>
	public static IReadOnlyList<string> BuildSetRootAppPoolArguments()
		=> ["set", "app", IisWebUiDefaults.SiteName + "/", "/applicationPool:" + IisWebUiDefaults.PoolName];

	/// <summary>Argument vector: remove an existing HTTP.sys certificate reservation for the loopback
	/// port (idempotency step; a missing reservation is not an error - the caller ignores the exit code).</summary>
	public static IReadOnlyList<string> BuildNetshDeleteSslCertArguments()
		=> ["http", "delete", "sslcert", "ipport=" + LoopbackBindingInformation.TrimEnd(':')];

	/// <summary>Argument vector: reserve the HTTPS certificate for the loopback port.</summary>
	public static IReadOnlyList<string> BuildNetshAddSslCertArguments(string certHash)
		=> ["http", "add", "sslcert",
			"ipport=" + LoopbackBindingInformation.TrimEnd(':'),
			"certhash=" + certHash,
			"appid=" + SslCertAppId];

	/// <summary>Executable used to stop/start the RdpAudit Windows service after the backend settings change.</summary>
	public const string ScExecutable = "sc.exe";

	/// <summary>Add-form binding literal: protocol/bindingInformation (https/127.0.0.1:443:).</summary>
	public static string BuildAddBindingLiteral() => "https/" + LoopbackBindingInformation;

	/// <summary>Argument vector: stop the RdpAudit service so a restart re-reads the backend API settings.
	/// A non-zero exit (service already stopped) is benign; the caller decides how to record it.</summary>
	public static IReadOnlyList<string> BuildScStopServiceArguments(string serviceName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		return ["stop", serviceName];
	}

	/// <summary>Argument vector: start the RdpAudit service after the backend settings changed.</summary>
	public static IReadOnlyList<string> BuildScStartServiceArguments(string serviceName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		return ["start", serviceName];
	}
}

/// <summary>
/// Locale-stable parsing of appcmd list output. The config-dump lines ('SITE "name" (...)' and
/// 'APPPOOL "name" (...)') are configuration element names, not localized messages, so matching
/// them is safe on any host language.
/// </summary>
public static class AppCmdListOutputs
{
	/// <summary>True when the site list contains a 'SITE "name"' config line.</summary>
	public static bool ContainsSiteNamed(string? stdout, string siteName)
		=> ContainsObjectLine(stdout, "SITE", siteName);

	/// <summary>True when the pool list contains an 'APPPOOL "name"' config line.</summary>
	public static bool ContainsAppPoolNamed(string? stdout, string poolName)
		=> ContainsObjectLine(stdout, "APPPOOL", poolName);

	/// <summary>True when the module list contains an AspNetCoreModuleV2 entry (the ANCM
	/// in-process hosting module). The module name is a configuration element, not a localized
	/// message, so matching it is locale-stable. This is in-process hosting's hard prerequisite.</summary>
	public static bool ContainsAspNetCoreModuleV2(string? stdout)
	{
		if (string.IsNullOrWhiteSpace(stdout))
		{
			return false;
		}

		foreach (string rawLine in stdout.Split('\r', '\n'))
		{
			if (rawLine.Contains("AspNetCoreModuleV2", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}

	private static bool ContainsObjectLine(string? stdout, string elementName, string objectName)
	{
		if (string.IsNullOrWhiteSpace(stdout) || string.IsNullOrWhiteSpace(objectName))
		{
			return false;
		}

		string prefix = elementName + " ";
		string quoted = "\"" + objectName + "\"";
		foreach (string rawLine in stdout.Split('\r', '\n'))
		{
			string line = rawLine.Trim();
			if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
				&& line.Contains(quoted, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}
}
