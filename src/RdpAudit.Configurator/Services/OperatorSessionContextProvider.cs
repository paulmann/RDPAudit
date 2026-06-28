// File:    src/RdpAudit.Configurator/Services/OperatorSessionContextProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: v1.3.8 — capture the interactive operator's runtime context (the WTS session the
//          Configurator process runs in, plus the current Windows identity / username) so the
//          pure Core CurrentRdpSessionMatcher can scope the RDP Clients "Current?" column to the
//          session that belongs to the operator. This MUST run inside the operator's interactive
//          process: the LocalSystem service cannot know which session the operator uses, which is
//          exactly why the prior version mislabelled every active rdp-tcp# session as Current.
//          Reading the process SessionId / WindowsIdentity is side-effect-free and never throws
//          for the caller (any failure degrades to an "unknown" component, which the matcher then
//          falls back from to identity / username matching).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Captures the operator's <see cref="OperatorSessionContext"/> from the running
/// Configurator process. Pure-ish: it reads OS state but performs no mutation and never throws.</summary>
[SupportedOSPlatform("windows")]
public sealed class OperatorSessionContextProvider
{
	/// <summary>Read the current process SessionId, the current Windows identity name
	/// (<c>WindowsIdentity.GetCurrent().Name</c>, e.g. "XEON\md") and the environment username
	/// (<c>Environment.UserName</c> / <c>$env:USERNAME</c>, e.g. "md"). Any component that cannot be
	/// resolved is returned as its "unknown" sentinel (negative session id / null string) so the
	/// matcher can fall back gracefully.</summary>
	public OperatorSessionContext Capture()
	{
		int sessionId = TryReadProcessSessionId();
		string? identityName = TryReadIdentityName();
		string? userName = TryReadUserName();
		return new OperatorSessionContext(sessionId, identityName, userName);
	}

	private static int TryReadProcessSessionId()
	{
		try
		{
			using Process current = Process.GetCurrentProcess();
			return current.SessionId;
		}
		catch (Exception ex) when (ex is InvalidOperationException or PlatformNotSupportedException or NotSupportedException)
		{
			return -1;
		}
	}

	private static string? TryReadIdentityName()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			return identity.Name;
		}
		catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or PlatformNotSupportedException)
		{
			return null;
		}
	}

	private static string? TryReadUserName()
	{
		try
		{
			string user = Environment.UserName;
			return string.IsNullOrWhiteSpace(user) ? null : user;
		}
		catch (InvalidOperationException)
		{
			return null;
		}
	}
}
