// File:    src/RdpAudit.Configurator/Services/ShadowLauncher.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side launcher for mstsc.exe /shadow. Because the service runs
//          under LocalSystem and cannot launch interactive UI, the Configurator is the
//          only safe place to spawn mstsc — but only after the service-side IPC handler
//          has approved the request against the SessionControl + shadow policy. The
//          launcher uses ProcessStartInfo.ArgumentList exclusively (no shell concat),
//          spawns mstsc detached, and surfaces the start-time exit / errors back to UI.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Result of a shadow-launch attempt — the Process is started but not awaited.</summary>
public sealed record ShadowLaunchResult(bool Started, int? ProcessId, string? Error);

/// <summary>Configurator-side launcher for <c>mstsc.exe /shadow</c>.</summary>
[SupportedOSPlatform("windows")]
public sealed class ShadowLauncher
{
	/// <summary>Spawns <c>mstsc.exe</c> with sanitized arguments. The process is started detached;
	/// the Configurator does NOT wait for it so the UI thread remains responsive.</summary>
	public ShadowLaunchResult Launch(int sessionId, SessionCommandBuilder.ShadowMode mode)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			return new ShadowLaunchResult(false, null, v.Error);
		}

		IReadOnlyList<string> args = SessionCommandBuilder.BuildShadow(sessionId, mode);
		ProcessStartInfo psi = new("mstsc.exe")
		{
			UseShellExecute = false,
			CreateNoWindow = false,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		try
		{
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return new ShadowLaunchResult(false, null, "mstsc.exe failed to start (Process.Start returned null).");
			}

			return new ShadowLaunchResult(true, proc.Id, null);
		}
		catch (Win32Exception ex)
		{
			return new ShadowLaunchResult(false, null,
				string.Format(CultureInfo.InvariantCulture,
					"mstsc.exe launch failed: Win32 error {0} — {1}", ex.NativeErrorCode, ex.Message));
		}
		catch (Exception ex)
		{
			return new ShadowLaunchResult(false, null,
				string.Format(CultureInfo.InvariantCulture,
					"mstsc.exe launch failed: {0} — {1}", ex.GetType().Name, ex.Message));
		}
	}
}
