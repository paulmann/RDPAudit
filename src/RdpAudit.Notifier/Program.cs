// File:    src/RdpAudit.Notifier/Program.cs
// Module:  RdpAudit.Notifier
// Purpose: WinForms tray entry point. Polls the service for new alerts in the background and
//          renders them as balloon tips via a single-tray NotifyIcon.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Notifier.Forms;

namespace RdpAudit.Notifier;

/// <summary>Tray notifier entry point.</summary>
[SupportedOSPlatform("windows10.0.19041.0")]
public static class Program
{
	[STAThread]
	public static void Main()
	{
		ApplicationConfiguration.Initialize();
		Application.SetHighDpiMode(HighDpiMode.SystemAware);
		Application.Run(new TrayApplicationContext());
	}
}
