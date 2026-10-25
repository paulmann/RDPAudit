// File:    src/RdpAudit.Configurator/Program.cs
// Module:  RdpAudit.Configurator
// Purpose: WinForms entry point.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Services;

namespace RdpAudit.Configurator;

/// <summary>WinForms entry point.</summary>
[SupportedOSPlatform("windows")]
public static class Program
{
	[STAThread]
	public static void Main()
	{
		ApplicationConfiguration.Initialize();
		Application.SetHighDpiMode(HighDpiMode.SystemAware);

		// Attach the global safety net before the first window exists: from here on an exception that
		// escapes an async event handler (async void - no caller left to catch it) is journalled and
		// reported instead of terminating the process and discarding unsaved state. See
		// ConfiguratorExceptionGuard and docs/30-configurator.md.
		ConfiguratorExceptionGuard.Default.Install();

		Application.Run(new MainForm());
	}
}
