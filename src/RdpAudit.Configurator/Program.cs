// File:    src/RdpAudit.Configurator/Program.cs
// Module:  RdpAudit.Configurator
// Purpose: WinForms entry point.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;

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
		Application.Run(new MainForm());
	}
}
